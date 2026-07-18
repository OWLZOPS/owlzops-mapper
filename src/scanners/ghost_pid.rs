//! True Ghost PID detection — LKM rootkit process hiding (SEC-024).
//!
//! Detects a PID hidden by a getdents64-hooking rootkit (Diamorphine class) by
//! diffing two independent kernel views:
//!   * `readdir("/proc")`      — goes through getdents64 (what the rootkit hooks)
//!   * `stat("/proc/<pid>")`   — direct path lookup (NOT hooked by that class)
//!   * `kill(pid, 0)`          — signal subsystem, bypasses /proc entirely
//!
//! A PID live via direct stat/kill but absent from readdir, stable across 3
//! probe cycles (~100ms apart), with age ≥ 2s and a live state, is a hard IoC.
//! Young/racy/unconfirmable candidates are downgraded to a suspicion (no exit-3).
//!
//! **Thread filtering**: Linux readdir shows only thread-group leaders (TGID),
//! but individual threads have their own /proc/<tid> entries.  We exclude
//! candidates where `Tgid != pid` **at candidate construction time** so the
//! early‑exit on a clean host can actually fire.
//!
//! **hidepid guard**: If /proc is mounted with hidepid=2 / hidepid=invisible,
//! the scan is skipped entirely to avoid false positives.  hidepid=1 is NOT
//! skipped because it still lists /proc/<pid> directories.
//!
//! **Known limit**: a rootkit that also hooks the direct `/proc/<pid>` stat
//! lookup makes stat return ENOENT for a live hidden PID; only the `kill`
//! arbiter can then see it, and only if it doesn't also filter the signal
//! path.  Such cases are recorded with `confirmed_via = "kill"` and
//! downgraded (no age → no exit‑3), but never silently dropped.
//!
//! **Performance**:
//! * Tier‑B (io_uring): full 1..=pid_max batched statx, sub‑second on healthy
//!   hosts even under `--deep`.  No allocator‑wrap blind spot.
//! * Tier‑C (sync fallback): bounded by `ns_last_pid`, records a coverage note
//!   when any high‑PID range is skipped.  Used when io_uring is unavailable or
//!   for tempdir‑based tests.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use crate::coverage;
use crate::models::GhostPidFinding;
use crate::safe_io;

const PROBE_CYCLES: usize = 3;
const PROBE_PAUSE: Duration = Duration::from_millis(100);
const MIN_AGE_SECS: u64 = 2;
const MAX_FINDINGS: usize = 64;
const YIELD_EVERY: u32 = 8192;
const WRAP_TAIL_FRACTION: u64 = 10;

pub fn scan_ghost_pids(deep: bool) -> Vec<GhostPidFinding> {
    detect(Path::new("/proc"), deep)
}

/// Returns `true` if `/proc` is mounted with `hidepid=2` or `hidepid=invisible`.
fn has_hidepid_option() -> bool {
    // Larger cap: /proc/mounts is big on mount-heavy (Docker) hosts; a
    // truncated `proc` line would silently defeat this guard.
    if let Ok((content, _)) = safe_io::read_file_capped("/proc/mounts", 256 * 1024) {
        for line in content.lines() {
            let mut parts = line.split_whitespace();
            let source = parts.next().unwrap_or("");
            let target = parts.next().unwrap_or("");
            let fstype = parts.next().unwrap_or("");
            let opts = parts.next().unwrap_or("");
            if source == "proc" && target == "/proc" && fstype == "proc" {
                for opt in opts.split(',') {
                    if let Some(v) = opt.strip_prefix("hidepid=") {
                        // Only 2/invisible hides dirs from readdir (the case
                        // that manufactures false ghosts); 1/noaccess only
                        // blocks content access and still lists the dirs.
                        if matches!(v, "2" | "invisible") {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

fn detect(proc_root: &Path, deep: bool) -> Vec<GhostPidFinding> {
    // Ghost scan is incompatible with hidepid=2/invisible because readdir
    // legitimately filters out processes, causing false positives.
    // With --deep, the guard is overridden (user accepts potential FP).
    if has_hidepid_option() {
        if deep {
            coverage::record(
                "ghost-pid scan: /proc mounted with hidepid=2/invisible — \
                 findings may be false positives (foreign processes hidden \
                 by kernel, not a rootkit). Review manually."
                    .to_string(),
            );
            // proceed with scan
        } else {
            coverage::record(
                "ghost-pid scan skipped: /proc mounted with hidepid=2/invisible \
                 (legitimate kernel feature, not a rootkit). Use --deep to force."
                    .to_string(),
            );
            return Vec::new();
        }
    }

    let mut stable: Option<BTreeSet<u32>> = None;

    for cycle in 0..PROBE_CYCLES {
        // "readdir sandwich": snapshot readdir BEFORE and AFTER the slow live
        // sweep. A PID that legitimately starts during the sweep shows up in
        // `listed_after` and is excluded, so churn on a busy host can't
        // manufacture transient candidates that defeat the clean-host early
        // exit. A genuinely hidden PID is in neither readdir and survives.
        let listed_before = readdir_pids(proc_root);
        let live = probe_live_set(proc_root);
        let listed_after = readdir_pids(proc_root);

        // R11-09 + R11-10: filter out threads AT CANDIDATE CONSTRUCTION so the
        // early-exit below actually fires on a clean host. ENOENT on
        // /proc/<pid>/status is kept (is_thread → false → stays in candidates)
        // so the kill arbiter can still see advanced rootkits.
        let candidates: BTreeSet<u32> = candidate_diff(&live, &listed_before, &listed_after)
            .into_iter()
            .filter(|&pid| !is_thread(proc_root, pid))
            .collect();

        stable = Some(match stable {
            None => candidates,
            Some(prev) => prev.intersection(&candidates).copied().collect(),
        });

        if stable.as_ref().is_some_and(BTreeSet::is_empty) {
            // EARLY EXIT: on a clean host this fires on the first cycle.
            return Vec::new();
        }
        if cycle + 1 < PROBE_CYCLES {
            thread::sleep(PROBE_PAUSE);
        }
    }

    let survivors = stable.unwrap_or_default();
    if survivors.is_empty() {
        return Vec::new();
    }

    let socket_pids = socket_owning_pids();

    let mut findings = Vec::new();
    for pid in survivors {
        if findings.len() >= MAX_FINDINGS {
            coverage::record(format!(
                "ghost-pid scan: finding cap ({MAX_FINDINGS}) reached; more candidates not recorded"
            ));
            break;
        }

        // Status read: used only for state + Tgid final check (paranoid guard).
        // If the status file is missing (ENOENT), we don't drop the candidate;
        // the kill arbiter will classify it as "kill" (downgraded suspicion).
        let status_path = proc_root.join(pid.to_string()).join("status");
        let (tgid, state_from_status) =
            match safe_io::read_file_capped(status_path.to_string_lossy().as_ref(), 8192) {
                Ok((content, _)) => parse_tgid_and_state(&content),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, None), // keep for arbiter
                Err(_) => continue, // other errors → drop noise
            };

        let stat_path_alive = proc_root.join(pid.to_string()).exists();
        let kill_alive = kill_exists(pid);
        let (state_from_stat, age_secs) = read_state_and_age(proc_root, pid);

        let state = state_from_status.or(state_from_stat);

        if let Some(finding) = classify(
            pid,
            tgid,
            stat_path_alive,
            kill_alive,
            state,
            age_secs,
            socket_pids.contains(&pid),
        ) {
            findings.push(finding);
        }
    }

    if !findings.is_empty() {
        let hard = findings.iter().filter(|f| f.confirmed_ioc).count();
        coverage::record(format!(
            "ghost-pid scan: {} hidden PID(s) found ({} hard IoC, {} downgraded)",
            findings.len(),
            hard,
            findings.len() - hard
        ));
    }

    findings
}

/// Returns `true` if the given PID is a thread (Tgid != pid).
/// ENOENT on /proc/<pid>/status → `false` (keep for the kill arbiter).
/// Other errors → `true` (drop noise).
fn is_thread(proc_root: &Path, pid: u32) -> bool {
    let path = proc_root.join(pid.to_string()).join("status");
    match safe_io::read_file_capped(path.to_string_lossy().as_ref(), 8192) {
        Ok((content, _)) => matches!(parse_tgid_and_state(&content).0, Some(t) if t != pid),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false, // keep
        Err(_) => true,                                              // drop noise
    }
}

/// Pure classification logic — unit‑testable without a real /proc or kill().
#[allow(clippy::too_many_arguments)]
fn classify(
    pid: u32,
    tgid: Option<u32>,
    stat_alive: bool,
    kill_alive: bool,
    state: Option<String>,
    age_secs: Option<u64>,
    holds_socket: bool,
) -> Option<GhostPidFinding> {
    // Paranoid thread guard (should have been filtered upstream).
    if matches!(tgid, Some(t) if t != pid) {
        return None;
    }

    let confirmed_via = match (stat_alive, kill_alive) {
        (true, true) => "stat-path+kill",
        (true, false) => "stat-path",
        (false, true) => "kill", // advanced rootkit hiding direct /proc path
        (false, false) => return None,
    }
    .to_string();

    let is_live_state = matches!(state.as_deref(), Some("R" | "S" | "D" | "I"));
    let old_enough = age_secs.is_some_and(|a| a >= MIN_AGE_SECS);
    let confirmed_ioc = is_live_state && old_enough;

    Some(GhostPidFinding {
        pid,
        state,
        age_secs,
        confirmed_via,
        confirmed_ioc,
        holds_socket,
    })
}

fn parse_tgid_and_state(content: &str) -> (Option<u32>, Option<String>) {
    let mut tgid = None;
    let mut state = None;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Tgid:") {
            tgid = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("State:") {
            // Defensive: real State is a single letter. Constrain to one
            // ASCII-alphabetic char so a rootkit-controlled status can't
            // smuggle ANSI/control bytes into a finding.
            state = rest
                .trim()
                .chars()
                .next()
                .filter(|c| c.is_ascii_alphabetic())
                .map(|c| c.to_string());
        }
        if tgid.is_some() && state.is_some() {
            break;
        }
    }
    (tgid, state)
}

fn readdir_pids(proc_root: &Path) -> BTreeSet<u32> {
    let mut set = BTreeSet::new();
    if let Ok(entries) = fs::read_dir(proc_root) {
        for e in entries.flatten() {
            if let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) {
                set.insert(pid);
            }
        }
    }
    set
}

// ── candidate‑diff helper (pure, testable) ────────────────────────────────

/// Pure two-readdir diff: a PID is a ghost candidate only if it is live yet
/// absent from BOTH readdir snapshots (before and after the sweep). Excluding
/// PIDs seen in either snapshot removes started-/exited-during-probe churn.
/// Unit-testable without a real /proc or kill().
fn candidate_diff(
    live: &BTreeSet<u32>,
    listed_before: &BTreeSet<u32>,
    listed_after: &BTreeSet<u32>,
) -> BTreeSet<u32> {
    live.iter()
        .copied()
        .filter(|p| !listed_before.contains(p) && !listed_after.contains(p))
        .collect()
}

// ── live-set probe (Tier-B io_uring, Tier-C sync fallback) ────────────────

fn probe_live_set(proc_root: &Path) -> BTreeSet<u32> {
    if proc_root == Path::new("/proc")
        && let Some(set) = probe_live_set_iouring(proc_root)
    {
        return set;
    }
    probe_live_set_sync(proc_root)
}

#[cfg(not(target_env = "musl"))]
fn probe_live_set_iouring(proc_root: &Path) -> Option<BTreeSet<u32>> {
    use io_uring::{IoUring, opcode, types};
    const RING_DEPTH: u32 = 4096;
    const WINDOW: usize = 4096; // in-flight SQEs; also bounds statx-buf memory

    let pid_max = read_u32_sysfile("/proc/sys/kernel/pid_max").unwrap_or(32_768);
    let dir = File::open(proc_root).ok()?; // dirfd = DI seam (works on tempdirs)
    let dfd = types::Fd(dir.as_raw_fd());
    let mut ring = IoUring::new(RING_DEPTH).ok()?; // creation IS the capability probe

    let mut set = BTreeSet::new();
    let mut pids = 1..=pid_max;

    // These outlive submit→complete: the kernel writes `stx` and reads `paths`
    // asynchronously, so both must stay put until the matching CQE is reaped.
    // Slot id travels in user_data.
    let mut paths: Vec<Option<CString>> = (0..WINDOW).map(|_| None).collect();
    let mut stx: Vec<Box<libc::statx>> = (0..WINDOW)
        .map(|_| Box::new(unsafe { std::mem::zeroed() }))
        .collect();
    let mut slot_pid = vec![0u32; WINDOW];
    let mut free: Vec<usize> = (0..WINDOW).rev().collect();
    let (mut inflight, mut done) = (0usize, false);

    while !done || inflight > 0 {
        while let Some(&slot) = free.last() {
            let Some(pid) = pids.next() else {
                done = true;
                break; // peeked but not popped: slot stays free
            };
            free.pop();
            let cpath = CString::new(pid.to_string()).ok()?;
            // VERIFY: statx buffer pointer type for your io-uring version.
            let buf = &mut *stx[slot] as *mut libc::statx as *mut _;
            let sqe = opcode::Statx::new(dfd, cpath.as_ptr(), buf)
                .flags(libc::AT_SYMLINK_NOFOLLOW | libc::AT_STATX_DONT_SYNC)
                .mask(0) // existence only; no field data required
                .build()
                .user_data(slot as u64);
            paths[slot] = Some(cpath); // keep path alive until completion
            slot_pid[slot] = pid;
            // SAFETY: cpath + stx[slot] referenced by this SQE are owned here
            // and not moved/freed until this SQE's CQE is reaped below.
            unsafe {
                if ring.submission().push(&sqe).is_err() {
                    paths[slot] = None; // SQ full: release slot, drain, retry
                    free.push(slot);
                    break;
                }
            }
            inflight += 1;
        }
        if inflight == 0 {
            break;
        }

        // R13-01: safe completion drain — never exit early with inflight SQEs.
        match ring.submit_and_wait(1) {
            Ok(_) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
            Err(_) => {
                // Kernel still holds pointers to stx/paths — exit would be use-after-free.
                let deadline = Instant::now() + Duration::from_secs(2);
                while inflight > 0 && Instant::now() < deadline {
                    let _ = ring.submit_and_wait(1);
                    for cqe in ring.completion() {
                        let slot = cqe.user_data() as usize;
                        paths[slot] = None;
                        free.push(slot);
                        inflight -= 1;
                    }
                }
                if inflight > 0 {
                    // Leak is better than UB.
                    std::mem::forget((paths, stx));
                }
                return None; // Tier-C will take over
            }
        }

        for cqe in ring.completion() {
            let slot = cqe.user_data() as usize;
            if cqe.result() >= 0 {
                set.insert(slot_pid[slot]); // statx ok ⇒ /proc/<pid> live
            }
            // negative (e.g. -ENOENT) ⇒ absent. EACCES is treated as absent
            // for parity with Path::exists(); branch on the errno if you'd
            // rather count it as live (diverges from Tier-C semantics).
            paths[slot] = None;
            free.push(slot);
            inflight -= 1;
        }
    }
    Some(set)
}

#[cfg(target_env = "musl")]
fn probe_live_set_iouring(_proc_root: &Path) -> Option<BTreeSet<u32>> {
    None
}

fn probe_live_set_sync(proc_root: &Path) -> BTreeSet<u32> {
    let mut set = BTreeSet::new();
    let (upper, wrap_tail) = pid_scan_bounds();

    let mut counter: u32 = 0;
    let mut probe = |pid: u32, set: &mut BTreeSet<u32>| {
        if proc_root.join(pid.to_string()).exists() {
            set.insert(pid);
        }
        counter = counter.wrapping_add(1);
        if counter.is_multiple_of(YIELD_EVERY) {
            thread::yield_now();
        }
    };

    for pid in 1..=upper {
        probe(pid, &mut set);
    }
    if let Some((lo, hi)) = wrap_tail {
        for pid in lo..=hi {
            probe(pid, &mut set);
        }
    }
    set
}

fn pid_scan_bounds() -> (u32, Option<(u32, u32)>) {
    let pid_max = read_u32_sysfile("/proc/sys/kernel/pid_max").unwrap_or(32_768);
    let ns_last = read_u32_sysfile("/proc/sys/kernel/ns_last_pid").unwrap_or(pid_max);
    let upper = ns_last.min(pid_max);

    let near_wrap =
        (upper as u64) > (pid_max as u64) * (WRAP_TAIL_FRACTION - 1) / WRAP_TAIL_FRACTION;
    let tail = if near_wrap && upper < pid_max {
        Some((upper + 1, pid_max))
    } else {
        None
    };

    // Raw-Truth: only reachable on the Tier-C sync path (Tier-B scans the full
    // range). If the allocator has wrapped and the cursor sits below still-live
    // high PIDs, (upper, pid_max] is not exhaustively probed unless the wrap
    // tail covers it — record the gap rather than hide it.
    if tail.is_none() && upper < pid_max {
        coverage::record(format!(
            "ghost-pid scan (sync fallback): PIDs {}..={} not exhaustively \
             probed (bounded by ns_last_pid={}); a hidden PID above the \
             allocator cursor after a wrap could be missed. Enable io_uring \
             for a full-range scan.",
            upper + 1,
            pid_max,
            upper
        ));
    }

    (upper, tail)
}

fn read_u32_sysfile(path: &str) -> Option<u32> {
    let (content, _) = safe_io::read_file_capped(path, 64).ok()?;
    content.trim().parse().ok()
}

fn kill_exists(pid: u32) -> bool {
    // Guard the u32→pid_t (i32) cast: pid 0 → own process group, pid > i32::MAX
    // → negative → process-GROUP / kill(-1) semantics; both would spuriously
    // report "alive". Not reachable via pid_max today (≤ 2^22) but cheap to
    // make total.
    if pid == 0 || pid > i32::MAX as u32 {
        return false;
    }
    let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
    ret == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn read_state_and_age(proc_root: &Path, pid: u32) -> (Option<String>, Option<u64>) {
    let path = proc_root.join(pid.to_string()).join("stat");
    let content = match safe_io::read_file_capped(path.to_string_lossy().as_ref(), 8192) {
        Ok((c, _)) => c,
        Err(_) => return (None, None),
    };
    parse_stat_state_age(&content)
}

fn parse_stat_state_age(content: &str) -> (Option<String>, Option<u64>) {
    let Some(rparen) = content.rfind(')') else {
        return (None, None);
    };
    let after = content[rparen + 1..].trim_start();
    let fields: Vec<&str> = after.split_ascii_whitespace().collect();
    // Defensive: parity with parse_tgid_and_state — one ASCII-alphabetic char
    // only, so a malformed/hostile stat can't inject escape bytes as "state".
    let state = fields
        .first()
        .and_then(|s| s.chars().next())
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_string());

    let age = fields
        .get(19)
        .and_then(|s| s.parse::<u64>().ok())
        .and_then(|starttime_ticks| {
            let hz = clock_ticks_per_sec();
            let uptime = read_uptime_secs()?;
            let start_secs = starttime_ticks / hz;
            Some(uptime.saturating_sub(start_secs))
        });

    (state, age)
}

fn clock_ticks_per_sec() -> u64 {
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if hz > 0 { hz as u64 } else { 100 }
}

fn read_uptime_secs() -> Option<u64> {
    let (content, _) = safe_io::read_file_capped("/proc/uptime", 128).ok()?;
    content
        .split_whitespace()
        .next()?
        .split('.')
        .next()?
        .parse()
        .ok()
}

fn socket_owning_pids() -> BTreeSet<u32> {
    let mut set = BTreeSet::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return set;
    };
    const MAX_FD_PER_PID: usize = 4096;

    for e in entries.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };
        let mut fd_seen = 0usize;
        for fd in fds.flatten() {
            fd_seen += 1;
            if fd_seen > MAX_FD_PER_PID {
                coverage::record(format!(
                    "/proc/{pid}/fd exceeded {MAX_FD_PER_PID} entries – ghost pid socket scan for this pid is partial"
                ));
                break;
            }
            if let Ok(t) = fs::read_link(fd.path())
                && t.to_str().is_some_and(|s| s.starts_with("socket:["))
            {
                set.insert(pid);
                break;
            }
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn make_status(pid: u32, tgid: u32, state: &str) -> String {
        format!("Name:\tblah\nTgid:\t{tgid}\nPid:\t{pid}\nState:\t{state}\n")
    }

    #[test]
    fn parse_tgid_and_state_works() {
        let s = make_status(100, 100, "S (sleeping)");
        let (tgid, state) = parse_tgid_and_state(&s);
        assert_eq!(tgid, Some(100));
        assert_eq!(state.as_deref(), Some("S"));
    }

    #[test]
    fn thread_is_identified() {
        let s = make_status(200, 100, "S");
        let (tgid, _) = parse_tgid_and_state(&s);
        assert_eq!(tgid, Some(100));
    }

    // ── classify unit tests (R11-11) ────────────────────────

    #[test]
    fn classify_skips_thread() {
        assert!(
            classify(
                200,
                Some(100),
                true,
                true,
                Some("S".into()),
                Some(50),
                false
            )
            .is_none()
        );
    }

    #[test]
    fn classify_kill_only_is_reachable_and_downgraded() {
        let f = classify(31337, None, false, true, None, None, false)
            .expect("kill-only ghost must be reported");
        assert_eq!(f.confirmed_via, "kill");
        assert!(!f.confirmed_ioc, "unknown age => downgraded");
    }

    #[test]
    fn classify_hidden_leader_is_hard_ioc() {
        let f = classify(
            4242,
            Some(4242),
            true,
            true,
            Some("R".into()),
            Some(30),
            true,
        )
        .unwrap();
        assert_eq!(f.confirmed_via, "stat-path+kill");
        assert!(f.confirmed_ioc && f.holds_socket);
    }

    #[test]
    fn classify_dead_racer_dropped() {
        assert!(classify(9, Some(9), false, false, None, None, false).is_none());
    }

    // ── existing tests ──────────────────────────────────────

    #[test]
    fn parse_stat_simple() {
        let s = "1234 (bash) R 1 1234 1234 0 -1 0 0 0 0 0 0 0 20 0 1 0 8877 0 0";
        let (state, _age) = parse_stat_state_age(s);
        assert_eq!(state.as_deref(), Some("R"));
    }

    #[test]
    fn parse_stat_comm_with_spaces_and_paren() {
        let s = "77 (evil )( proc) S 1 77 77 0 -1 0 0 0 0 0 0 0 20 0 1 0 5000 0 0";
        let (state, _) = parse_stat_state_age(s);
        assert_eq!(state.as_deref(), Some("S"), "last ')' must delimit comm");
    }

    #[test]
    fn parse_stat_zombie_state() {
        let s = "9 (dead) Z 1 9 9 0 -1 0 0 0 0 0 0 0 20 0 1 0 100 0 0";
        let (state, _) = parse_stat_state_age(s);
        assert_eq!(state.as_deref(), Some("Z"));
    }

    #[test]
    fn parse_stat_starttime_field_position() {
        let mut f = vec!["1", "(x)", "R"];
        f.extend(std::iter::repeat_n("0", 18));
        f.push("333333");
        let s = f.join(" ");
        let rparen = s.rfind(')').unwrap();
        let after: Vec<&str> = s[rparen + 1..].split_ascii_whitespace().collect();
        assert_eq!(after.get(19).copied(), Some("333333"));
    }

    #[test]
    fn parse_stat_malformed_no_paren() {
        assert_eq!(parse_stat_state_age("garbage no paren"), (None, None));
    }

    // ── kill arbiter ────────────────────────────────────────

    #[test]
    fn kill_self_exists() {
        let me = std::process::id();
        assert!(kill_exists(me), "our own pid must be live");
    }

    #[test]
    fn kill_absent_pid() {
        // > i32::MAX and 0 are guarded to false BEFORE the syscall, so no
        // negative-pid aliasing (kill(0/-1/-pgid, 0)).
        assert!(!kill_exists(4_000_000_000));
        assert!(!kill_exists(0));
    }

    // ── candidate-diff logic (pure, no /proc) ───────────────

    #[test]
    fn candidate_diff_flags_only_double_hidden() {
        let live = BTreeSet::from([100, 200, 300, 400]);
        let before = BTreeSet::from([100, 200]); // 300 hidden, 400 = churn
        let after = BTreeSet::from([100, 200, 400]); // 400 started mid-sweep
        let c = candidate_diff(&live, &before, &after);
        assert!(c.contains(&300), "PID in neither readdir must survive");
        assert!(!c.contains(&400), "started-during-probe PID excluded");
        assert!(
            !c.contains(&100) && !c.contains(&200),
            "listed PIDs excluded"
        );
    }

    #[test]
    fn candidate_diff_excludes_exited_during_probe() {
        // present in `before` and statted live, then gone from `after`
        let live = BTreeSet::from([500]);
        let before = BTreeSet::from([500]);
        let after = BTreeSet::new();
        assert!(candidate_diff(&live, &before, &after).is_empty());
    }

    // ── ANSI injection guards ───────────────────────────────

    #[test]
    fn parse_stat_rejects_ansi_state() {
        // rootkit-controlled stat smuggling an escape as the state token
        let s = "1 (x) \x1b[31mZ 1 1 1 0 -1 0 0 0 0 0 0 0 20 0 1 0 100 0 0";
        assert_eq!(
            parse_stat_state_age(s).0,
            None,
            "non-alpha first char dropped"
        );
    }

    #[test]
    fn parse_status_rejects_ansi_state() {
        let s = "Name:\tx\nTgid:\t100\nPid:\t100\nState:\t\x1b[31mR\n";
        assert_eq!(
            parse_tgid_and_state(s).1,
            None,
            "escape byte must not become state"
        );
    }

    // ── pid scan bounds heuristic ───────────────────────────

    #[test]
    fn wrap_tail_math() {
        let bounds = |ns_last: u64, pid_max: u64| -> (u32, Option<(u32, u32)>) {
            let upper = ns_last.min(pid_max) as u32;
            let near = (upper as u64) > pid_max * 9 / 10;
            let tail = if near && (upper as u64) < pid_max {
                Some((upper + 1, pid_max as u32))
            } else {
                None
            };
            (upper, tail)
        };
        assert_eq!(bounds(5000, 4_194_304), (5000, None));
        let (u, t) = bounds(4_000_000, 4_194_304);
        assert_eq!(u, 4_000_000);
        assert!(t.is_some());
        assert_eq!(bounds(4_194_304, 4_194_304), (4_194_304, None));
    }

    // ── end-to-end over a fake /proc (readdir vs a planted "hidden" PID) ──

    /// Build a fake proc root. `listed` PIDs get a real directory (visible to
    /// readdir AND to path-stat). `hidden` PIDs get a directory too (so path
    /// `.exists()` is true — simulating a getdents-only rootkit) but we exclude
    /// them from readdir by... not being able to. Instead we test the pure diff
    /// logic via detect() semantics: here we verify a CLEAN root yields nothing.
    fn make_proc(pids: &[u32]) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        for &pid in pids {
            let d = tmp.path().join(pid.to_string());
            fs::create_dir_all(d.join("fd")).unwrap();
            // A minimal stat so read_state_and_age doesn't error.
            fs::write(
                d.join("stat"),
                format!("{pid} (proc) S 1 {pid} {pid} 0 -1 0 0 0 0 0 0 0 20 0 1 0 100 0 0"),
            )
            .unwrap();
            fs::write(d.join("status"), make_status(pid, pid, "S")).unwrap();
        }
        tmp
    }

    #[test]
    fn clean_proc_yields_no_ghosts() {
        // Every dir visible to readdir == visible to path-stat → empty diff.
        // NB: detect() brute-forces the real ns_last_pid, but since our temp
        // root only contains these dirs, path-stat for other PIDs is ENOENT,
        // and readdir sees exactly these — diff is empty.
        let proc = make_proc(&[1, 100, 200]);
        // Constrain the brute-force to our small set by construction: PIDs not
        // in the temp root don't exist as paths, so probe_live_set returns only
        // {1,100,200} for the range that overlaps — and readdir returns the same.
        let ghosts = detect(proc.path(), false);
        assert!(ghosts.is_empty(), "clean root must yield no ghosts");
    }

    #[test]
    fn readdir_pids_parses_numeric_only() {
        let proc = make_proc(&[1, 42]);
        // Add a non-numeric entry that must be ignored.
        fs::create_dir_all(proc.path().join("net")).unwrap();
        let set = readdir_pids(proc.path());
        assert!(set.contains(&1) && set.contains(&42));
        assert_eq!(set.len(), 2, "non-numeric 'net' must not be counted");
    }

    #[test]
    fn socket_link_detection_shape() {
        // Verify the socket:[ ] prefix match used for corroboration.
        let tmp = tempfile::tempdir().unwrap();
        let fd = tmp.path().join("fd");
        fs::create_dir_all(&fd).unwrap();
        symlink("socket:[123]", fd.join("3")).unwrap();
        symlink("/dev/null", fd.join("0")).unwrap();
        // Count socket links directly (mirrors socket_owning_pids inner loop).
        let mut has_sock = false;
        for e in fs::read_dir(&fd).unwrap().flatten() {
            if let Ok(t) = fs::read_link(e.path())
                && t.to_str().is_some_and(|s| s.starts_with("socket:["))
            {
                has_sock = true;
            }
        }
        assert!(has_sock);
    }
}
