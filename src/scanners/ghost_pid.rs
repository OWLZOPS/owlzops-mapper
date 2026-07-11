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
//! Performance: brute-force is bounded by `ns_last_pid` (not pid_max), and the
//! expensive confirmation runs only over the readdir-diff, which is empty on a
//! clean host. Single-threaded, zero dependencies beyond libc (already direct).
//!
//! Known limit: a rootkit that also hooks the direct `/proc/<pid>` stat lookup
//! makes stat return ENOENT for a live hidden PID; only the `kill` arbiter can
//! then see it, and only if it doesn't also filter the signal path. Recorded
//! honestly in evidence rather than claimed as universally caught.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;

use crate::coverage;
use crate::models::GhostPidFinding;
use crate::safe_io;

const PROBE_CYCLES: usize = 3;
const PROBE_PAUSE: Duration = Duration::from_millis(100);
const MIN_AGE_SECS: u64 = 2;
const MAX_FINDINGS: usize = 64;
/// Throttle: yield to the scheduler every N brute-force probes to avoid a %sys
/// spike on hosts with a very large ns_last_pid.
const YIELD_EVERY: u32 = 8192;
/// If ns_last_pid is within this fraction of pid_max, also sweep the wrap tail.
const WRAP_TAIL_FRACTION: u64 = 10; // "within 10%" → ns_last_pid > pid_max*9/10

pub fn scan_ghost_pids() -> Vec<GhostPidFinding> {
    detect(Path::new("/proc"))
}

/// Split from scan_ghost_pids for testing against a fake proc root. In tests the
/// live-set is injected via `probe_live_at`; in production it brute-forces PIDs.
fn detect(proc_root: &Path) -> Vec<GhostPidFinding> {
    // Candidate = live-by-bruteforce ∧ absent-from-readdir, in EVERY cycle.
    // Intersect candidate sets across cycles: a PID that ever appears in readdir
    // or ever fails the live-probe drops out (legit ephemeral/race).
    let mut stable: Option<BTreeSet<u32>> = None;

    for cycle in 0..PROBE_CYCLES {
        // Order matters: readdir FIRST, brute-force SECOND. A process born
        // between the two is caught by the next cycle's readdir; a process that
        // died is absent from brute-force → not a candidate. See design notes.
        let listed = readdir_pids(proc_root);
        let live = probe_live_set(proc_root);

        let candidates: BTreeSet<u32> = live.difference(&listed).copied().collect();

        stable = Some(match stable {
            None => candidates,
            Some(prev) => prev.intersection(&candidates).copied().collect(),
        });

        if stable.as_ref().is_some_and(BTreeSet::is_empty) {
            // Clean host fast-path: nothing survived, stop probing early.
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

    // Optional corroboration: which hidden PIDs also own a network socket?
    let socket_pids = socket_owning_pids();

    let mut findings = Vec::new();
    for pid in survivors {
        if findings.len() >= MAX_FINDINGS {
            coverage::record(format!(
                "ghost-pid scan: finding cap ({MAX_FINDINGS}) reached; more candidates not recorded"
            ));
            break;
        }

        // Confirm existence independently and enrich with state/age.
        let stat_path_alive = proc_root.join(pid.to_string()).exists();
        let kill_alive = kill_exists(pid);
        let (state, age_secs) = read_state_and_age(proc_root, pid);

        let confirmed_via = match (stat_path_alive, kill_alive) {
            (true, true) => "stat-path+kill",
            (true, false) => "stat-path",
            (false, true) => "kill",    // advanced: direct path hidden too
            (false, false) => continue, // died during confirmation → drop (race)
        }
        .to_string();

        // IoC criteria: live, non-zombie state, and age ≥ threshold. A young
        // or unconfirmable-age candidate is downgraded to a suspicion.
        let is_live_state = matches!(state.as_deref(), Some("R" | "S" | "D" | "I"));
        let old_enough = age_secs.is_some_and(|a| a >= MIN_AGE_SECS);
        let confirmed_ioc = is_live_state && old_enough;

        findings.push(GhostPidFinding {
            pid,
            state,
            age_secs,
            confirmed_via,
            confirmed_ioc,
            holds_socket: socket_pids.contains(&pid),
        });
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

// ── readdir view (what the rootkit hooks) ─────────────────────────────────

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

// ── brute-force live view (bypasses getdents) ─────────────────────────────

/// Production live-probe: stat every PID in [1, ns_last_pid] (+ wrap tail if
/// near pid_max). Cheap ENOENT for absent PIDs; collects only live ones.
fn probe_live_set(proc_root: &Path) -> BTreeSet<u32> {
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

/// Determine the brute-force upper bound (ns_last_pid) and an optional wrap
/// tail [ns_last_pid+1, pid_max] when ns_last_pid is within 10% of pid_max.
fn pid_scan_bounds() -> (u32, Option<(u32, u32)>) {
    let pid_max = read_u32_sysfile("/proc/sys/kernel/pid_max").unwrap_or(32_768);
    let ns_last = read_u32_sysfile("/proc/sys/kernel/ns_last_pid").unwrap_or(pid_max);
    let upper = ns_last.min(pid_max);

    // "within 10% of pid_max" → upper > pid_max * 9/10.
    let near_wrap =
        (upper as u64) > (pid_max as u64) * (WRAP_TAIL_FRACTION - 1) / WRAP_TAIL_FRACTION;
    let tail = if near_wrap && upper < pid_max {
        Some((upper + 1, pid_max))
    } else {
        None
    };
    (upper, tail)
}

fn read_u32_sysfile(path: &str) -> Option<u32> {
    let (content, _) = safe_io::read_file_capped(path, 64).ok()?;
    content.trim().parse().ok()
}

// ── kill(pid, 0) arbiter (bypasses /proc entirely) ────────────────────────

/// True if the PID exists per the signal subsystem. Three-valued semantics:
/// Ok(0) → exists & signalable; EPERM → EXISTS but not signalable (still true);
/// ESRCH → does not exist.
fn kill_exists(pid: u32) -> bool {
    // SAFETY: sig 0 performs existence/permission checks only, sends nothing.
    let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if ret == 0 {
        return true;
    }
    // errno: EPERM = exists (not ours); ESRCH = gone.
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

// ── /proc/<pid>/stat → state + age ────────────────────────────────────────

/// Parse State (field 3) and starttime (field 22), compute age from uptime.
/// Returns (state, age_secs); either may be None if unreadable.
fn read_state_and_age(proc_root: &Path, pid: u32) -> (Option<String>, Option<u64>) {
    let path = proc_root.join(pid.to_string()).join("stat");
    let content = match safe_io::read_file_capped(path.to_string_lossy().as_ref(), 8192) {
        Ok((c, _)) => c,
        Err(_) => return (None, None), // hidden direct path, or no perms
    };
    parse_stat_state_age(&content)
}

/// Split out for testing. `/proc/<pid>/stat` format:
///   pid (comm) state ppid ... starttime ...
/// comm is in parentheses and MAY contain spaces AND ')'. The kernel guarantees
/// it is the LAST ')' that closes comm, so we split on `rfind(')')` — fields
/// after that are space-separated and fixed-position. State = field[0] after,
/// starttime = field[19] after (stat field 22, 1-based; 3rd field is index 0
/// post-comm, starttime is the 22nd overall → 22 - 2 = index 19 post-comm).
fn parse_stat_state_age(content: &str) -> (Option<String>, Option<u64>) {
    let Some(rparen) = content.rfind(')') else {
        return (None, None);
    };
    let after = content[rparen + 1..].trim_start();
    let fields: Vec<&str> = after.split_ascii_whitespace().collect();
    // fields[0] = state, fields[19] = starttime (ticks since boot).
    let state = fields.first().map(|s| s.to_string());

    let age = fields
        .get(19)
        .and_then(|s| s.parse::<u64>().ok())
        .and_then(|starttime_ticks| {
            let hz = clock_ticks_per_sec();
            let uptime = read_uptime_secs()?;
            let start_secs = starttime_ticks / hz;
            // Guard against clock skew: saturating sub, never underflow-panic.
            Some(uptime.saturating_sub(start_secs))
        });

    (state, age)
}

fn clock_ticks_per_sec() -> u64 {
    // SAFETY: sysconf is a pure query. Fallback to the near-universal 100.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if hz > 0 { hz as u64 } else { 100 }
}

fn read_uptime_secs() -> Option<u64> {
    let (content, _) = safe_io::read_file_capped("/proc/uptime", 128).ok()?;
    // "12345.67 89012.34" → first token, integer part.
    content
        .split_whitespace()
        .next()?
        .split('.')
        .next()?
        .parse()
        .ok()
}

// ── socket-owner corroboration (independent subsystem) ────────────────────

/// PIDs that own a network socket, via /proc/<pid>/fd → socket:[inode]. Reuses
/// the readdir listing (a hidden PID won't be here, but if the rootkit missed
/// fd-listing for it, a match is strong corroboration). Best-effort.
fn socket_owning_pids() -> BTreeSet<u32> {
    let mut set = BTreeSet::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return set;
    };
    for e in entries.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };
        for fd in fds.flatten() {
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

    // ── stat parsing: the comm-with-parens trap ─────────────

    #[test]
    fn parse_stat_simple() {
        // pid (comm) R ppid ... (22 fields; starttime at field 22 = "8877").
        let s = "1234 (bash) R 1 1234 1234 0 -1 0 0 0 0 0 0 0 20 0 1 0 8877 0 0";
        let (state, _age) = parse_stat_state_age(s);
        assert_eq!(state.as_deref(), Some("R"));
    }

    #[test]
    fn parse_stat_comm_with_spaces_and_paren() {
        // Malicious/edge comm: "(evil )( proc)" — spaces AND ')' inside comm.
        // rfind(')') must pick the LAST ')', so state parses as "S".
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
        // starttime is overall field 22; post-comm index 19. Value 333333.
        let mut f = vec!["1", "(x)", "R"];
        // fields 4..=21 (18 placeholders) then starttime at 22.
        f.extend(std::iter::repeat_n("0", 18));
        f.push("333333"); // field 22
        let s = f.join(" ");
        // We can't assert age without uptime, but starttime must be located:
        // re-parse the post-comm slice and confirm index 19 is our value.
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
        // A very high PID in the reserved-unlikely range should not exist.
        // (Not guaranteed, but astronomically unlikely on a test box.)
        assert!(!kill_exists(4_000_000_000));
    }

    // ── pid scan bounds heuristic ───────────────────────────
    // (pure arithmetic via a tiny helper mirror to avoid touching real sysfs)

    #[test]
    fn wrap_tail_math() {
        // Mirror the bound logic for deterministic testing.
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
        // Far from wrap: no tail.
        assert_eq!(bounds(5000, 4_194_304), (5000, None));
        // Within 10%: tail scanned.
        let (u, t) = bounds(4_000_000, 4_194_304);
        assert_eq!(u, 4_000_000);
        assert!(t.is_some());
        // Exactly at pid_max: no tail (nothing above).
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
        let ghosts = detect(proc.path());
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
