#![allow(dead_code)]

use std::borrow::Cow;
use std::collections::HashMap;
use std::os::unix::process::CommandExt; // for pre_exec
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use crate::coverage;
use crate::safe_io;

// ---------------------------------------------------------------------------
// Hardened tool resolution
// ---------------------------------------------------------------------------

// R35-05: the cache also stores refusals. A binary that is writable by a
// non-root principal must not be executed, and the disclosure of that refusal
// must happen exactly once per tool.
fn tool_cache() -> &'static Mutex<HashMap<String, Option<String>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

// R10-04: poison-tolerant lock helper
fn lock_cache() -> std::sync::MutexGuard<'static, HashMap<String, Option<String>>> {
    tool_cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Resolve a system tool by searching fixed standard directories.
/// This avoids a fork of `which` and is resilient against PATH manipulation.
///
/// R35-05: a candidate is only accepted if it and every directory on its
/// lexical AND canonical path is owned by root (or our euid) and is not
/// group/other writable. On a Debian layout `/usr/local` is `root:staff 2775`
/// — group writable — so `/usr/local/*` no longer resolves until the admin
/// fixes the mode. Intended.
///
/// Negative results are cached too: the refusal is disclosed once.
pub fn resolve_tool(tool: &str) -> Option<String> {
    // Fast path: hit the (poison-tolerant) cache. Scope the guard explicitly
    // so the lock is not held while `resolve_tool_uncached` runs.
    {
        let guard = lock_cache();
        if let Some(hit) = guard.get(tool) {
            return hit.clone();
        }
    }
    let found = resolve_tool_uncached(tool);
    lock_cache().insert(tool.to_string(), found.clone());
    found
}

fn resolve_tool_uncached(tool: &str) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    for dir in [
        "/usr/local/sbin",
        "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
    ] {
        let candidate = format!("{dir}/{tool}");
        let Ok(md) = std::fs::metadata(&candidate) else {
            continue;
        };
        if !md.is_file() || md.mode() & 0o111 == 0 {
            continue;
        }
        if is_trusted_exec(&candidate) {
            return Some(candidate);
        }
        coverage::record(format!(
            "tool resolution: {candidate} (or a directory on its path) is writable by a \
             non-root principal — NOT executed; trying the next standard directory"
        ));
    }
    None
}

/// R35-05: may we exec this file with our privileges? The file and every
/// directory on its lexical AND canonical paths must be owned by root (or our
/// euid) and not writable by group or other.
///
/// Both chains matter: an attacker who can rewrite the directory holding a
/// symlink can swap the target between check and exec. We do not stat the
/// symlink itself (which we would be able to replace), we canonicalise and
/// also verify the lexical ancestors.
fn is_trusted_exec(path: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid(2) cannot fail.
    let euid = unsafe { libc::geteuid() };
    let owned_ok =
        |md: &std::fs::Metadata| (md.uid() == 0 || md.uid() == euid) && md.mode() & 0o022 == 0;

    let lexical = std::path::Path::new(path);
    let Ok(real) = std::fs::canonicalize(lexical) else {
        return false;
    };
    let Ok(md) = std::fs::metadata(&real) else {
        return false;
    };
    md.is_file()
        && md.mode() & 0o111 != 0
        && owned_ok(&md)
        && lexical
            .ancestors()
            .skip(1)
            .chain(real.ancestors().skip(1))
            .all(|d| std::fs::metadata(d).is_ok_and(|m| owned_ok(&m)))
}

/// R35-05: the single gate for everything `run_*` execs. A bare name goes
/// through `resolve_tool`; an absolute path is re-verified in place. There is
/// no PATH fallback: the PATH dirs of `hardened_command` are a subset of the
/// search dirs, so the only thing PATH lookup could add is a refused binary.
fn exec_target(program: &str) -> Option<String> {
    if !program.starts_with('/') {
        return resolve_tool(program);
    }
    if is_trusted_exec(program) {
        return Some(program.to_string());
    }
    coverage::record(format!(
        "tool resolution: {program} (or a directory on its path) is writable by a \
         non-root principal — NOT executed"
    ));
    None
}

pub fn hardened_command(program: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C");
    // R24-04: own session ⇒ (a) kill(-pgid) reaches grandchildren,
    //                       (b) no controlling TTY ⇒ TIOCSTI injection impossible.
    // setsid() is async-signal-safe; it only fails when we already are a group
    // leader, which is harmless in the post-fork child.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    cmd
}

/// SIGKILL the whole process group (pgid == pid thanks to setsid), then reap.
///
/// R35-09: unregister the child BEFORE the reap. Once `wait()` returns the
/// PID/PGID is free for the kernel to recycle, and a group SIGTERM from
/// `terminate_registered_children` can land on an unrelated process. The
/// registry is what proves the PGID is still ours.
fn kill_group_and_reap(child: &mut Child) {
    let pid = child.id();
    unsafe {
        libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
        libc::kill(pid as libc::pid_t, libc::SIGKILL); // belt and braces
    }
    unregister_child(pid);
    let _ = child.wait();
}

pub(crate) const fn host_budget_secs(t: u64) -> u64 {
    t.saturating_mul(2).saturating_add(60)
}

// ---------------------------------------------------------------------------
// Network predicates
// ---------------------------------------------------------------------------

pub fn is_wildcard_bind(addr: &str) -> bool {
    matches!(addr, "0.0.0.0" | "::" | "::ffff:0.0.0.0")
}

pub fn is_loopback_bind(addr: &str) -> bool {
    fn v4_loopback(s: &str) -> bool {
        s.strip_prefix("127.").is_some_and(|rest| {
            !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        })
    }
    matches!(addr, "::1")
        || v4_loopback(addr)
        || addr.strip_prefix("::ffff:").is_some_and(v4_loopback)
}

// ── User‑space path predicates (shared by shadow‑IT and injection scanners) ──

/// Canonical home bases. `/var/home` is the physical location on Fedora
/// Atomic (Silverblue/Kinoite/Bluefin); /home is a symlink there, and
/// `/proc/<pid>/exe` reports the canonical path. Every predicate that
/// reasons about "user‑writable space" must consult this list — R22‑19.
pub(crate) const HOME_BASES: &[&str] = &["/home/", "/var/home/", "/root/"];

/// Executables served from writable/ephemeral locations — a shared signal
/// for shadow-IT (SEC-013), IoC (SEC-015) and ambiguous-malware corroboration.
///
/// `/memfd:` covers `memfd_create`-backed execution (fully in-memory implants);
/// the kernel renders such exe links as `/memfd:<name> (deleted)`. Prefix match
/// is deletion-suffix agnostic, so this holds whether called on the raw link
/// or on the base path after the ` (deleted)` suffix is stripped.
pub fn is_ephemeral_exec_path(path: &str) -> bool {
    // R22-23: NixOS setuid/capability wrappers live on tmpfs under
    // /run/wrappers/bin but are root-owned and generated by the system at
    // boot — the opposite of a dropper. fs_inventory scans them deliberately
    // (R22-14); the two must not contradict each other. Inert on FHS hosts.
    if path.starts_with("/run/wrappers/") {
        return false;
    }
    path.starts_with("/tmp/")
        || path.starts_with("/var/tmp/")
        || path.starts_with("/dev/shm/")
        // R22-22: /run is tmpfs and /run/user/<uid> is user-writable without
        // root — a session-lifetime implant location. library_injection already
        // treats /run as volatile for .so; exe must agree.
        || path.starts_with("/run/")
        || HOME_BASES.iter().any(|b| path.starts_with(b))
        || path.starts_with("/memfd:")
}

/// Volatile system locations: no legitimate long-lived install lives here.
/// Narrower than `is_ephemeral_exec_path` — omits home bases, where extracting
/// a tarball into ~/Downloads or ~/Applications is ordinary, not a dropper signature.
/// NOTE: also used for `.so` paths by library_injection (R22-22). Home bases must
/// stay excluded there too — IDEs and VSCode legitimately load libraries from $HOME.
pub fn is_volatile_exec_path(path: &str) -> bool {
    // R22-23: NixOS setuid/capability wrappers live on tmpfs under
    // /run/wrappers/bin but are root-owned and generated by the system at
    // boot — the opposite of a dropper. fs_inventory scans them deliberately
    // (R22-14); the two must not contradict each other. Inert on FHS hosts.
    if path.starts_with("/run/wrappers/") {
        return false;
    }
    path.starts_with("/tmp/")
        || path.starts_with("/var/tmp/")
        || path.starts_with("/dev/shm/")
        || path.starts_with("/run/")
        || path.starts_with("/memfd:")
}

/// Check whether a path resides on a volatile filesystem (tmpfs, devtmpfs, …).
/// Used by SEC-051 to flag directories from ld.so.conf that sit on ephemeral
/// storage — an attacker can place a malicious library there at runtime.
/// Delegates to `is_volatile_exec_path`; the prefix list intentionally
/// excludes home directories (volatile for a directory means system-wide tmpfs,
/// not user‑writable home).
pub fn is_volatile_mount(path: &str) -> bool {
    is_volatile_exec_path(path)
}

/// Home-relative depth: /home/u → 0, /home/u/Downloads → 1, /home/u/a/b → 2.
/// Covers /root and Fedora Atomic's /var/home/<user>.
fn home_relative_depth(dir: &str) -> Option<usize> {
    // The first two HOME_BASES are /home/ and /var/home/; /root/ is handled
    // separately because its structure is flat (no username component to skip).
    for base in HOME_BASES {
        if *base == "/root/" {
            if dir == "/root" {
                return Some(0);
            }
            if let Some(rest) = dir.strip_prefix("/root/") {
                return Some(rest.split('/').filter(|s| !s.is_empty()).count());
            }
        } else if let Some(rest) = dir.strip_prefix(base) {
            // skip(1) drops the username component itself
            return Some(rest.split('/').filter(|s| !s.is_empty()).skip(1).count());
        }
    }
    None
}

/// A directory holding many UNRELATED things: its entry count says nothing about
/// any particular binary inside it, so it may never vouch for one.
fn is_container_dir(dir: &str) -> bool {
    INSTALL_ROOTS
        .iter()
        .map(|r| r.trim_end_matches('/'))
        .any(|r| dir == r || dir.ends_with(r))
        || matches!(dir, "/" | "/home" | "/var/home" | "/root")
        || home_relative_depth(dir).is_some_and(|d| d <= 1)
}

// ---------------------------------------------------------------------------
// Usrmerge-aware canonical path
// ---------------------------------------------------------------------------

/// Canonical path under usrmerge: /bin/su → /usr/bin/su, /lib/foo → /usr/lib/foo.
/// Idempotent; returns `Cow::Borrowed` if no change, avoiding allocation in the
/// common case.
pub fn canon_path(path: &str) -> Cow<'_, str> {
    const MERGED: &[&str] = &["/bin/", "/sbin/", "/lib/", "/lib64/"];
    if MERGED.iter().any(|p| path.starts_with(p)) {
        Cow::Owned(format!("/usr{}", path))
    } else {
        Cow::Borrowed(path)
    }
}

// ---------------------------------------------------------------------------
// Log sanitization (R16 hardening)
// ---------------------------------------------------------------------------

/// Strip ANSI escape sequences from `s`.
///
/// Handles CSI, OSC, DCS, and simple ESC sequences based on the ANSI escape
/// code grammar. The state machine advances over the escape sequence and
/// returns a new string without them.
fn strip_ansi(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == 0x1B {
            // ESC found, try to parse the sequence.
            i += 1;
            if i >= bytes.len() {
                break;
            }

            match bytes[i] {
                // CSI: ESC [ ... final byte 0x40-0x7E
                b'[' => {
                    i += 1;
                    while i < bytes.len() && !(0x40..=0x7E).contains(&bytes[i]) {
                        i += 1;
                    }
                    if i < bytes.len() {
                        i += 1; // skip final byte
                    }
                }
                // OSC: ESC ] ... terminated by BEL (0x07) or ST (ESC \)
                b']' => {
                    i += 1;
                    while i < bytes.len() {
                        if bytes[i] == 0x07 {
                            i += 1;
                            break;
                        }
                        if bytes[i] == 0x1B && i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
                            i += 2;
                            break;
                        }
                        i += 1;
                    }
                }
                // DCS, SOS, PM, APC: ESC P/X/^/_ ... terminated by ST (ESC \)
                b'P' | b'X' | b'^' | b'_' => {
                    i += 1;
                    while i < bytes.len() {
                        if bytes[i] == 0x1B && i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
                            i += 2;
                            break;
                        }
                        i += 1;
                    }
                }
                // Simple escape: ESC followed by a single character in 0x30..=0x7E
                c if (0x30..=0x7E).contains(&c) => {
                    i += 1; // skip the character
                }
                // Invalid or unknown, skip the ESC itself
                _ => {}
            }
        } else {
            // Copy non-ESC bytes, but we'll later filter control chars.
            result.push(bytes[i]);
            i += 1;
        }
    }

    // Convert back to UTF-8, replacing invalid sequences.
    String::from_utf8_lossy(&result).into_owned()
}

/// Single source of truth for "this codepoint changes how a terminal renders
/// its neighbours or can be used to hide/override text".
///
/// Two hand-maintained lists in `utils.rs` and `ui.rs` previously diverged:
/// one caught bidi overrides and the other TAG characters (R25-65). Use this
/// predicate in BOTH sanitizers.
pub(crate) fn is_terminal_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(c as u32,
            0x00AD                    // SOFT HYPHEN
            | 0x061C                  // ARABIC LETTER MARK
            | 0x180E                  // MONGOLIAN VOWEL SEPARATOR
            | 0x115F                  // HANGUL CHOSEONG FILLER
            | 0x1160                  // HANGUL JUNGSEONG FILLER
            | 0x3164                  // HANGUL FILLER
            | 0xFFA0                  // HALFWIDTH HANGUL FILLER
            | 0x200B..=0x200F         // ZWSP, ZWNJ, ZWJ, LRM, RLM
            | 0x202A..=0x202E         // bidi overrides
            | 0x2028                  // LINE SEPARATOR
            | 0x2029                  // PARAGRAPH SEPARATOR
            | 0x2060..=0x206F         // word joiner, invisible operators, isolates
            | 0xFEFF                  // BOM / ZERO WIDTH NO-BREAK SPACE
            | 0xE0000..=0xE007F       // Unicode TAG block
        )
}

/// Replace all control characters with spaces, then truncate to `max_chars`.
fn sanitize_and_truncate(s: &str, max_chars: usize) -> String {
    let stripped = strip_ansi(s);
    let sanitized: String = stripped
        .chars()
        .map(|c| if is_terminal_unsafe(c) { ' ' } else { c })
        .collect();
    sanitized.chars().take(max_chars).collect()
}

/// Neutralise C0/C1 control bytes and ANSI escape sequences before they reach
/// a terminal-backed tracing sink. The result is safe to embed in log messages
/// and terminal output, truncated to 300 characters.
pub fn sanitize_for_log(s: &str) -> String {
    sanitize_and_truncate(s, 300)
}

/// Neutralise codepoints that change how neighbouring text renders, for any
/// document sink (XLSX cells, Typst report, CSV). Unlike `sanitize_for_log`
/// this does NOT truncate: a report must not silently lose a long path.
/// R26-07: the same predicate backs every sanitizer.
pub fn sanitize_for_document(s: &str) -> String {
    s.chars()
        .map(|c| if is_terminal_unsafe(c) { '\u{FFFD}' } else { c })
        .collect()
}

// ---------------------------------------------------------------------------
// Known malware / miner process names
// ---------------------------------------------------------------------------

pub const KNOWN_MALWARE: &[&str] = &["kdevtmpfsi", "kinsing", "xmrig", "sysupdate"];
pub const AMBIGUOUS_MALWARE: &[&str] = &["networkservice"];

pub fn is_known_malware(comm: &str) -> bool {
    let c = comm.trim();
    KNOWN_MALWARE.iter().any(|m| c.eq_ignore_ascii_case(m))
}

pub fn is_ambiguous_malware(comm: &str) -> bool {
    let c = comm.trim();
    AMBIGUOUS_MALWARE.iter().any(|m| c.eq_ignore_ascii_case(m))
}

// ---------------------------------------------------------------------------
// Child process registry (R10-07) — graceful shutdown of legacy SSH children
// ---------------------------------------------------------------------------

static CHILD_REGISTRY: OnceLock<Mutex<Vec<u32>>> = OnceLock::new();

fn with_registry<F, R>(f: F) -> R
where
    F: FnOnce(&Mutex<Vec<u32>>) -> R,
{
    let registry = CHILD_REGISTRY.get_or_init(|| Mutex::new(Vec::new()));
    f(registry)
}

pub fn register_child(pid: u32) {
    with_registry(|reg| {
        reg.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(pid);
    });
}

pub fn unregister_child(pid: u32) {
    with_registry(|reg| {
        reg.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|&p| p != pid);
    });
}

/// Send SIGTERM to all currently tracked child process groups and clear the list.
/// Used during graceful shutdown to terminate any remaining `ssh`/`scp`
/// processes started by the legacy engine.
///
/// R35-15: signal **while holding the registry lock**. Workers unregister
/// before they reap (R35-09), so no pid in this list can be reaped — and its
/// PGID recycled — until we release. The old shape snapshotted the list,
/// cleared it under the lock, and only then signalled: a worker could
/// unregister (no-op on the already-cleared list) and reap in that window,
/// leaving our SIGTERM to land on a recycled group.
///
/// `kill(2)` is non-blocking and the loop is bounded by `max_concurrent`
/// entries, so holding the lock for the duration is cheap; a worker blocked
/// on `unregister_child` cannot reach `wait()` until the loop finishes.
pub fn terminate_registered_children() {
    with_registry(|reg| {
        let mut guard = reg
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for &pid in guard.iter() {
            unsafe {
                // R24-04: whole group — helper processes spawned by the tool
                // must not survive graceful shutdown as orphans.
                libc::kill(-(pid as libc::pid_t), libc::SIGTERM);
            }
        }
        guard.clear();
    });
}

/// The stdout reader closed the pipe (common with `| head`, `| grep -q`, etc.).
/// This is not a scan failure. Terminate any managed children and exit
/// successfully (code 0) to preserve the exit contract and avoid panics.
/// Does NOT restore SIG_DFL for SIGPIPE because that would break socket
/// writes in russh — EPIPE is handled locally in the UI layer (R22-37).
pub fn exit_reader_gone() -> ! {
    terminate_registered_children();
    std::process::exit(0);
}

// ---------------------------------------------------------------------------
// Child helpers
// ---------------------------------------------------------------------------

/// Non-reaping exit check. `try_wait()` reaps the child, freeing its PID —
/// and with it the PGID, since the child is its own group leader (setsid).
/// A group kill issued after that can land on a freshly recycled group
/// (R24-34/R25-98). WNOWAIT leaves the zombie in place so the PGID stays
/// reserved until we explicitly reap.
fn peek_exited(pid: u32) -> bool {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is zeroed and lives for the call; WNOHANG makes this
    // non-blocking and WNOWAIT leaves the child unreaped.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    rc == 0 && unsafe { info.si_pid() } == pid as libc::pid_t
}

/// Non-destructive wait: waits until the child has exited, then kills its
/// process group BEFORE reaping, so the PGID cannot be recycled before the
/// group kill (R24-34/R25-98/R26-01). Uses exponential backoff.
fn wait_group_safe(child: &mut Child, deadline: Duration) -> Option<std::process::ExitStatus> {
    let pid = child.id();
    let start = Instant::now();
    const POLL_MIN: Duration = Duration::from_micros(200);
    const POLL_MAX: Duration = Duration::from_millis(50);
    let mut backoff = POLL_MIN;

    loop {
        if peek_exited(pid) {
            // Group killed BEFORE the reap: the PGID is still ours.
            unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) };
            // R35-09: forget the PGID before the reap reserves it no longer.
            unregister_child(pid);
            return child.wait().ok();
        }
        if start.elapsed() < deadline {
            thread::sleep(backoff);
            backoff = (backoff * 2).min(POLL_MAX);
        } else {
            // Timeout: kill group and reap, no status available.
            // `kill_group_and_reap` unregisters itself.
            kill_group_and_reap(child);
            return None;
        }
    }
}

pub fn run_child_with_timeout(
    program: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Option<std::process::Output> {
    // R35-05: no PATH fallback; a refused binary returns None here.
    let resolved = exec_target(program)?;
    let mut child = hardened_command(&resolved, args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
        .ok()?;

    let child_pid = child.id();
    register_child(child_pid);

    // stdout safety block
    let Some(out_pipe) = child.stdout.take() else {
        kill_group_and_reap(&mut child);
        return None;
    };

    // stderr safety block
    let Some(err_pipe) = child.stderr.take() else {
        kill_group_and_reap(&mut child);
        return None;
    };

    let prog = program.to_string();

    let out_handle = thread::spawn(move || {
        let (data, truncated) = safe_io::read_reader_capped(out_pipe, safe_io::CAP_CHILD_STDOUT);
        if truncated {
            coverage::record(format!(
                "Output of '{}' exceeded {} bytes and was truncated",
                prog,
                safe_io::CAP_CHILD_STDOUT
            ));
            tracing::warn!(tool = %prog, "child stdout truncated at cap");
        }
        data
    });
    let err_handle = thread::spawn(move || {
        let (data, _trunc) = safe_io::read_reader_capped(err_pipe, 1024 * 1024);
        data
    });

    let deadline = Duration::from_secs(timeout_secs);

    let status = match wait_group_safe(&mut child, deadline) {
        Some(status) => status,
        None => {
            // R28-07: drop() detaches, it does not wait. kill_group_and_reap()
            // inside wait_group_safe has already SIGKILLed the group and reaped,
            // so both write ends are closed and the readers hit EOF at once —
            // join is bounded and releases the pipe fds deterministically.
            // R35-09: the child was unregistered inside kill_group_and_reap.
            let _ = out_handle.join();
            let _ = err_handle.join();
            return None;
        }
    };

    // R35-09: the child was unregistered inside wait_group_safe.
    Some(std::process::Output {
        status,
        stdout: out_handle.join().unwrap_or_default(),
        stderr: err_handle.join().unwrap_or_default(),
    })
}

pub fn run_with_timeout(program: &str, args: &[&str], timeout_secs: u64) -> Option<String> {
    run_with_timeout_inner(program, args, timeout_secs, true)
}

pub fn run_with_timeout_any_exit(
    program: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Option<String> {
    run_with_timeout_inner(program, args, timeout_secs, false)
}

// R10-05: capped stdout reader + defensive take() guard instead of `?`
// R24-04: group kill on timeout and after successful exit to prevent
// orphaned grandchildren from holding the pipe.
fn run_with_timeout_inner(
    program: &str,
    args: &[&str],
    timeout_secs: u64,
    require_success: bool,
) -> Option<String> {
    // R35-05: no PATH fallback; a refused binary returns None here.
    let resolved = exec_target(program)?;
    let mut child = hardened_command(&resolved, args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .ok()?;

    let child_pid = child.id();
    register_child(child_pid);

    let (tx, rx) = mpsc::channel();
    // Defensive: if stdout was somehow not captured, reap the child immediately
    let Some(child_stdout) = child.stdout.take() else {
        kill_group_and_reap(&mut child);
        return None;
    };
    let prog = program.to_string();
    thread::spawn(move || {
        let (data, truncated) =
            safe_io::read_reader_capped(child_stdout, safe_io::CAP_CHILD_STDOUT);
        if truncated {
            coverage::record(format!(
                "Output of '{}' exceeded {} bytes and was truncated",
                prog,
                safe_io::CAP_CHILD_STDOUT
            ));
            tracing::warn!(tool = %prog, "child stdout truncated at cap");
        }
        // Lossy conversion preserves everything after the cap
        let _ = tx.send(String::from_utf8_lossy(&data).into_owned());
    });

    match rx.recv_timeout(Duration::from_secs(timeout_secs)) {
        Ok(stdout) => {
            // R26-01: the group kill is issued INSIDE wait_group_safe, before
            // the reap. Killing after wait() can land on a recycled PGID.
            // R35-09: wait_group_safe unregisters the child before reaping.
            let status = wait_group_safe(&mut child, Duration::from_secs(2));
            if require_success {
                match status {
                    Some(s) if s.success() => Some(stdout),
                    _ => None,
                }
            } else {
                Some(stdout)
            }
        }
        Err(_timeout) => {
            // kill_group_and_reap unregisters the child before the reap.
            kill_group_and_reap(&mut child);
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Structural provenance (exe install shape vs lone dropper)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExeProvenance {
    Deleted,           // "(deleted)" / memfd — image removed after launch
    LoneDropped,       // ephemeral path, sparse directory — trojan shape
    NestedUserInstall, // populated tree, but USER-writable -> weak trust
    InstalledApp,      // populated tree + ROOT-owned -> strong trust
}

/// Locations where applications are LEGITIMATELY installed (paths, NOT app names).
const INSTALL_ROOTS: &[&str] = &[
    "/.local/share/",
    "/.local/lib/",
    "/.vscode/",
    "/.vscode-server/",
    "/.config/",
    "/.var/app/",
    "/.cache/",
    "/opt/",
    "/snap/",
    "/usr/lib/",
    "/usr/share/",
    "/var/lib/flatpak/",
    "/nix/store/", // NixOS / Nix – content-addressed, read-only system prefix
];

/// System binary paths — territory of the package manager (root-owned).
///
/// Answers: "was this installed by the OS package manager?"
/// Narrow on purpose. The broader "is this on the system side of the
/// trust line?" question — used by mount-namespace classification —
/// is `is_system_managed_path` below. Do not merge the two: snap,
/// flatpak and nix packages are system-side but not package-manager
/// territory, and would misclassify provenance if included here.
const SYSTEM_BIN: &[&str] = &[
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/usr/libexec/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
];

/// System-managed roots for mount-namespace classification.
///
/// Answers a *different* question from SYSTEM_BIN: "does this exe live
/// on the system side, such that a mount-namespace anomaly involving
/// it is normal rather than suspicious?" Deliberately broader — nix,
/// snap, flatpak, /app and /opt all run legitimate system-side
/// processes here, even though none is package-manager territory.
///
/// `/usr/` is a prefix, not `/usr/bin/`, because usrmerge unifies the
/// whole tree; enumerating subdirectories would silently drop binaries
/// from newer usr layouts. On a pre-usrmerge container namespace the
/// relative `/bin/` and `/sbin/` still need their own entries.
pub(crate) fn is_system_managed_path(exe: &str) -> bool {
    const ROOTS: &[&str] = &[
        "/usr/",
        "/bin/",
        "/sbin/",
        "/opt/",
        "/nix/store/",
        "/app/",
        "/snap/",
        "/var/lib/flatpak/",
        "/run/wrappers/",
    ];
    ROOTS.iter().any(|p| exe.starts_with(p))
}

/// Version-managed runtime roots (nvm/pyenv/rbenv/...). The binary here IS the runtime
/// by convention. Membership-alone -> NestedUserInstall: the manager's layout keeps files
/// in child branches, not up the ancestor chain, so the populated-tree heuristic misfits.
/// User-writable -> WEAK tier (provisional-visible), residual risk is bound by parentage.
const RUNTIME_MANAGER_ROOTS: &[&str] = &[
    "/.nvm/",
    "/.fnm/",
    "/.volta/",
    "/.asdf/",
    "/.pyenv/",
    "/.rbenv/",
    "/.bun/",
    "/.deno/",
    "/linuxbrew/",
    "/usr/lib/node_modules/",
    "/node_modules/",
];

const INSTALL_TREE_MIN_FILES: usize = 8;
const MAX_UPWARD_DEPTH: usize = 6;

/// Factored out string check (SYSTEM_BIN ∪ RUNTIME_MANAGER ∪ INSTALL_ROOTS).
fn is_standard_install_path(p: &str) -> bool {
    SYSTEM_BIN.iter().any(|s| p.starts_with(s))
        || RUNTIME_MANAGER_ROOTS.iter().any(|r| p.contains(r))
        || INSTALL_ROOTS.iter().any(|r| p.contains(r))
}

/// Check if the given PID is running in a foreign mount namespace (i.e., a container).
/// This relies on comparing its mount namespace to the host's init process (PID 1).
pub fn in_foreign_mnt_ns(pid: u32) -> bool {
    let p = std::fs::read_link(format!("/proc/{}/ns/mnt", pid)).ok();
    let host = std::fs::read_link("/proc/1/ns/mnt").ok(); // host-init as reference
    matches!((p, host), (Some(a), Some(b)) if a != b)
}

/// Testable core of `populated_tree_within`. Takes a directory-entry-count
/// provider so the ancestor walk and boundary logic can be verified without
/// touching the filesystem.
fn populated_tree_within_with<F>(exe: &str, count_entries: F) -> bool
where
    F: Fn(&std::path::Path) -> Option<usize>,
{
    std::path::Path::new(exe)
        .ancestors()
        .skip(1) // skip the binary itself → start with its parent directory
        .take(MAX_UPWARD_DEPTH)
        // R22-18: stop at the first directory that cannot vouch. Previously the
        // boundary was INSTALL_ROOTS membership, which made the whole heuristic
        // inert outside the allowlist.
        .take_while(|dir| !is_container_dir(&dir.to_string_lossy()))
        .any(|dir| count_entries(dir).is_some_and(|n| n >= INSTALL_TREE_MIN_FILES))
}

/// Walk ancestors (up to MAX_UPWARD_DEPTH) and return true if any directory
/// contains at least INSTALL_TREE_MIN_FILES entries — indicating a populated
/// install tree rather than a sparse dropper location.
fn populated_tree_within(exe: &str) -> bool {
    populated_tree_within_with(exe, |dir| {
        std::fs::read_dir(dir)
            .map(|rd| rd.take(INSTALL_TREE_MIN_FILES + 1).count())
            .ok()
    })
}

pub fn exe_provenance(exe: &str, pid: u32) -> ExeProvenance {
    use std::os::unix::fs::MetadataExt;

    if exe.ends_with(" (deleted)") || exe.starts_with("/memfd:") {
        return ExeProvenance::Deleted;
    }

    // Foreign mount ns (container): CEILING at weak tier, classification by PATH STRING
    // (the file doesn't exist on the host — it's a phantom path here).
    // Ownership is irrelevant (container-root != trusted host-root), the file is never stat'd.
    // Residual risk is closed by parentage.
    if in_foreign_mnt_ns(pid) {
        return if is_standard_install_path(exe) {
            ExeProvenance::NestedUserInstall // provisional-visible
        } else {
            ExeProvenance::LoneDropped
        };
    }

    // Host ns: ownership via PINNED inode (magic symlink) — immune to binary swap
    // post-exec even on the host.
    let root_owned = std::fs::metadata(format!("/proc/{pid}/exe"))
        .map(|m| m.uid() == 0)
        .unwrap_or(false);

    if SYSTEM_BIN.iter().any(|p| exe.starts_with(p)) {
        return if root_owned {
            ExeProvenance::InstalledApp
        } else {
            ExeProvenance::LoneDropped
        };
    }

    // NixOS / Nix: /nix/store/<hash>-<pkg>/bin/<name> is root-owned,
    // read-only, content-addressed. Treat as installed.
    if exe.starts_with("/nix/store/") {
        return if root_owned {
            ExeProvenance::InstalledApp
        } else {
            ExeProvenance::LoneDropped // should never happen
        };
    }

    // R22-18/20: volatile locations can never host an install tree, whatever
    // the shape — an attacker fabricates one for free. MUST precede the
    // runtime-manager check, which matches by substring and would otherwise
    // vouch for /tmp/.nvm/payload.
    if is_volatile_exec_path(exe) {
        return ExeProvenance::LoneDropped;
    }

    if RUNTIME_MANAGER_ROOTS.iter().any(|r| exe.contains(r)) {
        return ExeProvenance::NestedUserInstall;
    }

    // Structure alone decides now; `is_container_dir` makes this safe to stand
    // without the allowlist gate.
    if !populated_tree_within(exe) {
        return ExeProvenance::LoneDropped;
    }

    if root_owned {
        ExeProvenance::InstalledApp
    } else {
        ExeProvenance::NestedUserInstall
    }
}

/// Tiered shadow-IT listener classification. Single source of truth for both
/// scoring (SEC-013/030/031) and terminal rendering — they must never disagree.
#[derive(Default)]
pub struct ListenerTiers {
    pub suspicious: Vec<String>,  // SEC-013, weight 20
    pub devtool: Vec<String>,     // SEC-030, advisory
    pub provisional: Vec<String>, // SEC-031, provisional
}

pub fn classify_listeners(ports: &[crate::models::PortInfo]) -> ListenerTiers {
    let mut t = ListenerTiers::default();
    for port in ports {
        let Some(exe) = port.exe_path.as_deref() else {
            continue;
        };
        if !is_ephemeral_exec_path(exe) {
            continue;
        }
        let label = format!(
            "{}/{} on {} ({})",
            port.port, port.protocol, port.bind_address, exe
        );
        let prov = port
            .pid
            .map(|p| exe_provenance(exe, p))
            .unwrap_or(ExeProvenance::LoneDropped);
        match (is_loopback_bind(&port.bind_address), prov) {
            // Root-owned tree: path alone is sufficient (need root to place binary).
            (true, ExeProvenance::InstalledApp) => t.devtool.push(label),
            // User-writable tree: path does NOT clear; parentage needed later.
            // For now — provisional trust.
            (true, ExeProvenance::NestedUserInstall) => t.provisional.push(label),
            // Lone/deleted binary OR exposed to the world → keep alert.
            _ => t.suspicious.push(label),
        }
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::PortInfo;
    use std::collections::HashMap;

    #[test]
    fn run_child_with_timeout_large_stdout_does_not_deadlock() {
        let result = run_child_with_timeout("sh", &["-c", "head -c 200000 /dev/zero | base64"], 10);
        assert!(result.is_some());
        let output = result.unwrap();
        assert!(output.status.success());
        assert!(output.stdout.len() > 100_000);
    }

    #[test]
    fn run_child_with_timeout_timeout_kills_child() {
        let result = run_child_with_timeout("sleep", &["60"], 1);
        assert!(result.is_none());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn wait_group_safe_reaps_and_returns_status() {
        let mut child = hardened_command("/bin/true", &[])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn /bin/true");
        let st = wait_group_safe(&mut child, Duration::from_secs(2));
        assert!(st.is_some_and(|s| s.success()));
        assert!(
            child.wait().is_ok(),
            "second wait must use the cached status"
        );
    }

    // ── R35-05: trusted-exec gate ────────────────────────────

    #[test]
    fn a_packaged_shell_is_trusted() {
        // usrmerge makes either canonical; at least one must exist and pass.
        assert!(
            is_trusted_exec("/bin/sh") || is_trusted_exec("/usr/bin/sh"),
            "/bin/sh or /usr/bin/sh must be trusted on a normal host"
        );
    }

    #[test]
    fn a_nonexistent_path_is_not_trusted() {
        assert!(!is_trusted_exec("/nonexistent/path/to/nothing"));
        assert!(exec_target("/nonexistent/absolute/tool").is_none());
    }

    #[test]
    fn a_group_writable_binary_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        // /tmp is o+w, so a fixture there fails the ancestor check for a
        // reason unrelated to the file's own mode. Use a private tree under
        // /root, reachable only when running as root.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let dir = std::path::Path::new("/root/.owlzops-test-r35-05");
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let bin = dir.join("tool");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(
            !is_trusted_exec(bin.to_str().unwrap()),
            "group-writable binary must be refused even under a root-owned dir"
        );
        assert!(
            exec_target(bin.to_str().unwrap()).is_none(),
            "absolute paths are re-verified"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn wildcard_bind_matches_canonical_forms() {
        assert!(is_wildcard_bind("0.0.0.0"));
        assert!(is_wildcard_bind("::"));
        assert!(is_wildcard_bind("::ffff:0.0.0.0"));
    }

    #[test]
    fn wildcard_bind_rejects_everything_else() {
        assert!(!is_wildcard_bind("127.0.0.1"));
        assert!(!is_wildcard_bind("::1"));
        assert!(!is_wildcard_bind("10.0.0.1"));
        assert!(!is_wildcard_bind("::ffff:127.0.0.1"));
        assert!(!is_wildcard_bind(""));
        assert!(!is_wildcard_bind("0.0.0.0 "));
        assert!(!is_wildcard_bind("[::]"));
        assert!(!is_wildcard_bind("*"));
        assert!(!is_wildcard_bind("::ffff:0:0"));
    }

    #[test]
    fn loopback_bind_matches_canonical_forms() {
        assert!(is_loopback_bind("127.0.0.1"));
        assert!(is_loopback_bind("127.0.0.53"));
        assert!(is_loopback_bind("127.0.1.1"));
        assert!(is_loopback_bind("::1"));
        assert!(is_loopback_bind("::ffff:127.0.0.1"));
        assert!(is_loopback_bind("::ffff:127.0.0.53"));
    }

    #[test]
    fn loopback_bind_rejects_everything_else() {
        assert!(!is_loopback_bind("0.0.0.0"));
        assert!(!is_loopback_bind("::"));
        assert!(!is_loopback_bind("::ffff:0.0.0.0"));
        assert!(!is_loopback_bind("10.0.0.1"));
        assert!(!is_loopback_bind("128.0.0.1"));
        assert!(!is_loopback_bind("1127.0.0.1"));
        assert!(!is_loopback_bind("127."));
        assert!(!is_loopback_bind("127.0.0.1 "));
        assert!(!is_loopback_bind("::ffff:10.0.0.1"));
        assert!(!is_loopback_bind("::2"));
        assert!(!is_loopback_bind("localhost"));
        assert!(!is_loopback_bind(""));
    }

    #[test]
    fn ephemeral_exec_path_matches_expected_directories() {
        assert!(is_ephemeral_exec_path("/tmp/malware"));
        assert!(is_ephemeral_exec_path("/var/tmp/.hidden"));
        assert!(is_ephemeral_exec_path("/dev/shm/session"));
        assert!(is_ephemeral_exec_path("/home/user/script"));
    }

    #[test]
    fn ephemeral_exec_path_rejects_system_paths() {
        assert!(!is_ephemeral_exec_path("/usr/bin/ls"));
        assert!(!is_ephemeral_exec_path("/bin/bash"));
        assert!(!is_ephemeral_exec_path("/opt/tmp/bin"));
        assert!(!is_ephemeral_exec_path("/etc/cron.d/backup"));
        assert!(!is_ephemeral_exec_path(""));
        assert!(!is_ephemeral_exec_path("/tmp"));
        assert!(!is_ephemeral_exec_path("/tmp "));
    }

    #[test]
    fn ephemeral_exec_path_boundary_cases() {
        assert!(is_ephemeral_exec_path("/tmp/"));
        assert!(!is_ephemeral_exec_path("/tmp"));
        assert!(!is_ephemeral_exec_path("/var/log/syslog"));
        assert!(!is_ephemeral_exec_path("/dev/null"));
        assert!(is_ephemeral_exec_path("/home/user/.local/share/something"));
    }

    #[test]
    fn ephemeral_path_matches_memfd() {
        assert!(is_ephemeral_exec_path("/memfd:kdevtmpfsi"));
        assert!(is_ephemeral_exec_path("/memfd:kdevtmpfsi (deleted)"));
        assert!(is_ephemeral_exec_path("/memfd:x"));
        assert!(!is_ephemeral_exec_path("/usr/bin/memfd:tool"));
        assert!(!is_ephemeral_exec_path("memfd:foo"));
        assert!(!is_ephemeral_exec_path("/opt/memfd:app"));
    }

    #[test]
    fn known_malware_exact_case_insensitive() {
        assert!(is_known_malware("xmrig"));
        assert!(is_known_malware("KDevTmpFSi"));
        assert!(is_known_malware("  kinsing  "));
        assert!(!is_known_malware("xmrigd"));
        assert!(!is_known_malware("networkservice"));
        assert!(!is_known_malware("nginx"));
        assert!(!is_known_malware(""));
    }

    #[test]
    fn ambiguous_malware_is_separate_tier() {
        assert!(is_ambiguous_malware("networkservice"));
        assert!(!is_ambiguous_malware("NetworkManager"));
        assert!(!is_known_malware("networkservice"));
    }

    #[test]
    fn canon_path_usrmerge() {
        assert_eq!(canon_path("/bin/su"), "/usr/bin/su");
        assert_eq!(canon_path("/lib/foo"), "/usr/lib/foo");
        assert_eq!(canon_path("/sbin/ip"), "/usr/sbin/ip");
        assert_eq!(canon_path("/lib64/bar"), "/usr/lib64/bar");
        assert_eq!(canon_path("/usr/bin/su"), "/usr/bin/su"); // idempotent
        assert_eq!(canon_path("/opt/app"), "/opt/app");
        assert_eq!(canon_path("/home/user"), "/home/user");
    }

    #[test]
    fn nix_store_paths_are_recognised_as_system_installs() {
        assert!(
            is_standard_install_path("/nix/store/0m0a1zw-coreutils-9.5/bin/ls"),
            "NixOS system binaries must not be treated as non-standard"
        );
    }

    #[test]
    fn volatile_paths_are_narrower_than_ephemeral() {
        assert!(is_ephemeral_exec_path("/home/u/Downloads/app-1.2/bin/app"));
        assert!(!is_volatile_exec_path("/home/u/Downloads/app-1.2/bin/app"));

        for p in ["/tmp/x", "/var/tmp/x", "/dev/shm/x", "/memfd:x"] {
            assert!(is_volatile_exec_path(p), "{p} must stay volatile");
        }
        assert!(!is_volatile_exec_path("/usr/bin/nginx"));
    }

    #[test]
    fn atomic_var_home_is_user_space() {
        // Fedora Silverblue: /home is a symlink, /proc/<pid>/exe canonicalises
        // to /var/home. Both must be treated as user-writable.
        assert!(is_ephemeral_exec_path("/var/home/u/.cache/implant"));
        assert!(is_ephemeral_exec_path("/root/x/payload"));
        assert!(
            !is_volatile_exec_path("/var/home/u/.cache/implant"),
            "user space, not volatile"
        );
    }

    #[test]
    fn shared_user_dirs_cannot_vouch_for_a_binary() {
        for d in [
            "/home/u",
            "/home/u/Downloads",
            "/home/u/.cache",
            "/home/u/.local/share",
            "/opt",
            "/usr/share",
            "/root",
            "/",
        ] {
            assert!(is_container_dir(d), "{d} must never vouch");
        }
        for d in [
            "/home/u/Downloads/jetbrains-toolbox-3.6.2",
            "/home/u/Downloads/jetbrains-toolbox-3.6.2/bin",
            "/opt/app/bin",
        ] {
            assert!(!is_container_dir(d), "{d} is a dedicated app subtree");
        }
    }

    #[test]
    fn home_relative_depth_counts_below_the_user_dir() {
        assert_eq!(home_relative_depth("/home/u"), Some(0));
        assert_eq!(home_relative_depth("/home/u/Downloads"), Some(1));
        assert_eq!(home_relative_depth("/home/u/Downloads/app/bin"), Some(3));
        assert_eq!(home_relative_depth("/var/home/u/apps"), Some(1));
        assert_eq!(home_relative_depth("/root"), Some(0));
        assert_eq!(home_relative_depth("/opt/app"), None);
    }

    #[test]
    fn loopback_volatile_path_keeps_full_weight() {
        let ports = vec![PortInfo {
            port: "4444".into(),
            protocol: "tcp".into(),
            bind_address: "127.0.0.1".into(),
            exe_path: Some("/dev/shm/.hidden/implant".into()),
            process: "implant".into(),
            pid: None,
        }];
        assert_eq!(classify_listeners(&ports).suspicious.len(), 1);
    }

    #[test]
    fn toolbox_subtree_vouches_shared_dir_does_not() {
        let fs: HashMap<&str, usize> = HashMap::from([
            ("/home/u/Downloads", 40),
            ("/home/u/Downloads/jetbrains-toolbox-3.6.2/bin", 24),
            ("/home/u/Downloads/jetbrains-toolbox-3.6.2", 3),
            ("/home/u/.cache", 120),
        ]);
        let count = |p: &std::path::Path| fs.get(p.to_string_lossy().as_ref()).copied();

        // Real app subtree → vouched, even though it lives under a shared dir.
        assert!(populated_tree_within_with(
            "/home/u/Downloads/jetbrains-toolbox-3.6.2/bin/jetbrains-toolbox",
            count
        ));
        // Lone dropper in the same shared dir → the 40 siblings must NOT vouch.
        assert!(!populated_tree_within_with(
            "/home/u/Downloads/payload",
            count
        ));
        // ~/.cache has 120 entries and still must not vouch.
        assert!(!populated_tree_within_with(
            "/home/u/.cache/systemd-update",
            count
        ));
    }

    #[test]
    fn run_tmpfs_is_volatile_and_reaches_classification() {
        // /run/user/<uid> is user-writable tmpfs — a session-lifetime implant home.
        assert!(is_ephemeral_exec_path("/run/user/1000/.x/implant"));
        assert!(is_volatile_exec_path("/run/user/1000/.x/implant"));
        // Boundary: /runtime-foo must NOT match.
        assert!(!is_volatile_exec_path("/runtime-foo/bin/app"));
    }

    #[test]
    fn nixos_wrappers_are_not_volatile_despite_living_on_run() {
        // fs_inventory scans /run/wrappers/bin as a legitimate binary root (R22-14);
        // the volatile predicate must agree.
        assert!(!is_volatile_exec_path("/run/wrappers/bin/sudo"));
        assert!(!is_ephemeral_exec_path("/run/wrappers/bin/ping"));
        // The carve-out must not leak to the rest of /run.
        assert!(is_volatile_exec_path("/run/user/1000/.x/implant"));
        assert!(is_volatile_exec_path("/run/wrappersX/payload"));
    }

    // --- New tests for sanitize_for_log ---

    #[test]
    fn sanitize_for_log_removes_ansi_csi_sequences() {
        let input = "\x1b[31mred\x1b[0m text";
        assert_eq!(sanitize_for_log(input), "red text");
    }

    #[test]
    fn sanitize_for_log_replaces_control_chars_with_spaces() {
        let input = "hello\x01\x1b[2Jworld";
        assert_eq!(sanitize_for_log(input), "hello world");
    }

    #[test]
    fn sanitize_for_log_truncates_to_300_chars() {
        let input = "a".repeat(500);
        assert_eq!(sanitize_for_log(&input).chars().count(), 300);
    }

    #[test]
    fn sanitize_for_log_removes_unicode_bidi_controls() {
        let out = sanitize_for_log("safe\u{202E}evil\u{2066}text\u{202C}");
        assert!(!out.contains('\u{202E}'));
        assert!(!out.contains('\u{2066}'));
        assert!(!out.contains('\u{202C}'));
    }

    #[test]
    fn sanitize_for_log_removes_zero_width_format_chars() {
        let out = sanitize_for_log("a\u{200B}b\u{FEFF}c");
        assert!(!out.contains('\u{200B}'));
        assert!(!out.contains('\u{FEFF}'));
        assert!(out.chars().all(|c| !is_terminal_unsafe(c)));
    }

    #[test]
    fn terminal_unsafe_predicate_catches_tag_block() {
        // U+E0061 is TAG LATIN SMALL LETTER A, used for spoofing.
        assert!(is_terminal_unsafe('\u{E0061}'));
        assert!(is_terminal_unsafe('\u{200F}')); // RLM
        assert!(is_terminal_unsafe('\u{1B}')); // ESC
        assert!(!is_terminal_unsafe('a'));
        assert!(!is_terminal_unsafe('1'));
        // Newline is a control char and must be neutralized by sanitizers.
        assert!(is_terminal_unsafe('\n'));
    }
}

#[cfg(test)]
mod system_path_tests {
    use super::*;

    #[test]
    fn system_managed_includes_non_package_manager_roots() {
        // These are system-side for classification but NOT package-manager
        // territory. If is_system_managed_path ever narrows to SYSTEM_BIN,
        // mount-namespace anomalies from nix/snap/flatpak will start
        // firing on normal processes.
        for p in [
            "/nix/store/abc/bin/foo",
            "/snap/firefox/1/usr/lib/firefox/firefox",
            "/var/lib/flatpak/app/x/y/z",
            "/opt/app/bin/server",
        ] {
            assert!(is_system_managed_path(p), "expected system-managed: {p}");
        }
    }

    #[test]
    fn system_bin_excludes_non_package_manager_roots() {
        // The mirror-image invariant. If SYSTEM_BIN ever widens to include
        // these, provenance will misclassify snap/flatpak/nix installs as
        // package-manager-owned.
        for p in [
            "/nix/store/abc/bin/foo",
            "/snap/firefox/1/usr/lib/firefox/firefox",
            "/var/lib/flatpak/app/x/y/z",
            "/opt/app/bin/foo",
        ] {
            assert!(
                !SYSTEM_BIN.iter().any(|s| p.starts_with(s)),
                "SYSTEM_BIN must not match: {p}"
            );
        }
    }

    #[test]
    fn usr_prefix_covers_modern_usr_layouts() {
        // /usr/ as a prefix (not /usr/bin/) so future usr layouts
        // (e.g. /usr/libexec/) don't need manual additions here.
        for p in ["/usr/bin/ls", "/usr/libexec/x", "/usr/local/bin/y"] {
            assert!(is_system_managed_path(p), "expected system-managed: {p}");
        }
    }

    #[test]
    fn user_and_temp_paths_are_not_system_managed() {
        for p in ["/home/user/bin/x", "/tmp/x", "/root/.local/bin/x"] {
            assert!(!is_system_managed_path(p), "expected non-system: {p}");
        }
    }
}
