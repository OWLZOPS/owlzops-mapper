use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use crate::coverage;
use crate::safe_io;

// ---------------------------------------------------------------------------
// Hardened tool resolution
// ---------------------------------------------------------------------------

fn tool_cache() -> &'static Mutex<HashMap<String, String>> {
    static CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

// R10-04: poison‑tolerant lock helper
fn lock_cache() -> std::sync::MutexGuard<'static, HashMap<String, String>> {
    tool_cache().lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Resolve a system tool by searching fixed standard directories.
/// This avoids a fork of `which` and is resilient against PATH manipulation.
pub fn resolve_tool(tool: &str) -> Option<String> {
    // Fast path: hit the (poison‑tolerant) cache
    if let Some(path) = lock_cache().get(tool) {
        return Some(path.clone());
    }

    use std::os::unix::fs::PermissionsExt;
    for dir in ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
        let candidate = format!("{dir}/{tool}");
        if let Ok(md) = std::fs::metadata(&candidate)
            && md.is_file()
            && md.permissions().mode() & 0o111 != 0
        {
            lock_cache().insert(tool.to_string(), candidate.clone());
            return Some(candidate);
        }
    }
    None
}

pub fn hardened_command(program: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C");
    cmd
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

/// Executables served from writable/ephemeral locations — a shared signal
/// for shadow-IT (SEC-013), IoC (SEC-015) and ambiguous-malware corroboration.
///
/// `/memfd:` covers `memfd_create`-backed execution (fully in-memory implants);
/// the kernel renders such exe links as `/memfd:<name> (deleted)`. Prefix match
/// is deletion-suffix agnostic, so this holds whether called on the raw link
/// or on the base path after the ` (deleted)` suffix is stripped.
pub fn is_ephemeral_exec_path(path: &str) -> bool {
    path.starts_with("/tmp/")
        || path.starts_with("/var/tmp/")
        || path.starts_with("/dev/shm/")
        || path.starts_with("/home/")
        || path.starts_with("/memfd:")
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
// Child helpers
// ---------------------------------------------------------------------------

/// Wait for a child process to finish, polling with `try_wait()` until `deadline`.
/// R10-05: defensive reap in the `Err(_)` branch so no zombie escapes.
fn poll_wait(child: &mut Child, deadline: Duration) -> Option<std::process::ExitStatus> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if start.elapsed() < deadline => {
                thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                return child.wait().ok();
            }
            Err(_) => {
                // try_wait failed (realistically ECHILD) – reap defensively
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

pub fn run_child_with_timeout(
    program: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Option<std::process::Output> {
    let resolved = resolve_tool(program).unwrap_or_else(|| program.to_string());
    let mut child = hardened_command(&resolved, args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
        .ok()?;

    let out_pipe = child.stdout.take()?;
    let err_pipe = child.stderr.take()?;
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
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if start.elapsed() < deadline => {
                thread::sleep(Duration::from_millis(50));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                drop(out_handle);
                drop(err_handle);
                return None;
            }
        }
    };

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
fn run_with_timeout_inner(
    program: &str,
    args: &[&str],
    timeout_secs: u64,
    require_success: bool,
) -> Option<String> {
    let resolved = resolve_tool(program).unwrap_or_else(|| program.to_string());
    let mut child = hardened_command(&resolved, args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .ok()?;

    let (tx, rx) = mpsc::channel();
    // Defensive: if stdout was somehow not captured, reap the child immediately
    let Some(child_stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
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
            let status = poll_wait(&mut child, Duration::from_secs(2));
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
            let _ = child.kill();
            let _ = child.wait();
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Base path after ` (deleted)` is stripped (classify_suspicious order).
        assert!(is_ephemeral_exec_path("/memfd:kdevtmpfsi"));
        // Raw readlink form, suffix still attached — prefix match is robust to it.
        assert!(is_ephemeral_exec_path("/memfd:kdevtmpfsi (deleted)"));
        assert!(is_ephemeral_exec_path("/memfd:x"));
        // Regression guard: a legit file literally named "memfd:" without the
        // leading slash, or a system path mentioning memfd, must NOT match.
        assert!(!is_ephemeral_exec_path("/usr/bin/memfd:tool"));
        assert!(!is_ephemeral_exec_path("memfd:foo")); // no leading slash
        assert!(!is_ephemeral_exec_path("/opt/memfd:app")); // memfd not at root
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
}