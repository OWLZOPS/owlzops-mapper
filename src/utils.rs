use std::collections::HashMap;
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use crate::coverage;
use crate::safe_io;

// ---------------------------------------------------------------------------
// Hardened tool resolution
// ---------------------------------------------------------------------------

/// Global cache of absolute paths resolved against a trusted `PATH`.
fn tool_cache() -> &'static Mutex<HashMap<String, String>> {
    static CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Resolve a short tool name (`dmesg`, `sshd`, …) to an absolute path using a
/// **trusted** `PATH` and a clean environment. The result is cached for the
/// lifetime of the process.
///
/// Returns `None` when the tool cannot be found, but the caller should still
/// attempt to spawn it using a hardened command (the short name will be used
/// as a fallback).
pub fn resolve_tool(tool: &str) -> Option<String> {
    // Look up in cache first
    {
        let cache = tool_cache().lock().unwrap();
        if let Some(path) = cache.get(tool) {
            return Some(path.clone());
        }
    }

    // Resolve with a safe `which` call
    let output = Command::new("which")
        .arg(tool)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .output()
        .ok()?;

    if output.status.success() {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            let mut cache = tool_cache().lock().unwrap();
            cache.insert(tool.to_string(), path.clone());
            return Some(path);
        }
    }

    None
}

/// Create a `Command` hardened against `PATH`‑hijack and `LD_PRELOAD`.
///
/// * The environment is **completely emptied** and only `PATH` and `LC_ALL`
///   are set to known‑safe values.
/// * The caller is expected to pass an **absolute** path obtained from
///   [`resolve_tool`], but a short name is also accepted as a fallback.
pub fn hardened_command(program: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C");
    cmd
}

/// Single source of truth for per‑host timeout budget.
/// Used by both the fleet orchestrator and the internal russh path.
pub(crate) const fn host_budget_secs(t: u64) -> u64 {
    t.saturating_mul(2).saturating_add(60)
}

// ---------------------------------------------------------------------------
// Network predicates
// ---------------------------------------------------------------------------

/// Single source of truth for "globally exposed" bind addresses.
///
/// Matches the canonical wildcard forms our `/proc/net` decoders can emit
/// (plain IPv4/IPv6 wildcards plus the IPv4-mapped IPv6 wildcard reported
/// for AF_INET6 sockets bound to all v4 interfaces). Comparison is exact
/// by design – the decoders never pad or alias.
pub fn is_wildcard_bind(addr: &str) -> bool {
    matches!(addr, "0.0.0.0" | "::" | "::ffff:0.0.0.0")
}

/// Single source of truth for "loopback" bind addresses.
///
/// Unlike the wildcard case, exact literals cannot be total here: IPv4
/// loopback is the whole 127.0.0.0/8 block (systemd-resolved alone binds
/// 127.0.0.53/127.0.0.54), so both v4 families — native and IPv4-mapped —
/// are matched by canonical prefix with a digits/dots tail check, keeping
/// padded or alphanumeric garbage out. `::1` stays an exact `matches!` arm:
/// IPv6 loopback is a single address. Zero-copy throughout.
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

// ---------------------------------------------------------------------------
// Child helpers (unchanged logic, now hardened and with stdin nulled)
// ---------------------------------------------------------------------------

/// Wait for a child process to finish, polling with `try_wait()` until `deadline`.
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
                thread::sleep(Duration::from_millis(100));
                return child.try_wait().ok().flatten();
            }
            Err(_) => return None,
        }
    }
}

/// Run a child process with capped stdout/stderr, a timeout, a hardened
/// environment, and **no stdin** to prevent the child from capturing the
/// operator's terminal input (R8-07).
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

/// Execute a command with a timeout.
/// See [`run_with_timeout_inner`].
pub fn run_with_timeout(program: &str, args: &[&str], timeout_secs: u64) -> Option<String> {
    run_with_timeout_inner(program, args, timeout_secs, true)
}

/// Execute a command with a timeout, accepting any exit code.
pub fn run_with_timeout_any_exit(
    program: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Option<String> {
    run_with_timeout_inner(program, args, timeout_secs, false)
}

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
    let mut child_stdout = child.stdout.take()?;

    thread::spawn(move || {
        let mut buf = String::new();
        let _ = child_stdout.read_to_string(&mut buf);
        let _ = tx.send(buf);
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
        assert!(result.is_some(), "Process should not time out");
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
        assert!(is_loopback_bind("127.0.0.53")); // systemd-resolved stub
        assert!(is_loopback_bind("127.0.1.1")); // full /8 — same semantics as is_local_ip
        assert!(is_loopback_bind("::1"));
        assert!(is_loopback_bind("::ffff:127.0.0.1")); // mapped loopback
        assert!(is_loopback_bind("::ffff:127.0.0.53"));
    }

    #[test]
    fn loopback_bind_rejects_everything_else() {
        assert!(!is_loopback_bind("0.0.0.0"));
        assert!(!is_loopback_bind("::"));
        assert!(!is_loopback_bind("::ffff:0.0.0.0")); // wildcard family, not loopback
        assert!(!is_loopback_bind("10.0.0.1"));
        assert!(!is_loopback_bind("128.0.0.1")); // /8 boundary
        assert!(!is_loopback_bind("1127.0.0.1")); // prefix, not substring
        assert!(!is_loopback_bind("127.")); // empty tail
        assert!(!is_loopback_bind("127.0.0.1 ")); // padded input stays rejected
        assert!(!is_loopback_bind("::ffff:10.0.0.1")); // mapped non-loopback
        assert!(!is_loopback_bind("::2"));
        assert!(!is_loopback_bind("localhost")); // names are not bind strings
        assert!(!is_loopback_bind(""));
    }
}
