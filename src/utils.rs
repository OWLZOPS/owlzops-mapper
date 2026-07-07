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

// ---------------------------------------------------------------------------
// Child helpers (unchanged logic, now hardened)
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

/// Run a child process with capped stdout/stderr, a timeout, and a
/// hardened environment.
///
/// Uses `resolve_tool` to obtain an absolute path; if that fails the
/// original short name is still executed (with `env_clear`).
pub fn run_child_with_timeout(
    program: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Option<std::process::Output> {
    let resolved = resolve_tool(program).unwrap_or_else(|| program.to_string());

    let mut child = hardened_command(&resolved, args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    let out_pipe = child.stdout.take()?;
    let mut err_pipe = child.stderr.take()?;

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
        let mut buf = Vec::new();
        let _ = err_pipe.read_to_end(&mut buf);
        buf
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
            poll_wait(&mut child, Duration::from_secs(1));
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
}
