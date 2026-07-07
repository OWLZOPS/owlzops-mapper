use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::coverage;
use crate::safe_io;

/// Wait for a child process to finish, polling with `try_wait()` until `deadline`.
/// If the process is still alive after the deadline, it is killed and we wait
/// a short grace period for the kill to take effect.
fn poll_wait(child: &mut Child, deadline: Duration) -> Option<std::process::ExitStatus> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if start.elapsed() < deadline => {
                thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                // Deadline exceeded – kill and give a short grace for cleanup
                let _ = child.kill();
                thread::sleep(Duration::from_millis(100));
                return child.try_wait().ok().flatten();
            }
            Err(_) => return None,
        }
    }
}

pub fn run_child_with_timeout(
    program: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Option<std::process::Output> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    let out_pipe = child.stdout.take()?;
    let mut err_pipe = child.stderr.take()?;

    // Own a copy for the thread
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
                // Detach reader threads: buffers are discarded, no need to wait for orphaned grandchildren
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
/// Returns stdout if the command exits with success **and** within the timeout.
/// On timeout the child process is killed and None is returned.
pub fn run_with_timeout(program: &str, args: &[&str], timeout_secs: u64) -> Option<String> {
    run_with_timeout_inner(program, args, timeout_secs, true)
}

/// Execute a command with a timeout, accepting any exit code (including non‑zero).
/// Still returns None on timeout.
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
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    let (tx, rx) = mpsc::channel();
    let mut child_stdout = child.stdout.take()?;

    // Reader thread: accumulate stdout and send it back
    thread::spawn(move || {
        let mut buf = String::new();
        let _ = child_stdout.read_to_string(&mut buf);
        let _ = tx.send(buf);
    });

    match rx.recv_timeout(Duration::from_secs(timeout_secs)) {
        Ok(stdout) => {
            // Process closed stdout (or finished). Wait for it to reap, but with a deadline.
            let status = poll_wait(&mut child, Duration::from_secs(2));
            if require_success {
                match status {
                    Some(s) if s.success() => Some(stdout),
                    _ => None,
                }
            } else {
                // Any exit code is acceptable (even if we killed it after deadline – we already have stdout)
                Some(stdout)
            }
        }
        Err(_timeout) => {
            // Timeout while waiting for stdout – kill the child
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
        // Use direct 'sleep' process to avoid orphan grandchildren holding pipe
        let result = run_child_with_timeout("sleep", &["60"], 1);
        assert!(result.is_none());
    }
}
