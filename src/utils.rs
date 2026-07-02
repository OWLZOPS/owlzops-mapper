use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

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

    let deadline = Duration::from_secs(timeout_secs);
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                child.stdout.take()?.read_to_end(&mut stdout).ok()?;
                child.stderr.take()?.read_to_end(&mut stderr).ok()?;
                return Some(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) if start.elapsed() < deadline => {
                thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                thread::sleep(Duration::from_millis(100));
                let _ = child.wait();
                return None;
            }
            Err(_) => return None,
        }
    }
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
