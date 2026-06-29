use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

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

    // Wait for the reader thread or timeout
    match rx.recv_timeout(Duration::from_secs(timeout_secs)) {
        Ok(stdout) => {
            // Process finished (or at least closed stdout). Wait for it to reap zombie.
            let status = child.wait().ok()?;
            if require_success && !status.success() {
                return None;
            }
            Some(stdout)
        }
        Err(_timeout) => {
            // Kill the child and the reader thread will finish
            let _ = child.kill();
            let _ = child.wait();
            None
        }
    }
}
