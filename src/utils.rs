use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

/// Run a command with a timeout and return its stdout if it exits successfully.
pub fn run_with_timeout(program: &str, args: &[&str], timeout_secs: u64) -> Option<String> {
    run_with_timeout_inner(program, args, timeout_secs, true)
}

/// Run a command with a timeout and return its stdout regardless of exit code
/// (except for real timeout). Use this for commands that use non-zero exit codes
/// to indicate success (e.g., `dnf check-update` returns 100 when updates are available).
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
    let (tx, rx) = mpsc::channel();
    let program = program.to_string();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();

    std::thread::spawn(move || {
        let result = Command::new(&program).args(&args).output();
        let _ = tx.send(result);
    });

    match rx.recv_timeout(Duration::from_secs(timeout_secs)) {
        Ok(Ok(output)) if !require_success || output.status.success() => {
            Some(String::from_utf8_lossy(&output.stdout).into_owned())
        }
        Ok(_) => None,  // command failed or exit code not 0 when require_success
        Err(_) => None, // timeout
    }
}
