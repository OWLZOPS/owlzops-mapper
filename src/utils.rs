use std::process::Command;

/// Execute a command with a timeout using system `timeout` (GNU coreutils).
/// `timeout` sends SIGTERM on expiration, then SIGKILL, guaranteeing cleanup.
/// Returns Some(stdout) only on successful execution (exit code 0).
pub fn run_with_timeout(program: &str, args: &[&str], timeout_secs: u64) -> Option<String> {
    run_with_timeout_inner(program, args, timeout_secs, true)
}

/// Execute a command with a timeout, accepting any exit code (including non-zero).
/// Use for commands like `dnf check-update` where exit 100 means "updates available".
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
    let output = Command::new("timeout")
        .arg(format!("{}s", timeout_secs))
        .arg(program)
        .args(args)
        .output()
        .ok()?;

    // Exit code 124 = timed out
    if output.status.code() == Some(124) {
        return None;
    }

    if require_success && !output.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}
