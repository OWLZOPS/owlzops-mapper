use std::process::Command;

/// Run a command with a timeout and return its stdout if it exits successfully.
pub fn run_with_timeout(program: &str, args: &[&str], timeout_secs: u64) -> Option<String> {
    run_with_timeout_inner(program, args, timeout_secs, true)
}

/// Run a command with a timeout and return its stdout regardless of exit code
/// (except for real timeout, exit code 124).
/// Use this for commands that use non-zero exit codes to indicate success
/// (e.g., `dnf check-update` returns 100 when updates are available).
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

    // Exit code 124 means the `timeout` command killed the process.
    if output.status.code() == Some(124) {
        return None;
    }

    if require_success && !output.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&output.stdout).to_string())
}
