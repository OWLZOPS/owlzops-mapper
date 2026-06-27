use std::process::Command;

/// Run an external command with a timeout (in seconds).
/// Returns stdout if the command succeeds, None otherwise.
pub fn run_with_timeout(program: &str, args: &[&str], timeout_secs: u64) -> Option<String> {
    let output = Command::new("timeout")
        .arg(format!("{}s", timeout_secs))
        .arg(program)
        .args(args)
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        None
    }
}
