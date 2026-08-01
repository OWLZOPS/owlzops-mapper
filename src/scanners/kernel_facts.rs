// src/scanners/kernel_facts.rs
// Collects three low-cost kernel security facts that are valuable for audit
// reports and directly feed into the risk scoring.

use crate::coverage;
use crate::safe_io;

/// Gather kernel hardening facts: core_pattern, modules_disabled, lockdown state.
///
/// core_pattern is now `Option<String>`: `None` means the file was unreadable
/// (EACCES, missing `/proc`, etc.) and the core-dump handler hijack check
/// **cannot** be performed.  An empty string (the previous sentinel) is
/// indistinguishable from a genuinely empty pattern, which the kernel treats
/// as "disabled" and is safe — coverage distinguishes the two (R23-07).
pub fn gather_kernel_facts() -> (Option<String>, Option<bool>, Option<String>) {
    let core_pattern = match safe_io::read_file_capped("/proc/sys/kernel/core_pattern", 4096) {
        Ok((s, _)) => Some(s.trim().to_string()),
        Err(e) => {
            coverage::record(format!(
                "core_pattern unreadable ({e}); core-dump handler hijack NOT verified"
            ));
            None
        }
    };

    let modules_disabled = safe_io::read_file_capped("/proc/sys/kernel/modules_disabled", 4096)
        .ok()
        .and_then(|(s, _)| s.trim().parse::<u8>().ok())
        .map(|v| v == 1);

    if modules_disabled.is_none() {
        coverage::record(
            "modules_disabled unreadable (no /proc/sys/kernel/modules_disabled?)".to_string(),
        );
    }

    let lockdown = safe_io::read_file_capped("/sys/kernel/security/lockdown", 4096)
        .ok()
        .map(|(s, _)| {
            let s = s.trim();
            // Format: "none [integrity] confidentiality"
            if let Some(start) = s.find('[')
                && let Some(end) = s[start..].find(']')
            {
                s[start + 1..start + end].to_string()
            } else {
                s.to_string()
            }
        });

    if lockdown.is_none() {
        coverage::record(
            "lockdown state not available (kernel too old or /sys/kernel/security/lockdown missing)".to_string(),
        );
    }

    (core_pattern, modules_disabled, lockdown)
}
