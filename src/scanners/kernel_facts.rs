// src/scanners/kernel_facts.rs
// Collects three low-cost kernel security facts that are valuable for audit
// reports and directly feed into the risk scoring.

use crate::coverage;
use crate::safe_io;
use std::collections::BTreeMap;

/// Sysctls that can only become stricter (or stay the same) without a reboot.
/// Weakening any of them between snapshots is either /proc tampering or a
/// reboot event — both are valuable drift signals.
const ONE_WAY_SWITCHES: &[(&str, &str)] = &[
    ("/proc/sys/kernel/modules_disabled", "modules_disabled"),
    (
        "/proc/sys/kernel/kexec_load_disabled",
        "kexec_load_disabled",
    ),
    (
        "/proc/sys/kernel/unprivileged_bpf_disabled",
        "unprivileged_bpf_disabled",
    ),
];

/// Read all one-way switches into a BTreeMap.  Unreadable files → `None`.
/// Missing files (e.g., kernel without BPF) are noted in coverage so that
/// `compare` can tell "never existed" from "vanished since baseline" (R24-07).
pub(crate) fn gather_one_way_switches() -> BTreeMap<String, Option<u8>> {
    let mut map = BTreeMap::new();
    for (path, label) in ONE_WAY_SWITCHES {
        let value = match safe_io::read_file_capped(path, 4096) {
            Ok((content, truncated)) => {
                if truncated {
                    coverage::record(format!("{path} truncated"));
                }
                match content.trim().parse::<u8>() {
                    Ok(v) => Some(v),
                    Err(_) => {
                        // R24-16: non-numeric content is itself an anomaly —
                        // possible /proc tampering or overlay. Distinguish it
                        // from a plain EACCES by recording coverage.
                        coverage::record(format!(
                            "{path} contains a non-numeric value — switch state UNKNOWN \
                             (possible /proc tampering)"
                        ));
                        None
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // File not present – legitimate on some kernels (e.g. no BPF),
                // but the *absence* must be visible so that compare.rs can tell
                // "never existed" from "vanished since baseline" (R24-07).
                coverage::record(format!(
                    "{path} absent — one-way switch '{label}' not tracked on this kernel"
                ));
                continue;
            }
            Err(e) => {
                coverage::record(format!("{path} unreadable ({e})"));
                None
            }
        };
        map.insert((*label).to_string(), value);
    }
    map
}

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
