//! Agentless LSM confinement audit (SEC-039).
//! Surfaces MAC *downgrades* — the near-zero-FP signals that a hardening
//! baseline has regressed or been switched off:
//!   • AppArmor profiles running in `complain` (non-enforcing) mode,
//!   • SELinux present but globally `permissive`.
//! The /proc walk runs only when a MAC LSM is actually loaded. std-only.

use crate::coverage;
use crate::models::{ComplainProc, ConfinementReport};
use crate::safe_io;
use std::fs;

pub(crate) fn parse_lsm_list(content: &str) -> Vec<String> {
    content
        .trim()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// `"<profile> (complain)"` → Some(profile); enforce/unconfined → None.
pub(crate) fn complain_profile(attr_current: &str) -> Option<&str> {
    attr_current
        .trim()
        .strip_suffix("(complain)")
        .map(str::trim)
}

#[cfg(target_os = "linux")]
pub fn gather_confinement() -> ConfinementReport {
    let mut report = ConfinementReport::default();

    if let Ok((content, _)) = safe_io::read_procfs_capped("/sys/kernel/security/lsm", 4096) {
        report.lsms = parse_lsm_list(&content);
    }
    let has = |name: &str| report.lsms.iter().any(|l| l == name);

    if has("selinux")
        && let Ok((v, _)) = safe_io::read_procfs_capped("/sys/fs/selinux/enforce", 16)
    {
        report.selinux_permissive = v.trim() == "0";
    }

    // AppArmor complain-mode processes — walk /proc only when AppArmor is loaded.
    if has("apparmor") {
        let mut denied = 0usize;
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let Some(pid) = entry
                    .file_name()
                    .to_str()
                    .and_then(|s| s.parse::<u32>().ok())
                else {
                    continue;
                };
                match safe_io::read_procfs_capped(&format!("/proc/{pid}/attr/current"), 4096) {
                    Ok((attr, _)) => {
                        if let Some(profile) = complain_profile(&attr) {
                            let comm =
                                safe_io::read_procfs_capped(&format!("/proc/{pid}/comm"), 256)
                                    .map(|(s, _)| s.trim().to_string())
                                    .unwrap_or_default();
                            report.complain_profiles.push(ComplainProc {
                                pid,
                                comm,
                                profile: profile.to_string(),
                            });
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => denied += 1,
                    Err(_) => {}
                }
            }
        }
        if denied > 0 {
            report.attr_read_incomplete = true;
            let hint = if !crate::is_running_as_root() {
                " — run as root for full coverage"
            } else {
                ""
            };
            coverage::record(format!(
                "confinement: {denied} process(es) with unreadable \
                 /proc/<pid>/attr/current{hint}; complain-mode audit INCOMPLETE"
            ));
        }
    }
    report
}

#[cfg(not(target_os = "linux"))]
pub fn gather_confinement() -> ConfinementReport {
    ConfinementReport::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lsm_list() {
        assert_eq!(
            parse_lsm_list("capability,yama,apparmor\n"),
            vec!["capability", "yama", "apparmor"]
        );
        assert!(parse_lsm_list("").is_empty());
    }

    #[test]
    fn detects_complain_mode_only() {
        assert_eq!(
            complain_profile("/usr/sbin/mysqld (complain)"),
            Some("/usr/sbin/mysqld")
        );
        assert_eq!(complain_profile("docker-default (enforce)"), None);
        assert_eq!(complain_profile("unconfined"), None);
    }
}
