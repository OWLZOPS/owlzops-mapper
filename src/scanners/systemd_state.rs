//! Active-state of systemd units without D-Bus or `systemctl`.
//! systemd ≥ v232 exports one symlink per **running** unit:
//!     /run/systemd/units/invocation:<unit>  →  <invocation id>
//! Presence is the fact. A missing directory means "no systemd or too old";
//! the caller falls back to `systemctl` in that case only.
//!
//! Scope is deliberate: only `running` units carry an invocation symlink.
//! A timer in its normal `active (waiting)` state does NOT — the link is
//! created when the unit starts and removed when it stops. Timers must go
//! through `systemctl list-timers` (without `--all`); reading them from
//! this directory silently returns an empty set.
use std::path::Path;

const UNITS_RUN_DIR: &str = "/run/systemd/units";

/// Is `unit` currently in the `running` state? `None` = the export is
/// unavailable (pre-v232 systemd, no systemd, or the directory is not
/// readable) — the caller must fall back, not assume `false`.
pub fn unit_is_active(unit: &str) -> Option<bool> {
    unit_is_active_in(Path::new(UNITS_RUN_DIR), unit)
}

pub(crate) fn unit_is_active_in(dir: &Path, unit: &str) -> Option<bool> {
    if !dir.is_dir() {
        return None;
    }
    Some(
        dir.join(format!("invocation:{unit}"))
            .symlink_metadata()
            .is_ok(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_symlink_means_active() {
        let tmp = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("0123abcd", tmp.path().join("invocation:fail2ban.service"))
            .unwrap();
        assert_eq!(
            unit_is_active_in(tmp.path(), "fail2ban.service"),
            Some(true)
        );
        assert_eq!(unit_is_active_in(tmp.path(), "auditd.service"), Some(false));
    }

    #[test]
    fn missing_directory_is_unknown_not_inactive() {
        let tmp = tempfile::tempdir().unwrap();
        let gone = tmp.path().join("absent");
        assert_eq!(
            unit_is_active_in(&gone, "x.service"),
            None,
            "caller must fall back"
        );
    }
}
