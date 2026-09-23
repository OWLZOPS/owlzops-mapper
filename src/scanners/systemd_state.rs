//! Active-state of systemd units without D-Bus or `systemctl`.
//! systemd ≥ v232 exports one symlink per active unit:
//!     /run/systemd/units/invocation:<unit>  →  <invocation id>
//! Presence is the fact. A missing directory means "no systemd or too old";
//! the caller falls back to `systemctl` in that case only.
use std::path::Path;

const UNITS_RUN_DIR: &str = "/run/systemd/units";

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

/// All active units whose name ends with `suffix`, sorted and deduplicated.
pub fn active_units(suffix: &str) -> Option<Vec<String>> {
    active_units_in(Path::new(UNITS_RUN_DIR), suffix)
}

pub(crate) fn active_units_in(dir: &Path, suffix: &str) -> Option<Vec<String>> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut out: Vec<String> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name();
            let unit = name.to_str()?.strip_prefix("invocation:")?;
            unit.ends_with(suffix).then(|| unit.to_string())
        })
        .collect();
    out.sort();
    out.dedup();
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_symlink_means_active() {
        let tmp = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("0123abcd", tmp.path().join("invocation:fail2ban.service"))
            .unwrap();
        std::os::unix::fs::symlink("0123abce", tmp.path().join("invocation:apt-daily.timer"))
            .unwrap();
        assert_eq!(
            unit_is_active_in(tmp.path(), "fail2ban.service"),
            Some(true)
        );
        assert_eq!(unit_is_active_in(tmp.path(), "auditd.service"), Some(false));
        assert_eq!(
            active_units_in(tmp.path(), ".timer"),
            Some(vec!["apt-daily.timer".to_string()])
        );
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
        assert_eq!(active_units_in(&gone, ".timer"), None);
    }
}
