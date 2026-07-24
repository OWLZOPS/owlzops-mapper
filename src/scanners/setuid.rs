//! Agentless setuid/setgid inventory.
//! Scans common binary directories and library paths for files with the setuid (S_ISUID) or
//! setgid (S_ISGID) permission bits.  Root‑owned setuid files are flagged
//! with `root_owner = true`.  No external tools needed.

use crate::models::SetuidFinding;
use crate::scanners::fs_inventory;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Inspect a file for setuid/setgid bits, reusing the shared `fs_inventory::inspect_file`
/// for setuid detection (R19V13‑04).
fn inspect_file(meta: &fs::Metadata, path: &Path) -> Option<SetuidFinding> {
    // Shared helper for setuid – avoids duplicating the mode-mask logic.
    let is_suid = fs_inventory::inspect_file(meta);
    let is_sgid = meta.mode() & 0o2000 != 0; // S_ISGID

    if !is_suid && !is_sgid {
        return None;
    }

    Some(SetuidFinding {
        path: path.to_string_lossy().into_owned(),
        setuid: is_suid,
        setgid: is_sgid,
        root_owner: meta.uid() == 0,
        package: None,
    })
}

#[cfg(target_os = "linux")]
#[allow(dead_code)] // retained for backward compatibility; prefer gather_binary_inventory()
pub fn gather_setuid_files() -> Vec<SetuidFinding> {
    let mut findings = Vec::new();

    // Use the unified filesystem walker; deduplication and budget
    // tracking are handled inside `fs_inventory`.
    fs_inventory::walk_scannable_dirs(
        "setuid",
        &mut |entry: &std::fs::DirEntry, meta: &std::fs::Metadata| {
            if let Some(finding) = inspect_file(meta, &entry.path()) {
                findings.push(finding);
            }
            // Callback now returns nothing (R19V14‑02/03).
        },
    );
    findings
}

#[cfg(not(target_os = "linux"))]
pub fn gather_setuid_files() -> Vec<SetuidFinding> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn inspect_file_suid() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut perms = tmp.as_file().metadata().unwrap().permissions();
        perms.set_mode(0o4755); // setuid + rwxr-xr-x
        tmp.as_file().set_permissions(perms).unwrap();
        let meta = tmp.as_file().metadata().unwrap();
        let f = inspect_file(&meta, tmp.path()).unwrap();
        assert!(f.setuid);
        assert!(!f.setgid);
    }

    #[test]
    fn inspect_file_no_bits() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let meta = tmp.as_file().metadata().unwrap();
        assert!(inspect_file(&meta, tmp.path()).is_none());
    }

    #[test]
    fn inspect_file_sgid() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut perms = tmp.as_file().metadata().unwrap().permissions();
        perms.set_mode(0o2755); // setgid
        tmp.as_file().set_permissions(perms).unwrap();
        let meta = tmp.as_file().metadata().unwrap();
        let f = inspect_file(&meta, tmp.path()).unwrap();
        assert!(f.setgid);
        assert!(!f.setuid);
    }
}
