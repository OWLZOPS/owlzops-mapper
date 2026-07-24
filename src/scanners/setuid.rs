//! Agentless setuid/setgid inventory.
//! Scans common binary directories and library paths for files with the setuid (S_ISUID) or
//! setgid (S_ISGID) permission bits.  Root‑owned setuid files are flagged
//! with `root_owner = true`.  No external tools needed.

use crate::models::SetuidFinding;
use crate::scanners::fs_inventory;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

fn inspect_file(meta: &fs::Metadata, path: &Path) -> Option<SetuidFinding> {
    let mode = meta.permissions().mode();

    #[allow(clippy::unnecessary_cast)]
    let is_suid = mode & libc::S_ISUID as u32 != 0;
    #[allow(clippy::unnecessary_cast)]
    let is_sgid = mode & libc::S_ISGID as u32 != 0;

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
            Ok(())
        },
    );
    findings
}

#[cfg(not(target_os = "linux"))]
pub fn gather_setuid_files() -> Vec<SetuidFinding> {
    Vec::new()
}

#[cfg(test)]
#[allow(clippy::unnecessary_cast)]
mod tests {
    use super::*;

    #[test]
    fn inspect_file_suid() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut perms = tmp.as_file().metadata().unwrap().permissions();
        let mode = perms.mode();
        perms.set_mode(mode | libc::S_ISUID as u32);
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
}
