//! Agentless setuid/setgid inventory.
//! Scans common binary directories for files with the setuid (S_ISUID) or
//! setgid (S_ISGID) permission bits.  Root‑owned setuid files are flagged
//! with `root_owner = true`.  No external tools needed.

use crate::models::SetuidFinding;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

const SCAN_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/bin",
    "/sbin",
];

const MAX_FILES_PER_DIR: usize = 512;

/// Check a single file for setuid/setgid bits.  Returns `None` if neither
/// bit is set.
fn inspect_file(path: &Path) -> Option<SetuidFinding> {
    let meta = path.symlink_metadata().ok()?;
    let mode = meta.permissions().mode();

    let is_suid = mode & libc::S_ISUID != 0;
    let is_sgid = mode & libc::S_ISGID != 0;

    if !is_suid && !is_sgid {
        return None;
    }

    Some(SetuidFinding {
        path: path.to_string_lossy().into_owned(),
        setuid: is_suid,
        setgid: is_sgid,
        root_owner: meta.uid() == 0,
    })
}

/// Scan the given directories and collect all files with setuid/setgid bits.
pub fn scan_directories(dirs: &[&str]) -> Vec<SetuidFinding> {
    let mut findings = Vec::new();

    for dir in dirs {
        let path = Path::new(dir);
        if !path.is_dir() {
            continue;
        }
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten().take(MAX_FILES_PER_DIR) {
                let p = entry.path();
                if !p.is_file() {
                    continue;
                }
                if let Some(finding) = inspect_file(&p) {
                    findings.push(finding);
                }
            }
        }
    }

    findings
}

/// Entry point for Linux (only).  Returns the list of setuid/setgid files.
#[cfg(target_os = "linux")]
pub fn gather_setuid_files() -> Vec<SetuidFinding> {
    scan_directories(SCAN_DIRS)
}

/// Stub for non‑Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn gather_setuid_files() -> Vec<SetuidFinding> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_file_suid() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        // Set SUID bit on a temporary file
        let mut perms = tmp.as_file().metadata().unwrap().permissions();
        let mode = perms.mode();
        perms.set_mode(mode | libc::S_ISUID);
        tmp.as_file().set_permissions(perms).unwrap();
        let f = inspect_file(tmp.path()).unwrap();
        assert!(f.setuid);
        assert!(!f.setgid);
    }

    #[test]
    fn inspect_file_no_bits() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        assert!(inspect_file(tmp.path()).is_none());
    }
}
