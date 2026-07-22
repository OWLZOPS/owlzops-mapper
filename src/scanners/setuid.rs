//! Agentless setuid/setgid inventory.
//! Scans common binary directories and library paths for files with the setuid (S_ISUID) or
//! setgid (S_ISGID) permission bits.  Root‑owned setuid files are flagged
//! with `root_owner = true`.  No external tools needed.

use crate::models::SetuidFinding;
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// Directories to scan.  We add `/usr/lib`, `/usr/libexec`, `/usr/local/lib` with
/// a limited recursion depth of 4 to catch helpers like `ssh-keysign`, `dbus-daemon-launch-helper`,
/// `polkit-agent-helper-1`, `snap-confine`, etc.
const SCAN_DIRS: &[(&str, u8)] = &[
    ("/usr/bin", 0),
    ("/usr/sbin", 0),
    ("/usr/local/bin", 0),
    ("/usr/local/sbin", 0),
    ("/bin", 0),
    ("/sbin", 0),
    ("/usr/lib", 4),
    ("/usr/libexec", 4),
    ("/usr/local/lib", 4),
    ("/usr/lib64", 4),
];

const MAX_FILES_PER_DIR: usize = 512;

/// Check a single file for setuid/setgid bits.  Uses `lstat` semantics.
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

fn scan_dir_recursive(
    dir: &Path,
    max_depth: u8,
    results: &mut Vec<SetuidFinding>,
    seen: &mut HashSet<(u64, u64)>,
    budget: &mut usize,
) {
    if max_depth == 0 || *budget == 0 {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        if *budget == 0 {
            break;
        }
        *budget -= 1;

        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };

        if ft.is_dir() && max_depth > 1 {
            scan_dir_recursive(&entry.path(), max_depth - 1, results, seen, budget);
            continue;
        }

        if !ft.is_file() {
            continue;
        }

        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        // Deduplication by device + inode (handles usrmerge and hardlinks)
        let dev_ino = (meta.dev(), meta.ino());
        if !seen.insert(dev_ino) {
            continue;
        }

        if let Some(finding) = inspect_file(&entry.path()) {
            results.push(finding);
        }
    }
}

/// Entry point for Linux.  Returns deduplicated list of setuid/setgid files.
#[cfg(target_os = "linux")]
pub fn gather_setuid_files() -> Vec<SetuidFinding> {
    let mut findings = Vec::new();
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    let mut budget = MAX_FILES_PER_DIR * SCAN_DIRS.len();

    for (dir, depth) in SCAN_DIRS {
        let path = Path::new(dir);
        if !path.is_dir() {
            continue;
        }
        let before = findings.len();
        scan_dir_recursive(path, *depth, &mut findings, &mut seen, &mut budget);
        // Emit coverage if we hit the per-directory limit
        if findings.len() - before >= MAX_FILES_PER_DIR {
            crate::coverage::record(format!(
                "setuid: {dir} scan truncated at {MAX_FILES_PER_DIR} entries — inventory incomplete"
            ));
        }
    }
    if budget == 0 {
        crate::coverage::record(
            "setuid: global entry budget exhausted — inventory INCOMPLETE".to_string(),
        );
    }
    findings
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
