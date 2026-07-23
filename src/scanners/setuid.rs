//! Agentless setuid/setgid inventory.
//! Scans common binary directories and library paths for files with the setuid (S_ISUID) or
//! setgid (S_ISGID) permission bits.  Root‑owned setuid files are flagged
//! with `root_owner = true`.  No external tools needed.

use crate::models::SetuidFinding;
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

const SCAN_DIRS: &[(&str, u8)] = &[
    ("/usr/bin", 1), // 1 = this directory only, no recursion
    ("/usr/sbin", 1),
    ("/usr/local/bin", 1),
    ("/usr/local/sbin", 1),
    ("/bin", 1),
    ("/sbin", 1),
    ("/usr/lib", 4),
    ("/usr/libexec", 4),
    ("/usr/local/lib", 4),
    ("/usr/lib64", 4),
];

const BUDGET_FLAT: usize = 4_096; // per flat bin directory
const BUDGET_DEEP: usize = 40_000; // per recursive lib root

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

fn scan_dir_recursive(
    dir: &Path,
    max_depth: u8,
    results: &mut Vec<SetuidFinding>,
    seen: &mut HashSet<(u64, u64)>,
    budget: &mut usize,
) {
    if *budget == 0 {
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

        let dev_ino = (meta.dev(), meta.ino());
        if !seen.insert(dev_ino) {
            continue;
        }

        if let Some(finding) = inspect_file(&meta, &entry.path()) {
            results.push(finding);
        }
    }
}

#[cfg(target_os = "linux")]
pub fn gather_setuid_files() -> Vec<SetuidFinding> {
    let mut findings = Vec::new();
    let mut seen: HashSet<(u64, u64)> = HashSet::new();

    for (dir, depth) in SCAN_DIRS {
        let path = Path::new(dir);
        if !path.is_dir() {
            continue;
        }
        let mut budget = if *depth > 1 { BUDGET_DEEP } else { BUDGET_FLAT };
        scan_dir_recursive(path, *depth, &mut findings, &mut seen, &mut budget);
        if budget == 0 {
            crate::coverage::record(format!(
                "setuid: {dir} entry budget exhausted — inventory INCOMPLETE for this root"
            ));
        }
    }
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
