//! Budget management (R19‑15 / R19V12‑02):
//! - The entry budget is shared across the whole root: one allowance per
//!   SCAN_DIRS entry, threaded by `&mut` through the recursion.
//! - Hardlinks are deduplicated *before* consuming the budget, so duplicates
//!   cannot trigger a false "budget exhausted" warning.
//!
//! Known limitation (R19‑14, partially open): among several hardlink aliases
//! the one returned first by `readdir` wins. Since `provenance::lookup` is
//! path-based, the finding's weight can differ between hosts or after the
//! directory is modified. Emitting all aliases would fix this.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use crate::models::{FileCapFinding, SetuidFinding};

pub(crate) const SCAN_DIRS: &[(&str, u8)] = &[
    ("/usr/bin", 1),
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

pub(crate) const BUDGET_FLAT: usize = 4_096;
pub(crate) const BUDGET_DEEP: usize = 40_000;

/// Shared setuid predicate — avoids duplication between binary inventory
/// and the stand-alone `setuid` module (R19V13‑04).
pub(crate) fn inspect_file(meta: &fs::Metadata) -> bool {
    meta.permissions().mode() & 0o4000 != 0
}

pub(crate) fn walk_scannable_dirs<F>(scanner_name: &str, mut on_file: &mut F)
where
    // Callback no longer returns a Result (R19V14‑02/03).
    F: FnMut(&fs::DirEntry, &fs::Metadata),
{
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    for &(dir, depth) in SCAN_DIRS {
        let path = Path::new(dir);
        if !path.is_dir() {
            continue;
        }
        let mut budget = if depth > 1 { BUDGET_DEEP } else { BUDGET_FLAT };
        let root_dev = match path.metadata() {
            Ok(m) => Some(m.dev()),
            Err(e) => {
                crate::coverage::record(format!(
                    "{scanner_name}: cannot stat root {dir} ({}) — filesystem boundary check disabled",
                    e.kind()
                ));
                None
            }
        };
        if let Err(()) = walk_recursive(
            path,
            depth,
            &mut seen,
            &mut budget,
            root_dev,
            scanner_name,
            &mut on_file,
        ) {
            crate::coverage::record(format!(
                "{scanner_name}: {dir} entry budget exhausted — inventory INCOMPLETE for this root"
            ));
        }
    }
}

fn walk_recursive<F>(
    dir: &Path,
    max_depth: u8,
    seen: &mut HashSet<(u64, u64)>,
    budget: &mut usize,
    root_dev: Option<u64>,
    scanner_name: &str,
    on_file: &mut F,
) -> Result<(), ()>
where
    F: FnMut(&fs::DirEntry, &fs::Metadata),
{
    if *budget == 0 {
        return Err(());
    }

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries.flatten() {
        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };

        if ft.is_dir() && max_depth > 1 {
            if let (Some(rd), Ok(meta)) = (root_dev, entry.metadata())
                && meta.dev() != rd
            {
                crate::coverage::record(format!(
                    "{scanner_name}: {} is on a different filesystem — not traversed",
                    entry.path().display()
                ));
                continue;
            }
            walk_recursive(
                &entry.path(),
                max_depth - 1,
                seen,
                budget,
                root_dev,
                scanner_name,
                on_file,
            )?;
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

        if *budget == 0 {
            return Err(());
        }
        *budget -= 1;

        // Callback returns nothing; budget exhaustion is only signalled
        // by the walker's own counter (R19V14‑02/03).
        on_file(&entry, &meta);
    }

    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn gather_binary_inventory() -> (Vec<SetuidFinding>, Vec<FileCapFinding>) {
    let mut setuid_findings = Vec::new();
    let mut cap_findings = Vec::new();
    let mut notsup_devs: HashSet<u64> = HashSet::new();

    walk_scannable_dirs("binary_inventory", &mut |entry, meta| {
        let mode = meta.permissions().mode();
        // Use the shared helper (R19V13‑04)
        let is_suid = inspect_file(meta);
        let is_sgid = mode & libc::S_ISGID != 0;
        if is_suid || is_sgid {
            setuid_findings.push(SetuidFinding {
                path: entry.path().to_string_lossy().into_owned(),
                setuid: is_suid,
                setgid: is_sgid,
                root_owner: meta.uid() == 0,
                package: None,
            });
        }

        match crate::scanners::file_capabilities::read_caps_raw(&entry.path()) {
            Ok(Some(buf)) => match crate::scanners::file_capabilities::parse_vfs_cap_data(&buf) {
                Ok(caps) => {
                    if caps.permitted != 0 || caps.inheritable != 0 || caps.effective {
                        let names = crate::scanners::file_capabilities::build_capability_names(
                            caps.permitted,
                            caps.inheritable,
                        );
                        cap_findings.push(FileCapFinding {
                            path: entry.path().to_string_lossy().into_owned(),
                            capabilities: names,
                            reason: Some(
                                "file capabilities granted via extended attributes".into(),
                            ),
                            permitted: caps.permitted,
                            inheritable: caps.inheritable,
                            effective: caps.effective,
                            revision: caps.revision,
                            rootid: caps.rootid,
                            package: None,
                        });
                    }
                }
                Err(reason) => {
                    crate::coverage::record(format!(
                        "binary_inventory: unparsed xattr at {}: {reason}",
                        entry.path().display()
                    ));
                }
            },
            Ok(None) => {}
            Err(e) => match e.raw_os_error() {
                Some(libc::ENOTSUP) => {
                    let dev = meta.dev();
                    if notsup_devs.insert(dev) {
                        crate::coverage::record(format!(
                            "binary_inventory: xattr unsupported on dev {dev} — inventory blind there"
                        ));
                    }
                }
                _ if e.kind() != std::io::ErrorKind::PermissionDenied => {
                    crate::coverage::record(format!(
                        "binary_inventory: error reading {}: {}",
                        entry.path().display(),
                        e
                    ));
                }
                _ => {}
            },
        }
        // The callback is now infallible; nothing to return.
    });

    (setuid_findings, cap_findings)
}
