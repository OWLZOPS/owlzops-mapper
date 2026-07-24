//! Unified filesystem inventory walk.
//! Scans the standard binary/library directories once and invokes
//! callbacks for each regular file, so that multiple scanners (setuid,
//! file capabilities) can collect their findings in a single pass.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

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

/// Walk the configured directories and call `on_file` for every regular file.
/// The closure receives the entry, its metadata, and the global deduplication set.
/// It may capture local state by reference.
pub(crate) fn walk_scannable_dirs<F>(scanner_name: &str, mut on_file: F)
where
    F: FnMut(&fs::DirEntry, &fs::Metadata, &mut HashSet<(u64, u64)>) -> Result<(), ()>,
{
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    for &(dir, depth) in SCAN_DIRS {
        let path = Path::new(dir);
        if !path.is_dir() {
            continue;
        }
        let mut budget = if depth > 1 { BUDGET_DEEP } else { BUDGET_FLAT };
        if walk_recursive(path, depth, &mut seen, &mut budget, &mut on_file).is_err() {
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
    on_file: &mut F,
) -> Result<(), ()>
where
    F: FnMut(&fs::DirEntry, &fs::Metadata, &mut HashSet<(u64, u64)>) -> Result<(), ()>,
{
    if *budget == 0 {
        return Err(());
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        if *budget == 0 {
            return Err(());
        }
        *budget -= 1;

        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if ft.is_dir() && max_depth > 1 {
            walk_recursive(&entry.path(), max_depth - 1, seen, budget, on_file)?;
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        on_file(&entry, &meta, seen)?;
    }
    Ok(())
}
