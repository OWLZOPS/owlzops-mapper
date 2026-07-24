//! Unified filesystem inventory walk.
//! Scans the standard binary/library directories once and invokes
//! callbacks for each regular file, so that multiple scanners (setuid,
//! file capabilities) can collect their findings in a single pass.
//!
//! Budget management (R19‑14 / R19‑15):
//! - Hardlinks are deduplicated *before* consuming the budget, so
//!   different readdir orders produce deterministic inventories.
//! - An "entry budget exhausted" message is emitted only when a unique
//!   file could not be processed because the per‑directory budget was
//!   depleted – not when duplicates filled the remaining budget.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
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

/// Walk the configured directories and call `on_file` for each unique
/// regular file. The closure may capture local state by reference.
pub(crate) fn walk_scannable_dirs<F>(scanner_name: &str, mut on_file: &mut F)
where
    F: FnMut(&fs::DirEntry, &fs::Metadata) -> Result<(), ()>,
{
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    for &(dir, depth) in SCAN_DIRS {
        let path = Path::new(dir);
        if !path.is_dir() {
            continue;
        }
        let budget = if depth > 1 { BUDGET_DEEP } else { BUDGET_FLAT };
        if let Err(()) = walk_recursive(path, depth, &mut seen, budget, &mut on_file) {
            crate::coverage::record(format!(
                "{scanner_name}: {dir} entry budget exhausted — inventory INCOMPLETE for this root"
            ));
        }
    }
}

/// Recursive walk with dedup‑before‑budget semantics.
fn walk_recursive<F>(
    dir: &Path,
    max_depth: u8,
    seen: &mut HashSet<(u64, u64)>,
    mut budget: usize,
    on_file: &mut F,
) -> Result<(), ()>
where
    F: FnMut(&fs::DirEntry, &fs::Metadata) -> Result<(), ()>,
{
    if budget == 0 {
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

        // Deduplication *before* spending the budget.
        let dev_ino = (meta.dev(), meta.ino());
        if !seen.insert(dev_ino) {
            continue; // hardlink – do not count
        }

        // Unique file – check budget.
        if budget == 0 {
            return Err(()); // genuine budget exhausted
        }
        budget -= 1;

        on_file(&entry, &meta)?;
    }

    Ok(())
}
