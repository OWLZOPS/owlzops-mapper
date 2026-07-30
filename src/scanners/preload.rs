// src/scanners/preload.rs
// SEC-042: System-wide LD_PRELOAD via /etc/ld.so.preload
//
// /etc/ld.so.preload is read by ld.so before every dynamic executable starts,
// injecting the listed shared objects into *every* process on the system. This
// mechanism does **not** show up in `/proc/<pid>/environ` (LD_PRELOAD variable),
// and the library may reside on a non-volatile path that the maps scanner treats
// as benign.  Canonical persistence for Azazel, Jynx2, bdvl, HiddenWasp, Symbiote.

use crate::coverage;
use crate::models::PreloadFinding;
use crate::safe_io;

/// Scan `/etc/ld.so.preload` and return any entries found.
///
/// Each entry becomes a `PreloadFinding`. Volatility is checked via
/// `is_volatile_exec_path`, and package ownership is resolved through the
/// existing provenance infrastructure.
///
/// # Coverage
/// - If the file is absent (ENOENT) the scan is considered clear — no finding
///   is emitted.
/// - If the file exists but is empty or contains only comments/whitespace, the
///   same applies.
/// - Any non-empty, non-comment line triggers a finding.
pub fn scan_ld_preload() -> Vec<PreloadFinding> {
    let path = "/etc/ld.so.preload";
    let (content, truncated) = match safe_io::read_file_capped(path, 64 * 1024) {
        Ok(tuple) => tuple,
        Err(e) => {
            // ENOENT is normal; any other error means we can't read the file.
            if e.kind() != std::io::ErrorKind::NotFound {
                coverage::record(format!(
                    "ld.so.preload unreadable ({e}); systemic preload state unknown"
                ));
            }
            return Vec::new();
        }
    };

    if truncated {
        coverage::record(
            "ld.so.preload truncated at 64 KB; entries beyond the cap were not inspected"
                .to_string(),
        );
    }

    let mut findings = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let volatile = crate::utils::is_volatile_exec_path(trimmed);
        let package = lookup_package_owner(trimmed);

        findings.push(PreloadFinding {
            path: trimmed.to_string(),
            volatile,
            package,
            mapped_by_pids: None, // filled later by the correlation step
        });
    }

    if findings.is_empty() && !truncated {
        // Explicitly record that the file was present but benign.
        coverage::record("ld.so.preload exists but contains no active entries".to_string());
    }

    findings
}

/// Resolve the package that owns the given file path.
///
/// This calls into the existing provenance logic (dpkg, rpm, apk, etc.) and
/// returns `Some(package_name)` if the file is tracked, or `None` otherwise.
fn lookup_package_owner(_path: &str) -> Option<String> {
    // TODO: integrate with the actual package ownership lookup (e.g.,
    // crate::provenance::resolve_package(path)).
    // For now, return None – the scanner will still flag the finding.
    None
}
