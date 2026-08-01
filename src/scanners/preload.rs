// src/scanners/preload.rs
// SEC-042: Inspect /etc/ld.so.preload for injected shared objects.
// Also covers /etc/ld.so.conf.d/* for library path hijacking (placeholder).

use crate::coverage;
use crate::models::PreloadFinding;
use std::collections::{HashMap, HashSet};

/// Parse ld.so.preload content according to glibc semantics:
/// - `#` starts a comment (the rest of the line is ignored)
/// - entries are separated by spaces, tabs, newlines, or colons
/// - empty entries are ignored
///
/// This is a pure function for testability.
pub(crate) fn parse_preload_entries(content: &str) -> Vec<&str> {
    content
        .lines()
        .map(|l| l.split_once('#').map_or(l, |(head, _)| head))
        .flat_map(|l| l.split([' ', '\t', ':']))
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .collect()
}

/// Count how many processes have each preload path mapped in /proc/<pid>/maps.
///
/// Returns `None` when `/proc` is unreadable or no maps could be read at all —
/// the count is UNKNOWN, not zero.
/// Returns `Some(map)` with zero counts for entries not found.
/// Paths are resolved (canonicalized) before matching because the kernel
/// prints the fully resolved path in maps.
fn count_mapped(paths: &[String]) -> Option<HashMap<String, usize>> {
    if paths.is_empty() {
        return Some(HashMap::new());
    }

    // Build a mapping from resolved path → original path.
    // R23‑21: try full canonicalization first (handles symlinks), fall back
    // to usrmerge-aware canon_path if the file no longer exists.
    let canon: Vec<(String, String)> = paths
        .iter()
        .map(|p| {
            let resolved = std::fs::canonicalize(p)
                .map(|c| c.to_string_lossy().into_owned())
                .unwrap_or_else(|_| crate::utils::canon_path(p).into_owned());
            (resolved, p.clone())
        })
        .collect();

    let mut counts: HashMap<String, usize> = paths.iter().cloned().map(|p| (p, 0)).collect();
    let Ok(procs) = std::fs::read_dir("/proc") else {
        coverage::record(
            "/proc unreadable; ld.so.preload map corroboration UNKNOWN (not zero)".to_string(),
        );
        return None;
    };

    let mut read_ok = 0usize;
    let mut denied = 0usize;

    for entry in procs.flatten() {
        let file_name = entry.file_name();
        let Some(pid_str) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };

        let maps = match crate::safe_io::read_file_capped(&format!("/proc/{pid}/maps"), 1024 * 1024)
        {
            Ok((m, _)) => {
                read_ok += 1;
                m
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                denied += 1;
                continue;
            }
            Err(_) => continue,
        };

        // Exact match on the path field (last column), not substring.
        let mapped: HashSet<&str> = maps
            .lines()
            .filter_map(|l| l.split_whitespace().nth(5))
            .collect();
        for (c, orig) in &canon {
            if mapped.contains(c.as_str()) {
                *counts.entry(orig.clone()).or_insert(0) += 1;
            }
        }
    }

    if denied > 0 {
        let hint = if crate::is_running_as_root() {
            ""
        } else {
            " — run as root for full coverage"
        };
        coverage::record(format!(
            "ld.so.preload corroboration: {denied} /proc/<pid>/maps unreadable{hint}"
        ));
    }
    if read_ok == 0 {
        // No observations at all — cannot assert zero (R23‑20).
        return None;
    }
    Some(counts)
}

pub fn scan_ld_preload() -> Vec<PreloadFinding> {
    let mut findings = Vec::new();
    let mut candidates: HashSet<String> = HashSet::new();

    let (content, truncated) =
        match crate::safe_io::read_file_capped_regular("/etc/ld.so.preload", 64 * 1024) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // No preload file → nothing injected, nothing to verify.
                return findings;
            }
            Err(e) => {
                coverage::record(format!(
                    "/etc/ld.so.preload unreadable ({e}); SEC-042 NOT verified"
                ));
                return findings;
            }
        };
    if truncated {
        coverage::record("/etc/ld.so.preload exceeded cap — SEC-042 scan truncated".to_string());
    }

    // R23-03: parse with glibc-compatible logic
    for entry in parse_preload_entries(&content) {
        let volatile = crate::utils::is_volatile_exec_path(entry);
        candidates.insert(crate::utils::canon_path(entry).into_owned());
        findings.push(PreloadFinding {
            path: entry.to_string(),
            volatile,
            package: None,
            mapped_by_pids: None,
        });
    }

    // Resolve package ownership for the collected candidates
    if !candidates.is_empty() {
        let prov = crate::scanners::provenance::resolve_batch(&candidates);
        for f in &mut findings {
            f.package = prov.lookup(crate::utils::canon_path(&f.path).as_ref());
        }
    }

    // Fill mapped_by_pids with live process counts (R23-09 / R23-17)
    if !findings.is_empty() {
        let paths: Vec<String> = findings.iter().map(|f| f.path.clone()).collect();
        if let Some(mapped) = count_mapped(&paths) {
            for f in &mut findings {
                f.mapped_by_pids = mapped.get(&f.path).copied();
            }
        }
        // None → field stays None: "unknown", not "zero"
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_preload_entries_matches_glibc() {
        assert_eq!(
            parse_preload_entries("/usr/lib/libsnoopy.so   # audit hook\n"),
            vec!["/usr/lib/libsnoopy.so"],
            "inline comment must not become part of path (otherwise package=None -> false exit-3)"
        );
        assert_eq!(
            parse_preload_entries("/usr/lib/libfoo.so:/dev/shm/evil.so\n"),
            vec!["/usr/lib/libfoo.so", "/dev/shm/evil.so"],
            "':' is a valid ld.so separator"
        );
        assert_eq!(
            parse_preload_entries("# all commented\n\n   \n"),
            Vec::<&str>::new()
        );
        assert_eq!(
            parse_preload_entries("/a.so\t/b.so /c.so"),
            vec!["/a.so", "/b.so", "/c.so"]
        );
    }
}
