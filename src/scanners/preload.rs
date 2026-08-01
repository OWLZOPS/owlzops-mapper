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
fn count_mapped(paths: &[String]) -> HashMap<String, usize> {
    let mut counts: HashMap<String, usize> = paths.iter().cloned().map(|p| (p, 0)).collect();
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return counts;
    };
    for entry in procs.flatten() {
        let file_name = entry.file_name();
        let Some(pid_str) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        let Ok((maps, _)) =
            crate::safe_io::read_file_capped(&format!("/proc/{pid}/maps"), 1024 * 1024)
        else {
            continue;
        };
        for (path, cnt) in counts.iter_mut() {
            if maps.contains(path.as_str()) {
                *cnt += 1;
            }
        }
    }
    counts
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

    // Fill mapped_by_pids with live process counts (R23-09)
    let paths: Vec<String> = findings.iter().map(|f| f.path.clone()).collect();
    let mapped = count_mapped(&paths);
    for f in &mut findings {
        f.mapped_by_pids = mapped.get(&f.path).copied();
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
