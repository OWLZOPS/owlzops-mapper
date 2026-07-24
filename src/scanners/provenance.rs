//! Package provenance resolver for dpkg, apk, and rpm.
//!
//! Given a set of file paths (candidates) returns which installed package owns
//! each file.  Candidates must be in **canonical** form (see
//! `crate::utils::canon_path`).  The resolver never allocates memory for the
//! entire package database – it streams through the on-disk files and stops as
//! soon as every candidate has been resolved.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::models::ProvenanceSource;

const MAX_LIST_BYTES: usize = 8 * 1024 * 1024; // largest real .list ≈ 2 MB
/// Batch size for rpm queries – one `rpm -qf` invocation per chunk.
const RPM_CHUNK_SIZE: usize = 100;

/// The result of a batch resolution together with the database that produced it.
pub struct ProvenanceIndex {
    pub source: ProvenanceSource,
    map: HashMap<String, String>,
}

impl ProvenanceIndex {
    pub fn lookup(&self, path: &str) -> Option<String> {
        self.map
            .get(crate::utils::canon_path(path).as_ref())
            .cloned()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

pub fn resolve_batch(candidates: &HashSet<String>) -> ProvenanceIndex {
    let unavailable = |why: &str| {
        crate::coverage::record(format!("provenance: {why} — attribution unavailable"));
        ProvenanceIndex {
            source: ProvenanceSource::Unavailable,
            map: HashMap::new(),
        }
    };

    // 1. dpkg
    if Path::new("/var/lib/dpkg/info").is_dir() {
        return match resolve_dpkg(candidates) {
            Some(map) => ProvenanceIndex {
                source: ProvenanceSource::Dpkg,
                map,
            },
            None => unavailable("dpkg DB present but not a single .list was readable"),
        };
    }

    // 2. apk
    if Path::new("/lib/apk/db/installed").is_file() {
        return match resolve_apk(candidates) {
            Some((map, truncated)) => ProvenanceIndex {
                source: if truncated {
                    ProvenanceSource::PartialApk
                } else {
                    ProvenanceSource::Apk
                },
                map,
            },
            None => unavailable("apk DB present but unreadable"),
        };
    }

    // 3. rpm (querying the rpm tool, no DB parsing)
    if let Some(map) = resolve_rpm(candidates) {
        return ProvenanceIndex {
            source: ProvenanceSource::Rpm,
            map,
        };
    }

    unavailable("no parseable package DB (rpm/pacman)")
}

// ---------------------------------------------------------------------------
// DPKG backend (capped, basename-prefiltered)
// ---------------------------------------------------------------------------

fn resolve_dpkg(candidates: &HashSet<String>) -> Option<HashMap<String, String>> {
    if candidates.is_empty() {
        return Some(HashMap::new());
    }

    // Basename index – zero allocations for ~99.9% of .list lines
    let basenames: HashSet<&str> = candidates
        .iter()
        .filter_map(|c| c.rsplit('/').next())
        .collect();

    let mut owned = HashMap::new();
    let mut lists_read = 0usize;
    let mut lists_skipped = 0usize;
    let rd = fs::read_dir("/var/lib/dpkg/info").ok()?;

    for entry in rd.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("list") {
            continue;
        }

        let Some(pkg) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.split_once(':').map_or(s, |(n, _arch)| n))
        else {
            continue;
        };

        let Ok((content, truncated)) =
            crate::safe_io::read_file_capped(&path.to_string_lossy(), MAX_LIST_BYTES)
        else {
            lists_skipped += 1;
            continue;
        };
        lists_read += 1;
        if truncated {
            crate::coverage::record(format!(
                "provenance: {} truncated at {MAX_LIST_BYTES} B — attribution partial for {pkg}",
                path.display()
            ));
        }

        for line in content.lines() {
            let line = line.trim_end();
            let Some(base) = line.rsplit('/').next() else {
                continue;
            };
            if !basenames.contains(base) {
                continue; // fast rejection without allocation
            }
            let key = crate::utils::canon_path(line);
            if candidates.contains(key.as_ref()) {
                owned.insert(key.into_owned(), pkg.to_string());
            }
        }
        if owned.len() == candidates.len() {
            break;
        }
    }

    if lists_skipped > 0 {
        crate::coverage::record(format!(
            "provenance: {lists_skipped} of {} dpkg .list file(s) unreadable — \
             files owned by those packages will be reported as unpackaged",
            lists_read + lists_skipped
        ));
    }
    (lists_read > 0).then_some(owned)
}

// ---------------------------------------------------------------------------
// APK backend (capped, basename-prefiltered, truncation-aware)
// ---------------------------------------------------------------------------

fn resolve_apk(candidates: &HashSet<String>) -> Option<(HashMap<String, String>, bool)> {
    if candidates.is_empty() {
        return Some((HashMap::new(), false));
    }

    let (content, truncated) = match crate::safe_io::read_file_capped(
        "/lib/apk/db/installed",
        MAX_LIST_BYTES,
    ) {
        Ok((c, t)) => (c, t),
        Err(e) => {
            crate::coverage::record(format!(
                "provenance: /lib/apk/db/installed unreadable ({}) — apk attribution unavailable",
                e.kind()
            ));
            return None;
        }
    };
    if truncated {
        crate::coverage::record(
            "provenance: apk DB truncated at cap — attribution PARTIAL, \
             unresolved files may be misreported as unpackaged",
        );
    }

    let mut owned = HashMap::new();
    let basenames: HashSet<&str> = candidates
        .iter()
        .filter_map(|c| c.rsplit('/').next())
        .collect();

    let mut pkg_name = String::new();
    let mut dir = String::new();

    for line in content.lines() {
        if line.is_empty() {
            pkg_name.clear();
            dir.clear();
            continue;
        }

        match line.split_once(':') {
            Some(("P", v)) => pkg_name = v.to_string(),
            Some(("F", v)) => dir = v.to_string(),
            Some(("R", v)) => {
                let full = if dir.is_empty() {
                    format!("/{v}")
                } else {
                    format!("/{dir}/{v}")
                };
                let Some(base) = full.rsplit('/').next() else {
                    continue;
                };
                if !basenames.contains(base) {
                    continue;
                }
                let key = crate::utils::canon_path(&full);
                if candidates.contains(key.as_ref()) {
                    owned.insert(key.into_owned(), pkg_name.clone());
                }
            }
            _ => {}
        }
    }

    Some((owned, truncated))
}

// ---------------------------------------------------------------------------
// RPM backend (uses external `rpm` tool with batching)
// ---------------------------------------------------------------------------

/// Resolve file ownership via `rpm -qf`.
/// Returns None if `rpm` is not available or fails entirely.
fn resolve_rpm(candidates: &HashSet<String>) -> Option<HashMap<String, String>> {
    if candidates.is_empty() {
        return Some(HashMap::new());
    }

    // Check for rpm binary
    let rpm_bin = if Path::new("/usr/bin/rpm").exists() {
        "/usr/bin/rpm"
    } else if Path::new("/bin/rpm").exists() {
        "/bin/rpm"
    } else {
        crate::coverage::record("provenance: RPM backend skipped (rpm binary not found)");
        return None;
    };

    let mut owned = HashMap::new();
    let candidate_vec: Vec<&String> = candidates.iter().collect();

    // Batch candidates into chunks of RPM_CHUNK_SIZE to avoid argument limits
    for chunk in candidate_vec.chunks(RPM_CHUNK_SIZE) {
        let paths: Vec<&str> = chunk.iter().map(|s| s.as_str()).collect();
        let output = match Command::new(rpm_bin)
            .args(["-qf", "--queryformat", "%{NAME}\n", "--"])
            .args(&paths)
            .output()
        {
            Ok(out) => out,
            Err(e) => {
                crate::coverage::record(format!("provenance: failed to execute rpm: {e}"));
                return None;
            }
        };

        // rpm prints package names to stdout, errors (like "file ... is not owned by any package") to stderr
        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = stdout.lines().collect();

        if lines.len() != paths.len() {
            // Safety net: if rpm output is misaligned, we skip this chunk to avoid incorrect assignments
            crate::coverage::record(format!(
                "provenance: rpm output line count mismatch (got {}, expected {}) — skipping chunk",
                lines.len(),
                paths.len()
            ));
            continue;
        }

        // Zip paths and lines: each line corresponds to the path at the same index
        for (i, line) in lines.iter().enumerate() {
            let pkg = line.trim();
            if pkg.is_empty() || pkg.starts_with("file ") {
                // "file <path> is not owned by any package" – skip
                continue;
            }
            owned.insert(paths[i].to_string(), pkg.to_string());
        }
    }

    if owned.is_empty() {
        // rpm worked but found nothing – still a valid (empty) resolution
        Some(HashMap::new())
    } else {
        Some(owned)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_batch_basics() {
        if Path::new("/var/lib/dpkg/info").is_dir() {
            let mut candidates = HashSet::new();
            candidates.insert("/bin/ls".to_string());
            candidates.insert("/usr/bin/ls".to_string());
            let idx = resolve_batch(&candidates);
            let ls_pkg = idx.lookup("/bin/ls").or_else(|| idx.lookup("/usr/bin/ls"));
            assert!(ls_pkg.is_some(), "ls must belong to a package");
        }
    }
}
