//! Package provenance resolver for dpkg and apk.
//!
//! Given a set of file paths (candidates) returns which installed package owns
//! each file.  Candidates must be in **canonical** form (see
//! `crate::utils::canon_path`).  The resolver never allocates memory for the
//! entire package database – it streams through the on-disk files and stops as
//! soon as every candidate has been resolved.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::models::ProvenanceSource;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// The result of a batch resolution together with the database that produced it.
pub struct ProvenanceIndex {
    pub source: ProvenanceSource,
    map: HashMap<String, String>,
}

impl ProvenanceIndex {
    /// Look up a raw scanner path in the index.  The path is first normalised
    /// via [`canon_path`] so that `/bin/su` and `/usr/bin/su` map to the same
    /// key.
    pub fn lookup(&self, path: &str) -> Option<String> {
        self.map
            .get(crate::utils::canon_path(path).as_ref())
            .cloned()
    }

    /// Returns `true` if the index is completely empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Resolve provenance for a batch of **canonical** candidate paths.
pub fn resolve_batch(candidates: &HashSet<String>) -> ProvenanceIndex {
    // Pick a backend based on which database actually exists.
    if Path::new("/var/lib/dpkg/info").is_dir() {
        return ProvenanceIndex {
            source: ProvenanceSource::Dpkg,
            map: resolve_dpkg(candidates),
        };
    }
    if Path::new("/lib/apk/db/installed").is_file() {
        return ProvenanceIndex {
            source: ProvenanceSource::Apk,
            map: resolve_apk(candidates),
        };
    }

    crate::coverage::record(
        "provenance: no parseable package DB (rpm/pacman) — attribution unavailable",
    );
    ProvenanceIndex {
        source: ProvenanceSource::Unavailable,
        map: HashMap::new(),
    }
}

// ---------------------------------------------------------------------------
// DPKG backend
// ---------------------------------------------------------------------------

fn resolve_dpkg(candidates: &HashSet<String>) -> HashMap<String, String> {
    let mut owned = HashMap::new();
    let info_dir = Path::new("/var/lib/dpkg/info");
    let rd = match fs::read_dir(info_dir) {
        Ok(rd) => rd,
        Err(_) => {
            crate::coverage::record(
                "provenance: /var/lib/dpkg/info unreadable — dpkg attribution degraded",
            );
            return owned;
        }
    };

    for entry in rd.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("list") {
            continue;
        }

        // Package name: "libfoo:amd64.list" → "libfoo"
        let Some(pkg) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.split_once(':').map_or(s, |(n, _arch)| n).to_string())
        else {
            continue;
        };

        let file = match fs::File::open(&path) {
            Ok(f) => f,
            Err(_) => continue,
        };

        for line in BufReader::new(file).lines().map_while(Result::ok) {
            let line = line.trim();
            // All paths – both from the .list and from the scanner – are
            // normalised through canon_path before comparison.
            let key = crate::utils::canon_path(line);
            if candidates.contains(key.as_ref()) {
                owned.insert(key.into_owned(), pkg.clone());
            }
        }

        if owned.len() == candidates.len() {
            break;
        }
    }
    owned
}

// ---------------------------------------------------------------------------
// APK backend
// ---------------------------------------------------------------------------

fn resolve_apk(candidates: &HashSet<String>) -> HashMap<String, String> {
    let mut owned = HashMap::new();
    let file = match fs::File::open("/lib/apk/db/installed") {
        Ok(f) => f,
        Err(_) => return owned,
    };

    let mut pkg_name = String::new();
    let mut dir = String::new();

    for line in BufReader::new(file).lines().map_while(Result::ok) {
        if line.is_empty() {
            // End of a package record – reset state for the next one.
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
                let key = crate::utils::canon_path(&full);
                if candidates.contains(key.as_ref()) {
                    owned.insert(key.into_owned(), pkg_name.clone());
                }
            }
            _ => {}
        }
    }

    owned
}

// ---------------------------------------------------------------------------
// RPM backend (honest degradation)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn resolve_rpm(_candidates: &HashSet<String>) -> HashMap<String, String> {
    crate::coverage::record("provenance: RPM backend skipped (no BDB/SQLite parser)");
    HashMap::new()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: on a Debian system /bin/ls must be attributed.
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
