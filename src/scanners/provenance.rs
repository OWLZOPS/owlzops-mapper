//! Package provenance resolver for dpkg, apk, and rpm.
//!
//! Given a set of file paths (candidates) returns which installed package owns
//! each file.  Candidates must be in **canonical** form (see
//! `crate::utils::canon_path`).  The resolver never allocates memory for the
//! entire package database – it streams through the on-disk files and stops as
//! soon as every candidate has been resolved.
//!
//! Results are memoised per process: the first call walks the package database
//! and all subsequent calls only query the cache, including negative entries
//! (files confirmed to belong to no package).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::{Mutex, OnceLock, PoisonError};

use crate::models::ProvenanceSource;

const MAX_LIST_BYTES: usize = 8 * 1024 * 1024; // largest real .list ≈ 2 MB

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

// ── Process‑global memo (R24-03) ──────────────────────────────────────────

struct ProvMemo {
    source: Option<ProvenanceSource>,
    /// path → Some(pkg) | None  (None = confirmed unpackaged, negative cache)
    known: HashMap<String, Option<String>>,
}

static MEMO: OnceLock<Mutex<ProvMemo>> = OnceLock::new();

fn memo() -> &'static Mutex<ProvMemo> {
    MEMO.get_or_init(|| {
        Mutex::new(ProvMemo {
            source: None,
            known: HashMap::new(),
        })
    })
}

/// Resolve package ownership for a set of paths, using a global cache so that
/// subsequent calls for overlapping sets avoid re‑walking the database.
pub fn resolve_batch(candidates: &HashSet<String>) -> ProvenanceIndex {
    // 1. Serve everything already known; collect genuine misses.
    let (mut map, missing, cached_source) = {
        let m = memo().lock().unwrap_or_else(PoisonError::into_inner);
        let mut map = HashMap::new();
        let mut missing = HashSet::new();
        for c in candidates {
            match m.known.get(c) {
                Some(Some(pkg)) => {
                    map.insert(c.clone(), pkg.clone());
                }
                Some(None) => {} // known-unpackaged: no re‑query
                None => {
                    missing.insert(c.clone());
                }
            }
        }
        (map, missing, m.source)
    };

    if missing.is_empty()
        && let Some(source) = cached_source
    {
        return ProvenanceIndex { source, map };
    }
    // otherwise fall through: either some candidates are missing, or we
    // haven't yet determined the source (all previous candidates were
    // negative entries – resolve at least once).

    let fresh = resolve_batch_uncached(&missing);

    // 2. Merge and record negatives so the next scanner never re‑queries.
    //    Unavailable is a transient backend failure — never cache it.
    if fresh.source != ProvenanceSource::Unavailable {
        let mut m = memo().lock().unwrap_or_else(PoisonError::into_inner);
        for c in &missing {
            m.known.insert(c.clone(), fresh.map.get(c).cloned());
        }
        m.source = Some(fresh.source);
    }

    map.extend(fresh.map.iter().map(|(k, v)| (k.clone(), v.clone())));
    ProvenanceIndex {
        source: if fresh.source == ProvenanceSource::Unavailable {
            cached_source.unwrap_or(ProvenanceSource::Unavailable)
        } else {
            fresh.source
        },
        map,
    }
}

/// Original uncached resolution, renamed from the previous `resolve_batch`.
fn resolve_batch_uncached(candidates: &HashSet<String>) -> ProvenanceIndex {
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
// RPM backend – one file per invocation (R20-01, R20-02, R24-56)
// ---------------------------------------------------------------------------

/// Result of a single `rpm -qf` query.
#[derive(Debug, PartialEq)]
enum RpmQueryResult {
    /// Package name found.
    Owned(String),
    /// rpm says the file is not owned by any package (exit code 1).
    NotOwned,
    /// Real error or unexpected output.
    Error,
}

/// Parse stdout of `rpm -qf --queryformat "%{NAME}\n"` together with its exit
/// code. Exit code 1 means "file is not owned by any package" and is a valid
/// negative result, not an error (R24-56).
fn parse_rpm_qf_output(stdout: &str, exit_code: i32) -> RpmQueryResult {
    match exit_code {
        0 => {
            let pkg = stdout
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty() && !l.starts_with("file ") && !l.starts_with("error:"));
            match pkg {
                Some(p) => RpmQueryResult::Owned(p.to_string()),
                None => RpmQueryResult::Error,
            }
        }
        1 => RpmQueryResult::NotOwned,
        _ => RpmQueryResult::Error,
    }
}

/// Resolve file ownership via `rpm -qf`.  Each candidate is queried
/// individually – no positional coupling between arguments and output lines.
/// Uses `run_child_with_timeout` to get both stdout and exit status.
fn resolve_rpm(candidates: &HashSet<String>) -> Option<HashMap<String, String>> {
    if candidates.is_empty() {
        return Some(HashMap::new());
    }

    // Symmetric to dpkg/apk: first check that a database exists, so we can
    // distinguish "no database" from "database present but tool unavailable".
    if !Path::new("/var/lib/rpm").is_dir() && !Path::new("/usr/lib/sysimage/rpm").is_dir() {
        crate::coverage::record(
            "provenance: rpm binary present but no rpmdb — attribution unavailable",
        );
        return None;
    }

    let Some(rpm_bin) = crate::utils::resolve_tool("rpm") else {
        crate::coverage::record("provenance: RPM backend skipped (rpm binary not found)");
        return None;
    };

    let mut owned = HashMap::new();
    let mut not_owned = 0usize;
    let mut failed = 0usize;

    for path in candidates {
        match crate::utils::run_child_with_timeout(
            &rpm_bin,
            &["-qf", "--queryformat", "%{NAME}\n", "--", path],
            10,
        ) {
            Some(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let exit_code = output.status.code().unwrap_or(-1);
                match parse_rpm_qf_output(&stdout, exit_code) {
                    RpmQueryResult::Owned(pkg) => {
                        owned.insert(path.clone(), pkg);
                    }
                    RpmQueryResult::NotOwned => {
                        not_owned += 1;
                    }
                    RpmQueryResult::Error => {
                        failed += 1;
                    }
                }
            }
            None => {
                failed += 1;
            }
        }
    }

    if failed > 0 {
        crate::coverage::record(format!(
            "provenance: {failed} of {} rpm queries failed or timed out — \
             those files will be reported as unpackaged",
            owned.len() + not_owned + failed
        ));
    }
    if not_owned > 0 {
        crate::coverage::record(format!(
            "provenance: {not_owned} file(s) confirmed not owned by any rpm package"
        ));
    }

    // Usable data = a definite answer, positive or negative. An `Error` result
    // is not an answer: counting it here would present "we could not ask" as
    // "not owned by any package" for every candidate (R25-29).
    let answered = owned.len() + not_owned;
    (answered > 0).then_some(owned)
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

    #[test]
    fn rpm_exit_1_is_not_owned_not_error() {
        assert_eq!(
            parse_rpm_qf_output("file /usr/bin/foo is not owned by any package\n", 1),
            RpmQueryResult::NotOwned
        );
    }

    #[test]
    fn rpm_exit_0_extracts_package_name() {
        assert_eq!(
            parse_rpm_qf_output("bash\n", 0),
            RpmQueryResult::Owned("bash".to_string())
        );
    }

    #[test]
    fn rpm_non_specific_error_is_error() {
        assert_eq!(
            parse_rpm_qf_output("weird output", 42),
            RpmQueryResult::Error
        );
    }

    #[test]
    fn every_query_erroring_is_not_usable_rpm_data() {
        assert_eq!(parse_rpm_qf_output("", 42), RpmQueryResult::Error);
        assert_eq!(
            parse_rpm_qf_output("", 0),
            RpmQueryResult::Error,
            "exit 0 with no package name is malformed output, not an empty answer"
        );
    }
}
