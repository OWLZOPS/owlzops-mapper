//! Package provenance resolver for dpkg and apk.
//! Given a set of file paths (candidates), returns a mapping from path to the
//! name of the installed package that owns it, without loading the entire
//! package database into memory (O(candidates) memory, O(database size) time).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Resolve provenance for a batch of candidate paths.
/// Returns a map from each candidate path to the owning package name (if found).
pub fn resolve_batch(candidates: &HashSet<String>) -> HashMap<String, String> {
    let result = resolve_dpkg(candidates);
    // TODO: add apk support here
    result
}

/// Resolve multiple candidate paths via dpkg's file lists.
fn resolve_dpkg(candidates: &HashSet<String>) -> HashMap<String, String> {
    let mut owned = HashMap::new();
    let info_dir = Path::new("/var/lib/dpkg/info");
    let rd = match fs::read_dir(info_dir) {
        Ok(rd) => rd,
        Err(_) => {
            crate::coverage::record(
                "provenance: /var/lib/dpkg/info unreadable — dpkg attribution degraded".to_string(),
            );
            return owned;
        }
    };

    for entry in rd.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("list") {
            continue;
        }
        // Extract package name: "libfoo:amd64.list" -> "libfoo"
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
            if candidates.contains(line) {
                owned.insert(line.to_string(), pkg.clone());
            }
            // Check usrmerge alias while scanning
            if let Some(usr_path) = line.strip_prefix("/usr") {
                if candidates.contains(usr_path) {
                    owned.insert(usr_path.to_string(), pkg.clone());
                }
            } else if !line.starts_with("/usr") && line.starts_with('/') {
                let usr_variant = format!("/usr{}", line);
                if candidates.contains(&usr_variant) {
                    owned.insert(usr_variant, pkg.clone());
                }
            }
        }
        if owned.len() == candidates.len() {
            break;
        }
    }
    owned
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_batch_basics() {
        if Path::new("/var/lib/dpkg/info").is_dir() {
            let mut candidates = HashSet::new();
            candidates.insert("/bin/ls".to_string());
            candidates.insert("/usr/bin/ls".to_string());
            let result = resolve_batch(&candidates);
            assert!(
                result.contains_key("/bin/ls") || result.contains_key("/usr/bin/ls"),
                "ls must belong to a package"
            );
        }
    }
}
