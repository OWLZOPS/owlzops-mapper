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
    // 1. Try dpkg (Debian/Ubuntu)
    let dpkg_result = resolve_dpkg(candidates);
    if !dpkg_result.is_empty() {
        return dpkg_result;
    }

    // 2. Try APK (Alpine)
    let apk_result = resolve_apk(candidates);
    if !apk_result.is_empty() {
        return apk_result;
    }

    // 3. RPM – honest degradation without heavy BDB/SQLite parsers
    resolve_rpm(candidates)
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

/// Resolve multiple candidate paths via APK's installed database.
fn resolve_apk(candidates: &HashSet<String>) -> HashMap<String, String> {
    let mut owned = HashMap::new();
    let apk_db = Path::new("/lib/apk/db/installed");
    let dir_iter = match fs::read_dir(apk_db) {
        Ok(it) => it,
        Err(_) => {
            crate::coverage::record(
                "provenance: /lib/apk/db/installed unreadable — apk attribution degraded"
                    .to_string(),
            );
            return owned;
        }
    };

    for entry in dir_iter.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let mut pkg_name = String::new();
        let mut files = Vec::new();

        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("P:") {
                pkg_name = rest.to_owned();
            } else if let Some(rest) = line.strip_prefix("F:") {
                // APK paths are relative to root, without a leading slash
                let abs_path = format!("/{}", rest);
                files.push(abs_path);
            }
        }

        if pkg_name.is_empty() {
            continue;
        }

        // Match candidates against owned files, including usrmerge aliases
        for f in &files {
            if candidates.contains(f.as_str()) {
                owned.insert(f.clone(), pkg_name.clone());
            }
            // usrmerge aliases
            if let Some(without_usr) = f.strip_prefix("/usr") {
                if candidates.contains(without_usr) {
                    owned.insert(without_usr.to_string(), pkg_name.clone());
                }
            } else if !f.starts_with("/usr") {
                let with_usr = format!("/usr{}", f);
                if candidates.contains(&with_usr) {
                    owned.insert(with_usr, pkg_name.clone());
                }
            }
        }

        if owned.len() == candidates.len() {
            break;
        }
    }

    owned
}

/// RPM backend stub – we consciously skip heavy BDB/SQLite parsing.
/// Returns an empty map so that further fallback heuristics can take over.
fn resolve_rpm(_candidates: &HashSet<String>) -> HashMap<String, String> {
    crate::coverage::record("provenance: RPM backend skipped (no BDB/SQLite parser)".to_string());
    HashMap::new()
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
