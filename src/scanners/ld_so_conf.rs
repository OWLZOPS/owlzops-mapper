// src/scanners/ld_so_conf.rs
// SEC-051: Detect unsafe library search paths in ld.so.conf / ld.so.conf.d

use crate::models::LdSoConfInjection;
use crate::{coverage, safe_io};
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MAX_CONF_BYTES: usize = 64 * 1024;
const MAX_CONF_FILES: usize = 256;

/// Pure parser for one ld.so.conf file content.
/// Returns (directories, include-patterns).
/// Semantics: `#` removes the rest of the line; `include` + isblank.
pub(crate) fn parse_ld_so_conf(content: &str) -> (Vec<&str>, Vec<&str>) {
    let mut dirs = Vec::new();
    let mut includes = Vec::new();
    for raw in content.lines() {
        let line = raw.split_once('#').map_or(raw, |(head, _)| head).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("include")
            && rest.starts_with([' ', '\t'])
        {
            let pattern = rest.trim();
            if !pattern.is_empty() {
                includes.push(pattern);
            }
            continue;
        }
        if line.starts_with('/') {
            dirs.push(line);
        }
    }
    (dirs, includes)
}

/// Simple glob: only '*' is used in ld.so.conf patterns.
pub(crate) fn glob_matches(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == name,
        Some((pre, suf)) => {
            name.len() >= pre.len() + suf.len() && name.starts_with(pre) && name.ends_with(suf)
        }
    }
}

fn expand_include(pattern: &str, queue: &mut Vec<PathBuf>) {
    let p = Path::new(pattern);
    let (Some(dir), Some(file_name)) = (p.parent(), p.file_name().and_then(|s| s.to_str())) else {
        return;
    };
    if !file_name.contains('*') {
        queue.push(p.to_path_buf());
        return;
    }
    match fs::read_dir(dir) {
        Ok(rd) => queue.extend(
            rd.flatten()
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .is_some_and(|n| glob_matches(file_name, n))
                })
                .map(|e| e.path()),
        ),
        Err(e) => coverage::record(format!(
            "ld.so.conf include {pattern} unreadable ({e}); SEC-051 partial"
        )),
    }
}

fn classify_dir(raw: &str) -> Option<LdSoConfInjection> {
    let md = fs::metadata(raw).ok()?;
    if !md.is_dir() {
        return None;
    }
    let mode = md.permissions().mode();
    let uid = md.uid();
    let gid = md.gid();
    let writable_by_non_root =
        mode & 0o002 != 0 || (uid != 0 && mode & 0o200 != 0) || (gid != 0 && mode & 0o020 != 0);
    let volatile = crate::utils::is_volatile_mount(raw);
    (volatile || writable_by_non_root).then(|| LdSoConfInjection {
        path: raw.to_string(),
        volatile,
        writable_by_non_root,
        mode: Some(mode),
        uid,
        gid,
    })
}

/// Scan /etc/ld.so.conf and /etc/ld.so.conf.d/*.conf for directories
/// that enable unprivileged library injection (SEC-051).
/// Returns all suspicious directories found.
pub fn scan_ld_so_conf() -> Vec<LdSoConfInjection> {
    let mut queue = Vec::new();
    // ldconfig always reads conf.d/*.conf regardless of main file
    expand_include("/etc/ld.so.conf.d/*.conf", &mut queue);
    // also try the main file for custom paths/includes
    queue.push(PathBuf::from("/etc/ld.so.conf"));

    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut dirs: Vec<String> = Vec::new();

    while let Some(path) = queue.pop() {
        if !seen.insert(path.clone()) {
            continue;
        }
        if seen.len() > MAX_CONF_FILES {
            coverage::record("ld.so.conf: include fan-out cap reached; SEC-051 partial");
            break;
        }
        let Some(p_str) = path.to_str() else {
            coverage::record(format!(
                "ld.so.conf fragment {} is not UTF-8; skipped",
                path.display()
            ));
            continue;
        };
        match safe_io::read_file_capped_regular(p_str, MAX_CONF_BYTES) {
            Ok((content, truncated)) => {
                if truncated {
                    coverage::record(format!("{p_str} exceeded cap — SEC-051 scan truncated"));
                }
                let (d, inc) = parse_ld_so_conf(&content);
                dirs.extend(d.iter().map(|s| (*s).to_string()));
                for pattern in inc {
                    expand_include(pattern, &mut queue);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => coverage::record(format!("{p_str} unreadable ({e}); SEC-051 NOT verified")),
        }
    }

    dirs.iter().filter_map(|d| classify_dir(d)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_matches_ldconfig() {
        let input =
            "/opt/lib # legacy\n\tinclude\t/etc/ld.so.conf.d/*.conf\nhwcap 1 nosegneg\n#/tmp/x\n";
        let (dirs, inc) = parse_ld_so_conf(input);
        assert_eq!(
            dirs,
            vec!["/opt/lib"],
            "inline comment must not kill the entry"
        );
        assert_eq!(
            inc,
            vec!["/etc/ld.so.conf.d/*.conf"],
            "include with tab must be recognized"
        );
    }

    #[test]
    fn glob_matches_works() {
        assert!(glob_matches("*.conf", "zz_i386-biarch.conf"));
        assert!(!glob_matches("*.conf", "backup.conf.bak"));
        assert!(!glob_matches("*.conf", "conf"));
    }

    #[test]
    fn classify_dir_detects_world_writable() {
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_str().unwrap();
        let mut perms = fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o777);
        fs::set_permissions(path, perms).unwrap();
        let inj = classify_dir(path).unwrap();
        assert!(inj.writable_by_non_root, "expected writable by non-root");
        // volatile may be true or false depending on filesystem; not checking it here.
    }
}
