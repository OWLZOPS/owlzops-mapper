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
const MAX_QUEUE_LEN: usize = MAX_CONF_FILES * 4; // safety cap for glob expansion

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

/// A directory is unsafe if a non-root principal can write to it.
/// Sticky bit intentionally ignored: it prevents deletion but not creation
/// of new files like `libfoo.so`.
pub(crate) fn unsafe_mode(mode: u32, uid: u32, gid: u32) -> bool {
    mode & 0o002 != 0 || (uid != 0 && mode & 0o200 != 0) || (gid != 0 && mode & 0o020 != 0)
}

fn expand_include(pattern: &str, queue: &mut Vec<PathBuf>) {
    if queue.len() >= MAX_QUEUE_LEN {
        coverage::record("ld.so.conf: include queue cap reached; SEC-051 partial".to_string());
        return;
    }
    let p = Path::new(pattern);
    let (Some(dir), Some(file_name)) = (p.parent(), p.file_name().and_then(|s| s.to_str())) else {
        return;
    };
    if !file_name.contains('*') {
        // If a plain directory is included, treat it as "dir/*" to read its
        // contents rather than failing on a directory read later.
        if let Ok(md) = fs::metadata(p)
            && md.is_dir()
        {
            let new_pattern = format!("{}/{}", dir.display(), "*");
            expand_include(&new_pattern, queue);
            return;
        }
        queue.push(p.to_path_buf());
        return;
    }
    match fs::read_dir(dir) {
        Ok(rd) => {
            for entry in rd.flatten() {
                if queue.len() >= MAX_QUEUE_LEN {
                    coverage::record(
                        "ld.so.conf: include queue cap reached during glob; SEC-051 partial"
                            .to_string(),
                    );
                    break;
                }
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(|n| glob_matches(file_name, n))
                {
                    queue.push(entry.path());
                }
            }
        }
        Err(e) => coverage::record(format!(
            "ld.so.conf include {pattern} unreadable ({e}); SEC-051 partial"
        )),
    }
}

fn classify_dir(raw: &str) -> Option<LdSoConfInjection> {
    let path = Path::new(raw);
    let md = match fs::metadata(raw) {
        Ok(md) => md,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Directory does not exist, but if the parent is writable,
            // an attacker can create it and take priority in the library path.
            let parent = path.parent()?;
            let pmd = fs::metadata(parent).ok()?;
            return unsafe_mode(pmd.permissions().mode(), pmd.uid(), pmd.gid()).then(|| {
                LdSoConfInjection {
                    path: raw.to_string(),
                    volatile: crate::utils::is_volatile_mount(&parent.to_string_lossy()),
                    writable_by_non_root: true,
                    mode: None, // directory doesn't exist yet
                    uid: pmd.uid(),
                    gid: pmd.gid(),
                }
            });
        }
        Err(_) => return None,
    };
    if !md.is_dir() {
        return None;
    }
    let mode = md.permissions().mode();
    let uid = md.uid();
    let gid = md.gid();
    let volatile = crate::utils::is_volatile_mount(raw);
    unsafe_mode(mode, uid, gid).then(|| LdSoConfInjection {
        path: raw.to_string(),
        volatile,
        writable_by_non_root: true,
        mode: Some(mode),
        uid,
        gid,
    })
}

/// Scan /etc/ld.so.conf and /etc/ld.so.conf.d/*.conf for directories
/// that enable unprivileged library injection (SEC-051).
/// Returns all suspicious directories found, sorted by path.
pub fn scan_ld_so_conf() -> Vec<LdSoConfInjection> {
    let mut queue = Vec::new();
    // ldconfig always reads conf.d/*.conf regardless of main file
    expand_include("/etc/ld.so.conf.d/*.conf", &mut queue);
    // also try the main file for custom paths/includes
    queue.push(PathBuf::from("/etc/ld.so.conf"));

    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut dirs: HashSet<String> = HashSet::new(); // dedup across includes

    while let Some(path) = queue.pop() {
        // R23-44: check limit before inserting
        if seen.len() >= MAX_CONF_FILES {
            coverage::record(
                "ld.so.conf: include fan-out cap reached; SEC-051 partial".to_string(),
            );
            break;
        }
        if !seen.insert(path.clone()) {
            continue;
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
                for dir in d {
                    // Normalize trailing slashes
                    dirs.insert(dir.trim_end_matches('/').to_string());
                }
                for pattern in inc {
                    expand_include(pattern, &mut queue);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => coverage::record(format!("{p_str} unreadable ({e}); SEC-051 NOT verified")),
        }
    }

    let mut out: Vec<_> = dirs.iter().filter_map(|d| classify_dir(d)).collect();
    out.sort_by(|a, b| a.path.cmp(&b.path)); // deterministic output
    out
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
    fn unsafe_mode_matrix() {
        assert!(!unsafe_mode(0o755, 0, 0), "root:root 755 — normal");
        assert!(unsafe_mode(0o777, 0, 0), "world-writable even for root");
        assert!(unsafe_mode(0o755, 1000, 0), "owner not root");
        assert!(
            unsafe_mode(0o775, 0, 1000),
            "group not root and group-write"
        );
        assert!(
            !unsafe_mode(0o755, 0, 1000),
            "group not root, but without w — normal"
        );
        assert!(
            unsafe_mode(0o1777, 0, 0),
            "sticky does not protect library path"
        );
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
        // volatile may be true or false depending on filesystem
    }
}
