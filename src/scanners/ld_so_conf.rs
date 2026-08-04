// src/scanners/ld_so_conf.rs
// SEC-051: Detect unsafe library search paths in ld.so.conf / ld.so.conf.d

use crate::models::LdSoConfInjection;
use crate::scanners::integrity::unsafe_mode;
use crate::{coverage, safe_io};
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MAX_CONF_BYTES: usize = 64 * 1024;
const MAX_CONF_FILES: usize = 256;
const MAX_QUEUE_LEN: usize = MAX_CONF_FILES * 4;

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

pub(crate) fn glob_matches(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == name,
        Some((pre, suf)) => {
            name.len() >= pre.len() + suf.len() && name.starts_with(pre) && name.ends_with(suf)
        }
    }
}

pub(crate) fn should_report(volatile: bool, writable_by_non_root: bool) -> bool {
    volatile || writable_by_non_root
}

pub(crate) fn dir_include_pattern(p: &Path) -> String {
    format!("{}/*", p.display())
}

pub(crate) fn classify_missing(volatile: bool, pmode: u32, puid: u32, pgid: u32) -> Option<bool> {
    let writable = unsafe_mode(pmode, puid, pgid);
    should_report(volatile, writable).then_some(writable)
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
        if let Ok(md) = fs::metadata(p)
            && md.is_dir()
        {
            let new_pattern = dir_include_pattern(p);
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
            let parent = path.parent()?;
            let pmd = fs::metadata(parent).ok()?;
            let volatile = crate::utils::is_volatile_mount(&parent.to_string_lossy());
            let writable_by_non_root =
                classify_missing(volatile, pmd.permissions().mode(), pmd.uid(), pmd.gid())?;
            return Some(LdSoConfInjection {
                path: raw.to_string(),
                volatile,
                writable_by_non_root,
                mode: None,
                uid: pmd.uid(),
                gid: pmd.gid(),
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
    let writable_by_non_root = unsafe_mode(mode, uid, gid);
    should_report(volatile, writable_by_non_root).then(|| LdSoConfInjection {
        path: raw.to_string(),
        volatile,
        writable_by_non_root,
        mode: Some(mode),
        uid,
        gid,
    })
}

pub fn scan_ld_so_conf() -> Vec<LdSoConfInjection> {
    let mut queue = Vec::new();
    expand_include("/etc/ld.so.conf.d/*.conf", &mut queue);
    queue.push(PathBuf::from("/etc/ld.so.conf"));

    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut dirs: HashSet<String> = HashSet::new();

    while let Some(path) = queue.pop() {
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
    out.sort_by(|a, b| a.path.cmp(&b.path));
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
    fn should_report_respects_both_axes() {
        assert!(should_report(true, false), "volatile alone must fire");
        assert!(should_report(false, true), "writable alone must fire");
        assert!(!should_report(false, false), "neither must be silent");
    }

    #[test]
    fn dir_include_pattern_is_self_not_parent() {
        assert_eq!(
            dir_include_pattern(Path::new("/etc/ld.so.conf.d")),
            "/etc/ld.so.conf.d/*"
        );
    }

    #[test]
    fn missing_dir_reported_only_when_parent_is_takeable() {
        assert!(
            classify_missing(false, 0o755, 0, 0).is_none(),
            "stale entry under root:root 0755 — must be silent"
        );
        assert_eq!(classify_missing(false, 0o777, 0, 0), Some(true));
        assert_eq!(classify_missing(false, 0o755, 1000, 0), Some(true));
        assert_eq!(classify_missing(true, 0o755, 0, 0), Some(false));
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
    }
}
