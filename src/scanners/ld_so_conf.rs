// src/scanners/ld_so_conf.rs

use crate::models::LdSoConfInjection;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// Scan /etc/ld.so.conf and its included fragments for library search path
/// directories that are writable by non-root or reside on volatile filesystems.
/// Returns None if the config file is unreadable or no suspicious directories
/// are found.
pub fn scan_ld_so_conf() -> Option<Vec<LdSoConfInjection>> {
    let config_path = "/etc/ld.so.conf";
    let conf_d_dir = "/etc/ld.so.conf.d";

    let content = fs::read_to_string(config_path).ok()?;

    let mut entries: Vec<String> = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(rest) = line.strip_prefix("include ") {
            let raw = rest.trim();
            // Support relative paths like "ld.so.conf.d/*.conf" (Fedora, RHEL, …).
            let pattern = if !raw.starts_with('/') {
                format!("/etc/{raw}")
            } else {
                raw.to_string()
            };
            if pattern.starts_with(conf_d_dir)
                && let Ok(dir) = fs::read_dir(conf_d_dir)
            {
                for entry in dir.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|ext| ext == "conf")
                        && let Ok(file_content) = fs::read_to_string(&path)
                    {
                        for file_line in file_content.lines() {
                            let file_line = file_line.trim();
                            if !file_line.is_empty() && !file_line.starts_with('#') {
                                entries.push(file_line.to_string());
                            }
                        }
                    }
                }
            }
        } else {
            entries.push(line.to_string());
        }
    }

    let mut results = Vec::new();

    for raw_path in entries {
        let path = Path::new(&raw_path);
        if !path.is_absolute() || !path.is_dir() {
            continue;
        }

        let volatile = crate::utils::is_volatile_mount(&raw_path);
        let writable_by_non_root = is_writable_by_non_root(&raw_path);
        let mode = read_dir_mode(&raw_path);

        if volatile || writable_by_non_root {
            results.push(LdSoConfInjection {
                path: raw_path,
                volatile,
                writable_by_non_root,
                mode,
            });
        }
    }

    if results.is_empty() {
        None
    } else {
        Some(results)
    }
}

fn is_writable_by_non_root(dir: &str) -> bool {
    if let Ok(meta) = fs::metadata(dir) {
        let mode = meta.permissions().mode();
        let uid = meta.uid();
        let gid = meta.gid();

        if (mode & 0o002) != 0 {
            return true; // world-writable
        }
        if uid != 0 && (mode & 0o200) != 0 {
            return true;
        }
        if gid != 0 && (mode & 0o020) != 0 {
            return true;
        }
    }
    false
}

fn read_dir_mode(dir: &str) -> Option<u32> {
    fs::metadata(dir).ok().map(|m| m.permissions().mode())
}
