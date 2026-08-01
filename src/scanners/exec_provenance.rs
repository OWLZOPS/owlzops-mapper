// src/scanners/exec_provenance.rs
// SEC-043: Check provenance and writability of executables launched by systemd units and cron.
//
// Parses ExecStart/ExecStartPre from systemd service files and cron commands,
// flags any executable path that is ephemeral/writable or whose target is writable
// by a non-root principal.
// Designed to catch persistence mechanisms like /tmp/backdoor or /run/user/... hidden
// as a systemd unit.

use crate::coverage;
use crate::models::{ExecStartFinding, ExecWritability};
use crate::safe_io;
use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Return `true` if the unit path already resides in a vendor-controlled
/// systemd directory.  For those units the owning package is known from the
/// directory hierarchy (rule R22-30) and does **not** need an `rpm -qf` call.
fn unit_path_is_vendor_dir(path: &str) -> bool {
    let canon = crate::utils::canon_path(path);
    canon.starts_with("/usr/lib/systemd/system/") || canon.starts_with("/usr/lib/systemd/user/")
    // On Fedora /lib/systemd/system is a symlink to /usr/lib/systemd/system,
    // so canonicalization already resolves it.  No extra prefix is required.
}

/// Scan all systemd unit directories and cron files, returning any suspicious exec paths.
///
/// When `deep` is false, only unit-file authorship is resolved; the provenance
/// of the target executable (`SEC-045` unpackaged target) is skipped, saving
/// ~350 `rpm -qf` spawns.  Deep mode performs full resolution for inventory.
pub fn scan_exec_provenance(deep: bool) -> Vec<ExecStartFinding> {
    let mut findings: Vec<ExecStartFinding> = Vec::new();
    let mut candidate_set: HashSet<String> = HashSet::new();

    // Helper – push a finding and (when deep) record its canonical path for batch resolution
    let mut push_candidate = |finding: ExecStartFinding| {
        if deep {
            let canon = crate::utils::canon_path(&finding.exec_path).into_owned();
            candidate_set.insert(canon);
        }
        findings.push(finding);
    };

    // System-wide systemd units
    let unit_dirs = &[
        "/etc/systemd/system",
        "/run/systemd/system",
        "/usr/lib/systemd/system",
    ];
    for dir in unit_dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "service") {
                    scan_service_file(&path, &mut push_candidate);
                }
            }
        }
    }

    // User systemd units (non-root persistence)
    if let Ok(entries) = std::fs::read_dir("/home") {
        for user_entry in entries.flatten() {
            let user_dir = user_entry.path().join(".config/systemd/user");
            if user_dir.is_dir()
                && let Ok(unit_entries) = std::fs::read_dir(&user_dir)
            {
                for unit in unit_entries.flatten() {
                    let path = unit.path();
                    if path.extension().is_some_and(|e| e == "service") {
                        scan_service_file(&path, &mut push_candidate);
                    }
                }
            }
        }
    }

    // Cron jobs
    scan_cron_files(&mut push_candidate);

    // Add unit paths as candidates for authorship resolution.
    // Units already inside the vendor directory are skipped: their package
    // ownership is implied by the directory (R22-30), saving ~400 rpm calls.
    for f in &findings {
        if !f.unit_path.is_empty() && !unit_path_is_vendor_dir(&f.unit_path) {
            candidate_set.insert(crate::utils::canon_path(&f.unit_path).into_owned());
        }
    }

    // Resolve package ownership for the collected candidates in one batch
    if !candidate_set.is_empty() {
        let prov = crate::scanners::provenance::resolve_batch(&candidate_set);
        for f in &mut findings {
            // SEC-045 target ownership is inventory, not forensics.
            // Only resolve when deep is requested (R22-38).
            if deep {
                f.package = prov.lookup(crate::utils::canon_path(&f.exec_path).as_ref());
            }
            if !f.unit_path.is_empty() {
                f.unit_package = prov.lookup(crate::utils::canon_path(&f.unit_path).as_ref());
            }
        }
    }

    findings
}

/// Assess who can modify the exec target. `metadata` (not `symlink_metadata`)
/// deliberately follows symlinks — the bytes that actually execute are what
/// matter, so /usr/bin/foo → /home/u/evil correctly reports NonRootWritable.
/// The parent is checked too: write permission on a directory allows
/// unlink+replace regardless of the file's own mode.
fn assess_writability(path: &str) -> ExecWritability {
    let loose = |m: &std::fs::Metadata| {
        m.uid() != 0 || m.mode() & 0o002 != 0 || (m.mode() & 0o020 != 0 && m.gid() != 0)
    };

    match std::fs::metadata(path) {
        Ok(md) if loose(&md) => return ExecWritability::NonRootWritable,
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ExecWritability::Missing,
        Err(_) => return ExecWritability::Unknown,
    }
    match Path::new(path).parent().map(std::fs::metadata) {
        Some(Ok(dir)) if loose(&dir) => ExecWritability::NonRootWritable,
        Some(Err(_)) => ExecWritability::Unknown,
        _ => ExecWritability::RootOnly,
    }
}

/// Extract ExecStart/ExecStartPre paths from a service file and check them.
fn scan_service_file(unit_path: &Path, push: &mut dyn FnMut(ExecStartFinding)) {
    let unit_path_s = unit_path.to_string_lossy().into_owned();

    let (content, truncated) =
        match safe_io::read_file_capped(unit_path.to_str().unwrap_or(""), 64 * 1024) {
            Ok(t) => t,
            Err(_) => return,
        };
    if truncated {
        coverage::record(format!("{} truncated", unit_path.display()));
    }

    let unit_name = unit_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('[') {
            continue;
        }
        // Look for ExecStart= or ExecStartPre=
        if let Some(rest) = trimmed
            .strip_prefix("ExecStart=")
            .or_else(|| trimmed.strip_prefix("ExecStartPre="))
        {
            // Strip optional prefixes: "-", "@", "+", "!", "!!"
            let args = rest.trim_start_matches(['-', '@', '+', '!']);
            if let Some(first_token) = args.split_whitespace().next() {
                if first_token.is_empty() {
                    continue;
                }
                // Only absolute paths are candidates; relative commands are ignored.
                if !first_token.starts_with('/') {
                    continue;
                }

                // Volatility is assessed on the RESOLVED target, not the literal string:
                //  • /run/current-system/sw/bin/foo → /nix/store/… → NOT volatile (NixOS)
                //  • /usr/bin/foo → /tmp/evil       → volatile     (symlinked payload)
                let resolved = std::fs::canonicalize(first_token)
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| first_token.to_string());
                let volatile = crate::utils::is_volatile_exec_path(&resolved);

                let writability = assess_writability(first_token);

                push(ExecStartFinding {
                    source: format!("systemd:{}", unit_name),
                    unit_name: unit_name.clone(),
                    unit_path: unit_path_s.clone(),
                    unit_package: None, // filled after batch resolution
                    exec_path: first_token.to_string(),
                    volatile,
                    writability,
                    package: None,
                });
            }
        }
    }
}

/// Scan crontabs (system and user) and check commands for suspicious paths.
fn scan_cron_files(push: &mut dyn FnMut(ExecStartFinding)) {
    // System crontab file
    if let Ok((content, _)) = safe_io::read_file_capped("/etc/crontab", 64 * 1024) {
        for line in content.lines() {
            check_cron_line(line, "cron:/etc/crontab", "/etc/crontab", push);
        }
    }

    // Cron.d directory
    if let Ok(entries) = std::fs::read_dir("/etc/cron.d") {
        for entry in entries.flatten() {
            let path = entry.path();
            let path_s = path.to_string_lossy().into_owned();
            if let Ok((content, _)) =
                safe_io::read_file_capped(path.to_str().unwrap_or(""), 64 * 1024)
            {
                let source = format!(
                    "cron.d:{}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                );
                for line in content.lines() {
                    check_cron_line(line, &source, &path_s, push);
                }
            }
        }
    }

    // TODO: user crontabs via `crontab -l`? For now, skip to avoid complexity.
}

// Shorthand schedules recognized by vixie/cronie.
const CRON_SHORTHANDS: &[&str] = &[
    "reboot", "yearly", "annually", "monthly", "weekly", "daily", "midnight", "hourly",
];

/// Check a cron line: ignore comments, empty lines, and environment assignments.
/// Handles both system crontab format (`/etc/crontab`, `/etc/cron.d/*`) with a
/// mandatory `user` field, and shorthand `@reboot user command`.
fn check_cron_line(
    line: &str,
    source: &str,
    unit_path: &str,
    push: &mut dyn FnMut(ExecStartFinding),
) {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return;
    }

    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    let Some(&first) = parts.first() else { return };

    // SHELL=/bin/sh, MAILTO="" – not schedules.
    if first.contains('=') {
        return;
    }

    // R23-01: /etc/crontab and /etc/cron.d/* use the SYSTEM format:
    // <schedule> <user> <command>. The user field is required.
    let cmd_idx = match first.strip_prefix('@') {
        Some(tag) => {
            if !CRON_SHORTHANDS.contains(&tag) {
                return;
            }
            2 // @reboot | user | command
        }
        None => 6, // 5 schedule fields | user | command
    };

    let Some(&first_token) = parts.get(cmd_idx) else {
        return;
    };
    if !first_token.starts_with('/') {
        return; // `cd / && ...`, relative commands – out of scope
    }

    let resolved = std::fs::canonicalize(first_token)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| first_token.to_string());
    let volatile = crate::utils::is_volatile_exec_path(&resolved);
    let writability = assess_writability(first_token);

    push(ExecStartFinding {
        source: source.to_string(),
        unit_name: source.to_string(),
        unit_path: unit_path.to_string(),
        unit_package: None,
        exec_path: first_token.to_string(),
        volatile,
        writability,
        package: None,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_crontab_command_is_after_user_field() {
        let mut got = Vec::new();
        let mut push = |f: ExecStartFinding| got.push(f.exec_path);

        check_cron_line(
            "* * * * * root /dev/shm/impl --quiet",
            "cron:/etc/crontab",
            "/etc/crontab",
            &mut push,
        );
        check_cron_line(
            "@reboot root /tmp/persist.sh",
            "cron.d:x",
            "/etc/cron.d/x",
            &mut push,
        );
        check_cron_line(
            "SHELL=/bin/sh",
            "cron:/etc/crontab",
            "/etc/crontab",
            &mut push,
        );
        check_cron_line(
            "17 * * * * root cd / && run-parts /etc/cron.hourly",
            "c",
            "c",
            &mut push,
        );

        assert_eq!(
            got,
            vec!["/dev/shm/impl".to_string(), "/tmp/persist.sh".to_string()]
        );
    }
}
