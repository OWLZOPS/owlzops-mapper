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

/// Scan all systemd unit directories and cron files, returning any suspicious exec paths.
pub fn scan_exec_provenance() -> Vec<ExecStartFinding> {
    let mut findings: Vec<ExecStartFinding> = Vec::new();
    let mut candidate_set: HashSet<String> = HashSet::new();

    // Helper – push a finding and record its canonical path for batch resolution
    let mut push_candidate = |finding: ExecStartFinding| {
        let canon = crate::utils::canon_path(&finding.exec_path).into_owned();
        candidate_set.insert(canon);
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

    // Resolve package ownership for all candidates in one batch
    if !candidate_set.is_empty() {
        let prov = crate::scanners::provenance::resolve_batch(&candidate_set);
        for f in &mut findings {
            f.package = prov.lookup(crate::utils::canon_path(&f.exec_path).as_ref());
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
    let loose = |m: &std::fs::Metadata| m.uid() != 0 || m.mode() & 0o022 != 0;

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
                    exec_path: first_token.to_string(),
                    volatile,
                    writability,
                    package: None, // filled after batch resolution
                    reason: String::new(),
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
            check_cron_line(line, "cron:/etc/crontab", push);
        }
    }

    // Cron.d directory
    if let Ok(entries) = std::fs::read_dir("/etc/cron.d") {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok((content, _)) =
                safe_io::read_file_capped(path.to_str().unwrap_or(""), 64 * 1024)
            {
                let source = format!(
                    "cron.d:{}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                );
                for line in content.lines() {
                    check_cron_line(line, &source, push);
                }
            }
        }
    }

    // TODO: user crontabs via `crontab -l`? For now, skip to avoid complexity.
}

/// Check a cron line: ignore comments, empty lines, and environment assignments.
/// Extract the command part (6th field onwards) and check its first token.
fn check_cron_line(line: &str, source: &str, push: &mut dyn FnMut(ExecStartFinding)) {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return;
    }
    // Cron lines: minute hour day month day-of-week command
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() < 6 {
        return;
    }
    // The command starts at index 5
    let first_token = parts[5];
    if first_token.starts_with('@') {
        // @reboot, etc. – skip for now
        return;
    }
    if !first_token.starts_with('/') {
        return;
    }

    let resolved = std::fs::canonicalize(first_token)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| first_token.to_string());
    let volatile = crate::utils::is_volatile_exec_path(&resolved);
    let writability = assess_writability(first_token);

    push(ExecStartFinding {
        source: source.to_string(),
        unit_name: source.to_string(),
        exec_path: first_token.to_string(),
        volatile,
        writability,
        package: None,
        reason: String::new(),
    });
}
