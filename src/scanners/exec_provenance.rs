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

// ── R23-16: Scope of the unit manager ──────────────────────────────────────

/// Who executes the unit.  For the user manager `User=` does NOT apply, so
/// identity is determined by the manager owner, not the file content.
#[derive(Clone, Copy)]
enum UnitScope {
    /// systemd (PID 1): identity comes from `User=`, defaults to root.
    System,
    /// systemd --user: runs as the session owner.
    UserManager { owner_is_root: bool },
}

/// Root directories for system units (PID 1).
const SYSTEM_UNIT_DIRS: &[&str] = &[
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/lib/systemd/system",
    "/usr/local/lib/systemd/system", // priority over /usr/lib, not vendor-owned
];

/// Root directories for user units (systemd --user).
/// None of these are executed by root (except /root's own manager).
const USER_UNIT_DIRS: &[&str] = &[
    "/etc/systemd/user",
    "/run/systemd/user",
    "/usr/lib/systemd/user",
];

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

    // R23-04: full systemd search path — includes /usr/local/lib/systemd,
    // drop-in directories (<unit>.d/*.conf), user units, and .socket units.
    fn is_unit_file(p: &Path) -> bool {
        p.extension()
            .is_some_and(|e| e == "service" || e == "socket")
    }

    fn scan_unit_dir(dir: &Path, scope: UnitScope, push: &mut dyn FnMut(ExecStartFinding)) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if is_unit_file(&path) {
                scan_service_file(&path, scope, push);
                continue;
            }
            // R23-04: drop-in directories <unit>.d/*.conf
            if path.extension().is_some_and(|e| e == "d")
                && let Ok(dropins) = std::fs::read_dir(&path)
            {
                for d in dropins.flatten() {
                    let dp = d.path();
                    if dp.extension().is_some_and(|e| e == "conf") {
                        scan_service_file(&dp, scope, push);
                    }
                }
            }
        }
    }

    for dir in SYSTEM_UNIT_DIRS {
        scan_unit_dir(Path::new(dir), UnitScope::System, &mut push_candidate);
    }
    for dir in USER_UNIT_DIRS {
        scan_unit_dir(
            Path::new(dir),
            UnitScope::UserManager {
                owner_is_root: false,
            },
            &mut push_candidate,
        );
    }

    // User systemd units (non-root persistence):
    // /home/*, /var/home/* (Fedora Atomic), and /root.
    for home_root in ["/home", "/var/home"] {
        if let Ok(users) = std::fs::read_dir(home_root) {
            for user_entry in users.flatten() {
                let user_dir = user_entry.path().join(".config/systemd/user");
                if user_dir.is_dir() {
                    scan_unit_dir(
                        &user_dir,
                        UnitScope::UserManager {
                            owner_is_root: false,
                        },
                        &mut push_candidate,
                    );
                }
            }
        }
    }
    let root_user_dir = Path::new("/root/.config/systemd/user");
    if root_user_dir.is_dir() {
        scan_unit_dir(
            root_user_dir,
            UnitScope::UserManager {
                owner_is_root: true,
            },
            &mut push_candidate,
        );
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

/// Returns true if the unit file does not set `User=` to a non-root account.
/// The last `User=` line wins (systemd behaviour). Fail-closed: absent or
/// root/0 → true.
///
/// R23-15: normalise whitespace around `=` — systemd's conf-parser strips
/// both sides, so `User = app` is a valid assignment.
fn unit_runs_as_root(content: &str) -> bool {
    content
        .lines()
        .filter_map(|l| split_directive(l.trim()).filter(|(k, _)| *k == "User"))
        .map(|(_, v)| v)
        .next_back()
        .is_none_or(|u| {
            let u = u.trim().trim_matches('"');
            u.is_empty() || u == "root" || u == "0"
        })
}

// ── R23-04 / R23-15: all Exec* directives understood by systemd, without '=' ─
const EXEC_DIRECTIVES: &[&str] = &[
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
    "ExecReload",
    "ExecStop",
    "ExecStopPost",
    "ExecCondition",
];

/// Split a line by the FIRST '=', trim both sides.  This mirrors systemd's
/// conf-parser which strips whitespace around the delimiter, so
/// `ExecStart = /tmp/x` is a valid assignment (R23-15).
fn split_directive(line: &str) -> Option<(&str, &str)> {
    let (k, v) = line.split_once('=')?;
    Some((k.trim_end(), v.trim_start()))
}

/// Extract paths from Exec* directives in a service/drop-in file and check them.
fn scan_service_file(unit_path: &Path, scope: UnitScope, push: &mut dyn FnMut(ExecStartFinding)) {
    let unit_path_s = unit_path.to_string_lossy().into_owned();

    let Some(path_str) = unit_path.to_str() else {
        coverage::record(format!(
            "unit path is not valid UTF-8 ({}); ExecStart NOT parsed",
            unit_path.display()
        ));
        return;
    };
    let (content, truncated) = match safe_io::read_file_capped_regular(path_str, 64 * 1024) {
        Ok(t) => t,
        Err(e) => {
            coverage::record(format!(
                "{} unreadable ({e}); ExecStart NOT parsed",
                unit_path.display()
            ));
            return;
        }
    };
    if truncated {
        coverage::record(format!("{} truncated", unit_path.display()));
    }

    let unit_name = unit_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    // R23-06 / R23-16: determine whether the unit runs as root.
    //
    // NOTE: drop-in files (<unit>.d/*.conf) do NOT inherit User= from the
    // base unit, so for them this is always true (fail-closed).  A full
    // solution would resolve the base unit by name, but that's deferred
    // (see R23-19).  The current behaviour errs on the side of FP, which
    // is the safe direction for SEC-046.
    let runs_as_root = match scope {
        UnitScope::System => unit_runs_as_root(&content),
        UnitScope::UserManager { owner_is_root } => owner_is_root,
    };

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('[') {
            continue;
        }

        let Some((key, rest)) = split_directive(trimmed) else {
            continue;
        };
        if EXEC_DIRECTIVES.contains(&key) {
            // R23-05: systemd allows optional prefixes '-', '@', '+', '!', ':'
            // and quoted paths.  Strip prefixes, then remove surrounding quotes.
            let args = rest
                .trim_start_matches(['-', '@', '+', '!', ':'])
                .trim_start();
            if let Some(raw) = args.split_whitespace().next() {
                let first_token = raw.trim_matches(|c| c == '"' || c == '\'');
                if first_token.is_empty() || !first_token.starts_with('/') {
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
                    runs_as_root, // R23-06 / R23-16
                });
            }
        }
    }
}

/// Scan crontabs (system and user) and check commands for suspicious paths.
fn scan_cron_files(push: &mut dyn FnMut(ExecStartFinding)) {
    // System crontab file
    if let Ok((content, _)) = safe_io::read_file_capped_regular("/etc/crontab", 64 * 1024) {
        for line in content.lines() {
            check_cron_line(line, "cron:/etc/crontab", "/etc/crontab", push);
        }
    }

    // Cron.d directory
    if let Ok(entries) = std::fs::read_dir("/etc/cron.d") {
        for entry in entries.flatten() {
            let path = entry.path();
            let path_s = path.to_string_lossy().into_owned();

            // R23-18: cron ignores files that don't match [A-Za-z0-9_-].
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            if !cron_d_is_active(&name) {
                continue;
            }

            let Some(path_str) = path.to_str() else {
                coverage::record(format!(
                    "cron.d path is not valid UTF-8 ({}); skipping",
                    path.display()
                ));
                continue;
            };
            if let Ok((content, _)) = safe_io::read_file_capped_regular(path_str, 64 * 1024) {
                let source = format!("cron.d:{}", name);
                for line in content.lines() {
                    check_cron_line(line, &source, &path_s, push);
                }
            }
        }
    }

    // TODO: user crontabs via `crontab -l`? For now, skip to avoid complexity.
}

/// R23-18: cron ignores files in /etc/cron.d that contain characters beyond
/// [A-Za-z0-9_-] — editor backups, package manager save files, etc.
fn cron_d_is_active(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
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

    // R23-13: extract the user field as well as the command index.
    let (cmd_idx, user_idx) = match first.strip_prefix('@') {
        Some(tag) => {
            if !CRON_SHORTHANDS.contains(&tag) {
                return;
            }
            (2, 1) // @reboot | user | command
        }
        None => (6, 5), // 5 schedule fields | user | command
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

    // R23-13: real identity from the user field.
    let runs_as_root = parts
        .get(user_idx)
        .is_none_or(|u| *u == "root" || *u == "0");

    push(ExecStartFinding {
        source: source.to_string(),
        unit_name: source.to_string(),
        unit_path: unit_path.to_string(),
        unit_package: None,
        exec_path: first_token.to_string(),
        volatile,
        writability,
        package: None,
        runs_as_root,
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

    #[test]
    fn cron_identity_comes_from_the_user_field() {
        let mut got = Vec::new();
        let mut push = |f: ExecStartFinding| got.push((f.exec_path, f.runs_as_root));

        check_cron_line("*/5 * * * * deploy /opt/app/sync.sh", "c", "c", &mut push);
        check_cron_line("0 3 * * * root /usr/local/sbin/backup", "c", "c", &mut push);

        assert!(!got[0].1, "User=deploy → SEC-046 not applicable");
        assert!(got[1].1);
    }

    #[test]
    fn quoted_exec_start_is_not_a_bypass() {
        let dir = tempfile::tempdir().unwrap();
        let unit = dir.path().join("evil.service");
        std::fs::write(&unit, "[Service]\nExecStart=-:\"/dev/shm/impl\" --daemon\n").unwrap();

        let mut got = Vec::new();
        scan_service_file(&unit, UnitScope::System, &mut |f| got.push(f.exec_path));
        assert_eq!(got, vec!["/dev/shm/impl".to_string()]);
    }

    #[test]
    fn whitespace_around_equals_is_not_a_bypass() {
        let dir = tempfile::tempdir().unwrap();
        let unit = dir.path().join("evil.service");
        std::fs::write(&unit, "[Service]\nUser = app\nExecStart = -/dev/shm/impl\n").unwrap();

        let mut got = Vec::new();
        scan_service_file(&unit, UnitScope::System, &mut |f| {
            got.push((f.exec_path, f.runs_as_root))
        });
        assert_eq!(got, vec![("/dev/shm/impl".to_string(), false)]);
    }
}
