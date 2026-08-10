// src/scanners/pam.rs
// SEC-055/056/057: PAM stack injection
//
// Parses /etc/pam.d/* files for modules loaded from outside the trusted
// system directories, and for pam_exec.so with a potentially hijacked script.
// PAM modules are dlopen'd by every authentication service; a backdoor here
// bypasses all other file-integrity checks.

use crate::models::PamScriptInfo;
use crate::models::{ExecWritability, PamFinding, PamModule};
use crate::scanners::integrity::{assess_writability, unsafe_mode};
use crate::{coverage, safe_io};
use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const MAX_PAM_FINDINGS: usize = 2048;

/// Directories where PAM modules are installed by the system package manager.
const TRUSTED_PAM_DIRS: &[&str] = &[
    "/lib/security/",
    "/lib64/security/",
    "/usr/lib/security/",
    "/usr/lib64/security/",
    "/usr/lib/x86_64-linux-gnu/security/",
];

fn is_trusted_module_path(path: &str) -> bool {
    TRUSTED_PAM_DIRS.iter().any(|d| path.starts_with(d))
}

/// Resolve a bare module name to a full path by searching the trusted
/// directories in order (mimics libpam).
fn resolve_module(module: &str) -> Option<String> {
    if module.contains('/') {
        return Some(module.to_string());
    }
    TRUSTED_PAM_DIRS
        .iter()
        .map(|d| format!("{d}{module}"))
        .find(|p| Path::new(p).exists())
}

/// Pure parser for one line of a PAM config file.
/// Returns Some((type, control, module_path, args_str)) or None if comment/empty.
pub(crate) fn parse_pam_line(line: &str) -> Option<(&str, &str, &str, &str)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let mut parts = trimmed.splitn(4, |c: char| c.is_whitespace());
    let type_ = parts.next()?;
    let control = parts.next()?;
    let module = parts.next()?;
    let args = parts.next().unwrap_or("");
    Some((type_, control, module, args))
}

/// Extract the script path from pam_exec arguments.
/// The first absolute token is the command. Options (seteuid, debug, quiet,
/// expose_authtok, log=..., type=...) never start with a slash, so an
/// allow‑list approach would break on unknown flags (R23-68).
fn extract_pam_exec_script(args: &str) -> Option<&str> {
    args.split_whitespace().find(|t| t.starts_with('/'))
}

/// Scan all files in /etc/pam.d and return suspicious findings.
/// Delegates to scan_pam_dir with the default system directory.
pub fn scan_pam() -> Vec<PamFinding> {
    scan_pam_dir(Path::new("/etc/pam.d"))
}

/// Scan PAM configuration files under `root` (for testing, pass a temp dir).
pub(crate) fn scan_pam_dir(root: &Path) -> Vec<PamFinding> {
    let mut aggregated: HashMap<String, PamFinding> = HashMap::new();

    let dir = match std::fs::read_dir(root) {
        Ok(d) => d,
        Err(e) => {
            coverage::record(format!(
                "{} unreadable ({e}); SEC-055 PAM scan NOT verified",
                root.display()
            ));
            return Vec::new();
        }
    };

    for entry in dir.flatten() {
        let path = entry.path();
        let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if fname.ends_with('~') || fname.ends_with(".bak") || fname.starts_with('.') {
            continue;
        }
        if !path.is_file() {
            continue;
        }
        let Some(path_str) = path.to_str() else {
            continue;
        };

        let (content, truncated) = match safe_io::read_file_capped_regular(path_str, 64 * 1024) {
            Ok(t) => t,
            Err(_) => continue,
        };
        if truncated {
            coverage::record(format!("{} truncated", path.display()));
        }

        for line in content.lines() {
            let Some((type_, control, module_path, args)) = parse_pam_line(line) else {
                continue;
            };

            // ── pam_exec.so is handled FIRST, before any filtering (R23-60) ──
            let basename = module_path.rsplit('/').next().unwrap_or(module_path);
            if basename == "pam_exec.so" {
                if let Some(script) = extract_pam_exec_script(args) {
                    let writability = assess_writability(Path::new(script));
                    let volatile = crate::utils::is_volatile_exec_path(script);
                    if writability != ExecWritability::RootOnly || volatile {
                        let (uid, gid) = std::fs::metadata(script)
                            .map(|m| (m.uid(), m.gid()))
                            .unwrap_or((0, 0));

                        let finding =
                            aggregated
                                .entry(script.to_string())
                                .or_insert_with(|| PamFinding {
                                    services: Vec::new(),
                                    module: PamModule {
                                        module_path: script.to_string(),
                                        // fix(R23-71): removed unused type_/control/args fields
                                    },
                                    writability,
                                    volatile,
                                    package: None,
                                    uid,
                                    gid,
                                    parent_takeable: false,
                                    script_info: Some(Box::new(PamScriptInfo {
                                        script_path: script.to_string(),
                                        writability,
                                        volatile,
                                    })),
                                });
                        finding
                            .services
                            .push(format!("{fname} ({type_} {control})"));
                    }
                }
                continue;
            }

            // ── Regular module checks ──────────────────────────────────────
            let resolved_path = resolve_module(module_path);
            let Some(resolved) = resolved_path else {
                // fix(R23-72): unresolved short names (e.g. pam_kwallet5.so
                // missing on a server) are skipped entirely – they can't be
                // loaded, so they have no inventory value and only create noise
                // in drift comparison.
                continue;
            };

            let writability = assess_writability(Path::new(&resolved));
            let volatile = crate::utils::is_volatile_exec_path(&resolved);
            let parent_takeable = if writability == ExecWritability::Missing {
                Path::new(&resolved)
                    .parent()
                    .and_then(|p| std::fs::metadata(p).ok())
                    .map(|m| unsafe_mode(m.permissions().mode(), m.uid(), m.gid()))
                    .unwrap_or(false)
            } else {
                false
            };

            let in_trusted_dir = is_trusted_module_path(&resolved);
            if !in_trusted_dir
                || writability == ExecWritability::NonRootWritable
                || volatile
                || (writability == ExecWritability::Missing && parent_takeable)
            {
                let (uid, gid) = std::fs::metadata(&resolved)
                    .map(|m| (m.uid(), m.gid()))
                    .unwrap_or((0, 0));

                let key = resolved.clone();
                let finding = aggregated.entry(key.clone()).or_insert_with(|| PamFinding {
                    services: Vec::new(),
                    module: PamModule { module_path: key },
                    writability,
                    volatile,
                    package: None,
                    uid,
                    gid,
                    parent_takeable,
                    script_info: None,
                });
                finding
                    .services
                    .push(format!("{fname} ({type_} {control})"));
            }
        }
    }

    // fix(R23-69): deterministic truncation after sorting.
    let mut findings: Vec<PamFinding> = aggregated.into_values().collect();
    findings.sort_by(|a, b| a.module.module_path.cmp(&b.module.module_path));
    if findings.len() > MAX_PAM_FINDINGS {
        let dropped = findings.len() - MAX_PAM_FINDINGS;
        findings.truncate(MAX_PAM_FINDINGS);
        coverage::record(format!(
            "pam: finding cap ({MAX_PAM_FINDINGS}) reached; {dropped} module(s) NOT reported"
        ));
    }

    // Provenance resolution for executable modules (scripts are already
    // included via module_path, no need to chain script_info — R23-73).
    let candidates: HashSet<String> = findings
        .iter()
        .filter_map(|f| {
            if f.module.module_path.starts_with('/') {
                Some(crate::utils::canon_path(&f.module.module_path).into_owned())
            } else {
                None
            }
        })
        .collect();

    if !candidates.is_empty() {
        let prov = crate::scanners::provenance::resolve_batch(&candidates);
        for f in &mut findings {
            let key = crate::utils::canon_path(&f.module.module_path);
            f.package = prov.lookup(key.as_ref());
        }
    }

    // Secondary sort key by first service for stable output
    findings.sort_by(|a, b| {
        a.module
            .module_path
            .cmp(&b.module.module_path)
            .then_with(|| a.services.first().cmp(&b.services.first()))
    });
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn parse_valid_line() {
        let (t, c, m, a) = parse_pam_line("auth required pam_unix.so").unwrap();
        assert_eq!(t, "auth");
        assert_eq!(c, "required");
        assert_eq!(m, "pam_unix.so");
        assert_eq!(a, "");
    }

    #[test]
    fn parse_line_with_args() {
        let (_, _, m, a) = parse_pam_line("session optional /tmp/pam_evil.so debug").unwrap();
        assert_eq!(m, "/tmp/pam_evil.so");
        assert_eq!(a, "debug");
    }

    #[test]
    fn parse_comment_is_none() {
        assert!(parse_pam_line("# comment").is_none());
        assert!(parse_pam_line("").is_none());
        assert!(parse_pam_line("   ").is_none());
    }

    #[test]
    fn trusted_dirs_detection() {
        assert!(is_trusted_module_path("/lib/security/pam_unix.so"));
        assert!(is_trusted_module_path(
            "/usr/lib/x86_64-linux-gnu/security/pam_sss.so"
        ));
        assert!(!is_trusted_module_path("/tmp/pam_evil.so"));
        assert!(!is_trusted_module_path("/home/user/pam.so"));
    }

    #[test]
    fn pam_exec_script_extraction_seteuid() {
        assert_eq!(
            extract_pam_exec_script("seteuid /usr/local/bin/hook.sh"),
            Some("/usr/local/bin/hook.sh")
        );
        assert_eq!(
            extract_pam_exec_script("debug log=/var/log/x /tmp/backdoor.sh"),
            Some("/tmp/backdoor.sh")
        );
        assert_eq!(extract_pam_exec_script("expose_authtok debug"), None);
        assert_eq!(extract_pam_exec_script(""), None);
    }

    #[test]
    fn pam_exec_records_script_and_writability() {
        let pamd = tempfile::tempdir().unwrap();
        let payload = tempfile::tempdir().unwrap();
        let script = payload.path().join("hook.sh");
        std::fs::write(&script, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o777)).unwrap();
        std::fs::write(
            pamd.path().join("sshd"),
            format!(
                "session optional pam_exec.so seteuid {}\n",
                script.display()
            ),
        )
        .unwrap();

        let findings = scan_pam_dir(pamd.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].module.module_path, script.to_string_lossy());
        assert_eq!(findings[0].writability, ExecWritability::NonRootWritable);
        assert_eq!(findings[0].services, vec!["sshd (session optional)"]);
    }
}
