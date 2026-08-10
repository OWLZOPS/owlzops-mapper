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

/// Check if a path looks like it's inside a trusted directory.
/// Paths containing ".." are never trusted, even if they start with a
/// trusted prefix (R23-81).
fn is_trusted_module_path(path: &str) -> bool {
    if path.contains("/../") || path.ends_with("/..") {
        return false;
    }
    TRUSTED_PAM_DIRS.iter().any(|d| path.starts_with(d))
}

/// Generate the candidate paths libpam would try for a given module name
/// (pure function, no I/O).  Useful for testing (R23-83).
pub(crate) fn module_candidates(module: &str) -> Vec<String> {
    if module.starts_with('/') {
        return vec![module.to_string()];
    }
    TRUSTED_PAM_DIRS
        .iter()
        .map(|d| format!("{d}{module}"))
        .collect()
}

/// Resolve a bare module name to a real absolute path, mimicking libpam.
/// Both branches are canonicalised; if the file does not exist the
/// raw candidate is returned (and protected by the ".." guard above).
fn resolve_module(module: &str) -> Option<String> {
    let candidate = if module.starts_with('/') {
        module.to_string()
    } else {
        // Find the first candidate that exists on disk.
        module_candidates(module)
            .into_iter()
            .find(|p| Path::new(p).exists())?
    };

    // Canonicalise both absolute user-supplied paths and resolved ones
    // to eliminate ".." and symlink tricks (R23-76, R23-81).
    Some(
        std::fs::canonicalize(&candidate)
            .map(|c| c.to_string_lossy().into_owned())
            .unwrap_or(candidate),
    )
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

            // ── pam_exec script extraction ────────────────────────────────
            // If the module name ends with pam_exec.so, try to extract a
            // script path.  This check runs *in addition* to the regular
            // module verification below; a pam_exec.so binary placed outside
            // the trusted directories must still be caught (R23-80).
            let basename = module_path.rsplit('/').next().unwrap_or(module_path);
            if basename == "pam_exec.so"
                && let Some(script) = extract_pam_exec_script(args)
            {
                let writability = assess_writability(Path::new(script));
                let volatile = crate::utils::is_volatile_exec_path(script);

                // R23-74: slot takeability even before script creation.
                let parent_takeable = if writability == ExecWritability::Missing {
                    Path::new(script)
                        .parent()
                        .and_then(|p| std::fs::metadata(p).ok())
                        .map(|m| unsafe_mode(m.permissions().mode(), m.uid(), m.gid()))
                        .unwrap_or(false)
                } else {
                    false
                };

                // R23-75: always record the script – it's never in a trusted
                // directory; scoring decides the tier.
                let (uid, gid) = std::fs::metadata(script)
                    .map(|m| (m.uid(), m.gid()))
                    .unwrap_or((0, 0));

                let finding = aggregated
                    .entry(script.to_string())
                    .or_insert_with(|| PamFinding {
                        services: Vec::new(),
                        module: PamModule {
                            module_path: script.to_string(),
                        },
                        writability,
                        volatile,
                        package: None,
                        uid,
                        gid,
                        parent_takeable,
                        script_info: Some(Box::new(PamScriptInfo {
                            script_path: script.to_string(),
                            writability,
                            volatile,
                        })),
                    });
                finding
                    .services
                    .push(format!("{fname} ({type_} {control})"));
                // NO continue here – the .so itself must be checked below.
            }

            // ── Regular module checks ──────────────────────────────────────
            let resolved_path = resolve_module(module_path);
            let Some(resolved) = resolved_path else {
                // Unresolved short name (e.g. pam_kwallet5.so missing on a
                // server) — cannot be loaded, skip (R23-72).
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

    // R23-69: deterministic truncation after sorting.
    let mut findings: Vec<PamFinding> = aggregated.into_values().collect();
    findings.sort_by(|a, b| a.module.module_path.cmp(&b.module.module_path));
    if findings.len() > MAX_PAM_FINDINGS {
        let dropped = findings.len() - MAX_PAM_FINDINGS;
        findings.truncate(MAX_PAM_FINDINGS);
        coverage::record(format!(
            "pam: finding cap ({MAX_PAM_FINDINGS}) reached; {dropped} module(s) NOT reported"
        ));
    }

    // Provenance resolution for executable modules (scripts already included
    // via module_path, no need to chain script_info — R23-73).
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

    // Stable sort order (primary key unique, so secondary never triggers,
    // kept for clarity – R23-84.2).
    findings.sort_by(|a, b| a.module.module_path.cmp(&b.module.module_path));
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
    fn dotdot_never_trusted() {
        assert!(!is_trusted_module_path(
            "/lib/security/../../../tmp/evil.so"
        ));
        assert!(!is_trusted_module_path("/usr/lib/security/.."));
        assert!(is_trusted_module_path("/lib/security/pam_unix.so"));
    }

    #[test]
    fn relative_module_is_prefixed_like_libpam() {
        let c = module_candidates("../../../tmp/evil.so");
        assert_eq!(
            c[0], "/lib/security/../../../tmp/evil.so",
            "libpam prefixes the default directory, never uses relative path as-is"
        );
        assert!(
            !is_trusted_module_path(&c[0]),
            "and such a path must not be considered trusted"
        );
        assert_eq!(module_candidates("/tmp/x.so"), vec!["/tmp/x.so"]);
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

    #[test]
    fn pam_exec_staged_slot_is_takeable() {
        let pamd = tempfile::tempdir().unwrap();
        let payload = tempfile::tempdir().unwrap();
        // Use a directory with permissive mode to guarantee takeability,
        // avoiding dependency on real /tmp (R23-84.1).
        let staging = payload.path().join("staging");
        std::fs::create_dir(&staging).unwrap();
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o777)).unwrap();
        let script_path = staging.join("not_yet_there.sh");

        std::fs::write(
            pamd.path().join("sshd"),
            format!(
                "session optional pam_exec.so seteuid {}\n",
                script_path.display()
            ),
        )
        .unwrap();

        let findings = scan_pam_dir(pamd.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].writability, ExecWritability::Missing);
        assert!(
            findings[0].parent_takeable,
            "Slot must be reported as takeable"
        );
    }

    #[test]
    fn pam_exec_root_only_script_still_recorded() {
        let pamd = tempfile::tempdir().unwrap();
        let payload = tempfile::tempdir().unwrap();
        let script = payload.path().join("secure_hook.sh");
        std::fs::write(&script, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(
            pamd.path().join("sshd"),
            format!(
                "session optional pam_exec.so seteuid {}\n",
                script.display()
            ),
        )
        .unwrap();

        let findings = scan_pam_dir(pamd.path());
        assert_eq!(
            findings.len(),
            1,
            "root-only script must still create a finding"
        );
    }

    #[test]
    fn pam_exec_named_module_outside_trusted_dir_is_still_checked() {
        let pamd = tempfile::tempdir().unwrap();
        let payload = tempfile::tempdir().unwrap();
        let evil = payload.path().join("pam_exec.so");
        std::fs::write(&evil, b"\x7fELF").unwrap();
        std::fs::write(
            pamd.path().join("sshd"),
            format!("auth sufficient {}\n", evil.display()),
        )
        .unwrap();

        let findings = scan_pam_dir(pamd.path());
        assert_eq!(
            findings.len(),
            1,
            "pam_exec.so binary outside trusted dir must be reported"
        );
        assert_eq!(findings[0].module.module_path, evil.to_string_lossy());
    }

    #[test]
    fn dotdot_absolute_path_is_not_trusted() {
        let pamd = tempfile::tempdir().unwrap();
        let payload = tempfile::tempdir().unwrap();
        // Create a dummy evil.so inside a subdirectory that we'll escape from.
        let decoy_dir = payload.path().join("trusted");
        std::fs::create_dir(&decoy_dir).unwrap();
        let decoy = decoy_dir.join("evil.so");
        std::fs::write(&decoy, b"\x7fELF").unwrap();

        // Construct a PAM line that uses .. to point to decoy, but without
        // creating the intermediate "lib/security" directories – that's the
        // attacker's trick: the path looks trusted, but .. redirects elsewhere.
        std::fs::write(
            pamd.path().join("sshd"),
            format!(
                "auth sufficient {}/lib/security/../../../{}/evil.so\n",
                payload.path().display(),
                decoy_dir.strip_prefix(payload.path()).unwrap().display()
            ),
        )
        .unwrap();

        let findings = scan_pam_dir(pamd.path());
        assert!(
            !findings.is_empty(),
            "Should detect module outside trust via .."
        );
        // The found path may still contain ".." if canonicalization failed
        // (because intermediate dirs didn't exist), but it must NOT be trusted.
        let found_path = &findings[0].module.module_path;
        assert!(
            !is_trusted_module_path(found_path),
            "Path with .. must never be considered trusted, got: {}",
            found_path
        );
        // If canonicalization did succeed, the path will be the real decoy;
        // if not, it still contains ".." – both are fine for detection.
    }
}
