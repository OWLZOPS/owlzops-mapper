// src/scanners/pam.rs
// SEC-055/056/057: PAM stack injection
//
// Parses /etc/pam.d/* files for modules loaded from outside the trusted
// system directories, and for pam_exec.so with a potentially hijacked script.
// PAM modules are dlopen'd by every authentication service; a backdoor here
// bypasses all other file-integrity checks.

use crate::models::{ExecWritability, PamFinding, PamModule, PamTargetKind};
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
/// Fields are separated by runs of whitespace (not single characters).
/// The control field may be a bracketed list: `[success=1 default=ignore]`.
/// The module path is always the third token; remaining text becomes args.
/// Returns `Some((type, control, module_path, args_str))` or `None` for
/// comments / empty lines / lines with fewer than three tokens.
/// This parser implements the same rules as libpam's `_pam_assemble_line`
/// (R24-01).  It is zero-copy and allocation-free.
pub(crate) fn parse_pam_line(line: &str) -> Option<(&str, &str, &str, &str)> {
    let s = line.trim();
    if s.is_empty() || s.starts_with('#') {
        return None;
    }

    // Extract one token:
    //   - `[ … ]` is kept as a single token (including brackets)
    //   - otherwise a whitespace-delimited word
    // Returns (token, rest_of_line).  Zero allocations.
    fn take_token(s: &str) -> Option<(&str, &str)> {
        let s = s.trim_start_matches(char::is_whitespace);
        if s.is_empty() {
            return None;
        }
        if let Some(after) = s.strip_prefix('[') {
            return Some(match after.find(']') {
                // end is relative to after, +2 accounts for '[' and ']'
                Some(end) => (&s[..end + 2], &s[end + 2..]),
                None => (s, ""), // unterminated '[' – swallow the rest (fail‑closed)
            });
        }
        let end = s.find(char::is_whitespace).unwrap_or(s.len());
        Some((&s[..end], &s[end..]))
    }

    let (type_, rest) = take_token(s)?;
    let (control, rest) = take_token(rest)?;
    let (module, rest) = take_token(rest)?;
    Some((
        type_,
        control,
        module,
        rest.trim_start_matches(char::is_whitespace),
    ))
}

/// Extract all absolute paths from pam_exec arguments.
/// The first token is the command; subsequent absolute tokens may be its
/// arguments (e.g., /bin/sh -c '/dev/shm/impl').  Shell quoting is stripped.
/// This replaces the earlier single-path extraction to catch wrappers (R23-85).
pub(crate) fn extract_pam_exec_targets(args: &str) -> Vec<&str> {
    args.split_whitespace()
        .map(|t| t.trim_matches(|c| c == '"' || c == '\''))
        .filter(|t| t.starts_with('/'))
        .collect()
}

/// Return true if `path` is an executable file, does not exist yet
/// (staged payload), or its executability cannot be determined (fail-open).
/// Non-executable regular files (logs, configs) are **not** targets (R23-88).
fn is_exec_target(path: &str) -> bool {
    match std::fs::metadata(path) {
        Ok(md) => md.permissions().mode() & 0o111 != 0,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => true, // EACCES etc. – check anyway
    }
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
            // If the module name ends with pam_exec.so, try to extract
            // script paths.  This check runs *in addition* to the regular
            // module verification below; a pam_exec.so binary placed outside
            // the trusted directories must still be caught (R23-80).
            let basename = module_path.rsplit('/').next().unwrap_or(module_path);
            if basename == "pam_exec.so" {
                for (idx, script) in extract_pam_exec_targets(args).into_iter().enumerate() {
                    // idx == 0 is the command itself – always inspect.
                    if idx > 0 && !is_exec_target(script) {
                        continue; // R23-88: skip non‑executable data arguments
                    }

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
                    // R24-09: `uid`/`gid` are `Option<u32>`, `None` means stat(2) failed.
                    let (uid, gid) = match std::fs::metadata(script) {
                        Ok(m) => (Some(m.uid()), Some(m.gid())),
                        Err(_) => (None, None),
                    };

                    let finding =
                        aggregated
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
                                target_kind: PamTargetKind::ExecScript,
                                declared_as: None,
                            });
                    finding
                        .services
                        .push(format!("{fname} ({type_} {control})"));
                }
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
                // R24-09: `uid`/`gid` are `Option<u32>`, `None` means stat(2) failed.
                let (uid, gid) = match std::fs::metadata(&resolved) {
                    Ok(m) => (Some(m.uid()), Some(m.gid())),
                    Err(_) => (None, None),
                };

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
                    target_kind: PamTargetKind::Module,
                    declared_as: if module_path != resolved {
                        Some(module_path.to_string())
                    } else {
                        None
                    },
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

    // Provenance resolution for executable modules/scripts.
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

    // R24-01: the parser now handles column‑aligned (RHEL‑style) configs,
    // bracketed control syntax, and double‑space evasion.
    #[test]
    fn column_aligned_line_is_parsed() {
        let (t, c, m, a) =
            parse_pam_line("auth        required                    pam_env.so").unwrap();
        assert_eq!((t, c, m, a), ("auth", "required", "pam_env.so", ""));
    }

    #[test]
    fn bracketed_control_is_one_token() {
        let (t, c, m, a) =
            parse_pam_line("auth [success=1 default=ignore] pam_unix.so nullok").unwrap();
        assert_eq!(t, "auth");
        assert_eq!(c, "[success=1 default=ignore]");
        assert_eq!(m, "pam_unix.so");
        assert_eq!(a, "nullok");
    }

    #[test]
    fn double_space_evasion_does_not_hide_payload() {
        let (_, _, m, _) = parse_pam_line("auth  sufficient  /dev/shm/evil.so").unwrap();
        assert_eq!(
            m, "/dev/shm/evil.so",
            "SEC-055 must not be evadable with one extra space"
        );
    }

    #[test]
    fn unterminated_bracket_does_not_shift_columns() {
        // fail-closed: no module resolved, but no column corruption either
        assert!(parse_pam_line("auth [success=1 pam_unix.so").is_none());
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
    fn shell_wrapper_payload_is_not_hidden() {
        let targets = extract_pam_exec_targets("seteuid /bin/sh -c '/dev/shm/impl'");
        assert_eq!(targets, vec!["/bin/sh", "/dev/shm/impl"]);
        let targets2 = extract_pam_exec_targets("debug log=/var/log/x /tmp/backdoor.sh");
        assert_eq!(targets2, vec!["/tmp/backdoor.sh"]);
        assert!(extract_pam_exec_targets("expose_authtok debug").is_empty());
    }

    #[test]
    fn data_arguments_are_not_targets() {
        let payload = tempfile::tempdir().unwrap();
        let log = payload.path().join("pam.log");
        std::fs::write(&log, b"").unwrap();
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert!(
            !is_exec_target(&log.to_string_lossy()),
            "log file is not an exec target"
        );

        // A staged (not yet existing) target is still considered a target.
        assert!(
            is_exec_target("/nonexistent/staged.sh"),
            "non-existent target is still checked"
        );

        // A command line where the second token is a non-executable regular file.
        let line = format!("/bin/sh -c '{}'", log.display());
        let targets = extract_pam_exec_targets(&line);
        assert_eq!(targets.len(), 2);
        let non_exec = targets[1];
        assert!(
            !is_exec_target(non_exec),
            "non-executable file must not be a target"
        );
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
}
