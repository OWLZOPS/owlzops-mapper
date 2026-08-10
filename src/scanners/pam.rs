// src/scanners/pam.rs
// SEC-055/056/057: PAM stack injection
//
// Parses /etc/pam.d/* files for modules loaded from outside the trusted
// system directories, and for pam_exec.so with a potentially hijacked script.
// PAM modules are dlopen'd by every authentication service; a backdoor here
// bypasses all other file-integrity checks.

use crate::models::PamScriptInfo; // ← единая структура из models
use crate::models::{ExecWritability, PamFinding, PamModule};
use crate::scanners::integrity::assess_writability;
use crate::{coverage, safe_io};
use std::collections::HashSet;
use std::path::Path;

/// Maximum number of PAM findings – consistent with other scanner budgets.
const MAX_PAM_FINDINGS: usize = 2048;

/// Trusted directories for PAM modules (canonical prefixes).
const TRUSTED_PAM_DIRS: &[&str] = &[
    "/lib/security/",
    "/lib64/security/",
    "/usr/lib/security/",
    "/usr/lib64/security/",
    "/usr/lib/x86_64-linux-gnu/security/",
];

/// Is `path` inside one of the trusted directories?
fn is_trusted_module_path(path: &str) -> bool {
    TRUSTED_PAM_DIRS.iter().any(|d| path.starts_with(d))
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
/// pam_exec.so [options] [log=...] <script> [script args...]
/// The script is the first positional argument after stripping known flags.
fn extract_pam_exec_script(args: &str) -> Option<&str> {
    let tokens = args.split_whitespace().peekable();
    for token in tokens {
        if token.contains('=')
            || token.eq_ignore_ascii_case("expose_authtok")
            || token.eq_ignore_ascii_case("debug")
            || token.eq_ignore_ascii_case("quiet")
            || token.eq_ignore_ascii_case("use_authtok")
            || token.eq_ignore_ascii_case("stdout")
        {
            continue;
        }
        if token.starts_with('/') {
            return Some(token);
        }
        break;
    }
    None
}

/// Scan all files in /etc/pam.d and return suspicious findings.
pub fn scan_pam() -> Vec<PamFinding> {
    let mut findings: Vec<PamFinding> = Vec::new();
    let mut over_cap = 0usize;

    let dir = match std::fs::read_dir("/etc/pam.d") {
        Ok(d) => d,
        Err(e) => {
            coverage::record(format!(
                "/etc/pam.d unreadable ({e}); SEC-055 PAM scan NOT verified"
            ));
            return findings;
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

            if !module_path.contains('/') {
                continue; // bare filename → trusted
            }
            if is_trusted_module_path(module_path) {
                continue;
            }

            let writability = assess_writability(Path::new(module_path));

            let mut finding = PamFinding {
                service: fname.to_string(),
                module: PamModule {
                    type_: type_.to_string(),
                    control: control.to_string(),
                    module_path: module_path.to_string(),
                    args: args.to_string(),
                },
                writability,
                volatile: crate::utils::is_volatile_exec_path(module_path),
                package: None,
                uid: 0,
                gid: 0,
                script_info: None,
            };

            if module_path == "pam_exec.so"
                && let Some(script_path) = extract_pam_exec_script(args)
            {
                let script_writable = assess_writability(Path::new(script_path));
                let script_volatile = crate::utils::is_volatile_exec_path(script_path);
                finding.script_info = Some(Box::new(PamScriptInfo {
                    script_path: script_path.to_string(),
                    writability: script_writable,
                    volatile: script_volatile,
                }));
                if script_writable == ExecWritability::NonRootWritable || script_volatile {
                    finding.writability = script_writable;
                    finding.volatile = script_volatile;
                }
            }

            if findings.len() >= MAX_PAM_FINDINGS {
                over_cap += 1;
                continue;
            }
            findings.push(finding);
        }
    }

    if over_cap > 0 {
        coverage::record(format!(
            "pam: finding cap ({MAX_PAM_FINDINGS}) reached; {over_cap} entr(ies) NOT inspected"
        ));
    }

    let candidates: HashSet<String> = findings
        .iter()
        .filter_map(|f| {
            if f.module.module_path.starts_with('/') {
                Some(crate::utils::canon_path(&f.module.module_path).into_owned())
            } else {
                None
            }
        })
        .chain(findings.iter().filter_map(|f| {
            f.script_info
                .as_ref()
                .map(|s| crate::utils::canon_path(&s.script_path).into_owned())
        }))
        .collect();

    if !candidates.is_empty() {
        let prov = crate::scanners::provenance::resolve_batch(&candidates);
        for f in &mut findings {
            let key = crate::utils::canon_path(&f.module.module_path);
            f.package = prov.lookup(key.as_ref());
        }
    }

    findings.sort_by(|a, b| {
        a.service
            .cmp(&b.service)
            .then(a.module.module_path.cmp(&b.module.module_path))
    });
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn pam_exec_script_extraction() {
        assert_eq!(
            extract_pam_exec_script("expose_authtok /bin/myscript.sh arg1"),
            Some("/bin/myscript.sh")
        );
        assert_eq!(
            extract_pam_exec_script("debug /tmp/backdoor.sh"),
            Some("/tmp/backdoor.sh")
        );
        assert_eq!(extract_pam_exec_script("expose_authtok debug"), None);
        assert_eq!(extract_pam_exec_script(""), None);
    }
}
