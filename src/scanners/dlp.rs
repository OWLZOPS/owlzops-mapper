use crate::models::SecretLeak;
use crate::{coverage, safe_io};
use std::fmt::Write;
use std::fs;

const SENSITIVE_KEYS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "DO_PAT",
    "DATABASE_URL",
    "DB_PASSWORD",
    "MYSQL_PWD",
    "PGPASSWORD",
    "STRIPE_SECRET_KEY",
    "SLACK_BOT_TOKEN",
    "NPM_TOKEN",
];

// R27-16: suffix-based sensitive key matching to catch OWLZOPS_SUDO_PASS,
// VAULT_TOKEN, etc., without false positives like SSH_ASKPASS (the char
// before PASS is 'K', not '_').
const SENSITIVE_SUFFIXES: &[&str] = &[
    "_PASS",
    "_PASSWD",
    "_PASSWORD",
    "_SECRET",
    "_TOKEN",
    "_API_KEY",
    "_SECRET_KEY",
    "_PRIVATE_KEY",
    "_ACCESS_KEY",
];

// System environment variables that look sensitive by suffix but are not secrets.
// XDG_ACTIVATION_TOKEN is a short-lived Wayland window-activation token,
// not a credential. DBUS_SESSION_BUS_ADDRESS / WAYLAND_DISPLAY / DISPLAY / XAUTHORITY
// are likewise not credentials. Excluding them here stops SEC-014 from flooding
// desktop reports with inherited session variables.
const NON_SECRET_SYSTEM_KEYS: &[&str] = &[
    "XDG_ACTIVATION_TOKEN",
    "DBUS_SESSION_BUS_ADDRESS",
    "WAYLAND_DISPLAY",
    "DISPLAY",
    "XAUTHORITY",
];

fn ends_with_icase(s: &str, suffix: &str) -> bool {
    s.len() >= suffix.len()
        && s.as_bytes()[s.len() - suffix.len()..].eq_ignore_ascii_case(suffix.as_bytes())
}

pub(crate) fn is_sensitive_key(key: &str) -> bool {
    if NON_SECRET_SYSTEM_KEYS
        .iter()
        .any(|&k| key.eq_ignore_ascii_case(k))
    {
        return false;
    }
    SENSITIVE_KEYS.iter().any(|&k| key.eq_ignore_ascii_case(k))
        || SENSITIVE_SUFFIXES.iter().any(|&s| ends_with_icase(key, s))
}

const SENSITIVE_FLAGS: &[&str] = &["--password=", "-p=", "--token=", "--secret="];

fn starts_with_icase(s: &str, prefix: &str) -> bool {
    s.len() >= prefix.len() && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

/// Is an EACCES on this /proc entry explainable by our own PR_SET_DUMPABLE(0)?
/// Only for entries the kernel registers 0400: dumpable reassigns the inode
/// owner to root but never changes the mode, so 0444 entries stay readable.
fn eacces_explained_by_dumpable(entry: &str) -> bool {
    matches!(entry, "environ" | "auxv" | "personality")
}

/// Handle EACCES on `/proc/<pid>/<entry>` for our own PID. Returns whether the
/// denial counts toward the aggregate. Single source of truth so a third procfs
/// entry cannot inherit the wrong explanation by copy-paste.
fn note_self_eacces(entry: &str) -> bool {
    if eacces_explained_by_dumpable(entry) {
        coverage::record(format!(
            "dlp: own /proc/self/{entry} unreadable — PR_SET_DUMPABLE=0 reassigned it \
             to root; the R27-16 self-check is inert on non-root scans"
        ));
        false
    } else {
        coverage::record(format!(
            "dlp: own /proc/self/{entry} is EACCES despite a world-readable mode — \
             not explainable by PR_SET_DUMPABLE; procfs may be masked or \
             LSM-restricted. INVESTIGATE."
        ));
        true
    }
}

/// Reason string for a leak attributed to our own process, keyed on the source.
/// Single source of truth so a second `source` cannot inherit the first one's
/// explanation by copy-paste (R27-46).
fn self_attribution(source: &str) -> String {
    match source {
        "environ" => "owlzops-mapper's own process — a secret still in our initial \
                      environment means the R27-13 scrub did not run"
            .to_string(),
        "cmdline" => "owlzops-mapper's own process — a secret on our own command line. \
                      The R27-13 scrub covers the environment only; argv is served from \
                      /proc/self/cmdline (mode 0444, no ptrace check) and is readable by \
                      any user on the host"
            .to_string(),
        other => format!(
            "owlzops-mapper's own process — secret found in {other}; no attribution \
             text is defined for this source"
        ),
    }
}

/// Age of `pid` in seconds, or `None` when it cannot be established.
///
/// `None` is load-bearing: SEC-014 treats unknown age as long-lived and keeps
/// the full weight. Every failure path here returns `None`, never 0.
fn process_age_secs(pid: u32, uptime_secs: u64, path_buf: &mut String) -> Option<u64> {
    path_buf.clear();
    let _ = write!(path_buf, "/proc/{}/stat", pid);
    let (stat, _truncated) = safe_io::read_procfs_capped(path_buf, 4096).ok()?;
    let clk_tck = crate::proc_time::clock_ticks_per_sec()?;
    crate::proc_time::age_from_parts(
        crate::proc_time::starttime_ticks(&stat)?,
        clk_tck,
        uptime_secs,
    )
}

pub fn scan_process_memory() -> Vec<SecretLeak> {
    let mut leaks = Vec::new();

    let Ok(entries) = fs::read_dir("/proc") else {
        return leaks;
    };

    let uptime_secs = crate::proc_time::uptime_secs();
    if uptime_secs.is_none() {
        coverage::record(
            "dlp: /proc/uptime unreadable — process ages unknown; every secret leak \
             keeps full SEC-014 weight (never downgraded on an unknown)"
                .to_string(),
        );
    }

    // Reusable buffer for constructing /proc/<pid>/... paths
    let mut path_buf = String::with_capacity(64);
    // R27-45: a SEPARATE buffer for the age lookup. Sharing `path_buf` left it
    // pointing at /proc/<pid>/stat while the enclosing section's coverage
    // messages still name /proc/<pid>/environ|cmdline.
    let mut age_buf = String::with_capacity(32);

    // Count how many *processes* had unreadable /proc/<pid>/environ or cmdline
    // due to EACCES (typically non‑root scan). One aggregate coverage line is
    // emitted at the end to avoid flooding the operator with per‑PID noise.
    let mut denied = 0usize;

    for entry in entries.flatten() {
        let Ok(file_name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = file_name.parse::<u32>() else {
            continue;
        };

        // R27-16: mark findings from the scanner's own process to avoid hiding them.
        let self_pid = (pid == std::process::id()).then_some(pid);

        // Per‑PID flag – raised once if either environ or cmdline is EACCES.
        let mut pid_denied = false;

        // Process name
        path_buf.clear();
        let _ = write!(path_buf, "/proc/{}/comm", pid);
        let process_name = safe_io::read_procfs_capped(&path_buf, 4096)
            .map(|(s, truncated)| {
                if truncated {
                    coverage::record(format!("{} truncated", path_buf));
                }
                s.trim().to_string()
            })
            .unwrap_or_else(|_| "unknown".to_string());

        if process_name.is_empty() || process_name.starts_with("kworker") {
            continue;
        }

        // Lazily resolved, then memoised: a clean host does no extra /proc
        // reads at all, and a leaking PID does exactly one regardless of how
        // many sensitive keys it carries.
        let mut age_memo: Option<Option<u64>> = None;

        // R27-46: one construction site. The three hand-written copies had already
        // drifted — both cmdline blocks carried the environ scrub's explanation.
        let mut push_leak = |source: &'static str, matched_key: String| {
            leaks.push(SecretLeak {
                pid,
                process: process_name.clone(),
                source: source.to_string(),
                matched_key,
                self_attributed: self_pid.map(|_| self_attribution(source)),
                age_secs: *age_memo.get_or_insert_with(|| {
                    uptime_secs.and_then(|u| process_age_secs(pid, u, &mut age_buf))
                }),
            });
        };

        // 1. Environment Variables
        path_buf.clear();
        let _ = write!(path_buf, "/proc/{}/environ", pid);
        match safe_io::read_procfs_bytes_capped(&path_buf, safe_io::CAP_PROC_ENVIRON) {
            Ok((env_data, truncated)) => {
                if truncated {
                    coverage::record(format!("{} truncated", path_buf));
                }
                for chunk in env_data.split(|&b| b == 0) {
                    let Ok(env_var) = std::str::from_utf8(chunk) else {
                        continue;
                    };
                    let Some((key, _value)) = env_var.split_once('=') else {
                        continue;
                    };

                    if is_sensitive_key(key) {
                        push_leak("environ", key.to_string());
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                pid_denied = self_pid.is_none() || note_self_eacces("environ");
            }
            Err(_) => {}
        }

        // 2. Command Line Arguments
        path_buf.clear();
        let _ = write!(path_buf, "/proc/{}/cmdline", pid);
        match safe_io::read_procfs_bytes_capped(&path_buf, safe_io::CAP_PROC_ENVIRON) {
            Ok((cmd_data, truncated)) => {
                if truncated {
                    coverage::record(format!("{} truncated", path_buf));
                }
                for chunk in cmd_data.split(|&b| b == 0) {
                    let Ok(arg) = std::str::from_utf8(chunk) else {
                        continue;
                    };

                    for &flag in SENSITIVE_FLAGS {
                        if starts_with_icase(arg, flag) {
                            push_leak("cmdline", flag.to_string());
                        }
                    }

                    // Cover `mysql -pSECRET` (without equals sign)
                    if (process_name == "mysql" || process_name == "mysqldump")
                        && let Some(pwd) = arg.strip_prefix("-p")
                        && !pwd.is_empty()
                    {
                        push_leak("cmdline", "mysql-password".to_string());
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                pid_denied = self_pid.is_none() || note_self_eacces("cmdline");
            }
            Err(_) => {}
        }

        if pid_denied {
            denied += 1;
        }
    }

    // Aggregate coverage: if any /proc/<pid>/environ or cmdline was denied,
    // warn the operator that secret hygiene is incomplete (mirrors proc_net).
    if denied > 0 {
        let hint = if !crate::is_running_as_root() {
            " — run as root for full coverage"
        } else {
            ""
        };
        coverage::record(format!(
            "dlp: {denied} process(es) with unreadable /proc/<pid>/environ|cmdline{hint}; \
             secret hygiene INCOMPLETE"
        ));
    }

    leaks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proc_time::{age_from_parts, starttime_ticks};

    #[test]
    fn sensitive_key_suffixes_match_without_overmatching() {
        for k in [
            "OWLZOPS_SUDO_PASS",
            "VAULT_TOKEN",
            "ANSIBLE_BECOME_PASS",
            "REDIS_PASSWORD",
            "PGPASSWORD",
            "aws_secret_access_key",
        ] {
            assert!(is_sensitive_key(k), "{k} must match");
        }
        for k in [
            "SSH_ASKPASS",
            "GIT_ASKPASS",
            "SUDO_ASKPASS",
            "TOKENIZERS_PARALLELISM",
            "PATH",
            "SSH_AUTH_SOCK",
        ] {
            assert!(!is_sensitive_key(k), "{k} is a false positive");
        }
    }

    #[test]
    fn non_secret_system_keys_are_excluded() {
        for k in [
            "XDG_ACTIVATION_TOKEN",
            "DBUS_SESSION_BUS_ADDRESS",
            "WAYLAND_DISPLAY",
            "DISPLAY",
            "XAUTHORITY",
        ] {
            assert!(!is_sensitive_key(k), "{k} must not be a secret");
        }
    }

    #[test]
    fn only_owner_readable_proc_entries_are_explained_by_dumpable() {
        assert!(eacces_explained_by_dumpable("environ"), "REG(.., S_IRUSR)");
        assert!(eacces_explained_by_dumpable("auxv"), "REG(.., S_IRUSR)");
        assert!(
            !eacces_explained_by_dumpable("cmdline"),
            "ONE(.., S_IRUGO) = 0444 and no ptrace check — dumpable cannot cause EACCES"
        );
        assert!(!eacces_explained_by_dumpable("status"), "ONE(.., S_IRUGO)");
        assert!(!eacces_explained_by_dumpable("maps"), "world-readable");
    }

    #[test]
    fn self_eacces_counts_only_when_unexplained() {
        assert!(
            !note_self_eacces("environ"),
            "0400 — explained, not a denial"
        );
        assert!(
            note_self_eacces("cmdline"),
            "0444 — unexplained, must be counted"
        );
    }

    #[test]
    fn self_attribution_matches_its_source() {
        let env = self_attribution("environ");
        let cmd = self_attribution("cmdline");
        assert!(env.contains("initial environment") && env.contains("R27-13"));
        assert!(
            !cmd.contains("scrub did not run"),
            "the environ scrub does not explain a secret on our own argv"
        );
        assert!(
            !cmd.contains("initial environment"),
            "cmdline explanation must not point at the environ scrub"
        );
        assert!(cmd.contains("command line"));
        // An unfamiliar source must name itself, not borrow someone else's reason.
        let other = self_attribution("maps");
        assert!(other.contains("maps") && !other.contains("R27-13"));
    }

    #[test]
    fn age_is_none_when_starttime_exceeds_uptime() {
        // lxcfs: container uptime vs host-boot starttime. Saturating to 0 here
        // would mark every leak on the host transient.
        assert_eq!(age_from_parts(100_000_000, 100, 60), None);
        assert_eq!(age_from_parts(6_000, 100, 120), Some(60));
        assert_eq!(age_from_parts(0, 100, 120), Some(120));
    }

    #[test]
    fn starttime_survives_hostile_comm() {
        const TAIL: &str = " S 1 1337 1337 0 -1 4194304 100 0 0 0 1 2 0 0 20 0 1 0 987654";
        assert_eq!(
            starttime_ticks(&format!("1337 (bash){TAIL}")),
            Some(987_654)
        );
        // ')' inside comm must not shift the fields.
        assert_eq!(
            starttime_ticks(&format!("1337 (evil)x){TAIL}")),
            Some(987_654)
        );
        // Spaces + digits: the shape used to land `flags` on the starttime index.
        assert_eq!(
            starttime_ticks(&format!("1337 (x) 4194304){TAIL}")),
            Some(987_654),
            "a crafted comm must not be able to forge starttime"
        );
    }

    #[test]
    fn starttime_is_none_on_malformed_stat() {
        assert_eq!(starttime_ticks("1337 (bash) S 1 2 3"), None, "truncated");
        assert_eq!(starttime_ticks("garbage"), None);
        assert_eq!(starttime_ticks(""), None);
        assert_eq!(
            starttime_ticks("1337 (bash) S x x x x x x x x x x x x x x x x x x x"),
            None
        );
    }
}
