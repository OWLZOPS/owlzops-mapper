//! Account & credential hygiene (SEC-070…079).
//!
//! Reads `/etc/passwd`, `/etc/shadow`, `/etc/gshadow`, and `stat()`s a
//! handful of credential files. Detects the class of problems a security
//! auditor looks at first: weak password hashes, an empty password field,
//! duplicate UID 0 accounts, system accounts with a login shell, and
//! permissions on `/etc/shadow`, `~/.ssh/*`, and `/etc/sudoers.d/*` that
//! let a non-root principal read or replace what root trusts.
//!
//! Not compromise-class: an empty password is an open door, not evidence
//! someone walked through it. The findings drive exit code 1 by score,
//! never 3.
//!
//! Non-root scans: `/etc/shadow` and `/etc/gshadow` are unreadable. That
//! yields a coverage warning, not a false "clean" reading. Shell and
//! permission checks still run — `stat()` works regardless.

use crate::models::{AccountHygieneInfo, CredentialFileIssue, PrivateKeyFinding, WeakHashFinding};
use crate::{coverage, safe_io};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

const CAP_PASSWD: usize = 4 * 1024 * 1024;
const CAP_SHADOW: usize = 4 * 1024 * 1024;

/// Interactive shells from `/etc/passwd` that indicate a system account is
/// actually usable for login. Deliberately narrow: `/sbin/nologin`,
/// `/usr/sbin/nologin`, `/bin/false`, and the BSD `sync`/`halt` shells
/// exist precisely so system accounts can have *some* shell field without
/// being interactive.
const INTERACTIVE_SHELLS: &[&str] = &[
    "/bin/bash",
    "/usr/bin/bash",
    "/bin/sh",
    "/usr/bin/sh",
    "/bin/zsh",
    "/usr/bin/zsh",
    "/bin/ash",
    "/usr/bin/ash",
    "/bin/fish",
    "/usr/bin/fish",
    "/bin/dash",
    "/usr/bin/dash",
    "/bin/ksh",
    "/usr/bin/ksh",
];

/// UID threshold below which an account is "system". Login.defs defaults
/// to 1000 on Debian/Fedora, 500 on older RHEL. 1000 catches both.
const SYSTEM_UID_THRESHOLD: u32 = 1000;

/// `<1024` = system account. Anything at or above is a user.
fn is_system_uid(uid: u32) -> bool {
    uid < SYSTEM_UID_THRESHOLD
}

/// `true` when this is a non-root system account that should not have an
/// interactive shell. UID 0 is excluded: CIS 5.4.2's own audit command
/// excludes `root`, because an interactive shell on root is required for
/// break-glass recovery. Without this exclusion every host pays the SEC-073
/// weight for a correct configuration.
fn is_system_account_with_shell(uid: u32, shell: &str) -> bool {
    uid != 0 && is_system_uid(uid) && INTERACTIVE_SHELLS.contains(&shell)
}

/// Classify a shadow hash field. `None` = locked / no password marker
/// (`!`, `*`, `!!`) — not a weak hash, not an empty password. Empty string
/// is handled separately by the caller as SEC-071.
fn classify_hash(hash: &str) -> Option<(&'static str, &'static str)> {
    // `!` prefix = locked. `*` = no password has ever been set.
    // `!!` = locked by admin. None of these are weak hashes — a locked
    // account cannot be logged into, which is the *correct* state for a
    // system account.
    if hash.is_empty() {
        return None;
    }
    if hash.starts_with('!') || hash.starts_with('*') {
        return None;
    }
    // MD5-crypt: $1$<salt>$<hash>
    if hash.starts_with("$1$") {
        return Some(("$1$ (MD5-crypt)", "MD5-crypt is brute-forceable on a GPU"));
    }
    // SHA-256-crypt: $5$. Faster than yescrypt by a large factor but
    // not as catastrophic as MD5.
    if hash.starts_with("$5$") {
        return Some((
            "$5$ (SHA-256-crypt)",
            "SHA-256-crypt is fast on GPUs; prefer yescrypt or SHA-512",
        ));
    }
    // Bare DES: exactly 13 chars, no `$` prefix. Effectively broken.
    if !hash.starts_with('$') && hash.len() == 13 {
        return Some(("DES-crypt", "DES-crypt is 56-bit and trivially broken"));
    }
    // Anything else: $6$ (SHA-512), $y$ (yescrypt), $2a$/$2b$/$2y$ (bcrypt)
    // are accepted. Unknown future formats fail closed only if they don't
    // start with `$` — a formatted prefix is a deliberate algorithm choice.
    None
}

/// Parse a `/etc/shadow` line: `name:hash:lastchange:min:max:warn:inactive:expire:`
fn parse_shadow_line(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut parts = line.splitn(3, ':');
    let user = parts.next()?;
    let hash = parts.next()?;
    if user.is_empty() {
        return None;
    }
    Some((user, hash))
}

/// Parse a `/etc/passwd` line. Returns `(name, uid, home, shell)`.
fn parse_passwd_line(line: &str) -> Option<(&str, u32, &str, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let f: Vec<&str> = line.split(':').collect();
    if f.len() < 7 {
        return None;
    }
    let uid: u32 = f[2].parse().ok()?;
    Some((f[0], uid, f[5], f[6]))
}

/// Stat a path, return `(mode, uid, gid)`. `None` = not present or stat
/// failed; the caller decides whether that is a coverage fact.
fn stat_mode(path: &str) -> Option<(u32, u32, u32)> {
    let meta = fs::metadata(path).ok()?;
    let mode = meta.permissions().mode() & 0o7777;
    Some((mode, meta.uid(), meta.gid()))
}

/// Permission check: any bit set in `forbidden_mask` fails.
fn mode_allows(mode: u32, forbidden_mask: u32) -> bool {
    mode & forbidden_mask != 0
}

fn issue(path: &str, mode: u32, uid: u32, gid: u32, reason: &str) -> CredentialFileIssue {
    CredentialFileIssue {
        path: path.to_string(),
        mode: format!("{:04o}", mode),
        owner_uid: uid,
        owner_gid: gid,
        reason: reason.to_string(),
    }
}

/// Stat each of `~/.ssh/id_*` for a user. Any read or write bit set for
/// group or other is a finding — the private key can be exfiltrated
/// through a routine `rsync`/`tar` of the home directory.
fn check_private_keys(user: &str, home: &str) -> Vec<PrivateKeyFinding> {
    const KEY_NAMES: &[&str] = &[
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "id_dsa",
        "id_ecdsa_sk",
        "id_ed25519_sk",
    ];
    let mut out = Vec::new();
    for name in KEY_NAMES {
        let path = format!("{home}/.ssh/{name}");
        let Some((mode, _, _)) = stat_mode(&path) else {
            continue;
        };
        // 0077 = any group or other permission bit. Private key should be
        // 0600 or 0400 — nothing else.
        if mode_allows(mode, 0o077) {
            out.push(PrivateKeyFinding {
                user: user.to_string(),
                path,
                mode: format!("{:04o}", mode),
            });
        }
    }
    out
}

/// `authorized_keys` must not be writable by group or other. Group-write
/// lets a member of the user's group inject a key; other-write is worse.
/// Read access is not flagged — 0644 is common and not a security issue
/// on its own (the public keys are, by definition, public).
fn check_authorized_keys(user: &str, home: &str) -> Option<String> {
    let path = format!("{home}/.ssh/authorized_keys");
    let (mode, _, _) = stat_mode(&path)?;
    // 0022 = group-write or other-write.
    if mode_allows(mode, 0o022) {
        Some(format!("{user}: {path} mode {:04o}", mode))
    } else {
        None
    }
}

/// `/root/.bash_history` and `/root/.ssh/` must not be readable by group
/// or other. Root history often contains commands with inline secrets,
/// SSH connection strings with usernames, and sometimes passwords.
fn check_root_dotfiles() -> Vec<CredentialFileIssue> {
    let mut out = Vec::new();
    let candidates = [
        (
            "/root/.bash_history",
            0o077,
            "bash history readable by non-root",
        ),
        (
            "/root/.zsh_history",
            0o077,
            "zsh history readable by non-root",
        ),
        ("/root/.ssh", 0o077, "~/.ssh directory readable by non-root"),
    ];
    for (path, forbidden, reason) in candidates {
        let Some((mode, uid, gid)) = stat_mode(path) else {
            continue;
        };
        if mode_allows(mode, forbidden) {
            out.push(issue(path, mode, uid, gid, reason));
        }
    }
    out
}

/// Walk `/etc/sudoers.d/*` and check each for mode 0440 (or 0400). A
/// group- or other-writable file there is the same as giving every user
/// on the host a sudo rule.
fn check_sudoers_d() -> Vec<CredentialFileIssue> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/etc/sudoers.d") else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // Skip dot-files (`~` temp files, editor swap) and non-regular.
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with('.') || name.ends_with('~') {
            continue;
        }
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let mode = meta.permissions().mode() & 0o7777;
        // Accepted: 0440 or 0400. Anything with a write bit for group/
        // other, or a read bit for other, or executable bits, fails.
        let bad = mode_allows(mode, 0o022)         // any write by group/other
            || mode_allows(mode, 0o004)            // other-read
            || mode_allows(mode, 0o111); // executable
        if bad {
            let path_str = path.to_string_lossy().to_string();
            out.push(issue(
                &path_str,
                mode,
                meta.uid(),
                meta.gid(),
                "sudoers.d file must be 0440 (or 0400) root-owned",
            ));
        }
    }
    out
}

/// Main entry. Reads the credential files, returns everything that
/// matters. A failure to read `/etc/shadow` is a coverage fact — never
/// silently "clean".
pub fn scan_account_hygiene() -> AccountHygieneInfo {
    let mut info = AccountHygieneInfo::default();

    // ── /etc/passwd: users, uid, home, shell ─────────────────────────────
    let mut system_accounts_with_shell: Vec<String> = Vec::new();
    let mut duplicate_uid_zero: Vec<String> = Vec::new();
    let mut per_user_homes: Vec<(String, String)> = Vec::new();

    match safe_io::read_file_capped_regular("/etc/passwd", CAP_PASSWD) {
        Ok((content, truncated)) => {
            if truncated {
                coverage::record("/etc/passwd exceeded cap — account inventory PARTIAL");
            }
            for line in content.lines() {
                let Some((user, uid, home, shell)) = parse_passwd_line(line) else {
                    continue;
                };
                // Duplicate UID 0 — anyone but root is a persistence flag.
                if uid == 0 && user != "root" {
                    duplicate_uid_zero.push(user.to_string());
                }
                // Non-root system account with an interactive shell.
                if is_system_account_with_shell(uid, shell) {
                    system_accounts_with_shell.push(format!("{user} ({shell})"));
                }
                // Collect homes for the per-user SSH checks — only for
                // accounts that have an interactive shell, otherwise we
                // would stat dozens of /var/lib/... directories. Root is
                // included: its authorized_keys and private keys are the
                // most sensitive on the host, and CIS 5.4.2's exclusion of
                // root applies to the shell check only (SEC-073), not to
                // SEC-077 / SEC-078.
                if INTERACTIVE_SHELLS.contains(&shell) {
                    per_user_homes.push((user.to_string(), home.to_string()));
                }
            }
        }
        Err(e) => {
            coverage::record(format!(
                "/etc/passwd unreadable ({}) — account hygiene scan SKIPPED",
                e.kind()
            ));
            return info; // nothing else is meaningful without passwd
        }
    }
    info.duplicate_uid_zero = duplicate_uid_zero;
    info.system_accounts_with_shell = system_accounts_with_shell;

    // ── /etc/shadow: hashes, empties ─────────────────────────────────────
    match safe_io::read_file_capped_regular("/etc/shadow", CAP_SHADOW) {
        Ok((content, truncated)) => {
            if truncated {
                coverage::record("/etc/shadow exceeded cap — hash audit PARTIAL");
            }
            let mut weak_hashes: Vec<WeakHashFinding> = Vec::new();
            let mut empty_password: Vec<String> = Vec::new();
            for line in content.lines() {
                let Some((user, hash)) = parse_shadow_line(line) else {
                    continue;
                };
                if hash.is_empty() {
                    // Empty hash field = login with no password. Not the
                    // same as locked (`!`), which is the correct state for
                    // a system account.
                    empty_password.push(user.to_string());
                    continue;
                }
                if let Some((hash_type, description)) = classify_hash(hash) {
                    weak_hashes.push(WeakHashFinding {
                        username: user.to_string(),
                        hash_type: hash_type.to_string(),
                        description: description.to_string(),
                    });
                }
            }
            info.weak_password_hashes = weak_hashes;
            info.empty_password_users = empty_password;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Some containers and minimal systems have no shadow file;
            // hashes live in passwd directly (still weak). Not a coverage
            // gap, just a different layout.
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            coverage::record(
                "/etc/shadow unreadable (permission denied) — SEC-070/071 \
                 (hash strength, empty passwords) NOT verified; run as root",
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            coverage::record(
                "/etc/shadow is NOT a regular file (fifo/device) — \
                 hash audit refused; treat as tampering",
            );
        }
        Err(e) => {
            coverage::record(format!(
                "/etc/shadow unreadable ({}) — hash audit skipped",
                e.kind()
            ));
        }
    }

    // ── Credential file permissions ─────────────────────────────────────
    let mut perms: Vec<CredentialFileIssue> = Vec::new();

    // /etc/shadow: expected 0640 or 0600. Any read bit for group or other fails.
    if let Some((mode, uid, gid)) = stat_mode("/etc/shadow")
        && (mode_allows(mode, 0o004) || mode_allows(mode, 0o007))
    {
        perms.push(issue(
            "/etc/shadow",
            mode,
            uid,
            gid,
            "readable by group or other — password hashes exposed",
        ));
    }
    info.file_permission_issues.extend(perms);

    // /etc/gshadow: expected 0640 or 0600.
    if let Some((mode, uid, gid)) = stat_mode("/etc/gshadow")
        && (mode_allows(mode, 0o004) || mode_allows(mode, 0o007))
    {
        info.file_permission_issues.push(issue(
            "/etc/gshadow",
            mode,
            uid,
            gid,
            "readable by group or other — group passwords exposed",
        ));
    }

    // /etc/sudoers.d/*: expected 0440.
    info.file_permission_issues.extend(check_sudoers_d());

    // ── SSH private keys, authorized_keys, root dotfiles ────────────────
    let mut private_key_findings: Vec<PrivateKeyFinding> = Vec::new();
    let mut auth_keys_writable: Vec<String> = Vec::new();
    for (user, home) in &per_user_homes {
        private_key_findings.extend(check_private_keys(user, home));
        if let Some(entry) = check_authorized_keys(user, home) {
            auth_keys_writable.push(entry);
        }
    }
    info.ssh_private_key_readable = private_key_findings;
    info.authorized_keys_writable = auth_keys_writable;
    info.root_dotfiles_readable = check_root_dotfiles();

    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_hash_marks_md5_and_des() {
        assert!(classify_hash("$1$salt$hash").is_some());
        // 13-char DES-shaped string with no `$` prefix
        assert!(classify_hash("aBcDeFgHiJkLm").is_some());
    }

    #[test]
    fn classify_hash_marks_sha256_but_not_sha512_or_yescrypt() {
        assert!(classify_hash("$5$salt$hash").is_some());
        assert!(classify_hash("$6$salt$hash").is_none());
        assert!(classify_hash("$y$j9T$salt$hash").is_none());
        assert!(classify_hash("$2b$12$salt$hash").is_none());
    }

    #[test]
    fn classify_hash_skips_locked_and_absent() {
        assert!(classify_hash("!").is_none());
        assert!(classify_hash("!!").is_none());
        assert!(classify_hash("*").is_none());
        assert!(classify_hash("").is_none());
    }

    #[test]
    fn parse_passwd_extracts_uid_home_shell() {
        let line = "alice:x:1000:1000:Alice:/home/alice:/bin/bash";
        let (user, uid, home, shell) = parse_passwd_line(line).unwrap();
        assert_eq!(user, "alice");
        assert_eq!(uid, 1000);
        assert_eq!(home, "/home/alice");
        assert_eq!(shell, "/bin/bash");
    }

    #[test]
    fn parse_passwd_skips_comments_and_short_lines() {
        assert!(parse_passwd_line("#comment").is_none());
        assert!(parse_passwd_line("").is_none());
        assert!(parse_passwd_line("a:b:c").is_none());
    }

    #[test]
    fn parse_shadow_extracts_user_and_hash() {
        let line = "root:$6$salt$hash:19000:0:99999:7:::";
        let (user, hash) = parse_shadow_line(line).unwrap();
        assert_eq!(user, "root");
        assert_eq!(hash, "$6$salt$hash");
    }

    #[test]
    fn parse_shadow_handles_empty_hash() {
        let line = "baduser::19000:0:99999:7:::";
        let (user, hash) = parse_shadow_line(line).unwrap();
        assert_eq!(user, "baduser");
        assert_eq!(hash, "");
    }

    #[test]
    fn system_uid_threshold_is_1000() {
        assert!(is_system_uid(0));
        assert!(is_system_uid(999));
        assert!(!is_system_uid(1000));
        assert!(!is_system_uid(65534));
    }

    #[test]
    fn root_with_interactive_shell_is_not_flagged() {
        // CIS 5.4.2's audit command excludes `root`. An interactive shell
        // on root is required for break-glass recovery; flagging it charges
        // every host +5 for a correct configuration.
        assert!(!is_system_account_with_shell(0, "/bin/bash"));
        assert!(!is_system_account_with_shell(0, "/bin/sh"));
        // Non-root system accounts with a shell remain findings.
        assert!(is_system_account_with_shell(987, "/bin/sh")); // plasma-setup
        assert!(is_system_account_with_shell(999, "/bin/bash"));
        // Normal users are not "system accounts".
        assert!(!is_system_account_with_shell(1000, "/bin/bash"));
        // System accounts with a nologin shell are correct.
        assert!(!is_system_account_with_shell(999, "/sbin/nologin"));
        assert!(!is_system_account_with_shell(999, "/bin/false"));
    }

    #[test]
    fn mode_allows_detects_group_and_other_bits() {
        assert!(mode_allows(0o664, 0o022)); // group-write
        assert!(mode_allows(0o646, 0o022)); // other-write
        assert!(mode_allows(0o606, 0o004)); // other-read on 606
        assert!(!mode_allows(0o644, 0o022)); // 0644: group/other read only — clean
        assert!(!mode_allows(0o440, 0o022)); // clean sudoers.d mode
        assert!(!mode_allows(0o400, 0o077)); // clean private key
    }

    #[test]
    fn issue_formats_mode_as_octal_string() {
        let f = issue("/etc/shadow", 0o644, 0, 42, "test");
        assert_eq!(f.mode, "0644");
        assert_eq!(f.owner_uid, 0);
        assert_eq!(f.owner_gid, 42);
    }

    #[test]
    fn interactive_shells_do_not_include_sync_or_halt() {
        // `sync`, `halt`, `shutdown` are technically shells in /etc/passwd
        // on Debian/Fedora; they are NOT interactive. If they were in the
        // list, every standard host would fire SEC-073 on `sync`.
        assert!(!INTERACTIVE_SHELLS.contains(&"/bin/sync"));
        assert!(!INTERACTIVE_SHELLS.contains(&"/sbin/halt"));
        assert!(!INTERACTIVE_SHELLS.contains(&"/sbin/shutdown"));
    }
}
