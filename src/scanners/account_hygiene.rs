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
//! R37-02: the password field in `/etc/passwd` is parsed. `x` defers to
//! `/etc/shadow`; empty is SEC-071; `*`/`!` is locked; anything else is
//! SEC-070 with `in /etc/passwd` on the hash type — pam_unix/glibc use
//! the passwd field as the hash whenever it is not `x`, so the
//! world-readable inline-hash and `root::0:0:` backdoors are now visible.
//!
//! R37-03: SEC-073 matches an exact-path denylist, not an allowlist.
//! passwd(5) defines an empty shell field as `/bin/sh`, and unlisted
//! interpreters (`/usr/bin/python3`, NixOS `/run/current-system/sw/bin/bash`)
//! were invisible. SEC-077/078 run for every account, deduplicated by
//! home. SEC-078 also detects an authorized_keys owned by a non-root uid
//! other than the account owner.
//!
//! R37-07: EACCES is disclosed as coverage, not silently reported clean —
//! `stat()` needs `x` on every parent, so non-root scans under a 0700 home
//! (Fedora) or NFS root_squash hit this routinely. The `/etc/shadow` mask
//! covers setuid/setgid/sticky, u+x, g+w/x and any other bit. sudo's
//! `@includedir` skips names containing '.' or ending in '~', and an
//! unreadable `/etc/sudoers.d` is a coverage fact, not a silent clean.

use crate::models::{AccountHygieneInfo, CredentialFileIssue, PrivateKeyFinding, WeakHashFinding};
use crate::{coverage, safe_io};
use std::collections::HashSet;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

const CAP_PASSWD: usize = 4 * 1024 * 1024;
const CAP_SHADOW: usize = 4 * 1024 * 1024;

/// Shells that refuse an interactive session — EXACT paths. A basename
/// match would let `/tmp/nologin` (a real shell with a reassuring name)
/// clear the check; an unknown path counts as usable and is shown in the
/// evidence — a visible FP the operator can `--accept` beats a silent
/// miss (R37-03).
const NON_INTERACTIVE_SHELLS: &[&str] = &[
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/usr/bin/nologin",
    "/bin/nologin",
    "/bin/false",
    "/usr/bin/false",
    "/bin/true",
    "/usr/bin/true",
    "/bin/sync",
    "/usr/bin/sync",
    "/sbin/shutdown",
    "/usr/sbin/shutdown",
    "/sbin/halt",
    "/usr/sbin/halt",
    "/usr/bin/git-shell",
    "/run/current-system/sw/bin/nologin", // NixOS
];

/// UID threshold below which an account is "system". Login.defs defaults
/// to 1000 on Debian/Fedora, 500 on older RHEL. 1000 catches both.
const SYSTEM_UID_THRESHOLD: u32 = 1000;

/// `<1024` = system account. Anything at or above is a user.
fn is_system_uid(uid: u32) -> bool {
    uid < SYSTEM_UID_THRESHOLD
}

/// passwd(5): an EMPTY shell field means /bin/sh — interactive (R37-03).
fn is_interactive_shell(shell: &str) -> bool {
    !NON_INTERACTIVE_SHELLS.contains(&shell.trim())
}

/// `true` when this is a non-root system account that should not have an
/// interactive shell. UID 0 is excluded: CIS 5.4.2's own audit command
/// excludes `root`, because an interactive shell on root is required for
/// break-glass recovery. Without this exclusion every host pays the
/// SEC-073 weight for a correct configuration.
fn is_system_account_with_shell(uid: u32, shell: &str) -> bool {
    uid != 0 && is_system_uid(uid) && is_interactive_shell(shell)
}

/// CIS 6.1.x: `/etc/shadow`, `/etc/gshadow` at most 0640 (Debian
/// root:shadow). Forbidden: setuid/setgid/sticky, u+x, g+w/x, any o bit
/// (R37-07). The previous mask only checked "other" and missed a 0660
/// shadow, where a group member could replace hashes.
const SHADOW_FORBIDDEN: u32 = 0o7137;

/// R37-07: absent = silent; present but not inspectable = counted.
#[derive(Default)]
struct Unreadable {
    count: usize,
    first: Option<String>,
}

impl Unreadable {
    fn meta(&mut self, path: &str) -> Option<fs::Metadata> {
        match fs::metadata(path) {
            Ok(m) => Some(m),
            Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => None,
            Err(e) => {
                self.count += 1;
                if self.first.is_none() {
                    self.first = Some(format!("{path} ({})", e.kind()));
                }
                None
            }
        }
    }

    fn stat(&mut self, path: &str) -> Option<(u32, u32, u32)> {
        self.meta(path)
            .map(|m| (m.permissions().mode() & 0o7777, m.uid(), m.gid()))
    }
}

/// One `/etc/passwd` record. `pw`: `x` = hash in `/etc/shadow`; any other
/// value is what pam_unix/glibc use as the hash itself (R37-02).
struct PasswdEntry<'a> {
    user: &'a str,
    pw: &'a str,
    uid: u32,
    home: &'a str,
    shell: &'a str,
}

/// `name:pw:uid:gid:gecos:home:shell`. `splitn(7)`: a stray ':' stays in
/// the shell field, where it reads as an unknown (= usable) shell.
fn parse_passwd_line(line: &str) -> Option<PasswdEntry<'_>> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut f = line.splitn(7, ':');
    let user = f.next().filter(|u| !u.is_empty())?;
    let pw = f.next()?;
    let uid = f.next()?.parse().ok()?;
    let _gid = f.next()?;
    let _gecos = f.next()?;
    let home = f.next()?;
    let shell = f.next()?;
    Some(PasswdEntry {
        user,
        pw,
        uid,
        home,
        shell,
    })
}

enum PasswdPw<'a> {
    Shadowed,
    Empty,
    Locked,
    Inline(&'a str),
}

fn classify_passwd_pw(pw: &str) -> PasswdPw<'_> {
    match pw {
        "x" => PasswdPw::Shadowed,
        "" => PasswdPw::Empty,
        p if p.starts_with('!') || p.starts_with('*') => PasswdPw::Locked,
        p => PasswdPw::Inline(p),
    }
}

/// Classify a shadow hash field. `None` = locked / no password marker
/// (`!`, `*`, `!!`) — not a weak hash, not an empty password. Empty
/// string is handled separately by the caller as SEC-071.
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
/// through a routine `rsync`/`tar` of the home directory. EACCES is
/// counted in `unread`, not treated as "no file" (R37-07).
fn check_private_keys(user: &str, home: &str, unread: &mut Unreadable) -> Vec<PrivateKeyFinding> {
    const KEY_NAMES: &[&str] = &[
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "id_dsa",
        "id_ecdsa_sk",
        "id_ed25519_sk",
    ];
    KEY_NAMES
        .iter()
        .filter_map(|name| {
            let path = format!("{home}/.ssh/{name}");
            let (mode, _, _) = unread.stat(&path)?;
            // 0077 = any group or other permission bit. Private key
            // should be 0600 or 0400 — nothing else.
            mode_allows(mode, 0o077).then(|| PrivateKeyFinding {
                user: user.to_string(),
                mode: format!("{mode:04o}"),
                path,
            })
        })
        .collect()
}

/// SEC-078: who besides the account owner can rewrite the key list —
/// group/other write bits, or an owner-writable file owned by another
/// non-root uid (R37-03). Group-write lets a member of the user's group
/// inject a key; other-write is worse; ownership by another non-root uid
/// is write-by-proxy through their owner bit. Read access is not flagged
/// — 0644 is common and the public keys are, by definition, public.
fn check_authorized_keys(
    user: &str,
    uid: u32,
    home: &str,
    unread: &mut Unreadable,
) -> Option<String> {
    let path = format!("{home}/.ssh/authorized_keys");
    let (mode, owner, _) = unread.stat(&path)?;
    if mode_allows(mode, 0o022) {
        Some(format!("{user}: {path} mode {mode:04o}"))
    } else if owner != uid && owner != 0 && mode_allows(mode, 0o200) {
        Some(format!("{user}: {path} owned by uid {owner}"))
    } else {
        None
    }
}

/// `/root/.bash_history` and `/root/.ssh/` must not be readable by group
/// or other. Root history often contains commands with inline secrets,
/// SSH connection strings with usernames, and sometimes passwords.
fn check_root_dotfiles(unread: &mut Unreadable) -> Vec<CredentialFileIssue> {
    [
        ("/root/.bash_history", "bash history readable by non-root"),
        ("/root/.zsh_history", "zsh history readable by non-root"),
        ("/root/.ssh", "~/.ssh directory readable by non-root"),
    ]
    .into_iter()
    .filter_map(|(path, reason)| {
        let (mode, uid, gid) = unread.stat(path)?;
        mode_allows(mode, 0o077).then(|| issue(path, mode, uid, gid, reason))
    })
    .collect()
}

/// SEC-076. sudo's `@includedir` skips names ending in `~` or containing
/// `.` (sudoers(5)) — never policy, never a finding (R37-07). An
/// unreadable directory is a coverage fact, not a silent clean: RHEL
/// ships `/etc/sudoers.d` 0750, so a non-root scan cannot list it.
fn check_sudoers_d(unread: &mut Unreadable) -> Vec<CredentialFileIssue> {
    let entries = match fs::read_dir("/etc/sudoers.d") {
        Ok(it) => it,
        Err(e) if e.kind() == ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            coverage::record(format!(
                "/etc/sudoers.d unreadable ({}) — SEC-076 NOT evaluated",
                e.kind()
            ));
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            unread.count += 1;
            continue;
        };
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if name.ends_with('~') || name.contains('.') {
            continue;
        }
        let path = format!("/etc/sudoers.d/{name}");
        let Some(meta) = unread.meta(&path) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let mode = meta.permissions().mode() & 0o7777;
        if mode_allows(mode, 0o022 | 0o004 | 0o111) || meta.uid() != 0 {
            out.push(issue(
                &path,
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
    let mut unread = Unreadable::default(); // R37-07
    let mut weak_hashes: Vec<WeakHashFinding> = Vec::new();
    let mut empty_password: Vec<String> = Vec::new();
    // (user, uid, home) — R37-03: every account, one entry per distinct home.
    let mut per_user: Vec<(String, u32, String)> = Vec::new();

    // ── /etc/passwd: users, pw field, uid, home, shell ───────────────────
    match safe_io::read_file_capped_regular("/etc/passwd", CAP_PASSWD) {
        Ok((content, truncated)) => {
            if truncated {
                coverage::record("/etc/passwd exceeded cap — account inventory PARTIAL");
            }
            let mut seen_homes: HashSet<&str> = HashSet::new();
            for line in content.lines() {
                let Some(e) = parse_passwd_line(line) else {
                    continue;
                };
                if e.uid == 0 && e.user != "root" {
                    info.duplicate_uid_zero.push(e.user.to_string());
                }
                if is_system_account_with_shell(e.uid, e.shell) {
                    let shell = if e.shell.is_empty() {
                        "<empty> = /bin/sh"
                    } else {
                        e.shell
                    };
                    info.system_accounts_with_shell
                        .push(format!("{} ({shell})", e.user));
                }
                // R37-02: only `x` defers to /etc/shadow.
                match classify_passwd_pw(e.pw) {
                    PasswdPw::Shadowed | PasswdPw::Locked => {}
                    PasswdPw::Empty => empty_password.push(format!("{} (/etc/passwd)", e.user)),
                    PasswdPw::Inline(h) => {
                        // World-readable hash: offline-crackable whatever the
                        // algorithm. Suffix keeps scoring's prefix match intact.
                        let (t, d) = classify_hash(h).unwrap_or((
                            "inline hash",
                            "password hash stored in world-readable /etc/passwd",
                        ));
                        weak_hashes.push(WeakHashFinding {
                            username: e.user.to_string(),
                            hash_type: format!("{t} in /etc/passwd"),
                            description: d.to_string(),
                        });
                    }
                }
                // R37-03: every account, one entry per distinct home.
                // Deduplicated so N service accounts sharing `/nonexistent`
                // produce zero stats, not N.
                if !e.home.is_empty() && seen_homes.insert(e.home) {
                    per_user.push((e.user.to_string(), e.uid, e.home.to_string()));
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

    // ── /etc/shadow: hashes, empties ─────────────────────────────────────
    match safe_io::read_file_capped_regular("/etc/shadow", CAP_SHADOW) {
        Ok((content, truncated)) => {
            if truncated {
                coverage::record("/etc/shadow exceeded cap — hash audit PARTIAL");
            }
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
        }
        // No shadow: the passwd loop already audited the inline hashes
        // this layout implies (R37-02).
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            coverage::record(
                "/etc/shadow unreadable (permission denied) — SEC-070/071 \
                 (hash strength, empty passwords) NOT verified; run as root",
            );
        }
        Err(e) if e.kind() == ErrorKind::InvalidData => {
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
    info.weak_password_hashes = weak_hashes;
    info.empty_password_users = empty_password;

    // ── Credential file permissions (R37-07) ─────────────────────────────
    for (path, reason) in [
        (
            "/etc/shadow",
            "exceeds 0640 or not root-owned — password hashes readable or replaceable",
        ),
        (
            "/etc/gshadow",
            "exceeds 0640 or not root-owned — group passwords readable or replaceable",
        ),
    ] {
        if let Some((mode, uid, gid)) = unread.stat(path)
            && (mode_allows(mode, SHADOW_FORBIDDEN) || uid != 0)
        {
            info.file_permission_issues
                .push(issue(path, mode, uid, gid, reason));
        }
    }
    info.file_permission_issues
        .extend(check_sudoers_d(&mut unread));

    // ── SSH private keys, authorized_keys, root dotfiles (R37-03) ────────
    for (user, uid, home) in &per_user {
        info.ssh_private_key_readable
            .extend(check_private_keys(user, home, &mut unread));
        if let Some(entry) = check_authorized_keys(user, *uid, home, &mut unread) {
            info.authorized_keys_writable.push(entry);
        }
    }
    info.root_dotfiles_readable = check_root_dotfiles(&mut unread);

    // R37-07: not inspectable ≠ clean.
    if unread.count > 0 {
        coverage::record(format!(
            "account hygiene: {} credential path(s) could not be stat()ed (first: {}) — \
             SEC-074…079 are a LOWER BOUND",
            unread.count,
            unread.first.as_deref().unwrap_or("?")
        ));
    }
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

    // R37-02: the pw field is read, not discarded.
    #[test]
    fn parse_passwd_extracts_all_fields() {
        let e = parse_passwd_line("alice:x:1000:1000:Alice:/home/alice:/bin/bash").unwrap();
        assert_eq!(
            (e.user, e.pw, e.uid, e.home, e.shell),
            ("alice", "x", 1000, "/home/alice", "/bin/bash")
        );
        let e = parse_passwd_line("root::0:0:root:/root:").unwrap();
        assert_eq!((e.pw, e.shell), ("", ""));
    }

    #[test]
    fn parse_passwd_skips_comments_and_short_lines() {
        assert!(parse_passwd_line("#comment").is_none());
        assert!(parse_passwd_line("").is_none());
        assert!(parse_passwd_line("a:b:c").is_none());
    }

    // R37-02: pam_unix/glibc consult passwd's pw field unless it is `x`.
    #[test]
    fn passwd_password_field_is_what_pam_uses() {
        assert!(matches!(classify_passwd_pw("x"), PasswdPw::Shadowed));
        assert!(matches!(classify_passwd_pw(""), PasswdPw::Empty));
        assert!(matches!(classify_passwd_pw("!$6$a$b"), PasswdPw::Locked));
        assert!(matches!(
            classify_passwd_pw("$1$s$h"),
            PasswdPw::Inline("$1$s$h")
        ));
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

    // R37-03: a denylist on exact paths, not an allowlist. `sync`,
    // `halt`, `shutdown`, and every nologin path are recognised as
    // non-interactive; an unlisted shell is treated as usable.
    #[test]
    fn halt_sync_shutdown_nologin_are_not_interactive() {
        for s in [
            "/bin/sync",
            "/sbin/halt",
            "/sbin/shutdown",
            "/usr/sbin/nologin",
            "/usr/bin/nologin",
        ] {
            assert!(!is_interactive_shell(s), "{s}");
        }
    }

    #[test]
    fn unknown_or_empty_shells_are_interactive() {
        for s in [
            "",
            "/run/current-system/sw/bin/bash",
            "/usr/local/bin/bash",
            "/usr/bin/python3",
            "/tmp/nologin",
        ] {
            assert!(is_interactive_shell(s), "{s:?}");
        }
        assert!(
            is_system_account_with_shell(1, ""),
            "daemon with an empty shell logs in via /bin/sh"
        );
    }

    // R37-07: SHADOW_FORBIDDEN covers setuid/setgid/sticky, u+x, g+w/x,
    // and any other bit. A 0660 shadow (group-write) is now flagged;
    // 0440 and 0600 stay clean.
    #[test]
    fn shadow_forbidden_mask_catches_group_write_and_setuid() {
        assert!(mode_allows(0o660, SHADOW_FORBIDDEN)); // group-write
        assert!(mode_allows(0o644, SHADOW_FORBIDDEN)); // other-read
        assert!(mode_allows(0o4644, SHADOW_FORBIDDEN)); // setuid
        assert!(mode_allows(0o0700, SHADOW_FORBIDDEN)); // u+x
        assert!(!mode_allows(0o440, SHADOW_FORBIDDEN)); // clean
        assert!(!mode_allows(0o600, SHADOW_FORBIDDEN)); // clean
        assert!(!mode_allows(0o640, SHADOW_FORBIDDEN)); // clean (Debian root:shadow)
    }
}
