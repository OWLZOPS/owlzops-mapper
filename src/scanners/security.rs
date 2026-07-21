use crate::models::{SecurityInfo, UserInfo};
use crate::{coverage, safe_io};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

/// Marker embedded in a NOPASSWD entry whose granted path is replaceable by an
/// unprivileged user. Shared with `scoring.rs` so the policy has exactly one
/// source of truth and cannot drift.
pub const SUDO_PRIVESC_MARKER: &str = "[PRIVESC:";

// ── Unified sudoers parser (R16 hardening) ────────────────────────────────
use crate::scanners::sudoers;

// ── Helpers ──────────────────────────────────────────────────────────────

/// Extract a directive value from `sshd -T` output (format: "directive value").
fn sshd_effective_config() -> Option<String> {
    crate::utils::run_with_timeout("sshd", &["-T"], 5)
}

fn parse_sshd_directive(config: &str, directive: &str) -> Option<String> {
    config.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let key = parts.next()?;
        if key.eq_ignore_ascii_case(directive) {
            Some(parts.collect::<Vec<_>>().join(" "))
        } else {
            None
        }
    })
}

/// Fallback used when `sshd -T` is unavailable.
fn fallback_parse_main_config(pass_auth: &mut bool, root_login: &mut bool) {
    let mut config_lines = Vec::new();

    // Read the main config file
    if let Ok((contents, truncated)) =
        safe_io::read_file_capped("/etc/ssh/sshd_config", 4 * 1024 * 1024)
    {
        if truncated {
            coverage::record("/etc/ssh/sshd_config truncated".to_string());
        }
        for line in contents.lines() {
            let clean = line.trim();
            if clean.is_empty() || clean.starts_with('#') {
                continue;
            }
            if clean.starts_with("Include") {
                let path_part = clean.strip_prefix("Include").unwrap_or("").trim();
                if path_part.is_empty() {
                    continue;
                }
                // Expand glob pattern if present
                if path_part.contains('*') {
                    if let Some(parent) = std::path::Path::new(path_part).parent()
                        && let Some(_pattern) = std::path::Path::new(path_part).file_name()
                        && let Ok(entries) = std::fs::read_dir(parent)
                    {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if let Some(name) = path.file_name() {
                                let name = name.to_string_lossy();
                                if name.ends_with(".conf")
                                    && !name.starts_with('.')
                                    && let Ok((inc_contents, inc_trunc)) = safe_io::read_file_capped(
                                        path.to_str().unwrap_or(""),
                                        4 * 1024 * 1024,
                                    )
                                {
                                    if inc_trunc {
                                        coverage::record(format!(
                                            "sshd config include {} truncated",
                                            path.display()
                                        ));
                                    }
                                    for l in inc_contents.lines() {
                                        let l = l.trim();
                                        if !l.is_empty() && !l.starts_with('#') {
                                            config_lines.push(l.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else if let Ok((inc_contents, inc_trunc)) =
                    safe_io::read_file_capped(path_part, 4 * 1024 * 1024)
                {
                    if inc_trunc {
                        coverage::record(format!("sshd config include {} truncated", path_part));
                    }
                    for l in inc_contents.lines() {
                        let l = l.trim();
                        if !l.is_empty() && !l.starts_with('#') {
                            config_lines.push(l.to_string());
                        }
                    }
                }
            } else {
                config_lines.push(clean.to_string());
            }
        }
    }

    // Parse collected config lines using first-match semantics,
    // stop at Match blocks, and perform case-insensitive matching.
    let mut pa_seen = false;
    let mut rl_seen = false;

    for line in &config_lines {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else { continue };
        let Some(val) = parts.next() else { continue };

        // Directives inside Match blocks are conditional; ignore them.
        if key.eq_ignore_ascii_case("match") {
            break;
        }

        if !pa_seen && key.eq_ignore_ascii_case("passwordauthentication") {
            *pass_auth = val.eq_ignore_ascii_case("yes");
            pa_seen = true;
        } else if !rl_seen && key.eq_ignore_ascii_case("permitrootlogin") {
            *root_login = !val.eq_ignore_ascii_case("no");
            rl_seen = true;
        }

        if pa_seen && rl_seen {
            break;
        }
    }
}

/// Determine if an IP address is local (loopback, private, unspecified).
/// Uses the standard library's `Ipv4Addr::is_private()` which correctly
/// covers all three RFC1918 ranges (10/8, 172.16/12, 192.168/16).
fn is_local_ip(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_loopback() || v4.is_private() || v4.is_unspecified(),
        Ok(IpAddr::V6(v6)) => {
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00 == 0xfc00)
        }
        Err(_) => true,
    }
}

// ── Sudo audit ───────────────────────────────────────────────────────────

fn gather_sudo_nopasswd() -> Vec<String> {
    let mut entries = Vec::new();

    sudoers::each_sudoers_entry(|file, entry| {
        if !sudoers::entry_has_nopasswd(entry) {
            return;
        }
        // Check for self-target (tamper-proof path of the scanner itself)
        match self_sudo_target(entry) {
            Some(t) if sudo_target_is_tamper_proof(t) => {
                coverage::record(format!(
                    "{file}: NOPASSWD entry for the scanner's own install path \
                     ({t}) excluded from the audit (every path component is \
                     root-owned and not group/world-writable)"
                ));
            }
            Some(t) => entries.push(format!(
                "{file}: {entry}  {SUDO_PRIVESC_MARKER} {t} is replaceable by an \
                 unprivileged user (world-writable path or parent); this rule \
                 grants an unrestricted root shell]"
            )),
            None => entries.push(format!("{}: {}", file, entry)),
        }
    });

    entries
}

/// Returns the scanner path a NOPASSWD line grants, iff the line grants *only*
/// that path. Pure string logic — the writability verdict is the caller's.
///
/// A hardcoded path allowlist is deliberately gone: `/tmp/owlzops-mapper` is in
/// a mode-1777 directory, and our own unlink-on-exec frees that name after every
/// scan. Anyone may then create it and `sudo` will exec it as root without
/// checking owner or hash. Such a rule is equivalent to `NOPASSWD: ALL` and is
/// never "self".
pub fn self_sudo_target(line: &str) -> Option<&str> {
    const SELF_BASENAME: &str = "owlzops-mapper";
    if !line.contains(SELF_BASENAME) {
        return None;
    }
    let mut cmds = line.rsplit(':').next()?.split(',').map(str::trim);
    let first = cmds.next()?;
    // "NOPASSWD: /path/owlzops-mapper, /usr/bin/other" grants more than us.
    if cmds.next().is_some() {
        return None;
    }
    let p = std::path::Path::new(first);
    (p.is_absolute()
        && p.file_name().is_some_and(|f| f == SELF_BASENAME)
        && !first.contains(['*', '?', ' ']))
    .then_some(first)
}

/// Excludable only when no unprivileged user can replace the binary: every path
/// component must be root-owned and not group/world-writable. Fails closed —
/// ENOENT means the name is free, which is exactly the dangerous case.
fn sudo_target_is_tamper_proof(path: &str) -> bool {
    let p = std::path::Path::new(path);
    if !p.is_absolute() {
        return false;
    }
    let mut cur = std::path::PathBuf::new();
    for c in p.components() {
        cur.push(c);
        let Ok(meta) = fs::metadata(&cur) else {
            return false;
        };
        if meta.uid() != 0 || meta.permissions().mode() & 0o022 != 0 {
            return false;
        }
    }
    true
}

fn get_sudoers_mode() -> Option<u32> {
    let path = "/etc/sudoers";
    if let Ok(meta) = fs::metadata(path) {
        let mode = meta.permissions().mode();
        Some(mode & 0o777)
    } else {
        None
    }
}

// ── Sysctl audit ─────────────────────────────────────────────────────────

fn gather_sysctl_issues() -> Vec<String> {
    let mut issues = Vec::new();

    // Check suid_dumpable with consideration of core_pattern
    if let Ok((v, truncated)) = safe_io::read_file_capped("/proc/sys/fs/suid_dumpable", 4096) {
        if truncated {
            coverage::record("/proc/sys/fs/suid_dumpable truncated".to_string());
        }
        let v = v.trim().to_string();
        let piped = safe_io::read_file_capped("/proc/sys/kernel/core_pattern", 4096)
            .map(|(s, _)| s.trim_start().starts_with('|'))
            .unwrap_or(false);
        let ok = v == "0" || (v == "2" && piped);
        if !ok {
            issues.push(format!(
                "fs.suid_dumpable={} (expected 0, or 2 with piped core_pattern)",
                v
            ));
        }
    }

    // Net.ipv4.ip_forward – context-aware handling done in runner.rs
    if let Ok((v, truncated)) = safe_io::read_file_capped("/proc/sys/net/ipv4/ip_forward", 4096) {
        if truncated {
            coverage::record("/proc/sys/net/ipv4/ip_forward truncated".to_string());
        }
        let v = v.trim().to_string();
        if v == "1" {
            issues.push(format!("net.ipv4.ip_forward={} (expected 0)", v));
        }
    }

    // Other checks remain unchanged
    let other_checks: &[(&str, &str, &str)] = &[
        (
            "/proc/sys/kernel/randomize_va_space",
            "2",
            "kernel.randomize_va_space",
        ),
        (
            "/proc/sys/net/ipv4/tcp_syncookies",
            "1",
            "net.ipv4.tcp_syncookies",
        ),
        (
            "/proc/sys/kernel/dmesg_restrict",
            "1",
            "kernel.dmesg_restrict",
        ),
        (
            "/proc/sys/net/ipv4/conf/all/accept_redirects",
            "0",
            "net.ipv4.conf.all.accept_redirects",
        ),
    ];

    for &(path, expected, name) in other_checks {
        if let Ok((value, truncated)) = safe_io::read_file_capped(path, 4096) {
            if truncated {
                coverage::record(format!("{} truncated", path));
            }
            let value = value.trim();
            if value != expected {
                issues.push(format!("{}={} (expected {})", name, value, expected));
            }
        }
    }
    issues
}

// ── Main gather function ─────────────────────────────────────────────────

pub fn gather_security_info(deep: bool, verdict_cache: Option<PathBuf>) -> SecurityInfo {
    // --- SSH config parsing ------------------------------------------------
    let (
        ssh_password_auth_enabled,
        ssh_root_login_enabled,
        ssh_permit_root_detail,
        ssh_config_source,
    ) = match sshd_effective_config() {
        Some(config) => {
            let pwd = parse_sshd_directive(&config, "passwordauthentication")
                .map(|v| v.eq_ignore_ascii_case("yes"))
                .unwrap_or(true);
            let root = parse_sshd_directive(&config, "permitrootlogin")
                .map(|v| !v.eq_ignore_ascii_case("no"))
                .unwrap_or(true);
            let root_detail = parse_sshd_directive(&config, "permitrootlogin");
            (pwd, root, root_detail, "sshd -T (effective)".to_string())
        }
        None => {
            let mut pwd = true;
            let mut root_login = true;
            fallback_parse_main_config(&mut pwd, &mut root_login);
            // Fallback does not provide raw value; derive from boolean.
            let root_detail = if root_login {
                Some("yes".to_string())
            } else {
                Some("no".to_string())
            };
            (
                pwd,
                root_login,
                root_detail,
                "fallback (/etc/ssh/sshd_config)".to_string(),
            )
        }
    };

    // --- Shell users – collect usernames and authorized_keys counts --------
    const VALID_SHELLS: &[&str] = &[
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
    let valid_shells: std::collections::HashSet<&str> = VALID_SHELLS.iter().copied().collect();

    let mut shell_usernames: Vec<String> = Vec::new();
    let mut auth_keys_map: HashMap<String, usize> = HashMap::new();

    if let Ok((contents, truncated)) = safe_io::read_file_capped("/etc/passwd", 4 * 1024 * 1024) {
        if truncated {
            coverage::record("/etc/passwd truncated".to_string());
        }
        for line in contents.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() == 7 && valid_shells.contains(parts[6]) {
                let username = parts[0].to_string();

                // Count authorized keys
                let home = parts[5];
                let auth_keys_path = format!("{}/.ssh/authorized_keys", home);
                let count = safe_io::read_file_capped(&auth_keys_path, 4 * 1024 * 1024)
                    .map(|(s, _)| {
                        s.lines()
                            .filter(|k| !k.trim().is_empty() && !k.starts_with('#'))
                            .count()
                    })
                    .unwrap_or(0);
                auth_keys_map.insert(username.clone(), count);
                shell_usernames.push(username);
            }
        }
    }

    // --- Optimized login collection: single `last -i` call ----------------
    let all_logins: HashMap<String, (String, Option<String>)> = {
        let mut map = HashMap::new();
        if let Some(output) = crate::utils::run_with_timeout("last", &["-i"], 10) {
            for line in output.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 3 {
                    continue;
                }
                let user = parts[0].to_string();
                if !shell_usernames.contains(&user) {
                    continue;
                }
                let detail = line[user.len()..].trim().to_string();
                let ip = parts.get(2).map(|s| s.to_string()).unwrap_or_default();
                let is_remote = !is_local_ip(&ip);
                let entry = map
                    .entry(user.clone())
                    .or_insert_with(|| (detail.clone(), None));
                if entry.1.is_none() && is_remote {
                    entry.1 = Some(detail);
                }
            }
        }
        map
    };

    // Build UserInfo list
    let shell_users: Vec<UserInfo> = shell_usernames
        .into_iter()
        .map(|username| {
            let authorized_keys_count = auth_keys_map.remove(&username).unwrap_or(0);
            let (last_login, last_ssh_login) = all_logins
                .get(&username)
                .map(|(ll, sl)| {
                    (
                        ll.clone(),
                        sl.clone()
                            .unwrap_or_else(|| "No remote SSH login found".to_string()),
                    )
                })
                .unwrap_or_else(|| {
                    (
                        "No login records found".to_string(),
                        "No remote SSH login found".to_string(),
                    )
                });
            UserInfo {
                username,
                last_login,
                last_ssh_login,
                authorized_keys_count,
            }
        })
        .collect();

    // --- Fail2Ban and Auditd (with timeout wrapper) ------------------------
    let fail2ban_active =
        crate::utils::run_with_timeout("systemctl", &["is-active", "--quiet", "fail2ban"], 5)
            .is_some();

    let auditd_active =
        crate::utils::run_with_timeout("systemctl", &["is-active", "--quiet", "auditd"], 5)
            .is_some();

    // --- Sudo and Sysctl audits --------------------------------------------
    let sudo_nopasswd_entries = gather_sudo_nopasswd();
    let sudoers_mode = get_sudoers_mode();
    let sysctl_issues = gather_sysctl_issues();

    let access_alignment = crate::scanners::access::gather_access_alignment(
        &crate::scanners::access::KeyPolicy::default(),
    );

    let secret_hygiene = crate::scanners::dlp::scan_process_memory();

    // --- Capability and malware sweep (single /proc walk) ------------------
    let (capability_audit, mut suspicious_processes) =
        crate::scanners::capabilities::audit_host_processes(std::path::Path::new("/proc"));

    // Attribute (never drop) our own record: unlink-on-exec makes the scanner a
    // textbook SEC-017/019 hit. PID anchor — a renamed miner cannot inherit it.
    // Injection-class scanners deliberately do not consult this marker.
    crate::self_identity::identity().attribute(&mut suspicious_processes);

    // --- Bind-mount / overlay masking (SEC-021) ---------------------------
    let mount_masking = crate::scanners::mounts::scan_mount_masking();

    // --- Reverse-shell / C2 correlation (SEC-022) -------------------------
    let reverse_shells = crate::scanners::reverse_shell::scan_reverse_shells();

    // --- File capabilities inventory (R16) --------------------------------
    let file_capabilities = crate::scanners::file_capabilities::gather_file_capabilities();

    // --- Userspace rootkit / library injection (SEC-023) ------------------
    let scan_cfg = crate::scanners::library_injection::ScanConfig {
        deep,
        target_pid: None,
        verdict_cache_path: verdict_cache
            .unwrap_or_else(|| PathBuf::from("/var/lib/owlzops/verdict-cache.json")),
    };
    let library_injections = crate::scanners::library_injection::scan_library_injections(&scan_cfg);

    // --- True Ghost PID / LKM rootkit hiding (SEC-024) --------------------
    // Only run the expensive ghost-pid scan when explicitly requested via --deep.
    let ghost_pids = if deep {
        crate::scanners::ghost_pid::scan_ghost_pids(deep)
    } else {
        Vec::new()
    };

    SecurityInfo {
        ssh_password_auth_enabled,
        ssh_root_login_enabled,
        ssh_permit_root_login_detail: ssh_permit_root_detail,
        shell_users,
        fail2ban_active,
        auditd_active,
        ssh_config_source,
        sudo_nopasswd_entries,
        sudoers_mode,
        sysctl_issues,
        access_alignment,
        secret_hygiene,
        capability_audit,
        suspicious_processes,
        mount_masking,      // SEC-021
        reverse_shells,     // SEC-022
        library_injections, // SEC-023
        ghost_pids,         // SEC-024 true ghost PID / LKM rootkit
        file_capabilities,  // R16 file capability inventory
        ebpf_inventory: crate::scanners::ebpf::gather_ebpf_inventory(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_local_ip ────────────────────────────────────────

    #[test]
    fn local_ip_v4_loopback() {
        assert!(is_local_ip("127.0.0.1"));
        assert!(is_local_ip("127.0.1.1"));
    }

    #[test]
    fn local_ip_v4_private() {
        assert!(is_local_ip("10.0.0.1"));
        assert!(is_local_ip("172.16.0.1"));
        assert!(is_local_ip("192.168.1.1"));
    }

    #[test]
    fn local_ip_v4_public() {
        assert!(!is_local_ip("8.8.8.8"));
        assert!(!is_local_ip("1.1.1.1"));
    }

    #[test]
    fn local_ip_v6_loopback() {
        assert!(is_local_ip("::1"));
    }

    #[test]
    fn local_ip_v6_unspecified() {
        assert!(is_local_ip("::"));
    }

    #[test]
    fn local_ip_v6_ula() {
        assert!(is_local_ip("fc00::1"));
        assert!(is_local_ip("fd00::1"));
    }

    #[test]
    fn local_ip_v6_global() {
        assert!(!is_local_ip("2001:db8::1"));
    }

    // ── self_sudo_target & sudo_target_is_tamper_proof ──

    #[test]
    fn tmp_path_is_never_self() {
        // R12-02: this ASSERTED the vulnerable behaviour before. /tmp is 1777 and
        // our own rm -f frees the name — the rule is NOPASSWD: ALL in disguise.
        let t = self_sudo_target("drobot ALL=(ALL) NOPASSWD: /tmp/owlzops-mapper");
        assert_eq!(t, Some("/tmp/owlzops-mapper"), "target must be recognised…");
        assert!(
            !sudo_target_is_tamper_proof("/tmp/owlzops-mapper"),
            "…but never excluded"
        );
    }

    #[test]
    fn install_path_is_recognised_as_self_target() {
        assert_eq!(
            self_sudo_target("user ALL=(ALL) NOPASSWD: /usr/local/bin/owlzops-mapper"),
            Some("/usr/local/bin/owlzops-mapper")
        );
    }

    #[test]
    fn self_plus_another_command_is_not_self() {
        assert_eq!(
            self_sudo_target("operator ALL=(ALL) NOPASSWD: /tmp/owlzops-mapper, /usr/bin/other"),
            None
        );
    }

    #[test]
    fn wildcard_args_are_not_self() {
        assert_eq!(
            self_sudo_target("u ALL=(ALL) NOPASSWD: /usr/local/bin/owlzops-mapper *"),
            None
        );
    }

    #[test]
    fn all_is_not_self() {
        assert_eq!(self_sudo_target("root ALL=(ALL) NOPASSWD: ALL"), None);
    }

    #[test]
    fn nonexistent_target_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("owlzops-mapper");
        assert!(
            !sudo_target_is_tamper_proof(p.to_str().unwrap()),
            "free name in a user-owned dir must never be excluded"
        );
    }
}
