use crate::models::{SecurityInfo, UserInfo};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;

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
    if let Ok(contents) = fs::read_to_string("/etc/ssh/sshd_config") {
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
                                    && let Ok(inc_contents) = std::fs::read_to_string(&path)
                                {
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
                } else if let Ok(inc_contents) = std::fs::read_to_string(path_part) {
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
    let mut files = vec!["/etc/sudoers".to_string()];
    if let Ok(dir) = fs::read_dir("/etc/sudoers.d") {
        for entry in dir.flatten() {
            if entry.path().is_file() && !entry.file_name().to_string_lossy().starts_with('.') {
                files.push(entry.path().display().to_string());
            }
        }
    }

    for file in files {
        if let Ok(contents) = fs::read_to_string(&file) {
            for line in contents.lines() {
                let l = line.trim();
                if l.is_empty() || l.starts_with('#') {
                    continue;
                }
                if l.to_lowercase().contains("nopasswd") {
                    // Exclude entries that are exclusively for the scanner itself,
                    // to avoid flagging our own remote scanning capability.
                    if is_self_only_sudo_line(l) {
                        continue;
                    }
                    entries.push(format!("{}: {}", file, l));
                }
            }
        }
    }
    entries
}

/// Return `true` if the given sudoers line is solely for the scanner itself
/// and should be excluded from the NOPASSWD audit.
pub fn is_self_only_sudo_line(line: &str) -> bool {
    const SELF_PATHS: &[&str] = &["/tmp/owlzops-mapper", "/usr/local/bin/owlzops-mapper"];
    line.contains("owlzops-mapper")
        && line
            .rsplit(':')
            .next()
            .map(|cmd| cmd.split(',').all(|c| SELF_PATHS.contains(&c.trim())))
            .unwrap_or(false)
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
    let checks: &[(&str, &str, &str)] = &[
        (
            "/proc/sys/kernel/randomize_va_space",
            "2",
            "kernel.randomize_va_space",
        ),
        ("/proc/sys/net/ipv4/ip_forward", "0", "net.ipv4.ip_forward"),
        (
            "/proc/sys/net/ipv4/tcp_syncookies",
            "1",
            "net.ipv4.tcp_syncookies",
        ),
        ("/proc/sys/fs/suid_dumpable", "0", "fs.suid_dumpable"),
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

    for &(path, expected, name) in checks {
        if let Ok(value) = fs::read_to_string(path) {
            let value = value.trim();
            if value != expected {
                issues.push(format!("{}={} (expected {})", name, value, expected));
            }
        }
    }
    issues
}

// ── Main gather function ─────────────────────────────────────────────────

pub fn gather_security_info() -> SecurityInfo {
    // --- SSH config parsing ------------------------------------------------
    let (ssh_password_auth_enabled, ssh_root_login_enabled, ssh_config_source) =
        match sshd_effective_config() {
            Some(config) => {
                let pwd = parse_sshd_directive(&config, "passwordauthentication")
                    .map(|v| v.eq_ignore_ascii_case("yes"))
                    .unwrap_or(true);
                let root = parse_sshd_directive(&config, "permitrootlogin")
                    .map(|v| !v.eq_ignore_ascii_case("no"))
                    .unwrap_or(true);
                (pwd, root, "sshd -T (effective)".to_string())
            }
            None => {
                let mut pwd = true;
                let mut root = true;
                fallback_parse_main_config(&mut pwd, &mut root);
                (pwd, root, "fallback (/etc/ssh/sshd_config)".to_string())
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

    if let Ok(contents) = fs::read_to_string("/etc/passwd") {
        for line in contents.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() == 7 && valid_shells.contains(parts[6]) {
                let username = parts[0].to_string();

                // Count authorized keys
                let home = parts[5];
                let auth_keys_path = format!("{}/.ssh/authorized_keys", home);
                let count = fs::read_to_string(&auth_keys_path)
                    .unwrap_or_default()
                    .lines()
                    .filter(|k| !k.trim().is_empty() && !k.starts_with('#'))
                    .count();
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

    SecurityInfo {
        ssh_password_auth_enabled,
        ssh_root_login_enabled,
        shell_users,
        fail2ban_active,
        auditd_active,
        ssh_config_source,
        sudo_nopasswd_entries,
        sudoers_mode,
        sysctl_issues,
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

    // ── is_self_only_sudo_line (sudoers exclusion) ────────

    #[test]
    fn self_only_single_canonical_path() {
        assert!(is_self_only_sudo_line(
            "drobot ALL=(ALL) NOPASSWD: /tmp/owlzops-mapper"
        ));
        assert!(is_self_only_sudo_line(
            "user ALL=(ALL) NOPASSWD: /usr/local/bin/owlzops-mapper"
        ));
    }

    #[test]
    fn self_only_with_another_command() {
        assert!(!is_self_only_sudo_line(
            "operator ALL=(ALL) NOPASSWD: /tmp/owlzops-mapper, /usr/bin/other"
        ));
    }

    #[test]
    fn self_only_all_is_not_self() {
        assert!(!is_self_only_sudo_line("root ALL=(ALL) NOPASSWD: ALL"));
    }

    #[test]
    fn self_only_does_not_exclude_non_canonical_path() {
        assert!(!is_self_only_sudo_line(
            "operator ALL=(ALL) NOPASSWD: /home/x/owlzops-mapper"
        ));
    }

    // ── fallback_parse_main_config ─────────────────────────

    #[test]
    fn fallback_parse_main_config_no_include() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("sshd_config");
        let mut f = std::fs::File::create(&config_path).unwrap();
        writeln!(f, "PasswordAuthentication yes").unwrap();
        writeln!(f, "PermitRootLogin no").unwrap();

        let mut pass_auth = false;
        let mut root_login = true;
        fallback_parse_main_config(&mut pass_auth, &mut root_login);
    }

    #[test]
    fn fallback_parse_main_config_include() {
        let mut pass_auth = false;
        let mut root_login = true;
        fallback_parse_main_config(&mut pass_auth, &mut root_login);
    }
}
