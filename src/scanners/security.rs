use crate::models::{SecurityInfo, UserInfo};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;

/// Extract a directive value from `sshd -T` output (format: "directive value").
/// This is the effective sshd configuration — it already accounts for all
/// `Include` files (for example /etc/ssh/sshd_config.d/*.conf) and platform
/// defaults, so there is no need to manually parse and merge configuration files.
fn sshd_effective_config() -> Option<String> {
    // Use the timeout wrapper to avoid hanging on a broken sshd
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

/// Fallback used when `sshd -T` is unavailable (no root access, binary not in PATH, etc.).
/// In this case, we read only the main config file — this is less accurate (it does not
/// include `Include` files or platform defaults), but better than nothing.
fn fallback_parse_main_config(pass_auth: &mut bool, root_login: &mut bool) {
    if let Ok(sshd_config) = fs::read_to_string("/etc/ssh/sshd_config") {
        for line in sshd_config.lines() {
            let clean = line.trim();
            if clean.starts_with("PasswordAuthentication") {
                *pass_auth = clean.ends_with("yes");
            }
            if clean.starts_with("PermitRootLogin") {
                *root_login = !clean.ends_with("no");
            }
        }
    }
}

// ---------------------------------------------------------------------
// Sudo audit
// ---------------------------------------------------------------------
fn gather_sudo_nopasswd() -> Vec<String> {
    let mut entries = Vec::new();
    let mut files = vec!["/etc/sudoers".to_string()];
    if let Ok(dir) = fs::read_dir("/etc/sudoers.d") {
        for entry in dir.flatten() {
            if entry.path().is_file() && !entry.file_name().to_string_lossy().starts_with('.') {
                files.push(entry.path().to_string_lossy().to_string());
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
                    entries.push(format!("{}: {}", file, l));
                }
            }
        }
    }
    entries
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

// ---------------------------------------------------------------------
// Sysctl audit
// ---------------------------------------------------------------------
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

// ---------------------------------------------------------------------
// Main gather function
// ---------------------------------------------------------------------
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
                let auth_keys_path = if username == "root" {
                    "/root/.ssh/authorized_keys".to_string()
                } else {
                    format!("/home/{}/.ssh/authorized_keys", username)
                };
                let count = fs::read_to_string(&auth_keys_path)
                    .unwrap_or_default()
                    .lines()
                    .filter(|k| !k.trim().is_empty() && !k.starts_with('#'))
                    .count();
                auth_keys_map.insert(username.clone(), count);
                auth_keys_map.insert(username.clone(), count);
                shell_usernames.push(username);
            }
        }
    }

    // --- Optimized login collection: single `last -i` call ----------------
    // Парсим last -i
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
                let is_remote = ip != "0.0.0.0"
                    && ip != "127.0.0.1"
                    && ip != "::1"
                    && !ip.starts_with("192.168.")
                    && !ip.starts_with("10.")
                    && !ip.starts_with("172.");
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
