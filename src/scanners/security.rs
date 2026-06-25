use crate::models::{SecurityInfo, UserInfo};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

/// Extract a directive value from `sshd -T` output (format: "directive value").
/// This is the effective sshd configuration — it already accounts for all
/// `Include` files (for example /etc/ssh/sshd_config.d/*.conf) and platform
/// defaults, so there is no need to manually parse and merge configuration files.
fn sshd_effective_config() -> Option<String> {
    let output = Command::new("sshd").arg("-T").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout).to_string();
    if s.trim().is_empty() { None } else { Some(s) }
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
    let mut shell_users = Vec::new();

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

    // --- Shell users -------------------------------------------------------
    if let Ok(contents) = fs::read_to_string("/etc/passwd") {
        let valid_shells = ["/bin/bash", "/bin/sh", "/bin/zsh", "/bin/ash"];
        for line in contents.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() == 7 {
                let username = parts[0].to_string();
                if valid_shells.contains(&parts[6]) {
                    let mut last_login = "Never logged in".to_string();
                    let mut last_ssh_login = "No remote SSH login found".to_string();

                    if let Ok(output) = Command::new("last").arg("-i").arg(&username).output() {
                        let mut found_first = false;
                        let mut found_ssh = false;
                        let stdout_str = String::from_utf8_lossy(&output.stdout);
                        for l in stdout_str.lines() {
                            let cl = l.trim();
                            if cl.is_empty() || cl.starts_with("wtmp") || !cl.starts_with(&username)
                            {
                                continue;
                            }
                            let clean_line = cl.replacen(&username, "", 1).trim().to_string();
                            if !found_first {
                                last_login = clean_line.clone();
                                found_first = true;
                            }
                            if !found_ssh {
                                let cols: Vec<&str> = clean_line.split_whitespace().collect();
                                if cols.len() >= 2
                                    && cols[1] != "0.0.0.0"
                                    && (cols[1].contains('.') || cols[1].contains(':'))
                                {
                                    last_ssh_login = clean_line.clone();
                                    found_ssh = true;
                                }
                            }
                        }
                    }
                    let auth_keys_path = if username == "root" {
                        "/root/.ssh/authorized_keys".to_string()
                    } else {
                        format!("/home/{}/.ssh/authorized_keys", username)
                    };
                    let authorized_keys_count = fs::read_to_string(&auth_keys_path)
                        .unwrap_or_default()
                        .lines()
                        .filter(|k| !k.trim().is_empty() && !k.starts_with('#'))
                        .count();
                    shell_users.push(UserInfo {
                        username,
                        last_login,
                        last_ssh_login,
                        authorized_keys_count,
                    });
                }
            }
        }
    }

    // --- Fail2Ban and Auditd -----------------------------------------------
    let fail2ban_active = Command::new("systemctl")
        .args(["is-active", "--quiet", "fail2ban"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let auditd_active = Command::new("systemctl")
        .args(["is-active", "--quiet", "auditd"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

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
