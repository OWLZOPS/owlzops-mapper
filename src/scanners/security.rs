use crate::models::{SecurityInfo, UserInfo};
use std::fs;
use std::process::Command;

/// Extract a directive value from `sshd -T` output (format: "directive value").
/// This is the effective sshd configuration — it already accounts for all
/// `Include` files (for example /etc/ssh/sshd_config.d/*.conf) and platform
/// defaults, so there is no need to manually parse and merge configuration files.
fn sshd_effective_config() -> Option<String> {
    let output = Command::new("sshd").arg("-T").output().ok()?;
    if !output.status.success() { return None; }
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
            if clean.starts_with("PasswordAuthentication") { *pass_auth = clean.ends_with("yes"); }
            if clean.starts_with("PermitRootLogin") { *root_login = !clean.ends_with("no"); }
        }
    }
}

pub fn gather_security_info() -> SecurityInfo {
    let mut shell_users = Vec::new();
    let mut ssh_password_auth_enabled = true;
    let mut ssh_root_login_enabled = true;

    match sshd_effective_config() {
        Some(config) => {
            if let Some(val) = parse_sshd_directive(&config, "passwordauthentication") {
                ssh_password_auth_enabled = val.eq_ignore_ascii_case("yes");
            }
            if let Some(val) = parse_sshd_directive(&config, "permitrootlogin") {
                // Реальные значения sshd: "yes", "no", "prohibit-password", "forced-commands-only".
                // Только "no" по-настоящему запрещает root login — остальное так или иначе разрешает.
                ssh_root_login_enabled = !val.eq_ignore_ascii_case("no");
            }
        }
        None => fallback_parse_main_config(&mut ssh_password_auth_enabled, &mut ssh_root_login_enabled),
    }

    if let Ok(contents) = fs::read_to_string("/etc/passwd") {
        let valid_shells = vec!["/bin/bash", "/bin/sh", "/bin/zsh", "/bin/ash"];
        for line in contents.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() == 7 {
                let username = parts[0].to_string();
                if valid_shells.contains(&parts[6]) {
                    let mut last_login = "Never logged in".to_string();
                    let mut last_ssh_login = "No remote SSH login found".to_string();

                    if let Ok(output) = Command::new("last").arg("-i").arg(&username).output() {
                        let mut found_first = false; let mut found_ssh = false;
                        let stdout_str = String::from_utf8_lossy(&output.stdout);
                        for l in stdout_str.lines() {
                            let cl = l.trim();
                            if cl.is_empty() || cl.starts_with("wtmp") || !cl.starts_with(&username) { continue; }
                            let clean_line = cl.replacen(&username, "", 1).trim().to_string();
                            if !found_first { last_login = clean_line.clone(); found_first = true; }
                            if !found_ssh {
                                let cols: Vec<&str> = clean_line.split_whitespace().collect();
                                if cols.len() >= 2 && cols[1] != "0.0.0.0" && (cols[1].contains('.') || cols[1].contains(':')) {
                                    last_ssh_login = clean_line.clone(); found_ssh = true;
                                }
                            }
                        }
                    }
                    let auth_keys_path = if username == "root" { "/root/.ssh/authorized_keys".to_string() } else { format!("/home/{}/.ssh/authorized_keys", username) };
                    let authorized_keys_count = fs::read_to_string(&auth_keys_path).unwrap_or_default().lines().filter(|k| !k.trim().is_empty() && !k.starts_with('#')).count();
                    shell_users.push(UserInfo { username, last_login, last_ssh_login, authorized_keys_count });
                }
            }
        }
    }
    SecurityInfo { ssh_password_auth_enabled, ssh_root_login_enabled, shell_users }
}