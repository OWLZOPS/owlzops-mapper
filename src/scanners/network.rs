use crate::models::{NetworkInfo, PortInfo, SslCertInfo};
use chrono::{NaiveDateTime, Utc};
use std::fs;
use std::process::Command;

/// openssl `-enddate` always returns dates in the format
/// "MMM D HH:MM:SS YYYY GMT", for example:
/// "Sep 15 12:00:00 2026 GMT".
/// The timezone is always GMT, so we parse it as a naive datetime
/// and treat it directly as UTC.
fn parse_openssl_enddate(raw: &str) -> Option<i64> {
    let trimmed = raw.trim().trim_end_matches("GMT").trim();
    let naive = NaiveDateTime::parse_from_str(trimmed, "%b %e %H:%M:%S %Y").ok()?;
    let expiry_utc = naive.and_utc();
    Some((expiry_utc - Utc::now()).num_days())
}

pub fn gather_network_info() -> NetworkInfo {
    let mut listening_ports = Vec::new();
    let mut firewall_active = false;

    if let Ok(output) = Command::new("ufw").arg("status").output() {
        let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
        if stdout.contains("active") && !stdout.contains("inactive") {
            firewall_active = true;
        }
    }
    if !firewall_active && let Ok(output) = Command::new("firewall-cmd").arg("--state").output() {
        let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
        if stdout.contains("running") {
            firewall_active = true;
        }
    }

    // Parse DNS Resolvers
    let mut dns_resolvers = Vec::new();
    if let Ok(resolv) = fs::read_to_string("/etc/resolv.conf") {
        for line in resolv.lines() {
            let l = line.trim();
            if l.starts_with("nameserver") {
                let parts: Vec<&str> = l.split_whitespace().collect();
                if parts.len() >= 2 {
                    dns_resolvers.push(parts[1].to_string());
                }
            }
        }
    }

    let mut custom_host_overrides = Vec::new();
    if let Ok(hosts) = fs::read_to_string("/etc/hosts") {
        for line in hosts.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = l.split_whitespace().collect();
            if !parts.is_empty() {
                let ip = parts[0];
                if ip != "127.0.0.1"
                    && ip != "::1"
                    && ip != "127.0.1.1"
                    && !ip.starts_with("ff02")
                    && !ip.starts_with("fe00")
                {
                    custom_host_overrides.push(l.to_string());
                }
            }
        }
    }

    let mut ssl_certificates = Vec::new();
    if let Ok(entries) = fs::read_dir("/etc/letsencrypt/live") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && !path.ends_with("README") {
                let domain = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let cert_path = path.join("cert.pem");
                let mut expiry_date = "unknown".to_string();
                let mut days_remaining = None;
                if cert_path.exists()
                    && let Ok(output) = Command::new("openssl")
                        .args([
                            "x509",
                            "-enddate",
                            "-noout",
                            "-in",
                            cert_path.to_str().unwrap_or(""),
                        ])
                        .output()
                {
                    let out_str = String::from_utf8_lossy(&output.stdout);
                    if out_str.starts_with("notAfter=") {
                        let date_part = out_str.replace("notAfter=", "").trim().to_string();
                        days_remaining = parse_openssl_enddate(&date_part);
                        expiry_date = date_part;
                    }
                }
                let is_critical = days_remaining.map(|d| d < 7).unwrap_or(false);
                let is_warning = !is_critical && days_remaining.map(|d| d < 30).unwrap_or(false);
                ssl_certificates.push(SslCertInfo {
                    domain,
                    expiry_date,
                    days_remaining,
                    is_critical,
                    is_warning,
                });
            }
        }
    }

    if let Ok(output) = Command::new("ss").arg("-tulnp").output() {
        let stdout_str = String::from_utf8_lossy(&output.stdout);
        for line in stdout_str.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let protocol = parts[0].to_string();
                let local_addr_col = if protocol.starts_with("tcp") {
                    parts[4]
                } else {
                    parts[3]
                };
                let port = local_addr_col
                    .split(':')
                    .next_back()
                    .unwrap_or("unknown")
                    .to_string();
                let mut process_name = "unknown".to_string();
                if let Some(start) = line.find("users:((\"") {
                    let proc_str = &line[start + 9..];
                    if let Some(end) = proc_str.find('"') {
                        process_name = proc_str[..end].to_string();
                    }
                }
                if !listening_ports
                    .iter()
                    .any(|p: &PortInfo| p.port == port && p.protocol == protocol)
                {
                    listening_ports.push(PortInfo {
                        protocol,
                        port,
                        process: process_name,
                    });
                }
            }
        }
    }
    NetworkInfo {
        firewall_active,
        dns_resolvers,
        custom_host_overrides,
        ssl_certificates,
        listening_ports,
    }
}
