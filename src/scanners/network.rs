use crate::models::{NetworkInfo, PortInfo, SslCertInfo};
use crate::utils::run_with_timeout;
use chrono::{NaiveDateTime, Utc};
use std::fs;

/// openssl `-enddate` always returns dates in the format
/// "MMM D HH:MM:SS YYYY GMT", for example:
/// "Sep 15 12:00:00 2026 GMT".
/// The timezone is always GMT, so we parse it as a naive datetime
/// and treat it directly as UTC.
fn parse_openssl_enddate(raw: &str) -> Option<i64> {
    let trimmed = raw.trim().trim_end_matches("GMT").trim();
    let naive = NaiveDateTime::parse_from_str(trimmed, "%b %e %H:%M:%S %Y").ok()?;
    let expiry_utc = naive.and_utc();
    let diff = expiry_utc.signed_duration_since(Utc::now());
    Some(diff.num_days())
}

/// Extract bind address from the "Local Address:Port" column of `ss`.
fn parse_bind_address(local_addr: &str, port: &str) -> String {
    if local_addr.ends_with(&format!(":{}", port)) {
        let addr_part = &local_addr[..local_addr.len() - port.len() - 1];
        let addr_part = addr_part.trim();
        if addr_part.starts_with('[') && addr_part.ends_with(']') {
            addr_part[1..addr_part.len() - 1].to_string()
        } else {
            addr_part.to_string()
        }
    } else if let Some((addr, _)) = local_addr.rsplit_once(':') {
        let addr = addr.trim();
        if addr.starts_with('[') && addr.ends_with(']') {
            addr[1..addr.len() - 1].to_string()
        } else {
            addr.to_string()
        }
    } else {
        "unknown".to_string()
    }
}

pub fn gather_network_info() -> NetworkInfo {
    let mut listening_ports = Vec::new();
    let mut firewall_active = false;

    // ufw
    if let Some(out) = run_with_timeout("ufw", &["status"], 5) {
        let stdout = out.to_lowercase();
        if stdout.contains("active") && !stdout.contains("inactive") {
            firewall_active = true;
        }
    }
    // firewall-cmd
    if !firewall_active
        && let Some(out) = run_with_timeout("firewall-cmd", &["--state"], 5)
        && out.to_lowercase().contains("running")
    {
        firewall_active = true;
    }
    // nftables – consider firewall active if there are rules beyond empty tables
    if !firewall_active && let Some(out) = run_with_timeout("nft", &["list", "ruleset"], 5) {
        let meaningful = out
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.trim().starts_with("table"))
            .count();
        firewall_active = meaningful > 0;
    }

    // iptables – presence of rules (beyond standard chains) indicates a working firewall
    if !firewall_active && let Some(out) = run_with_timeout("iptables-save", &[], 5) {
        let rules = out
            .lines()
            .filter(|l| l.starts_with("-A") && !l.contains("ACCEPT"))
            .count();
        firewall_active = rules > 0;
    }

    // DNS Resolvers
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

    // Custom /etc/hosts overrides
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

    // SSL certificates
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
                    && let Some(out_str) = run_with_timeout(
                        "openssl",
                        &[
                            "x509",
                            "-enddate",
                            "-noout",
                            "-in",
                            cert_path.to_str().unwrap_or(""),
                        ],
                        5,
                    )
                    && out_str.starts_with("notAfter=")
                {
                    let date_part = out_str.replace("notAfter=", "").trim().to_string();
                    days_remaining = parse_openssl_enddate(&date_part);
                    expiry_date = date_part;
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

    // Listening ports via ss
    if let Some(out) = run_with_timeout("ss", &["-tulnp"], 5) {
        for line in out.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let protocol = parts[0].to_string();
                let local_addr_col = parts[4];
                let port = local_addr_col
                    .split(':')
                    .next_back()
                    .unwrap_or("unknown")
                    .to_string();
                let bind_address = parse_bind_address(local_addr_col, &port);

                let mut process_name = "unknown".to_string();
                if let Some(start) = line.find("users:((\"") {
                    let proc_str = &line[start + 9..];
                    if let Some(end) = proc_str.find('"') {
                        process_name = proc_str[..end].to_string();
                    }
                }
                if !listening_ports.iter().any(|p: &PortInfo| {
                    p.port == port && p.protocol == protocol && p.bind_address == bind_address
                }) {
                    listening_ports.push(PortInfo {
                        protocol,
                        port,
                        process: process_name,
                        bind_address,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bind_ipv4_standard() {
        assert_eq!(parse_bind_address("0.0.0.0:22", "22"), "0.0.0.0");
        assert_eq!(parse_bind_address("127.0.0.1:5432", "5432"), "127.0.0.1");
    }

    #[test]
    fn parse_bind_ipv6_bracketed() {
        assert_eq!(parse_bind_address("[::1]:80", "80"), "::1");
        assert_eq!(parse_bind_address("[::]:443", "443"), "::");
    }

    #[test]
    fn parse_openssl_future_date() {
        let days = parse_openssl_enddate("Sep 15 12:00:00 2099 GMT");
        assert!(days.is_some());
        assert!(days.unwrap() > 0);
    }

    #[test]
    fn parse_openssl_expired() {
        let days = parse_openssl_enddate("Jan  1 00:00:00 2020 GMT");
        assert!(days.is_some());
        assert!(days.unwrap() < 0);
    }
}
