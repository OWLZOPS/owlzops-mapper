use crate::models::{NetworkInfo, PortInfo, SslCertInfo};
use crate::scanners::proc_net::{attribute_sockets, collect_listening_sockets};
use crate::utils::run_with_timeout;
use chrono::{NaiveDateTime, Utc};
use std::fs;

fn parse_openssl_enddate(raw: &str) -> Option<i64> {
    let trimmed = raw.trim().trim_end_matches("GMT").trim();
    let naive = NaiveDateTime::parse_from_str(trimmed, "%b %e %H:%M:%S %Y").ok()?;
    let expiry_utc = naive.and_utc();
    let diff = expiry_utc.signed_duration_since(Utc::now());
    Some(diff.num_days())
}

pub fn gather_network_info() -> NetworkInfo {
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
    if !firewall_active && let Some(out) = run_with_timeout("nft", &["list", "ruleset"], 5) {
        let mut in_filter_table = false;
        let mut has_input_rules = false;
        for line in out.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("table") {
                in_filter_table = trimmed.contains("filter");
            } else if in_filter_table
                && (trimmed.contains("hook input") || trimmed.contains("chain INPUT"))
                && !trimmed.contains("DOCKER")
                && !trimmed.contains("docker")
            {
                has_input_rules = true;
                break;
            }
        }
        firewall_active = has_input_rules;
    }

    if !firewall_active && let Some(out) = run_with_timeout("iptables-save", &[], 5) {
        let has_input_drop_policy = out.lines().any(|l| {
            (l.starts_with(":INPUT DROP") || l.starts_with(":INPUT REJECT"))
                && !l.contains("DOCKER")
        });
        let has_input_rules = out
            .lines()
            .filter(|l| l.starts_with("-A INPUT") && !l.contains("DOCKER") && !l.contains("docker"))
            .count()
            > 0;
        firewall_active = has_input_drop_policy || has_input_rules;
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

    // ---------- Listening ports via /proc (zero-dependency) ----------
    let sockets = collect_listening_sockets();
    let attrs = attribute_sockets(&sockets);

    let mut listening_ports = Vec::new();

    for (inode, meta) in &sockets {
        let attr = attrs.get(inode).cloned().unwrap_or_default();

        let process = attr
            .comm
            .clone()
            .or_else(|| {
                attr.exe_path
                    .as_deref()
                    .and_then(|p| p.rsplit('/').next().map(str::to_string))
            })
            .unwrap_or_else(|| "unknown process".to_string());

        let port_str = meta.port.to_string();

        if listening_ports.iter().any(|p: &PortInfo| {
            p.port == port_str && p.protocol == meta.proto && p.bind_address == meta.bind_address
        }) {
            continue;
        }

        listening_ports.push(PortInfo {
            protocol: meta.proto.to_string(),
            port: port_str,
            process,
            bind_address: meta.bind_address.clone(),
            pid: attr.pid,
            exe_path: attr.exe_path,
        });
    }

    listening_ports.sort_unstable_by(|a, b| {
        a.protocol
            .cmp(&b.protocol)
            .then_with(|| a.bind_address.cmp(&b.bind_address))
            .then_with(|| {
                a.port
                    .parse::<u16>()
                    .unwrap_or(0)
                    .cmp(&b.port.parse::<u16>().unwrap_or(0))
            })
    });

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
