//! Cross-reference Docker's published ports against the host firewall
//! state (SEC-065 / SEC-066).
//!
//! Docker writes its own iptables rules when a container publishes a port
//! on a wildcard address (`-p 8080:80`, i.e. `0.0.0.0:8080->80/tcp`). Those
//! rules sit in the `DOCKER` chain, which is traversed *before* the
//! `ufw-user-input` / `INPUT` chains that a host firewall manages.
//!
//! The result: `ufw status` says `active`, `firewall_active: true` in the
//! report, and a port that the operator believes is firewalled is reachable
//! from the internet. This is not a Docker bug — it is documented behaviour
//! of how Docker integrates with the netfilter stack. But it is a gap
//! between what the operator believes and what is true, and this scanner
//! closes it.
//!
//! Two outcomes, distinguished by `firewall_active`:
//!
//!   * **SEC-065** — firewall active, Docker bypasses it. The fix is in the
//!     Docker config (`-p 127.0.0.1:8080:80`, `"ip": "127.0.0.1"` in
//!     `/etc/docker/daemon.json`, or a rule in `DOCKER-USER`).
//!   * **SEC-066** — no firewall, the port is exposed because nothing
//!     protects it. The fix is to enable one.
//!
//! Loopback bindings (`127.0.0.1:*`, `[::1]:*`) are never flagged: they are
//! already unreachable from the network.

use crate::models::{ContainerInfo, FirewallBypassFinding};

/// Ports where a wildcard publish is materially worse than a loopback one.
/// Not an exhaustive "dangerous port" list — a curated set that catches the
/// services people actually forget to lock down. `80` and `443` are
/// deliberately absent: publishing a reverse proxy on `0.0.0.0` is the
/// intended pattern, and flagging it would drown the signal.
const SENSITIVE_PORTS: &[u16] = &[
    22,    // ssh
    23,    // telnet
    25,    // smtp
    143,   // imap
    465,   // smtps
    587,   // submission
    993,   // imaps
    995,   // pop3s
    3306,  // mysql / mariadb
    3389,  // rdp
    5432,  // postgresql
    5900,  // vnc
    6379,  // redis
    9200,  // elasticsearch
    9300,  // elasticsearch transport
    11211, // memcached
    2375,  // docker api (unencrypted)
    2376,  // docker api (tls)
    27017, // mongodb
    27018, // mongodb shard
    6443,  // kubernetes apiserver
    10250, // kubelet
];

/// One parsed Docker port binding.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedBinding {
    bind_address: String,
    host_port: u16,
    container_port: u16,
    protocol: String,
}

/// Parse a single binding token from `ContainerInfo.ports`, e.g.
/// `"0.0.0.0:8080->80/tcp"`, `"[::]:8080->80/tcp"`, `"127.0.0.1:8080->80/tcp"`.
///
/// `None` for anything that is not a published binding — including the
/// bare `"8080/tcp"` form Docker emits for EXPOSE-only ports (no host
/// publish, no exposure to the network).
fn parse_binding(s: &str) -> Option<ParsedBinding> {
    let (host_side, container_side) = s.trim().split_once("->")?;

    let (container_port_s, protocol) = container_side.split_once('/')?;
    let container_port: u16 = container_port_s.parse().ok()?;

    // IPv6 bindings are bracketed: `[::]:8080`, `[::1]:8080`, `[fe80::1]:8080`.
    // rsplit_once(':') would split the IPv6 address into garbage.
    let (bind_address, host_port_s) = if host_side.starts_with('[') {
        let close = host_side.find(']')?;
        let addr = &host_side[..=close];
        let rest = host_side.get(close + 1..)?;
        (addr, rest.strip_prefix(':')?)
    } else {
        host_side.rsplit_once(':')?
    };

    let host_port: u16 = host_port_s.parse().ok()?;

    Some(ParsedBinding {
        bind_address: bind_address.to_string(),
        host_port,
        container_port,
        protocol: protocol.to_string(),
    })
}

/// A binding is "wildcard" when it is reachable from off-host. `0.0.0.0`
/// and `[::]` (unspecified addresses) bind every interface; loopback and
/// link-local are not exposed.
fn is_wildcard_bind(addr: &str) -> bool {
    matches!(addr, "0.0.0.0" | "[::]" | "::" | "[::0]")
}

/// Compute the list of bypass findings. Called from `run_local_scan_async`
/// after both `topology_info` and `network_info` are available.
///
/// Stopped and exited containers are skipped — a container that is not
/// running has no live socket, and its `ports` list is historical state.
pub fn detect_firewall_bypass(
    containers: &[ContainerInfo],
    firewall_active: bool,
) -> Vec<FirewallBypassFinding> {
    let mut findings = Vec::new();

    for c in containers {
        if c.state != "running" {
            continue;
        }
        for port_str in &c.ports {
            // Bollard can return one string per published binding, or several
            // comma-joined if the runtime collapses them. Handle both.
            for binding in port_str.split(',').map(str::trim) {
                let Some(p) = parse_binding(binding) else {
                    continue;
                };
                if !is_wildcard_bind(&p.bind_address) {
                    continue;
                }
                findings.push(FirewallBypassFinding {
                    container: c.name.clone(),
                    published: binding.to_string(),
                    host_port: p.host_port,
                    container_port: p.container_port,
                    protocol: p.protocol,
                    sensitive: SENSITIVE_PORTS.contains(&p.host_port),
                    firewall_was_active: firewall_active,
                });
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_container(name: &str, state: &str, ports: &[&str]) -> ContainerInfo {
        ContainerInfo {
            name: name.to_string(),
            state: state.to_string(),
            ports: ports.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn parses_ipv4_wildcard_binding() {
        let p = parse_binding("0.0.0.0:8080->80/tcp").expect("parses");
        assert_eq!(p.bind_address, "0.0.0.0");
        assert_eq!(p.host_port, 8080);
        assert_eq!(p.container_port, 80);
        assert_eq!(p.protocol, "tcp");
    }

    #[test]
    fn parses_loopback_binding() {
        let p = parse_binding("127.0.0.1:6379->6379/tcp").expect("parses");
        assert_eq!(p.bind_address, "127.0.0.1");
        assert_eq!(p.host_port, 6379);
    }

    #[test]
    fn parses_ipv6_wildcard_binding() {
        let p = parse_binding("[::]:8080->80/tcp").expect("parses");
        assert_eq!(p.bind_address, "[::]");
        assert_eq!(p.host_port, 8080);
        assert!(is_wildcard_bind(&p.bind_address));
    }

    #[test]
    fn parses_ipv6_loopback_binding() {
        let p = parse_binding("[::1]:8080->80/tcp").expect("parses");
        assert_eq!(p.bind_address, "[::1]");
        assert!(!is_wildcard_bind(&p.bind_address));
    }

    #[test]
    fn rejects_expose_only_binding() {
        // Docker emits "8080/tcp" for EXPOSE without publish.
        assert!(parse_binding("8080/tcp").is_none());
    }

    #[test]
    fn no_finding_for_loopback_publish() {
        let containers = vec![make_container(
            "db",
            "running",
            &["127.0.0.1:5432->5432/tcp"],
        )];
        let findings = detect_firewall_bypass(&containers, true);
        assert!(findings.is_empty(), "loopback is not a bypass");
    }

    #[test]
    fn finding_for_wildcard_publish_with_firewall() {
        let containers = vec![make_container(
            "redis",
            "running",
            &["0.0.0.0:6379->6379/tcp"],
        )];
        let findings = detect_firewall_bypass(&containers, true);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].firewall_was_active);
        assert!(findings[0].sensitive, "6379 is a sensitive port");
        assert_eq!(findings[0].container, "redis");
    }

    #[test]
    fn finding_for_wildcard_publish_without_firewall() {
        let containers = vec![make_container("web", "running", &["0.0.0.0:8080->80/tcp"])];
        let findings = detect_firewall_bypass(&containers, false);
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].firewall_was_active);
        assert!(!findings[0].sensitive, "8080 is not in the sensitive set");
    }

    #[test]
    fn stopped_containers_are_skipped() {
        let containers = vec![make_container("old", "exited", &["0.0.0.0:6379->6379/tcp"])];
        let findings = detect_firewall_bypass(&containers, true);
        assert!(findings.is_empty(), "exited container has no live socket");
    }

    #[test]
    fn multiple_bindings_in_one_string() {
        // Some runtimes collapse several bindings into one comma-separated
        // string when reading from `docker ps --format '{{.Ports}}'`.
        let containers = vec![make_container(
            "web",
            "running",
            &["0.0.0.0:8080->80/tcp, [::]:8080->80/tcp"],
        )];
        let findings = detect_firewall_bypass(&containers, true);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.host_port == 8080));
    }

    #[test]
    fn unknown_binding_format_is_ignored() {
        let containers = vec![make_container(
            "weird",
            "running",
            &["garbage", "also-not-a-binding"],
        )];
        let findings = detect_firewall_bypass(&containers, true);
        assert!(findings.is_empty());
    }
}
