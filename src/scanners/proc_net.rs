use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::coverage;
use crate::safe_io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
}

impl Proto {
    pub fn label(self) -> &'static str {
        match self {
            Proto::Tcp | Proto::Tcp6 => "tcp",
            Proto::Udp | Proto::Udp6 => "udp",
        }
    }
    pub fn is_v6(self) -> bool {
        matches!(self, Proto::Tcp6 | Proto::Udp6)
    }
}

#[derive(Debug, Clone)]
pub struct SocketMeta {
    pub proto: &'static str,
    pub bind_address: String,
    pub port: u16,
}

#[derive(Debug, Clone, Default)]
pub struct ProcAttr {
    pub pid: Option<u32>,
    pub exe_path: Option<String>,
    pub comm: Option<String>,
}

const TCP_LISTEN: u8 = 0x0A;
const TCP_CLOSE: u8 = 0x07;

/// Decode an IPv4 address from its little-endian hex representation
/// (8 hex digits) as found in /proc/net/tcp{,6}.
pub(crate) fn decode_v4(hex: &str) -> Option<String> {
    if hex.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(hex, 16).ok()?;
    let [a, b, c, d] = raw.to_le_bytes();
    Some(Ipv4Addr::new(a, b, c, d).to_string())
}

/// Decode an IPv6 address from its little-endian hex representation
/// (32 hex digits) as found in /proc/net/tcp6.
pub(crate) fn decode_v6(hex: &str) -> Option<String> {
    if hex.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for i in 0..4 {
        let word = &hex[i * 8..i * 8 + 8];
        let w = u32::from_str_radix(word, 16).ok()?;
        octets[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    Some(Ipv6Addr::from(octets).to_string())
}

/// Extract the socket inode from a link target like "socket:[12345]".
pub(crate) fn socket_inode(link_target: &str) -> Option<u64> {
    link_target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn parse_local(field: &str, v6: bool) -> Option<(String, u16)> {
    let (addr_hex, port_hex) = field.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let addr = if v6 {
        decode_v6(addr_hex)?
    } else {
        decode_v4(addr_hex)?
    };
    Some((addr, port))
}

/// Parse a `/proc/net/{tcp,tcp6,udp,udp6}`-style file from `base_dir`.
/// For the host namespace `base_dir` is `/proc`; for a foreign network
/// namespace it is `/proc/<pid>`.
fn parse_proc_net(proto: Proto, into: &mut HashMap<u64, SocketMeta>, base_dir: &str) {
    let path = match proto {
        Proto::Tcp => format!("{base_dir}/net/tcp"),
        Proto::Tcp6 => format!("{base_dir}/net/tcp6"),
        Proto::Udp => format!("{base_dir}/net/udp"),
        Proto::Udp6 => format!("{base_dir}/net/udp6"),
    };

    let (content, truncated) = match safe_io::read_procfs_capped(&path, safe_io::CAP_PROC_NET) {
        Ok((c, t)) => (c, t),
        // Kernel without IPv6 support → legitimate absence, silence is correct.
        Err(e) if e.kind() == ErrorKind::NotFound => return,
        Err(e) => {
            coverage::record(format!(
                "{path} unreadable ({}) — listening {} sockets NOT enumerated; \
                 port inventory INCOMPLETE",
                e.kind(),
                proto.label()
            ));
            return;
        }
    };

    if truncated {
        coverage::record(format!(
            "/proc/net file {path} exceeded cap and was truncated"
        ));
    }

    for line in content.lines().skip(1) {
        let mut parts = line.split_ascii_whitespace();

        // sl
        parts.next();
        let local = parts.next();
        let _rem = parts.next();
        let state_hex = parts.next();

        let (Some(local), Some(state_hex)) = (local, state_hex) else {
            continue;
        };

        let state = u8::from_str_radix(state_hex, 16).unwrap_or(0);
        let is_listening = match proto {
            Proto::Tcp | Proto::Tcp6 => state == TCP_LISTEN,
            Proto::Udp | Proto::Udp6 => {
                state == TCP_CLOSE
                    && local
                        .rsplit_once(':')
                        .map(|(_, p)| p != "0000")
                        .unwrap_or(false)
            }
        };
        if !is_listening {
            continue;
        }

        let Some((bind_address, port)) = parse_local(local, proto.is_v6()) else {
            continue;
        };

        // Skip indices 4..=8 (tx_queue, rx_queue, tr, tm->when, retrnsmt)
        for _ in 0..5 {
            parts.next();
        }
        let inode_str = parts.next();
        let Some(inode_str) = inode_str else { continue };
        let Ok(inode) = inode_str.parse::<u64>() else {
            continue;
        };
        if inode == 0 {
            continue;
        }

        into.insert(
            inode,
            SocketMeta {
                proto: proto.label(),
                bind_address,
                port,
            },
        );
    }
}

/// Collect listening sockets visible in the current/host network namespace.
pub fn collect_listening_sockets() -> HashMap<u64, SocketMeta> {
    let mut map = HashMap::new();
    for p in [Proto::Tcp, Proto::Tcp6, Proto::Udp, Proto::Udp6] {
        parse_proc_net(p, &mut map, "/proc");
    }
    map
}

/// Read the network namespace inode for a process.
fn netns_inode(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/ns/net"))
        .ok()?
        .to_str()
        .map(str::to_string)
}

/// Walk all processes and report listeners that exist in foreign network
/// namespaces but are NOT present in the host namespace inventory.
///
/// These sockets are invisible to the host-level port scanner and therefore
/// absent from `network.listening_ports`. Raw Truth demands they be surfaced;
/// they land in coverage so the operator knows the host view is incomplete.
///
/// Aggregated per network namespace: a Docker host has many processes sharing
/// one netns, but only one coverage record is emitted with example listeners.
pub fn report_foreign_netns_listeners() {
    let host_ns = match std::fs::read_link("/proc/1/ns/net") {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(_) => return,
    };

    // Host-visible keys: (proto, address, port)
    let host_sockets = collect_listening_sockets();
    let host_keys: HashSet<(String, String, u16)> = host_sockets
        .values()
        .map(|s| (s.proto.to_string(), s.bind_address.clone(), s.port))
        .collect();

    let Ok(entries) = fs::read_dir("/proc") else {
        return;
    };

    // netns_inode -> (non-host-visible listeners, example process name)
    let mut ns_cache: HashMap<String, (Vec<SocketMeta>, String)> = HashMap::new();

    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };

        let Some(ns) = netns_inode(pid) else { continue };
        if ns == host_ns {
            continue;
        }

        if let Some((_, example)) = ns_cache.get_mut(&ns) {
            if example.is_empty() {
                let comm = safe_io::read_procfs_capped(&format!("/proc/{pid}/comm"), 4096)
                    .ok()
                    .map(|(c, _)| c.trim().to_string())
                    .unwrap_or_else(|| "?".to_string());
                *example = comm;
            }
            continue;
        }

        let base = format!("/proc/{pid}");
        let mut foreign = HashMap::new();
        for p in [Proto::Tcp, Proto::Tcp6, Proto::Udp, Proto::Udp6] {
            parse_proc_net(p, &mut foreign, &base);
        }

        let mut invisible = Vec::new();
        for meta in foreign.values() {
            let key = (meta.proto.to_string(), meta.bind_address.clone(), meta.port);
            if !host_keys.contains(&key) {
                invisible.push(meta.clone());
            }
        }

        let comm = safe_io::read_procfs_capped(&format!("/proc/{pid}/comm"), 4096)
            .ok()
            .map(|(c, _)| c.trim().to_string())
            .unwrap_or_else(|| "?".to_string());

        ns_cache.insert(ns, (invisible, comm));
    }

    for (ns, (sockets, comm)) in ns_cache {
        if sockets.is_empty() {
            continue;
        }
        let examples: Vec<String> = sockets
            .iter()
            .take(3)
            .map(|s| format!("{}:{}/{}", s.bind_address, s.port, s.proto))
            .collect();
        let more = sockets.len().saturating_sub(3);
        let msg = if more > 0 {
            format!(
                "netns {} (example process: {}): {} listener(s) not visible in host netns — e.g. {} (+{} more)",
                ns,
                comm,
                sockets.len(),
                examples.join(", "),
                more
            )
        } else {
            format!(
                "netns {} (example process: {}): {} listener(s) not visible in host netns — {}",
                ns,
                comm,
                sockets.len(),
                examples.join(", ")
            )
        };
        coverage::record(msg);
    }
}

pub fn attribute_sockets(wanted: &HashMap<u64, SocketMeta>) -> HashMap<u64, ProcAttr> {
    let mut attributed: HashMap<u64, ProcAttr> = HashMap::new();
    if wanted.is_empty() {
        return attributed;
    }

    let mut pids: Vec<u32> = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for e in entries.flatten() {
            if let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) {
                pids.push(pid);
            }
        }
    }
    pids.sort_unstable();

    let mut denied = 0usize;
    const MAX_FD_PER_PID: usize = 4096;

    for pid in pids {
        if attributed.len() == wanted.len() {
            break;
        }

        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            denied += 1;
            continue;
        };

        let mut exe_cache: Option<Option<String>> = None;
        // R28-06: comm is per-PID, exactly like exe. Reading it inside the fd
        // loop repeats the syscall once per matched socket on the same process.
        let mut comm_cache: Option<Option<String>> = None;
        let mut fd_seen = 0usize;

        for fd in fds.flatten() {
            fd_seen += 1;
            if fd_seen > MAX_FD_PER_PID {
                coverage::record(format!(
                    "/proc/{pid}/fd exceeded {MAX_FD_PER_PID} entries – socket attribution for this pid is partial"
                ));
                break;
            }

            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let Some(inode) = target.to_str().and_then(socket_inode) else {
                continue;
            };

            if !wanted.contains_key(&inode) || attributed.contains_key(&inode) {
                continue;
            }

            let exe_path = exe_cache
                .get_or_insert_with(|| {
                    fs::read_link(format!("/proc/{pid}/exe"))
                        .ok()
                        .map(|p| p.to_string_lossy().into_owned())
                })
                .clone();

            let comm = comm_cache
                .get_or_insert_with(|| {
                    match safe_io::read_procfs_capped(&format!("/proc/{pid}/comm"), 4096) {
                        Ok((c, truncated)) => {
                            if truncated {
                                coverage::record(format!("/proc/{pid}/comm truncated"));
                            }
                            Some(c.trim().to_string())
                        }
                        Err(_) => None,
                    }
                })
                .clone();

            attributed.insert(
                inode,
                ProcAttr {
                    pid: Some(pid),
                    exe_path,
                    comm,
                },
            );
        }
    }

    if attributed.len() < wanted.len() {
        let hint = if !crate::is_running_as_root() {
            " — run as root for full attribution"
        } else {
            ""
        };
        coverage::record(format!(
            "port attribution incomplete: {}/{} sockets attributed, {} /proc/<pid>/fd unreadable{}",
            attributed.len(),
            wanted.len(),
            denied,
            hint
        ));
    }

    attributed
}
