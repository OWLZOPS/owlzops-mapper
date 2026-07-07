use std::collections::HashMap;
use std::fs;
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

fn decode_v4(hex: &str) -> Option<String> {
    if hex.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(hex, 16).ok()?;
    let [a, b, c, d] = raw.to_le_bytes();
    Some(Ipv4Addr::new(a, b, c, d).to_string())
}

fn decode_v6(hex: &str) -> Option<String> {
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

fn parse_proc_net(proto: Proto, into: &mut HashMap<u64, SocketMeta>) {
    let path = match proto {
        Proto::Tcp => "/proc/net/tcp",
        Proto::Tcp6 => "/proc/net/tcp6",
        Proto::Udp => "/proc/net/udp",
        Proto::Udp6 => "/proc/net/udp6",
    };

    let (content, truncated) = match safe_io::read_file_capped(path, safe_io::CAP_PROC_NET) {
        Ok((c, t)) => (c, t),
        Err(_) => return,
    };

    if truncated {
        coverage::record(format!(
            "/proc/net file {path} exceeded cap and was truncated"
        ));
    }

    for line in content.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() <= 9 {
            continue;
        }

        let state = u8::from_str_radix(f[3], 16).unwrap_or(0);
        let is_listening = match proto {
            Proto::Tcp | Proto::Tcp6 => state == TCP_LISTEN,
            Proto::Udp | Proto::Udp6 => {
                state == TCP_CLOSE
                    && f[1]
                        .rsplit_once(':')
                        .map(|(_, p)| p != "0000")
                        .unwrap_or(false)
            }
        };
        if !is_listening {
            continue;
        }

        let Some((bind_address, port)) = parse_local(f[1], proto.is_v6()) else {
            continue;
        };
        let Ok(inode) = f[9].parse::<u64>() else {
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

pub fn collect_listening_sockets() -> HashMap<u64, SocketMeta> {
    let mut map = HashMap::new();
    for p in [Proto::Tcp, Proto::Tcp6, Proto::Udp, Proto::Udp6] {
        parse_proc_net(p, &mut map);
    }
    map
}

fn socket_inode(link_target: &str) -> Option<u64> {
    link_target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
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

    for pid in pids {
        if attributed.len() == wanted.len() {
            break;
        }

        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };

        let mut exe_cache: Option<Option<String>> = None;

        for fd in fds.flatten() {
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

            let comm = {
                match safe_io::read_file_capped(
                    &format!("/proc/{pid}/comm"),
                    4096, // safe cap for comm
                ) {
                    Ok((c, truncated)) => {
                        if truncated {
                            coverage::record(format!("/proc/{pid}/comm truncated"));
                        }
                        Some(c.trim().to_string())
                    }
                    Err(_) => None,
                }
            };

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
    attributed
}
