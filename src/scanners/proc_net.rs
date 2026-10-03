use std::collections::HashMap;
use std::fs;
use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use crate::coverage;
use crate::models::ForeignNetnsListener;
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

/// Upper bound on foreign namespaces probed. Every other scanner in this
/// crate is capped; an uncapped walk on a Kubernetes node with hundreds of
/// pods would read 4 seq_files per pod, each iterating that netns' socket
/// tables. Exceeding the cap is a coverage fact, not a silent stop.
const MAX_FOREIGN_NETNS: usize = 64;

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
///
/// Returns true if the file was actually read. The caller needs to tell
/// "this namespace has no listeners" from "this pid is gone" (R29‑03).
fn parse_proc_net(proto: Proto, into: &mut HashMap<u64, SocketMeta>, base_dir: &str) -> bool {
    let path = match proto {
        Proto::Tcp => format!("{base_dir}/net/tcp"),
        Proto::Tcp6 => format!("{base_dir}/net/tcp6"),
        Proto::Udp => format!("{base_dir}/net/udp"),
        Proto::Udp6 => format!("{base_dir}/net/udp6"),
    };

    let (content, truncated) = match safe_io::read_procfs_capped(&path, safe_io::CAP_PROC_NET) {
        Ok((c, t)) => (c, t),
        // Two different situations share ENOENT here: a kernel without IPv6
        // (base_dir = /proc, legitimate absence) and a pid that exited between
        // readdir and this read (base_dir = /proc/<pid>). Silence is correct
        // for the first; the caller resolves the second via the return value.
        Err(e) if e.kind() == ErrorKind::NotFound => return false,
        Err(e) => {
            coverage::record(format!(
                "{path} unreadable ({}) — listening {} sockets NOT enumerated; \
                 port inventory INCOMPLETE",
                e.kind(),
                proto.label()
            ));
            return false;
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

    true
}

/// R35-06: base of the HOST network namespace, defined as PID 1's — the same
/// definition `report_foreign_netns_listeners` compares against. `/proc/net`
/// is `/proc/self/net`: the scanner's own namespace, not the host's when we
/// run in a container. When the two differ we read the host's tables from
/// `/proc/1`; otherwise the current behaviour (`/proc`) is correct.
///
/// If `/proc/self/ns/net` and `/proc/1/ns/net` cannot be compared (e.g.
/// `/proc/1/ns/net` is unreadable under non-root) we fall back to `/proc`
/// and disclose the ambiguity — the caller must not silently present the
/// scanner's own namespace as the host's.
fn host_net_base() -> &'static str {
    match (
        fs::read_link("/proc/self/ns/net"),
        fs::read_link("/proc/1/ns/net"),
    ) {
        (Ok(me), Ok(init)) if me != init => "/proc/1",
        (Ok(_), Err(e)) => {
            coverage::record(format!(
                "network inventory: /proc/1/ns/net unreadable ({}) — host listener table \
                 read from /proc/self/net; if the scanner is containerised this may be the \
                 wrong namespace",
                e.kind()
            ));
            "/proc"
        }
        _ => "/proc",
    }
}

/// Collect listening sockets visible in the host network namespace.
///
/// R35-06: `listening_ports` means "sockets in PID 1's netns", not "sockets in
/// the scanner's netns". `/proc/net` is `/proc/self/net`; on a containerised
/// scanner (DaemonSet without hostNetwork, `--pid=host` container) that is
/// the scanner's namespace, and the real host listeners were enumerated
/// nowhere. `host_net_base` picks the same namespace `report_foreign_netns_listeners`
/// treats as host.
pub fn collect_listening_sockets() -> HashMap<u64, SocketMeta> {
    collect_listening_sockets_from(Path::new(host_net_base()))
}

/// M9: same walk, rooted at `proc_root`. Tests pass a tempdir; production
/// uses `host_net_base()` (see the wrapper above).
pub fn collect_listening_sockets_from(proc_root: &Path) -> HashMap<u64, SocketMeta> {
    let root = proc_root.to_string_lossy().into_owned();
    let mut map = HashMap::new();
    for p in [Proto::Tcp, Proto::Tcp6, Proto::Udp, Proto::Udp6] {
        let _ = parse_proc_net(p, &mut map, &root);
    }
    map
}

/// Read the network namespace inode for a process rooted at `proc_root`.
///
/// R33-05: returns `io::Result` so the caller can distinguish a vanished
/// pid (ENOENT, a race) from a permission failure (EACCES, a real
/// coverage fact). The pre-R33-05 `Option` collapsed both into one.
///
/// M9: takes `&Path` so the walk can be rooted at any procfs mount.
fn netns_inode(proc_root: &Path, pid: u32) -> io::Result<String> {
    let link = fs::read_link(proc_root.join(format!("{pid}/ns/net")))?;
    link.to_str().map(str::to_string).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "ns/net link target is not valid UTF-8",
        )
    })
}

/// Walk all processes and report EVERY listening socket in a network
/// namespace other than PID 1's. None of these is in `listening_ports`,
/// whatever its tuple — the host tuple is not unique (R35-06).
///
/// Before R35-06 a foreign socket was dropped when its `(proto, addr, port)`
/// matched the host's. But socket identity is the inode, and inodes never
/// cross namespaces; a matching tuple is a coincidence. Under that filter a
/// container's `0.0.0.0:22` hid behind the host sshd, and with
/// `userland-proxy: false` a published port fell into `listening_ports`
/// — the heuristic was wrong in both directions.
///
/// Aggregated per network namespace: a Docker host has many processes sharing
/// one netns, but only one entry per unique socket is returned.
pub fn report_foreign_netns_listeners() -> Vec<ForeignNetnsListener> {
    report_foreign_netns_listeners_from(Path::new("/proc"))
}

/// M9: same walk, rooted at `proc_root`. Production calls
/// `report_foreign_netns_listeners` (`/proc`); tests call this against a
/// tempdir so the tuple-filter regression (R35-06) has a real behavioural
/// check instead of a signature check.
pub(crate) fn report_foreign_netns_listeners_from(proc_root: &Path) -> Vec<ForeignNetnsListener> {
    let proc_root_str = proc_root.to_string_lossy().into_owned();

    let host_ns = match fs::read_link(proc_root.join("1/ns/net")) {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(e) => {
            coverage::record(format!(
                "netns visibility: {proc_root_str}/1/ns/net unreadable ({}) — foreign-namespace \
                 listeners NOT enumerated; the port inventory may be missing sockets",
                e.kind()
            ));
            return Vec::new();
        }
    };

    let entries = match fs::read_dir(proc_root) {
        Ok(e) => e,
        Err(e) => {
            coverage::record(format!(
                "netns visibility: {proc_root_str} unreadable ({}) — foreign-namespace \
                 listeners NOT enumerated",
                e.kind()
            ));
            return Vec::new();
        }
    };

    // R29-04: readdir order is arbitrary, so the first pid seen in a namespace
    // decides `example_process`. Sort so the lowest pid wins — it is both
    // deterministic and usually the container's init process. R29-03 depends
    // on this too: a dead pid must be followed by the next-lowest, not by an
    // arbitrary one.
    let mut pids: Vec<u32> = entries
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .collect();
    pids.sort_unstable();

    // netns_inode -> (all listeners, example process name)
    let mut ns_cache: HashMap<String, (Vec<SocketMeta>, String)> = HashMap::new();
    // M4-02: reading /proc/<pid>/ns/net requires ptrace_may_access. Without
    // root or CAP_SYS_PTRACE every foreign process is skipped and an empty
    // result reads as "no hidden listeners" when it means "not checked".
    let mut ns_denied = 0usize;
    let mut ns_over_cap = 0usize;

    for pid in pids {
        let ns = match netns_inode(proc_root, pid) {
            Ok(ns) => ns,
            // R33-05: the pid exited between readdir and readlink. A race,
            // not a permission fact — do not count it as "unreadable (needs
            // root)". On a busy host this used to inflate the coverage line
            // on every single scan.
            Err(e) => match safe_io::proc_miss(&e) {
                safe_io::ProcMiss::Vanished => continue,
                _ => {
                    ns_denied += 1;
                    continue;
                }
            },
        };
        if ns == host_ns {
            continue;
        }

        // The insert path below always writes a non-empty name, so a cached
        // entry never needs backfilling — just skip (M4-04).
        if ns_cache.contains_key(&ns) {
            continue;
        }
        if ns_cache.len() >= MAX_FOREIGN_NETNS {
            ns_over_cap += 1;
            continue;
        }

        let base = format!("{proc_root_str}/{pid}");
        let mut foreign = HashMap::new();
        let mut any_read = false;
        for p in [Proto::Tcp, Proto::Tcp6, Proto::Udp, Proto::Udp6] {
            any_read |= parse_proc_net(p, &mut foreign, &base);
        }

        // R29-03: the pid died between readdir and here. Caching the namespace
        // now would record an empty listener set and permanently skip every
        // other live pid in it — the whole container would vanish from the
        // inventory with nothing in coverage to say so.
        if !any_read {
            continue;
        }

        // R35-06: no tuple filter. Every socket in a foreign namespace is an
        // inventory item.
        let listeners: Vec<SocketMeta> = foreign.into_values().collect();

        let comm = safe_io::read_procfs_capped(&format!("{proc_root_str}/{pid}/comm"), 4096)
            .ok()
            .map(|(c, _)| c.trim().to_string())
            .unwrap_or_else(|| "?".to_string());

        ns_cache.insert(ns, (listeners, comm));
    }

    let mut result = Vec::new();
    for (ns, (sockets, comm)) in ns_cache {
        for meta in sockets {
            result.push(ForeignNetnsListener {
                netns: ns.clone(),
                protocol: meta.proto.to_string(),
                bind_address: meta.bind_address.clone(),
                port: meta.port.to_string(),
                example_process: Some(comm.clone()),
                container: None, // filled later by runner
                runtime_infrastructure: meta.bind_address == "127.0.0.11",
            });
        }
    }

    // Deterministic order: R29-02, same principle as R28-11.
    result.sort_by(|a, b| {
        a.netns
            .cmp(&b.netns)
            .then_with(|| a.protocol.cmp(&b.protocol))
            .then_with(|| a.bind_address.cmp(&b.bind_address))
            .then_with(|| {
                a.port
                    .parse::<u16>()
                    .unwrap_or(0)
                    .cmp(&b.port.parse::<u16>().unwrap_or(0))
            })
    });

    if ns_denied > 0 {
        coverage::record(format!(
            "netns visibility: {proc_root_str}/<pid>/ns/net unreadable for {ns_denied} process(es) \
             (needs root/CAP_SYS_PTRACE) — foreign-namespace listeners are a LOWER BOUND"
        ));
    }
    if ns_over_cap > 0 {
        coverage::record(format!(
            "netns visibility: cap ({MAX_FOREIGN_NETNS}) reached; {ns_over_cap} further \
             process(es) in unprobed namespaces — foreign listeners are a LOWER BOUND"
        ));
    }

    result
}

pub fn attribute_sockets(wanted: &HashMap<u64, SocketMeta>) -> HashMap<u64, ProcAttr> {
    attribute_sockets_from(Path::new("/proc"), wanted)
}

/// M9: same walk, rooted at `proc_root`. Production uses `/proc`; tests pass
/// a tempdir. Returns `inode -> ProcAttr` for every socket in `wanted` that
/// could be attributed to a live pid's `/proc/<pid>/fd`.
pub fn attribute_sockets_from(
    proc_root: &Path,
    wanted: &HashMap<u64, SocketMeta>,
) -> HashMap<u64, ProcAttr> {
    let mut attributed: HashMap<u64, ProcAttr> = HashMap::new();
    if wanted.is_empty() {
        return attributed;
    }

    let mut pids: Vec<u32> = Vec::new();
    if let Ok(entries) = fs::read_dir(proc_root) {
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

        let pid_dir = proc_root.join(pid.to_string());
        let fd_dir = pid_dir.join("fd");
        let fds = match fs::read_dir(&fd_dir) {
            Ok(f) => f,
            // R33-05: the pid exited between the outer readdir(proc_root) and
            // this readdir. A race, not a permission fact. Before this fix
            // every vanishing pid on a busy host bumped `denied` and inflated
            // the "port attribution incomplete" line.
            Err(e) => match safe_io::proc_miss(&e) {
                safe_io::ProcMiss::Vanished => continue,
                _ => {
                    denied += 1;
                    continue;
                }
            },
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
                    fs::read_link(pid_dir.join("exe"))
                        .ok()
                        .map(|p| p.to_string_lossy().into_owned())
                })
                .clone();

            let comm_path = pid_dir.join("comm");
            let comm = comm_cache
                .get_or_insert_with(|| {
                    match safe_io::read_procfs_capped(comm_path.to_string_lossy().as_ref(), 4096) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vanished_pid_does_not_poison_the_namespace_cache() {
        // R29-03: /proc/<pid>/net/tcp for a dead pid is ENOENT, which used to be
        // indistinguishable from "kernel without IPv6".
        let mut into = HashMap::new();
        assert!(
            !parse_proc_net(Proto::Tcp, &mut into, "/proc/4194305"),
            "an unreadable base_dir must report false so the caller retries"
        );
        assert!(into.is_empty());

        let mut host = HashMap::new();
        assert!(
            parse_proc_net(Proto::Tcp, &mut host, "/proc"),
            "the host namespace must report true even when it yields no listeners"
        );
    }

    // ── R35-06 regression: tuple filter is gone ──────────────────────────

    /// One fake PID with its netns symlink, comm, and a single TCP listener
    /// line. `inode` distinguishes the socket inside its namespace.
    fn fake_ns_pid(root: &Path, pid: u32, netns: &str, inode: u64) {
        let base = root.join(pid.to_string());
        std::fs::create_dir_all(base.join("ns")).unwrap();
        std::fs::create_dir_all(base.join("net")).unwrap();
        std::os::unix::fs::symlink(netns, base.join("ns/net")).unwrap();
        std::fs::write(base.join("comm"), "sshd\n").unwrap();
        // 0.0.0.0:22 in the tcp/LE hex encoding, state 0A = LISTEN.
        let line = format!(
            "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 \
             00000000     0        0 {inode} 1 0000 0 0 0 0 0"
        );
        std::fs::write(
            base.join("net/tcp"),
            format!("  sl  local rem st\n{line}\n"),
        )
        .unwrap();
    }

    #[test]
    fn a_foreign_listener_survives_a_matching_host_tuple() {
        // R35-06: the host sshd and a container sshd both on 0.0.0.0:22.
        // Under the old tuple filter the container listener was dropped —
        // it looked like the host's. Identity is the inode, and inodes never
        // cross namespaces.
        let tmp = tempfile::tempdir().unwrap();
        fake_ns_pid(tmp.path(), 1, "net:[1]", 5001);
        fake_ns_pid(tmp.path(), 4242, "net:[2]", 6001);
        let out = report_foreign_netns_listeners_from(tmp.path());
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(
            (
                out[0].netns.as_str(),
                out[0].bind_address.as_str(),
                out[0].port.as_str()
            ),
            ("net:[2]", "0.0.0.0", "22")
        );
    }

    // ── M9: full-fixture test ─────────────────────────────────

    /// Two-namespace fixture:
    ///   host netns `net:[1]` — socket 12345 listening on 8080, owned by
    ///     pid 100 (`nginx`), so `attribute_sockets` can find it via fd 3;
    ///   foreign netns `net:[2]` — pid 4242 (`sandboxed`) listening on 9000.
    fn fake_proc(root: &Path) {
        use std::os::unix::fs::symlink;
        let tcp = |port: u16, inode: u64| {
            format!(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                 \x20  0: 00000000:{port:04X} 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 {inode} 1 0000000000000000 100 0 0 10 0\n"
            )
        };

        // Host's own socket table (read by collect_listening_sockets_from).
        std::fs::create_dir_all(root.join("net")).unwrap();
        std::fs::write(root.join("net/tcp"), tcp(8080, 12345)).unwrap();

        // PID 1 in the host netns — provides the reference host_ns.
        std::fs::create_dir_all(root.join("1/ns")).unwrap();
        symlink("net:[1]", root.join("1/ns/net")).unwrap();

        // PID 100 in the host netns, owning socket 12345 via fd 3.
        std::fs::create_dir_all(root.join("100/ns")).unwrap();
        std::fs::create_dir_all(root.join("100/fd")).unwrap();
        symlink("net:[1]", root.join("100/ns/net")).unwrap();
        symlink("socket:[12345]", root.join("100/fd/3")).unwrap();
        symlink("/usr/sbin/nginx", root.join("100/exe")).unwrap();
        std::fs::write(root.join("100/comm"), "nginx\n").unwrap();

        // PID 4242 in a foreign netns with its own listener on 9000.
        std::fs::create_dir_all(root.join("4242/ns")).unwrap();
        std::fs::create_dir_all(root.join("4242/net")).unwrap();
        symlink("net:[2]", root.join("4242/ns/net")).unwrap();
        std::fs::write(root.join("4242/net/tcp"), tcp(9000, 777)).unwrap();
        std::fs::write(root.join("4242/comm"), "sandboxed\n").unwrap();
    }

    #[test]
    fn host_inventory_foreign_netns_and_attribution_work_on_a_fixture() {
        let tmp = tempfile::tempdir().unwrap();
        fake_proc(tmp.path());

        // collect_listening_sockets_from reads `{root}/net/tcp`.
        let host = collect_listening_sockets_from(tmp.path());
        assert_eq!(host.get(&12345).map(|s| s.port), Some(8080));

        // report_foreign_netns_listeners_from compares against pid 1's netns.
        let (foreign, cov) =
            crate::coverage::capture(|| report_foreign_netns_listeners_from(tmp.path()));
        assert_eq!(foreign.len(), 1, "{foreign:?}");
        assert_eq!(foreign[0].netns, "net:[2]");
        assert_eq!(foreign[0].port, "9000");
        assert_eq!(foreign[0].example_process.as_deref(), Some("sandboxed"));
        assert!(
            cov.is_empty(),
            "complete fixture must not degrade coverage: {cov:?}"
        );

        // attribute_sockets_from walks `{root}/<pid>/fd` for each pid.
        let attr = attribute_sockets_from(tmp.path(), &host);
        let a = attr.get(&12345).expect("host socket attributed");
        assert_eq!(a.pid, Some(100));
        assert_eq!(a.exe_path.as_deref(), Some("/usr/sbin/nginx"));
        assert_eq!(a.comm.as_deref(), Some("nginx"));
    }
}
