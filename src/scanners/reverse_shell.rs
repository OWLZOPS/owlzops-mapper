//! Reverse-shell / C2 detection (SEC-022).
//!
//! Correlates ESTABLISHED outbound TCP sockets with the processes that own
//! them, and flags the narrow, high-signal case: an interactive interpreter
//! (bash/sh/python/nc/socat/…) whose socket is wired to a stdio fd (0/1/2)
//! and points at a PUBLIC remote address.
//!
//! R35-01: each interpreter is correlated against the table of ITS OWN
//! network namespace (`/proc/<pid>/net/tcp{,6}`), not the scanner's. The
//! socket on a containerised shell's fd 0/1/2 is never listed in the host's
//! `/proc/net/tcp`, so the host-only table made every such shell invisible.
//! Memory stays flat: candidates are grouped by netns and each table is
//! dropped before the next namespace is read.
//!
//! FP control is by funnel, not exclusion list:
//!   interpreter allowlist ∧ established outbound ∧ public remote ∧ stdio-fd.
//! A legit `bash` spawning `curl` does NOT match — the socket belongs to curl.
//! Internal targets (RFC1918/loopback/CGNAT/ULA) are intentionally NOT flagged
//! to keep the exit(3) signal near-zero-FP, at the cost of missing LAN-local C2.
//!
//! R24-115: the stdio-fd leg of the funnel is mandatory. Previously a socket
//! on a HIGH fd (e.g. a python agent making an ordinary HTTPS API call) still
//! produced a finding, causing exit(3) false positives.
//!
//! `/proc/net/tcp` line 4 (0-based 3) is `st`; 0x01 = ESTABLISHED. Field 2 is
//! the remote `addr:port` in the same hex/LE encoding as the local field.

use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;

use crate::coverage;
use crate::models::ReverseShellFinding;
use crate::safe_io;

use super::proc_net::{decode_v4, decode_v6, socket_inode};

const TCP_ESTABLISHED: u8 = 0x01;

/// Interpreters that have no business owning a raw outbound socket on their
/// stdio. Matched case-insensitively against comm; `python3.11` etc. handled
/// by prefix for the python family.
const SHELL_COMMS: [&str; 11] = [
    "bash", "sh", "dash", "zsh", "ksh", "nc", "ncat", "socat", "perl", "ruby", "php",
];

fn is_shell_comm(comm: &str) -> bool {
    let c = comm.trim();
    SHELL_COMMS.iter().any(|s| c.eq_ignore_ascii_case(s))
        || c.to_ascii_lowercase().starts_with("python")
}

/// Cap on stored findings — a hostile /proc must not drive unbounded growth.
const MAX_FINDINGS: usize = 64;

/// Distinct network namespaces whose tables are parsed. Exhaustion is
/// disclosed via coverage (SEC-022 is a LOWER BOUND when reached).
const MAX_NETNS: usize = 64;

// ── Remote endpoint of an established socket ──────────────────────────────

#[derive(Clone)]
struct EstSocket {
    remote: String, // "ip:port", decoded
    public: bool,
}

// ── Entry point ───────────────────────────────────────────────────────────

pub fn scan_reverse_shells() -> Vec<ReverseShellFinding> {
    scan_reverse_shells_from("/proc")
}

/// R35-01: each interpreter is correlated against the table of its own
/// network namespace. Candidates are grouped by netns; one table is held in
/// memory at a time.
fn scan_reverse_shells_from(proc_root: &str) -> Vec<ReverseShellFinding> {
    let mut findings = Vec::new();
    let entries = match fs::read_dir(proc_root) {
        Ok(e) => e,
        Err(e) => {
            coverage::record(format!(
                "reverse-shell scan skipped: {proc_root} unreadable ({}) — SEC-022 NOT performed",
                e.kind()
            ));
            return findings;
        }
    };

    let mut denied = 0usize;

    // Pass 1: interpreters only (cheap comm gate), each tagged with its netns.
    let mut candidates: Vec<(String, u32, String)> = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let comm = match safe_io::read_procfs_capped(&format!("{proc_root}/{pid}/comm"), 4096) {
            Ok((c, _)) => c.trim().to_string(),
            Err(_) => continue,
        };
        if !is_shell_comm(&comm) {
            continue;
        }
        match fs::read_link(format!("{proc_root}/{pid}/ns/net")) {
            Ok(ns) => candidates.push((ns.to_string_lossy().into_owned(), pid, comm)),
            // R33-05: a vanished pid is a race, not a denial.
            Err(e) if safe_io::proc_miss(&e) == safe_io::ProcMiss::Vanished => {}
            Err(_) => denied += 1,
        }
    }
    // Deterministic: namespace first, then lowest pid (R29-04).
    candidates.sort_unstable();

    let mut netns_parsed = 0usize;
    let mut over_netns_cap = 0usize;
    let mut over_findings_cap = 0usize;

    for group in candidates.chunk_by(|a, b| a.0 == b.0) {
        if netns_parsed >= MAX_NETNS {
            over_netns_cap += group.len();
            continue;
        }
        // One table per namespace, read through the first live pid in it.
        // A pid that exited after pass 1 answers ENOENT: fall through to the
        // next one instead of treating the namespace as socket-less (R29-03).
        // An EACCES on the first pid must not blind the rest either.
        let mut established: Option<HashMap<u64, EstSocket>> = None;
        for (_, pid, _) in group {
            match established_in(proc_root, *pid) {
                NsRead::Ok(m) => {
                    established = Some(m);
                    break;
                }
                NsRead::Vanished => continue,
                NsRead::Denied => {
                    denied += 1;
                    continue;
                }
            }
        }
        let Some(established) = established else {
            continue;
        };
        netns_parsed += 1;
        if established.is_empty() {
            continue;
        }
        for (_, pid, comm) in group {
            if findings.len() >= MAX_FINDINGS {
                over_findings_cap += 1;
                continue;
            }
            match correlate_pid(proc_root, *pid, comm, &established) {
                PidScan::Hit(f) => findings.push(f),
                PidScan::Clean => {}
                PidScan::Denied => denied += 1,
            }
        }
    }

    findings.sort_unstable_by_key(|f| f.pid);

    if denied > 0 {
        let hint = if !crate::is_running_as_root() {
            " — run as root for full fd visibility"
        } else {
            ""
        };
        coverage::record(format!(
            "reverse-shell scan: {denied} process(es) with unreadable /proc/<pid>/ns/net, \
             net/tcp{{,6}} or fd{hint}"
        ));
    }
    if over_netns_cap > 0 {
        coverage::record(format!(
            "reverse-shell scan: namespace cap ({MAX_NETNS}) reached — {over_netns_cap} \
             interpreter(s) in further namespaces NOT correlated; SEC-022 is a LOWER BOUND"
        ));
    }
    if over_findings_cap > 0 {
        coverage::record(format!(
            "reverse-shell scan: finding cap ({MAX_FINDINGS}) reached — {over_findings_cap} \
             further interpreter(s) NOT correlated; SEC-022 is a LOWER BOUND"
        ));
    }
    findings
}

// ── /proc/<pid>/net/tcp{,6} → inode → established remote ──────────────────

/// Outcome of reading one pid's namespace table.
enum NsRead {
    Ok(HashMap<u64, EstSocket>),
    /// ENOENT on `net/tcp` — the pid vanished while we were scanning.
    Vanished,
    /// Unreadable for any other reason; coverage already recorded.
    Denied,
}

/// Established sockets of `pid`'s network namespace. `net/tcp` is mandatory:
/// ENOENT means the pid is gone. A missing `tcp6` is a kernel without IPv6
/// and stays silent; a denied `tcp6` degrades to tcp-only.
fn established_in(proc_root: &str, pid: u32) -> NsRead {
    let mut map = match collect_established(&format!("{proc_root}/{pid}/net/tcp"), false) {
        TableRead::Ok(m) => m,
        TableRead::Missing => return NsRead::Vanished,
        TableRead::Denied => return NsRead::Denied,
    };
    if let TableRead::Ok(v6) = collect_established(&format!("{proc_root}/{pid}/net/tcp6"), true) {
        map.extend(v6);
    }
    NsRead::Ok(map)
}

enum PidScan {
    Hit(ReverseShellFinding),
    Clean,
    Denied,
}

/// R24-115 makes the stdio leg mandatory, so read exactly fd/0..=2 instead of
/// walking /proc/<pid>/fd. Ascending order IS the determinism rule: the
/// lowest stdio fd wins by construction.
fn correlate_pid(
    proc_root: &str,
    pid: u32,
    comm: &str,
    established: &HashMap<u64, EstSocket>,
) -> PidScan {
    for fd in 0u8..=2 {
        let target = match fs::read_link(format!("{proc_root}/{pid}/fd/{fd}")) {
            Ok(t) => t,
            // fd closed, or the pid exited: neither is a denial (R33-05).
            Err(e) if safe_io::proc_miss(&e) == safe_io::ProcMiss::Vanished => continue,
            Err(_) => return PidScan::Denied,
        };
        let Some(inode) = target.to_str().and_then(socket_inode) else {
            continue;
        };
        let Some(sock) = established.get(&inode) else {
            continue;
        };
        if !sock.public {
            continue; // internal target — not flagged (FP control)
        }
        let exe_path = fs::read_link(format!("{proc_root}/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());
        return PidScan::Hit(ReverseShellFinding {
            pid,
            process: comm.to_string(),
            exe_path,
            remote_address: sock.remote.clone(),
            stdio_fd: Some(fd),
        });
    }
    PidScan::Clean
}

// ── Table parser ──────────────────────────────────────────────────────────

/// Outcome of parsing one `net/tcp{,6}` file.
enum TableRead {
    Ok(HashMap<u64, EstSocket>),
    /// ENOENT — the file does not exist. For `tcp` that means the pid
    /// vanished; for `tcp6`, a kernel without IPv6. The caller decides.
    Missing,
    /// Read error other than ENOENT. Coverage already recorded.
    Denied,
}

fn collect_established(path: &str, v6: bool) -> TableRead {
    let mut map = HashMap::new();
    let (content, truncated) = match safe_io::read_procfs_capped(path, safe_io::CAP_PROC_NET) {
        Ok(v) => v,
        Err(e) if e.kind() == ErrorKind::NotFound => return TableRead::Missing,
        Err(e) => {
            coverage::record(format!(
                "{path} unreadable ({}) — SEC-022 correlation NOT performed for this namespace",
                e.kind()
            ));
            return TableRead::Denied;
        }
    };
    if truncated {
        coverage::record(format!(
            "{path} exceeded cap — reverse-shell scan may be incomplete"
        ));
    }

    for line in content.lines().skip(1) {
        let mut p = line.split_ascii_whitespace();
        p.next(); // sl
        let _local = p.next();
        let remote = p.next();
        let st = p.next();
        let (Some(remote_field), Some(st_hex)) = (remote, st) else {
            continue;
        };
        if u8::from_str_radix(st_hex, 16).unwrap_or(0) != TCP_ESTABLISHED {
            continue;
        }
        // Layout after st: tx_queue:rx_queue tr:tm->when retrnsmt uid timeout
        // inode. Because the paired fields are separated by ':' and not space,
        // split_ascii_whitespace sees them as single tokens — skip 5 to land
        // on inode.
        for _ in 0..5 {
            p.next();
        }
        let Some(inode_str) = p.next() else { continue };
        let Ok(inode) = inode_str.parse::<u64>() else {
            continue;
        };
        if inode == 0 {
            continue;
        }

        let Some((ip, port)) = decode_endpoint(remote_field, v6) else {
            continue;
        };
        let public = is_public_addr(&ip);
        map.insert(
            inode,
            EstSocket {
                remote: format!("{ip}:{port}"),
                public,
            },
        );
    }
    TableRead::Ok(map)
}

/// Decode a `addr:port` hex field (LE) into (ip_string, port).
fn decode_endpoint(field: &str, v6: bool) -> Option<(String, u16)> {
    let (addr_hex, port_hex) = field.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = if v6 {
        decode_v6(addr_hex)?
    } else {
        decode_v4(addr_hex)?
    };
    Some((ip, port))
}

// ── Public vs. internal address classification ────────────────────────────

/// True only for globally-routable addresses. RFC1918, loopback, link-local,
/// CGNAT (100.64/10), and IPv6 ULA/loopback are treated as internal (not C2).
/// IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) are converted back to IPv4
/// and classified with the IPv4 rules.
fn is_public_addr(ip: &str) -> bool {
    if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
        let o = v4.octets();
        let internal = v4.is_loopback()
            || v4.is_private()
            || v4.is_link_local()
            || (o[0] == 100 && (o[1] & 0xC0) == 64) // 100.64.0.0/10 CGNAT
            || v4.is_broadcast()
            || v4.is_unspecified()
            || o[0] == 0;
        return !internal;
    }
    if let Ok(v6) = ip.parse::<std::net::Ipv6Addr>() {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return is_public_addr(&v4.to_string());
        }
        let internal = v6.is_loopback()
            || v6.is_unspecified()
            || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 ULA
            || (v6.segments()[0] & 0xffc0) == 0xfe80; // fe80::/10 link-local
        return !internal;
    }
    false // undecodable → don't flag
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::symlink;

    // ── Address classification ──────────────────────────────

    #[test]
    fn public_v4_is_public() {
        assert!(is_public_addr("8.8.8.8"));
        assert!(is_public_addr("203.0.113.10"));
    }

    #[test]
    fn internal_v4_is_not_public() {
        for ip in [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "0.0.0.0",
        ] {
            assert!(!is_public_addr(ip), "{ip} must be internal");
        }
    }

    #[test]
    fn v6_loopback_and_ula_not_public() {
        assert!(!is_public_addr("::1"));
        assert!(!is_public_addr("fc00::1"));
        assert!(!is_public_addr("fe80::1"));
        assert!(is_public_addr("2606:4700:4700::1111"));
    }

    #[test]
    fn v4_mapped_ipv6_classification() {
        assert!(is_public_addr("::ffff:8.8.8.8"));
        assert!(!is_public_addr("::ffff:10.0.0.1"));
        assert!(!is_public_addr("::ffff:192.168.1.1"));
        assert!(is_public_addr("2001:4860:4860::8888"));
        assert!(!is_public_addr("fe80::1"));
    }

    // ── comm allowlist ──────────────────────────────────────

    #[test]
    fn shell_comm_matches_family() {
        assert!(is_shell_comm("bash"));
        assert!(is_shell_comm("SH"));
        assert!(is_shell_comm("python3.11"));
        assert!(is_shell_comm("socat"));
        assert!(!is_shell_comm("nginx"));
        assert!(!is_shell_comm("curl"));
        assert!(!is_shell_comm("systemd"));
    }

    // ── helpers ─────────────────────────────────────────────

    fn write(dir: &std::path::Path, rel: &str, contents: &str) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
    }

    fn est_line(inode: u64, remote_hex: &str) -> String {
        format!(
            "  0: 0100007F:8000 {remote_hex} 01 00000000:00000000 00:00000000 00000000  1000        0 {inode} 1 0000 0 0 0 0 0"
        )
    }

    // ── /proc/net/tcp parsing ───────────────────────────────

    #[test]
    fn parses_established_remote_and_inode() {
        let tmp = tempfile::tempdir().unwrap();
        let body = format!(
            "  sl  local rem st ...\n{}\n",
            est_line(555555, "08080808:01BB")
        );
        write(tmp.path(), "net/tcp", &body);
        let TableRead::Ok(map) =
            collect_established(tmp.path().join("net/tcp").to_str().unwrap(), false)
        else {
            panic!("table should be readable");
        };
        let s = map.get(&555555).expect("inode parsed");
        assert_eq!(s.remote, "8.8.8.8:443");
        assert!(s.public);
    }

    #[test]
    fn skips_non_established() {
        let tmp = tempfile::tempdir().unwrap();
        let line = "  0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0000 0 0 0 0 0";
        write(tmp.path(), "net/tcp", &format!("sl ...\n{line}\n"));
        let TableRead::Ok(map) =
            collect_established(tmp.path().join("net/tcp").to_str().unwrap(), false)
        else {
            panic!();
        };
        assert!(map.is_empty());
    }

    #[test]
    fn a_missing_table_is_missing_not_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("net/tcp");
        assert!(matches!(
            collect_established(p.to_str().unwrap(), false),
            TableRead::Missing
        ));
    }

    // ── End-to-end correlation over a fake /proc ────────────

    fn fake_pid(
        root: &std::path::Path,
        pid: u32,
        comm: &str,
        netns: &str,
        sockets: &[(u8, u64)],
        tcp: Option<&str>,
    ) {
        let base = root.join(pid.to_string());
        std::fs::create_dir_all(base.join("fd")).unwrap();
        std::fs::create_dir_all(base.join("ns")).unwrap();
        std::fs::write(base.join("comm"), format!("{comm}\n")).unwrap();
        symlink(netns, base.join("ns/net")).unwrap();
        let _ = symlink("/bin/bash", base.join("exe"));
        for (fd, inode) in sockets {
            symlink(
                format!("socket:[{inode}]"),
                base.join("fd").join(fd.to_string()),
            )
            .unwrap();
        }
        if let Some(line) = tcp {
            write(
                &base,
                "net/tcp",
                &format!("  sl  local rem st ...\n{line}\n"),
            );
        }
    }

    fn scan(root: &tempfile::TempDir) -> Vec<ReverseShellFinding> {
        scan_reverse_shells_from(root.path().to_str().unwrap())
    }

    #[test]
    fn containerised_reverse_shell_is_flagged() {
        // R35-01: the socket exists only in the container's namespace table.
        let tmp = tempfile::tempdir().unwrap();
        fake_pid(tmp.path(), 1, "bash", "net:[4026531840]", &[], Some(""));
        let est = est_line(777, "08080808:01BB");
        fake_pid(
            tmp.path(),
            4242,
            "bash",
            "net:[4026532999]",
            &[(0, 777), (1, 777)],
            Some(&est),
        );
        let out = scan(&tmp);
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].pid, 4242);
        assert_eq!(out[0].remote_address, "8.8.8.8:443");
        assert_eq!(out[0].stdio_fd, Some(0));
    }

    #[test]
    fn a_vanished_pid_does_not_blind_its_namespace() {
        // R29-03 shape: the namespace's first pid exited (no net/tcp).
        let tmp = tempfile::tempdir().unwrap();
        fake_pid(tmp.path(), 100, "sh", "net:[1]", &[], None);
        let est = est_line(900, "08080808:01BB");
        fake_pid(tmp.path(), 101, "bash", "net:[1]", &[(2, 900)], Some(&est));
        let out = scan(&tmp);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pid, 101);
        assert_eq!(out[0].stdio_fd, Some(2));
    }

    #[test]
    fn a_denied_first_pid_does_not_blind_its_namespace() {
        // Regression: first pid in the netns is unreadable (EACCES via a
        // non-readable directory standing in for net/tcp), second one is
        // readable and holds the socket. Must still fire.
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let est = est_line(901, "08080808:01BB");
        fake_pid(tmp.path(), 100, "sh", "net:[1]", &[], Some(&est));
        let tcp = tmp.path().join("100/net/tcp");
        std::fs::remove_file(&tcp).unwrap();
        std::fs::create_dir(&tcp).unwrap();
        std::fs::set_permissions(&tcp, std::fs::Permissions::from_mode(0o000)).unwrap();
        fake_pid(tmp.path(), 101, "bash", "net:[1]", &[(0, 901)], Some(&est));
        let out = scan(&tmp);
        // Root can read through 0o000; non-root cannot. Either way the
        // second pid must be correlated if the first is unreadable.
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(out.len(), 1, "{out:?}");
            assert_eq!(out[0].pid, 101);
        }
        let _ = std::fs::set_permissions(&tcp, std::fs::Permissions::from_mode(0o755));
    }

    #[test]
    fn internal_target_is_not_flagged() {
        let tmp = tempfile::tempdir().unwrap();
        let est = est_line(901, "0900000A:1F90"); // 10.0.0.9:8080
        fake_pid(
            tmp.path(),
            1338,
            "python3",
            "net:[1]",
            &[(0, 901)],
            Some(&est),
        );
        assert!(
            scan(&tmp).is_empty(),
            "internal C2 target must not raise SEC-022"
        );
    }

    #[test]
    fn non_shell_process_is_not_flagged() {
        let tmp = tempfile::tempdir().unwrap();
        let est = est_line(902, "08080808:01BB");
        fake_pid(
            tmp.path(),
            1339,
            "nginx",
            "net:[1]",
            &[(0, 902)],
            Some(&est),
        );
        assert!(
            scan(&tmp).is_empty(),
            "nginx holding an outbound socket is normal"
        );
    }

    #[test]
    fn non_stdio_socket_is_not_flagged() {
        // R24-115 regression: python HTTPS agent with the socket on fd 9.
        let tmp = tempfile::tempdir().unwrap();
        let est = est_line(903, "08080808:01BB");
        fake_pid(
            tmp.path(),
            4243,
            "python3",
            "net:[1]",
            &[(9, 903)],
            Some(&est),
        );
        assert!(
            scan(&tmp).is_empty(),
            "non-stdio socket must not fire SEC-022"
        );
    }

    #[test]
    fn lowest_stdio_fd_wins_deterministically() {
        let tmp = tempfile::tempdir().unwrap();
        let est = est_line(700, "08080808:0539"); // 8.8.8.8:1337
        fake_pid(
            tmp.path(),
            1340,
            "bash",
            "net:[1]",
            &[(9, 700), (2, 700), (1, 700)],
            Some(&est),
        );
        let out = scan(&tmp);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].stdio_fd, Some(1));
    }

    #[test]
    fn non_socket_fds_are_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let est = est_line(704, "08080808:01BB");
        fake_pid(tmp.path(), 1341, "bash", "net:[1]", &[], Some(&est));
        symlink("/dev/null", tmp.path().join("1341/fd/0")).unwrap();
        assert!(scan(&tmp).is_empty());
    }
}
