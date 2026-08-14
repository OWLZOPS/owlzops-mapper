//! Reverse-shell / C2 detection (SEC-022).
//!
//! Correlates ESTABLISHED outbound TCP sockets (`/proc/net/tcp{,6}`) with the
//! processes that own them (`/proc/<pid>/fd`), and flags the narrow, high-signal
//! case: an interactive interpreter (bash/sh/python/nc/socat/…) whose socket is
//! wired to a stdio fd (0/1/2) and points at a PUBLIC remote address.
//!
//! FP control is by funnel, not exclusion list:
//!   interpreter allowlist ∧ established outbound ∧ public remote ∧ stdio-fd.
//! A legit `bash` spawning `curl` does NOT match — the socket belongs to curl.
//! Internal targets (RFC1918/loopback/CGNAT/ULA) are intentionally NOT flagged
//! to keep the exit(3) signal near-zero-FP, at the cost of missing LAN-local C2.
//!
//! R24-115: the stdio-fd leg of the funnel is now mandatory. Previously a
//! socket on a HIGH fd (e.g. a python agent making an ordinary HTTPS API call)
//! still produced a finding, causing exit(3) false positives.
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

// ── Remote endpoint of an established socket ──────────────────────────────

#[derive(Clone)]
struct EstSocket {
    remote: String, // "ip:port", decoded
    public: bool,
}

pub fn scan_reverse_shells() -> Vec<ReverseShellFinding> {
    let established = collect_established("/proc/net/tcp", false);
    let mut all = established;
    all.extend(collect_established("/proc/net/tcp6", true));
    correlate_with_processes(&all, "/proc")
}

// ── /proc/net/tcp{,6} → inode → established remote ────────────────────────

fn collect_established(path: &str, v6: bool) -> HashMap<u64, EstSocket> {
    let mut map = HashMap::new();
    let (content, truncated) = match safe_io::read_file_capped(path, safe_io::CAP_PROC_NET) {
        Ok(v) => v,
        // Kernel without IPv6 has no /proc/net/tcp6 – silence is correct.
        Err(e) if e.kind() == ErrorKind::NotFound => return map,
        Err(e) => {
            coverage::record(format!(
                "{path} unreadable ({}) — SEC-022 reverse-shell correlation NOT performed",
                e.kind()
            ));
            return map;
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
        // The real /proc/net/tcp layout after st is:
        // tx_queue:rx_queue  tr:tm->when  retrnsmt  uid  timeout  inode ...
        // Because the paired fields are separated by ':', not space,
        // split_ascii_whitespace treats them as single tokens.
        // So we skip exactly 5 tokens to land on inode.
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
    map
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
        // Unwrap IPv4-mapped addresses (::ffff:a.b.c.d) and classify as IPv4.
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

// ── /proc/<pid>/fd correlation ────────────────────────────────────────────

fn correlate_with_processes(
    established: &HashMap<u64, EstSocket>,
    proc_root: &str,
) -> Vec<ReverseShellFinding> {
    let mut findings = Vec::new();
    if established.is_empty() {
        return findings;
    }

    let mut denied = 0usize;
    let entries = match fs::read_dir(proc_root) {
        Ok(e) => e,
        Err(_) => {
            coverage::record(format!(
                "reverse-shell scan skipped: {proc_root} unreadable"
            ));
            return findings;
        }
    };

    const MAX_FD_PER_PID: usize = 4096;

    for entry in entries.flatten() {
        if findings.len() >= MAX_FINDINGS {
            break;
        }
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };

        // Cheap gate: read comm first, skip non-interpreters before the fd walk.
        let comm = match safe_io::read_file_capped(&format!("{proc_root}/{pid}/comm"), 4096) {
            Ok((c, _)) => c.trim().to_string(),
            Err(_) => continue,
        };
        if !is_shell_comm(&comm) {
            continue;
        }

        let fd_dir = format!("{proc_root}/{pid}/fd");
        let fds = match fs::read_dir(&fd_dir) {
            Ok(f) => f,
            Err(_) => {
                denied += 1;
                continue;
            }
        };

        let mut exe_cache: Option<Option<String>> = None;
        let mut best: Option<ReverseShellFinding> = None;
        let mut fd_seen = 0usize;

        for fd in fds.flatten() {
            fd_seen += 1;
            if fd_seen > MAX_FD_PER_PID {
                coverage::record(format!(
                    "/proc/{pid}/fd exceeded {MAX_FD_PER_PID} entries – reverse-shell correlation for this pid is partial"
                ));
                break;
            }

            // fd number is the file name (0,1,2,…).
            let fd_num: Option<u8> = fd.file_name().to_str().and_then(|s| s.parse().ok());
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
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

            // R24-115: the stdio-fd leg of the funnel is mandatory. A socket on
            // a HIGH fd (e.g. python HTTPS agent) must NOT produce a finding.
            let stdio_fd = match fd_num {
                Some(n @ 0..=2) => Some(n),
                _ => None,
            };
            if stdio_fd.is_none() {
                continue;
            }

            let exe_path = exe_cache
                .get_or_insert_with(|| {
                    fs::read_link(format!("{proc_root}/{pid}/exe"))
                        .ok()
                        .map(|p| p.to_string_lossy().into_owned())
                })
                .clone();

            let candidate = ReverseShellFinding {
                pid,
                process: comm.clone(),
                exe_path,
                remote_address: sock.remote.clone(),
                stdio_fd,
            };

            // Prefer the first stdio fd found; there is usually just one.
            if best.is_none() {
                best = Some(candidate);
            }
        }

        if let Some(f) = best {
            findings.push(f);
        }
    }

    if denied > 0 {
        let hint = if !crate::is_running_as_root() {
            " — run as root for full fd visibility"
        } else {
            ""
        };
        coverage::record(format!(
            "reverse-shell scan: {denied} /proc/<pid>/fd unreadable{hint}"
        ));
    }

    findings
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

    // ── /proc/net/tcp parsing ───────────────────────────────

    fn write(dir: &std::path::Path, rel: &str, contents: &str) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
    }

    #[test]
    fn parses_established_remote_and_inode() {
        let tmp = tempfile::tempdir().unwrap();
        let line = "  0: 0100007F:8000 08080808:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 555555 1 0000 0 0 0 0 0";
        write(
            tmp.path(),
            "net/tcp",
            &format!("  sl  local rem st ...\n{line}\n"),
        );
        let map = collect_established(tmp.path().join("net/tcp").to_str().unwrap(), false);
        let s = map.get(&555555).expect("inode parsed");
        assert_eq!(s.remote, "8.8.8.8:443");
        assert!(s.public);
    }

    #[test]
    fn skips_non_established() {
        let tmp = tempfile::tempdir().unwrap();
        let line = "  0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0000 0 0 0 0 0";
        write(tmp.path(), "net/tcp", &format!("sl ...\n{line}\n"));
        let map = collect_established(tmp.path().join("net/tcp").to_str().unwrap(), false);
        assert!(map.is_empty());
    }

    // ── End-to-end correlation over a fake /proc ────────────

    fn fake_proc(pid: u32, comm: &str, fd: &str, inode: u64) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join(pid.to_string());
        std::fs::create_dir_all(base.join("fd")).unwrap();
        std::fs::write(base.join("comm"), format!("{comm}\n")).unwrap();
        let _ = symlink("/bin/bash", base.join("exe"));
        symlink(format!("socket:[{inode}]"), base.join("fd").join(fd)).unwrap();
        tmp
    }

    #[test]
    fn bash_stdio_socket_to_public_is_flagged() {
        let proc = fake_proc(1337, "bash", "1", 900900); // fd 1 = stdout
        let mut est = HashMap::new();
        est.insert(
            900900,
            EstSocket {
                remote: "203.0.113.5:443".into(),
                public: true,
            },
        );
        let out = correlate_with_processes(&est, proc.path().to_str().unwrap());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pid, 1337);
        assert_eq!(out[0].process, "bash");
        assert_eq!(out[0].remote_address, "203.0.113.5:443");
        assert_eq!(out[0].stdio_fd, Some(1));
    }

    #[test]
    fn internal_target_is_not_flagged() {
        let proc = fake_proc(1338, "python3", "0", 900901);
        let mut est = HashMap::new();
        est.insert(
            900901,
            EstSocket {
                remote: "10.0.0.9:8080".into(),
                public: false,
            },
        );
        let out = correlate_with_processes(&est, proc.path().to_str().unwrap());
        assert!(out.is_empty(), "internal C2 target must not raise SEC-022");
    }

    #[test]
    fn non_shell_process_is_not_flagged() {
        let proc = fake_proc(1339, "nginx", "5", 900902);
        let mut est = HashMap::new();
        est.insert(
            900902,
            EstSocket {
                remote: "8.8.8.8:443".into(),
                public: true,
            },
        );
        let out = correlate_with_processes(&est, proc.path().to_str().unwrap());
        assert!(out.is_empty(), "nginx holding an outbound socket is normal");
    }

    #[test]
    fn stdio_fd_preferred_over_high_fd() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("1340");
        std::fs::create_dir_all(base.join("fd")).unwrap();
        std::fs::write(base.join("comm"), "bash\n").unwrap();
        symlink("socket:[700]", base.join("fd").join("9")).unwrap();
        symlink("socket:[700]", base.join("fd").join("2")).unwrap();
        let mut est = HashMap::new();
        est.insert(
            700,
            EstSocket {
                remote: "8.8.8.8:1337".into(),
                public: true,
            },
        );
        let out = correlate_with_processes(&est, tmp.path().to_str().unwrap());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].stdio_fd, Some(2));
    }

    #[test]
    fn non_stdio_socket_is_not_flagged() {
        // R24-115 regression: a python HTTPS agent with the socket on fd 9
        // must NOT be flagged as a reverse shell.
        let proc = fake_proc(4242, "python3", "9", 123123);
        let mut est = HashMap::new();
        est.insert(
            123123,
            EstSocket {
                remote: "8.8.8.8:443".into(),
                public: true,
            },
        );
        let out = correlate_with_processes(&est, proc.path().to_str().unwrap());
        assert!(out.is_empty(), "non-stdio socket must not fire SEC-022");
    }

    #[test]
    fn non_socket_fds_are_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("1341");
        std::fs::create_dir_all(base.join("fd")).unwrap();
        std::fs::write(base.join("comm"), "bash\n").unwrap();
        symlink("/dev/null", base.join("fd").join("0")).unwrap();
        let est: HashMap<u64, EstSocket> = HashMap::new();
        let out = correlate_with_processes(&est, tmp.path().to_str().unwrap());
        assert!(out.is_empty());
    }
}
