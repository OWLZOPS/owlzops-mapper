//! Agentless Linux capability audit: parses CapInh/CapPrm/CapEff/CapBnd/CapAmb
//! from /proc/<pid>/status and flags non-root processes holding critical
//! kernel capabilities. std-only, zero-copy line parsing, no new crates.

use std::fmt::Write;
use std::path::Path;

use crate::models::{ProcCapFinding, SuspiciousProcess};
use crate::{coverage, safe_io};

// ── Capability bit numbers (include/uapi/linux/capability.h) ────────────

pub const CAP_DAC_OVERRIDE: u32 = 1;
pub const CAP_NET_RAW: u32 = 13;
pub const CAP_SYS_PTRACE: u32 = 19;
pub const CAP_SYS_ADMIN: u32 = 21;

/// Escalation-grade capabilities when held by a non-root process.
pub const CRITICAL_CAPS: &[(u32, &str)] = &[
    (CAP_SYS_ADMIN, "CAP_SYS_ADMIN"),
    (CAP_SYS_PTRACE, "CAP_SYS_PTRACE"),
    (CAP_DAC_OVERRIDE, "CAP_DAC_OVERRIDE"),
    (CAP_NET_RAW, "CAP_NET_RAW"),
];

/// index == capability number; CAP_LAST_CAP = 40 as of Linux 5.9+.
pub const CAP_NAMES: [&str; 41] = [
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
];

#[inline]
const fn bit(cap: u32) -> u64 {
    1u64 << cap
}

/// Decode a mask into names. Unknown high bits (future kernels) are rendered
/// as `CAP_<n>` instead of being dropped — raw truth over aesthetics.
pub fn decode_mask(mask: u64) -> Vec<String> {
    (0..u64::BITS)
        .filter(|&b| mask & bit(b) != 0)
        .map(|b| match CAP_NAMES.get(b as usize) {
            Some(name) => (*name).to_string(),
            None => format!("CAP_{b}"),
        })
        .collect()
}

// ── Parsing ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CapabilitySets {
    pub inheritable: u64,
    pub permitted: u64,
    pub effective: u64,
    pub bounding: u64,
    /// 0 on kernels < 4.3 (line absent).
    pub ambient: u64,
}

/// Subset of /proc/<pid>/status needed for the audit.
#[derive(Debug, Clone)]
pub struct ProcStatus {
    pub name: String,
    pub euid: u32,
    pub caps: CapabilitySets,
    /// `NoNewPrivs:` line – present since Linux 4.10; None on older kernels.
    pub no_new_privs: Option<bool>,
    /// `Seccomp:` 0 = disabled, 1 = strict, 2 = filter.
    /// Line present since Linux 3.8 and only with CONFIG_SECCOMP.
    pub seccomp: Option<u8>,
}

/// Strict decimal u8 field (e.g. `Seccomp:\t2`).  Rejects signs and
/// non‑digit bytes – bare `str::parse` would accept a leading `+`,
/// same rationale as `parse_hex_mask`.  Zero‑copy: operates on the slice.
fn parse_u8_field(value: &str) -> Option<u8> {
    let v = value.trim_ascii();
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    v.parse().ok() // > 255 overflows → None
}

/// Strict hex parser: rejects empty, >16 chars, signs and radix prefixes.
/// `from_str_radix` alone would accept a leading `+` — we don't (defensive
/// parsing: /proc content is treated as untrusted).
fn parse_hex_mask(value: &str) -> Option<u64> {
    let hex = value.trim_ascii();
    if hex.is_empty() || hex.len() > 16 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}

/// Single-pass, zero-copy parse of a `status` buffer. Returns `None` if the
/// four mandatory Cap* lines or Name/Uid are missing (truncated read, exotic
/// kernel). Last occurrence wins: real kernel Cap* lines always follow the
/// (kernel-escaped) `Name:` field, so a hostile comm cannot spoof masks.
pub fn parse_status(content: &str) -> Option<ProcStatus> {
    let mut name: Option<&str> = None;
    let mut euid: Option<u32> = None;
    let mut caps = CapabilitySets::default();
    let mut seen = 0u8;
    let mut no_new_privs: Option<bool> = None;
    let mut seccomp: Option<u8> = None;

    for line in content.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key {
            "Name" => name = Some(value.trim_ascii()),
            "Uid" => {
                // Uid: <real> <effective> <saved> <fs>
                euid = value
                    .split_ascii_whitespace()
                    .nth(1)
                    .and_then(|f| f.parse().ok());
            }
            "CapInh" => {
                if let Some(m) = parse_hex_mask(value) {
                    caps.inheritable = m;
                    seen |= 1 << 0;
                }
            }
            "CapPrm" => {
                if let Some(m) = parse_hex_mask(value) {
                    caps.permitted = m;
                    seen |= 1 << 1;
                }
            }
            "CapEff" => {
                if let Some(m) = parse_hex_mask(value) {
                    caps.effective = m;
                    seen |= 1 << 2;
                }
            }
            "CapBnd" => {
                if let Some(m) = parse_hex_mask(value) {
                    caps.bounding = m;
                    seen |= 1 << 3;
                }
            }
            "CapAmb" => {
                if let Some(m) = parse_hex_mask(value) {
                    caps.ambient = m;
                }
            }
            "NoNewPrivs" => {
                no_new_privs = match parse_u8_field(value) {
                    Some(0) => Some(false),
                    Some(1) => Some(true),
                    _ => None,
                };
            }
            "Seccomp" => seccomp = parse_u8_field(value),
            _ => {}
        }
    }

    if seen != 0b1111 {
        return None;
    }
    Some(ProcStatus {
        name: name?.to_string(),
        euid: euid?,
        caps,
        no_new_privs,
        seccomp,
    })
}

// ── Suspicious process classification ────────────────────────────────────

/// Hard cap on stored suspicious processes — keeps JSONL flat under a fork-bomb
/// of a matched implant name.
const MAX_SUSPICIOUS: usize = 64;

/// Classify one process from its comm and (already-resolved) exe link.
///
/// Two independent triggers, name-independent for the deleted case:
///   * deleted executable whose *base* path is ephemeral (fileless implant);
///   * name in the malware blocklist (explicit always; ambiguous only when
///     the clean exe path is ephemeral).
///
/// Returns the record (if any) plus a flag: an ambiguous name whose exe could
/// not be resolved (so the caller can aggregate a coverage warning).
///
/// Pure & zero-copy: only the final record allocates.
fn classify_suspicious(
    comm: &str,
    pid: u32,
    exe_link: Option<&str>,
) -> (Option<SuspiciousProcess>, bool) {
    // Split the kernel's " (deleted)" suffix off the true base path.
    let (base_path, deleted) = match exe_link {
        Some(l) => match l.strip_suffix(" (deleted)") {
            Some(base) => (Some(base), true),
            None => (Some(l), false),
        },
        None => (None, false),
    };

    // Trigger 1 — fileless execution, two forms:
    //   (a) deleted executable whose base path is ephemeral — FP-protected:
    //       system-path deletions (apt upgrade) are excluded; OR
    //   (b) a /memfd: base path — memfd_create-backed, in-memory-only — which is
    //       intrinsically fileless whether or not the kernel appended the
    //       " (deleted)" suffix (some kernels/configs omit it).
    // NOTE: `deleted_ephemeral` is now a slight misnomer — it means "fileless"
    // (cf. the is_deleted Note from the SEC-017 session); kept for continuity
    // with the field it feeds. Zero-copy: starts_with / is_some_and, no alloc.
    let deleted_ephemeral = base_path.is_some_and(|p| {
        (deleted && crate::utils::is_ephemeral_exec_path(p)) || p.starts_with("/memfd:")
    });

    // Trigger 2 — name blocklist.
    let name_recorded = if crate::utils::is_known_malware(comm) {
        true
    } else if crate::utils::is_ambiguous_malware(comm) {
        match base_path {
            Some(p) if crate::utils::is_ephemeral_exec_path(p) => true,
            Some(_) => false,            // ambiguous name, legit path → not flagged
            None => return (None, true), // ambiguous name, exe unresolved → dropped
        }
    } else {
        false
    };

    if name_recorded || deleted_ephemeral {
        (
            Some(SuspiciousProcess {
                pid,
                name: comm.trim().to_string(),
                exe_path: base_path.map(str::to_string), // cleaned of the suffix
                is_deleted: deleted_ephemeral,
            }),
            false,
        )
    } else {
        (None, false)
    }
}

// ── Walker ───────────────────────────────────────────────────────────────

/// Hard cap on stored capability findings.
const MAX_FINDINGS: usize = 64;
/// status is ~1–3 KiB; 16 KiB leaves headroom for long Groups:/Cpus_allowed:.
const CAP_PROC_STATUS: usize = 16 * 1024;

/// Walk `proc_root` (production: `/proc`; tests: tempdir) and flag non-root
/// processes with critical CapEff|CapPrm bits or any ambient set.
/// Root (euid 0) is skipped for capability findings but is still inspected
/// for malware names (to catch root-run implants).
/// Returns a tuple of (capability findings, suspicious process names).
pub fn audit_host_processes(proc_root: &Path) -> (Vec<ProcCapFinding>, Vec<SuspiciousProcess>) {
    let mut findings = Vec::new();
    let mut suspicious = Vec::new();
    let mut denied = 0usize;
    let mut over_cap = 0usize;
    let mut ambiguous_dropped = 0usize;

    let entries = match std::fs::read_dir(proc_root) {
        Ok(e) => e,
        Err(err) => {
            coverage::record(format!(
                "capability audit skipped: {} unreadable ({err})",
                proc_root.display()
            ));
            return (findings, suspicious);
        }
    };

    let mut path_buf = String::with_capacity(64);

    for entry in entries.flatten() {
        let Ok(file_name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = file_name.parse::<u32>() else {
            continue; // non-PID entries: self, sys, net, …
        };

        path_buf.clear();
        let _ = write!(path_buf, "{}/{pid}/status", proc_root.display());

        let (content, truncated) = match safe_io::read_file_capped(&path_buf, CAP_PROC_STATUS) {
            Ok(v) => v,
            Err(_) => {
                // TOCTOU exit churn (dir gone) is normal; a still-present but
                // unreadable status means hidepid/LSM restriction — count it.
                if entry.path().exists() {
                    denied += 1;
                }
                continue;
            }
        };
        if truncated {
            coverage::record(format!("{path_buf} truncated"));
        }

        let Some(st) = parse_status(&content) else {
            coverage::record(format!("{path_buf}: mandatory Cap*/Uid fields missing"));
            continue;
        };

        // Suspicious-process sweep — runs for EVERY process (root included),
        // BEFORE the capability euid==0 suppression. One readlink per process
        // (required for fileless detection), reused for name exe_path.
        let exe_link = std::fs::read_link(format!("{}/{pid}/exe", proc_root.display()))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());
        let (record, dropped) = classify_suspicious(&st.name, pid, exe_link.as_deref());
        if dropped {
            ambiguous_dropped += 1;
        }
        if let Some(sp) = record
            && suspicious.len() < MAX_SUSPICIOUS
        {
            suspicious.push(sp);
        }

        if st.euid == 0 {
            continue; // root: full capability masks are the default — flagging is noise
        }

        // Possession, not acquisition potential: bounding excluded on purpose.
        let scope = st.caps.effective | st.caps.permitted;
        let critical: Vec<String> = CRITICAL_CAPS
            .iter()
            .copied()
            .filter(|&(b, _)| scope & bit(b) != 0)
            .map(|(_, name)| name.to_string())
            .collect();

        if critical.is_empty() && st.caps.ambient == 0 {
            continue;
        }
        if findings.len() >= MAX_FINDINGS {
            over_cap += 1;
            continue;
        }

        findings.push(ProcCapFinding {
            pid,
            comm: st.name,
            euid: st.euid,
            effective: st.caps.effective,
            permitted: st.caps.permitted,
            inheritable: st.caps.inheritable,
            bounding: st.caps.bounding,
            ambient: st.caps.ambient,
            no_new_privs: st.no_new_privs,
            seccomp: st.seccomp,
            critical_caps: critical,
        });
    }

    if denied > 0 {
        let hint = if crate::is_running_as_root() {
            ""
        } else {
            " — run as root for full coverage"
        };
        coverage::record(format!(
            "capability audit: {denied} /proc/<pid>/status unreadable{hint}"
        ));
    }
    if over_cap > 0 {
        coverage::record(format!(
            "capability audit: finding cap ({MAX_FINDINGS}) reached; {over_cap} more processes matched but were not recorded"
        ));
    }
    if ambiguous_dropped > 0 {
        let hint = if crate::is_running_as_root() {
            ""
        } else {
            " — run as root to resolve exe paths"
        };
        coverage::record(format!(
            "malware sweep: {ambiguous_dropped} ambiguous name match(es) unresolved (exe unreadable){hint}"
        ));
    }

    findings.sort_unstable_by_key(|f| f.pid);
    suspicious.sort_unstable_by_key(|s| s.pid);
    (findings, suspicious)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;

    const FULL_ROOT: &str = "Name:\tsystemd\nUmask:\t0022\nState:\tS (sleeping)\n\
Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n\
CapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\n\
CapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n\
NoNewPrivs:\t0\nSeccomp:\t0\n";

    // Docker default cap set held by a non-root container process.
    const DOCKER_DEFAULT_NONROOT: &str = "Name:\tnginx\nUid:\t101\t101\t101\t101\n\
CapInh:\t0000000000000000\nCapPrm:\t00000000a80425fb\nCapEff:\t00000000a80425fb\n\
CapBnd:\t00000000a80425fb\nCapAmb:\t0000000000000000\n\
NoNewPrivs:\t0\nSeccomp:\t2\n";

    fn write_proc(root: &Path, pid: u32, status: &str) {
        let dir = root.join(pid.to_string());
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("status"), status).unwrap();
    }

    #[test]
    fn parses_full_root_mask() {
        let st = parse_status(FULL_ROOT).expect("parse");
        assert_eq!(st.name, "systemd");
        assert_eq!(st.euid, 0);
        assert_eq!(st.caps.effective, 0x0000_01ff_ffff_ffff);
        assert_eq!(st.caps.ambient, 0);
        assert_eq!(st.no_new_privs, Some(false));
        assert_eq!(st.seccomp, Some(0));
    }

    #[test]
    fn hex_mask_rejects_garbage() {
        assert_eq!(parse_hex_mask("\t000001ffffffffff"), Some(0x1ff_ffff_ffff));
        assert_eq!(parse_hex_mask(" ff "), Some(0xff));
        assert_eq!(parse_hex_mask(""), None);
        assert_eq!(parse_hex_mask("\t"), None);
        assert_eq!(parse_hex_mask("0x1f"), None); // no radix prefixes
        assert_eq!(parse_hex_mask("+ff"), None); // from_str_radix alone accepts this
        assert_eq!(parse_hex_mask("zzzz"), None);
        assert_eq!(parse_hex_mask("00000000000000000"), None); // 17 chars
    }

    #[test]
    fn u8_field_rejects_garbage() {
        assert_eq!(parse_u8_field("\t2"), Some(2));
        assert_eq!(parse_u8_field(" 0 "), Some(0));
        assert_eq!(parse_u8_field("03"), Some(3));
        assert_eq!(parse_u8_field(""), None);
        assert_eq!(parse_u8_field("+1"), None); // bare str::parse would accept this
        assert_eq!(parse_u8_field("-1"), None);
        assert_eq!(parse_u8_field("x"), None);
        assert_eq!(parse_u8_field("256"), None); // u8 overflow
    }

    #[test]
    fn truncated_status_returns_none() {
        let cut = &FULL_ROOT[..FULL_ROOT.find("CapBnd").unwrap()];
        assert!(parse_status(cut).is_none());
    }

    #[test]
    fn missing_capamb_is_tolerated() {
        // Kernels < 4.3 emit no CapAmb line.
        let legacy = FULL_ROOT.replace("CapAmb:\t0000000000000000\n", "");
        let st = parse_status(&legacy).expect("parse");
        assert_eq!(st.caps.ambient, 0);
    }

    #[test]
    fn missing_nnp_and_seccomp_lines_are_none() {
        // Kernels < 4.10 / no CONFIG_SECCOMP: lines absent, parse must succeed.
        let legacy = FULL_ROOT
            .replace("NoNewPrivs:\t0\n", "")
            .replace("Seccomp:\t0\n", "");
        let st = parse_status(&legacy).expect("parse must still succeed");
        assert!(st.no_new_privs.is_none());
        assert!(st.seccomp.is_none());
    }

    #[test]
    fn decode_reports_unknown_future_bits() {
        let names = decode_mask(bit(CAP_SYS_ADMIN) | bit(63));
        assert!(names.contains(&"CAP_SYS_ADMIN".to_string()));
        assert!(names.contains(&"CAP_63".to_string()));
    }

    #[test]
    fn walker_flags_nonroot_and_suppresses_root() {
        let tmp = tempfile::tempdir().unwrap();
        write_proc(tmp.path(), 1, FULL_ROOT); // root — suppressed by design
        write_proc(tmp.path(), 4242, DOCKER_DEFAULT_NONROOT);
        fs::create_dir_all(tmp.path().join("sys")).unwrap(); // non-PID entry
        fs::write(tmp.path().join("uptime"), "1 1").unwrap();

        let (findings, _) = audit_host_processes(tmp.path());
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!((f.pid, f.euid), (4242, 101));
        assert_eq!(f.effective, 0xa804_25fb);
        assert!(f.critical_caps.iter().any(|c| c == "CAP_NET_RAW"));
        assert!(f.critical_caps.iter().any(|c| c == "CAP_DAC_OVERRIDE"));
        assert!(!f.critical_caps.iter().any(|c| c == "CAP_SYS_ADMIN"));
        assert_eq!(f.no_new_privs, Some(false));
        assert_eq!(f.seccomp, Some(2));
    }

    #[test]
    fn nonroot_without_caps_is_clean() {
        // Invariant: full default CapBnd must NOT trigger a finding.
        let tmp = tempfile::tempdir().unwrap();
        write_proc(
            tmp.path(),
            777,
            "Name:\tbash\nUid:\t1000\t1000\t1000\t1000\n\
CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n\
CapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n\
NoNewPrivs:\t0\nSeccomp:\t0\n",
        );
        let (findings, _) = audit_host_processes(tmp.path());
        assert!(findings.is_empty());
    }

    #[test]
    fn ambient_set_is_flagged_even_without_critical_caps() {
        // e.g. systemd AmbientCapabilities=CAP_NET_BIND_SERVICE (bit 10)
        let tmp = tempfile::tempdir().unwrap();
        write_proc(
            tmp.path(),
            900,
            "Name:\tnode\nUid:\t998\t998\t998\t998\n\
CapInh:\t0000000000000400\nCapPrm:\t0000000000000400\nCapEff:\t0000000000000400\n\
CapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000400\n\
NoNewPrivs:\t1\nSeccomp:\t2\n",
        );
        let (findings, _) = audit_host_processes(tmp.path());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].ambient, 0x400);
        assert!(findings[0].critical_caps.is_empty());
        assert_eq!(findings[0].no_new_privs, Some(true));
        assert_eq!(findings[0].seccomp, Some(2));
    }

    #[test]
    fn unreadable_status_is_counted_not_fatal() {
        if unsafe { libc::geteuid() } == 0 {
            return; // root bypasses mode bits — nothing to assert
        }
        let tmp = tempfile::tempdir().unwrap();
        write_proc(tmp.path(), 55, FULL_ROOT);
        fs::set_permissions(
            tmp.path().join("55/status"),
            fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        // Graceful degradation: no panic, empty result, denial aggregated.
        let (findings, _) = audit_host_processes(tmp.path());
        assert!(findings.is_empty());
    }

    #[test]
    fn malware_sweep_flags_explicit_and_corroborates_ambiguous() {
        let tmp = tempfile::tempdir().unwrap();
        let status = |name: &str, uid: &str| {
            format!(
                "Name:\t{name}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n\
CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\n"
            )
        };
        let mk = |pid: u32, name: &str, uid: &str, exe: Option<&str>| {
            let d = tmp.path().join(pid.to_string());
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("status"), status(name, uid)).unwrap();
            if let Some(e) = exe {
                symlink(e, d.join("exe")).unwrap();
            }
        };

        mk(10, "xmrig", "0", Some("/usr/bin/xmrig")); // explicit + ROOT → caught
        mk(
            20,
            "networkservice",
            "1000",
            Some("/usr/bin/networkservice"),
        ); // legit path → NOT
        mk(30, "networkservice", "1000", Some("/tmp/networkservice")); // ephemeral → caught

        let (_caps, suspicious) = audit_host_processes(tmp.path());
        let pids: Vec<u32> = suspicious.iter().map(|s| s.pid).collect();
        assert!(pids.contains(&10), "root-run explicit miner must be caught");
        assert!(
            pids.contains(&30),
            "ambiguous name from /tmp must be flagged"
        );
        assert!(
            !pids.contains(&20),
            "ambiguous name from /usr/bin must be suppressed"
        );
    }

    #[test]
    fn deleted_exe_flags_ephemeral_not_system() {
        // Legit: service binary deleted by apt upgrade — system path → NOT flagged.
        let (rec, dropped) = classify_suspicious("nginx", 100, Some("/usr/sbin/nginx (deleted)"));
        assert!(rec.is_none(), "system-path deletion must not flag (apt FP)");
        assert!(!dropped);

        // Fileless: unknown-named binary deleted from /dev/shm → flagged,
        // is_deleted, suffix stripped, name-independent.
        let (rec, _) = classify_suspicious("systemd-worker", 200, Some("/dev/shm/x (deleted)"));
        let r = rec.expect("ephemeral deletion must be recorded");
        assert!(r.is_deleted);
        assert_eq!(r.exe_path.as_deref(), Some("/dev/shm/x")); // suffix cleaned
        assert_eq!(r.pid, 200);

        // Known miner, live (not deleted) — recorded by name, is_deleted=false.
        let (rec, _) = classify_suspicious("xmrig", 300, Some("/tmp/xmrig"));
        assert!(!rec.unwrap().is_deleted);

        // Known miner deleted from ephemeral → single record, is_deleted=true.
        let (rec, _) = classify_suspicious("xmrig", 400, Some("/tmp/xmrig (deleted)"));
        assert!(rec.unwrap().is_deleted);

        // Known miner deleted from SYSTEM path → recorded by name, is_deleted=false
        // (SEC-017 must not fire; SEC-016 catches it by name).
        let (rec, _) = classify_suspicious("kinsing", 500, Some("/usr/bin/kinsing (deleted)"));
        assert!(!rec.unwrap().is_deleted);
    }

    #[test]
    fn walker_records_fileless_from_ephemeral() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("42");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("status"),
            "Name:\tobfuscated\nUid:\t0\t0\t0\t0\n\
CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\n",
        )
        .unwrap();
        symlink("/dev/shm/loader (deleted)", d.join("exe")).unwrap();

        let (_caps, suspicious) = audit_host_processes(tmp.path());
        let f = suspicious
            .iter()
            .find(|s| s.pid == 42)
            .expect("fileless flagged");
        assert!(f.is_deleted);
        assert_eq!(f.exe_path.as_deref(), Some("/dev/shm/loader"));
    }

    #[test]
    fn memfd_is_fileless_without_deleted_suffix() {
        // Raw memfd link, NO " (deleted)", name not in any blocklist → still flagged.
        let (rec, _) = classify_suspicious("stealth", 900, Some("/memfd:stealth"));
        let r = rec.expect("memfd execution must be recorded even without the suffix");
        assert!(r.is_deleted, "memfd is intrinsically fileless");
        assert_eq!(r.exe_path.as_deref(), Some("/memfd:stealth"));
        assert_eq!(r.pid, 900);

        // memfd WITH the suffix → stripped, still fileless.
        let (rec, _) = classify_suspicious("stealth", 901, Some("/memfd:stealth (deleted)"));
        let r = rec.unwrap();
        assert!(r.is_deleted);
        assert_eq!(r.exe_path.as_deref(), Some("/memfd:stealth")); // suffix cleaned

        // Regression guard: a live on-disk /tmp binary (no name, not deleted)
        // must NOT be fileless — broadening memfd must not leak into this case.
        let (rec, _) = classify_suspicious("harmless", 902, Some("/tmp/harmless"));
        assert!(rec.is_none());
    }
}
