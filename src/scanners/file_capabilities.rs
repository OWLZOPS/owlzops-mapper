//! Agentless file capability inventory.
//! Scans common binary directories for files with `security.capability` extended
//! attributes (set via `setcap`). Capability sets are decoded from raw xattr
//! using only `libc::lgetxattr` and binary parsing – no external tools.

// On non-Linux targets the Linux-specific imports and the `VfsCaps` struct are
// genuinely unused (the `gather_file_capabilities` stub just returns an empty
// vector).  Suppress those warnings only there so that Linux builds stay strict.
#![cfg_attr(not(target_os = "linux"), allow(unused_imports, dead_code))]

use crate::models::FileCapFinding;
use crate::scanners::fs_inventory;
use std::collections::HashSet;
use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Convert a capability bitmask (u64) into a list of human‑readable names.
/// Bits beyond the last known constant (40) are reported as `cap_<N>` so that
/// no capability is silently discarded (R19‑05).
fn cap_mask_to_names(mask: u64) -> Vec<String> {
    const CAP_NAMES: &[&str] = &[
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

    let mut out = Vec::new();
    for i in 0..64 {
        if (mask >> i) & 1 != 0 {
            if let Some(&name) = CAP_NAMES.get(i) {
                out.push(name.to_string());
            } else {
                out.push(format!("cap_{i}"));
            }
        }
    }
    out
}

/// Build the human‑readable capability list from both permitted and inheritable masks.
/// Inheritable‑only entries are tagged `(inh)` so they don't collapse
/// `all()` checks on the permitted list and are visible to the operator.
pub(crate) fn build_capability_names(permitted: u64, inheritable: u64) -> Vec<String> {
    let mut names = cap_mask_to_names(permitted);
    for n in cap_mask_to_names(inheritable) {
        let tagged = format!("{n}(inh)");
        if !names.contains(&tagged) {
            names.push(tagged);
        }
    }
    names
}

/// Parsed VFS capability structure.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // inheritable/rootid kept for upcoming usage
pub(crate) struct VfsCaps {
    pub(crate) revision: u8,
    pub(crate) permitted: u64,
    pub(crate) inheritable: u64,
    pub(crate) effective: bool,
    /// v3 rootid (uid mapped to root in the user namespace where the caps are valid)
    pub(crate) rootid: Option<u32>,
}

/// Parse a raw `security.capability` xattr value.  Returns an error string on
/// unsupported revision or truncated data.
pub(crate) fn parse_vfs_cap_data(bytes: &[u8]) -> Result<VfsCaps, &'static str> {
    if bytes.len() < 4 {
        return Err("xattr too short");
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let revision = ((magic >> 24) & 0xFF) as u8;
    let need = match revision {
        2 => 20,
        3 => 24,
        _ => return Err("unsupported VFS_CAP_REVISION"),
    };
    if bytes.len() < need {
        return Err("xattr truncated");
    }
    let le = |o: usize| -> u64 {
        u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]) as u64
    };
    Ok(VfsCaps {
        revision,
        permitted: le(4) | (le(12) << 32),
        inheritable: le(8) | (le(16) << 32),
        effective: magic & 0x0000_0001 != 0,
        rootid: (revision == 3)
            .then(|| u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]])),
    })
}

/// Read the `security.capability` xattr of a file using `lgetxattr` (does NOT follow symlinks).
/// Implements a retry loop for `ERANGE` (TOCTOU-safe) and handles `ENODATA`, `ENOENT`, `ENOTSUP`.
#[cfg(target_os = "linux")]
pub(crate) fn read_caps_raw(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let cpath = CString::new(path.as_os_str().as_bytes())?;
    let mut buf = vec![0u8; 64]; // v3 fits in 24 bytes; 64 covers everything
    loop {
        let n = unsafe {
            libc::lgetxattr(
                cpath.as_ptr(),
                c"security.capability".as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if n >= 0 {
            buf.truncate(n as usize);
            return Ok(Some(buf));
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ENODATA) | Some(libc::ENOENT) => return Ok(None),
            Some(libc::ERANGE) if buf.len() < 4096 => buf.resize(buf.len() * 4, 0),
            _ => return Err(err),
        }
    }
}

/// Unified inventory using the common `fs_inventory` walker.
/// Deduplication and budget management are handled by the walker;
/// the callback only processes individual unique files.
#[cfg(target_os = "linux")]
#[allow(dead_code)] // retained for backward compatibility; prefer gather_binary_inventory()
pub fn gather_file_capabilities() -> Vec<FileCapFinding> {
    let mut findings = Vec::new();
    let mut notsup_devs: HashSet<u64> = HashSet::new();

    fs_inventory::walk_scannable_dirs(
        "file_capabilities",
        &mut |entry: &std::fs::DirEntry, meta: &std::fs::Metadata| {
            match read_caps_raw(&entry.path()) {
                Ok(Some(buf)) => match parse_vfs_cap_data(&buf) {
                    Ok(caps) => {
                        if caps.permitted != 0 || caps.inheritable != 0 || caps.effective {
                            let names = build_capability_names(caps.permitted, caps.inheritable);
                            findings.push(FileCapFinding {
                                path: entry.path().to_string_lossy().into_owned(),
                                capabilities: names,
                                reason: Some(
                                    "file capabilities granted via extended attributes".into(),
                                ),
                                permitted: caps.permitted,
                                inheritable: caps.inheritable,
                                effective: caps.effective,
                                revision: caps.revision,
                                rootid: caps.rootid,
                                package: None,
                            });
                        }
                    }
                    Err(reason) => {
                        crate::coverage::record(format!(
                            "file_capabilities: unparsed xattr at {}: {}",
                            entry.path().display(),
                            reason
                        ));
                    }
                },
                Ok(None) => {}
                Err(e) => match e.raw_os_error() {
                    Some(libc::ENOTSUP) => {
                        let dev = meta.dev();
                        if notsup_devs.insert(dev) {
                            crate::coverage::record(format!(
                                "file_capabilities: xattr unsupported on dev {dev} — inventory blind there"
                            ));
                        }
                    }
                    _ if e.kind() != std::io::ErrorKind::PermissionDenied => {
                        crate::coverage::record(format!(
                            "file_capabilities: error reading {}: {}",
                            entry.path().display(),
                            e
                        ));
                    }
                    _ => {}
                },
            }
            Ok(())
        },
    );
    findings
}

#[cfg(not(target_os = "linux"))]
pub fn gather_file_capabilities() -> Vec<FileCapFinding> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_v2_cap_data_low_bit() {
        let mut data = vec![0u8; 20];
        data[0..4].copy_from_slice(&0x02000000u32.to_le_bytes());
        let p: u32 = 1 << 10;
        data[4..8].copy_from_slice(&p.to_le_bytes());
        let caps = parse_vfs_cap_data(&data).unwrap();
        assert_eq!(caps.revision, 2);
        assert_eq!(caps.permitted, 1 << 10);
        assert!(!caps.effective);
    }

    #[test]
    fn parse_v2_cap_data_high_bit() {
        let mut data = vec![0u8; 20];
        data[0..4].copy_from_slice(&0x02000001u32.to_le_bytes());
        let high: u32 = 1 << (39 - 32);
        data[12..16].copy_from_slice(&high.to_le_bytes());
        let caps = parse_vfs_cap_data(&data).unwrap();
        assert_eq!(caps.permitted, 1 << 39);
        assert!(caps.effective);
    }

    #[test]
    fn cap_mask_to_names_multiple() {
        let mask: u64 = (1 << 7) | (1 << 21) | (1 << 39);
        let names = cap_mask_to_names(mask);
        assert!(names.contains(&"CAP_SETUID".to_string()));
        assert!(names.contains(&"CAP_SYS_ADMIN".to_string()));
        assert!(names.contains(&"CAP_BPF".to_string()));
        assert_eq!(names.len(), 3);
    }

    #[test]
    fn cap_mask_high_bits_are_not_silent() {
        let mask = (1u64 << 41) | (1u64 << 63);
        let names = cap_mask_to_names(mask);
        assert!(names.contains(&"cap_41".to_string()));
        assert!(names.contains(&"cap_63".to_string()));
    }

    #[test]
    fn inheritable_only_yields_non_empty_capability_list() {
        let names = build_capability_names(0, 1 << 13); // CAP_NET_RAW
        assert!(
            !names.is_empty(),
            "inheritable-only file must not report zero capabilities"
        );
        assert!(names.iter().any(|n| n.starts_with("CAP_NET_RAW")));
    }
}
