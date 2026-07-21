//! Agentless file capability inventory.
//! Scans common binary directories for files with `security.capability` extended
//! attributes (set via `setcap`). Capability sets are decoded from raw xattr
//! using only `libc::getxattr` and binary parsing – no external tools.

use crate::models::FileCapFinding;

// Directories to scan for capabilities (common binary paths)
const SCAN_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/bin",
    "/sbin",
];

// Maximum number of files to scan per directory (avoid runaway on huge filesystems)
const MAX_FILES_PER_DIR: usize = 512;

/// Convert a capability bitmask (u64) into a list of human‑readable names.
/// Only the lower 41 bits are defined (CAP_LAST_CAP = 40 on Linux 6.x).
fn cap_mask_to_names(mask: u64) -> Vec<String> {
    const CAP_NAMES: &[&str] = &[
        "CAP_CHOWN",              // 0
        "CAP_DAC_OVERRIDE",       // 1
        "CAP_DAC_READ_SEARCH",    // 2
        "CAP_FOWNER",             // 3
        "CAP_FSETID",             // 4
        "CAP_KILL",               // 5
        "CAP_SETGID",             // 6
        "CAP_SETUID",             // 7
        "CAP_SETPCAP",            // 8
        "CAP_LINUX_IMMUTABLE",    // 9
        "CAP_NET_BIND_SERVICE",   // 10
        "CAP_NET_BROADCAST",      // 11
        "CAP_NET_ADMIN",          // 12
        "CAP_NET_RAW",            // 13
        "CAP_IPC_LOCK",           // 14
        "CAP_IPC_OWNER",          // 15
        "CAP_SYS_MODULE",         // 16
        "CAP_SYS_RAWIO",          // 17
        "CAP_SYS_CHROOT",         // 18
        "CAP_SYS_PTRACE",         // 19
        "CAP_SYS_PACCT",          // 20
        "CAP_SYS_ADMIN",          // 21
        "CAP_SYS_BOOT",           // 22
        "CAP_SYS_NICE",           // 23
        "CAP_SYS_RESOURCE",       // 24
        "CAP_SYS_TIME",           // 25
        "CAP_SYS_TTY_CONFIG",     // 26
        "CAP_MKNOD",              // 27
        "CAP_LEASE",              // 28
        "CAP_AUDIT_WRITE",        // 29
        "CAP_AUDIT_CONTROL",      // 30
        "CAP_SETFCAP",            // 31
        "CAP_MAC_OVERRIDE",       // 32
        "CAP_MAC_ADMIN",          // 33
        "CAP_SYSLOG",             // 34
        "CAP_WAKE_ALARM",         // 35
        "CAP_BLOCK_SUSPEND",      // 36
        "CAP_AUDIT_READ",         // 37
        "CAP_PERFMON",            // 38
        "CAP_BPF",                // 39
        "CAP_CHECKPOINT_RESTORE", // 40
    ];

    let mut out = Vec::new();
    for (i, name) in CAP_NAMES.iter().enumerate() {
        if (mask >> i) & 1 != 0 {
            out.push(name.to_string());
        }
    }
    out
}

/// Parse a raw `security.capability` xattr value into (permitted, inheritable, effective_flag).
/// Handles both v2 (20 bytes) and v3 (24 bytes) structures, reading full 64-bit capability masks
/// from the two 32-bit halves (data[0] and data[1]) for each set.
fn parse_vfs_cap_data(bytes: &[u8]) -> Option<(u64, u64, bool)> {
    if bytes.len() < 20 {
        return None;
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    match (magic >> 24) & 0xFF {
        2 | 3 => {}
        _ => return None,
    }
    let le = |o: usize| -> u64 { u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap()) as u64 };
    let permitted = le(4) | (le(12) << 32); // data[0].permitted | data[1].permitted << 32
    let inheritable = le(8) | (le(16) << 32); // data[0].inheritable | data[1].inheritable << 32
    let effective_flag = magic & 0x1 != 0; // VFS_CAP_FLAGS_EFFECTIVE
    Some((permitted, inheritable, effective_flag))
}

// ── Linux-specific implementation ──────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use std::ffi::CString;
    use std::fs;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    /// Read the `security.capability` xattr of a file and return its effective
    /// and inheritable capability sets (human-readable names).
    fn get_file_caps(path: &Path) -> io::Result<Vec<String>> {
        let cpath = CString::new(path.as_os_str().as_bytes())?;
        // First, query the size of the attribute
        let size = unsafe {
            libc::getxattr(
                cpath.as_ptr(),
                c"security.capability".as_ptr(),
                std::ptr::null_mut(),
                0,
            )
        };
        if size <= 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENODATA) || err.kind() == io::ErrorKind::NotFound {
                return Ok(Vec::new());
            }
            return Err(err);
        }

        let mut buf = vec![0u8; size as usize];
        let res = unsafe {
            libc::getxattr(
                cpath.as_ptr(),
                c"security.capability".as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                size as libc::size_t,
            )
        };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }
        buf.truncate(res as usize);

        let (permitted, _inheritable, _effective) = parse_vfs_cap_data(&buf).unwrap_or_default();
        Ok(cap_mask_to_names(permitted))
    }

    /// Scan the provided directories for files with capabilities, returning findings.
    pub fn scan_directories(dirs: &[&str]) -> Vec<FileCapFinding> {
        let mut findings = Vec::new();

        for dir in dirs {
            let path = Path::new(dir);
            if !path.is_dir() {
                continue;
            }
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten().take(MAX_FILES_PER_DIR) {
                    let p = entry.path();
                    if !p.is_file() {
                        continue;
                    }
                    match get_file_caps(&p) {
                        Ok(caps) if !caps.is_empty() => {
                            findings.push(FileCapFinding {
                                path: p.to_string_lossy().to_string(),
                                capabilities: caps,
                                reason: Some(
                                    "file capabilities granted via extended attributes".into(),
                                ),
                            });
                        }
                        Ok(_) => {} // no caps
                        Err(e) => {
                            if e.kind() != io::ErrorKind::PermissionDenied {
                                crate::coverage::record(format!(
                                    "file_capabilities: error reading {}: {}",
                                    p.display(),
                                    e
                                ));
                            }
                        }
                    }
                }
            }
        }
        findings
    }
}

/// Main entry point – returns all files with capabilities found in common binary paths.
#[cfg(target_os = "linux")]
pub fn gather_file_capabilities() -> Vec<FileCapFinding> {
    linux_impl::scan_directories(SCAN_DIRS)
}

/// Stub for non-Linux platforms – file capabilities are a Linux-specific feature.
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
        data[0..4].copy_from_slice(&0x02000000u32.to_le_bytes()); // v2, effective flag not set
        // Set CAP_NET_BIND_SERVICE (bit 10) in data[0].permitted
        let p: u32 = 1 << 10;
        data[4..8].copy_from_slice(&p.to_le_bytes());
        // inheritable all zeros
        let (permitted, inheritable, effective) = parse_vfs_cap_data(&data).unwrap();
        assert_eq!(permitted, 1 << 10);
        assert_eq!(inheritable, 0);
        assert!(!effective);
        let names = cap_mask_to_names(permitted);
        assert_eq!(names, vec!["CAP_NET_BIND_SERVICE"]);
    }

    #[test]
    fn parse_v2_cap_data_high_bit() {
        let mut data = vec![0u8; 20];
        // v2 with effective flag
        data[0..4].copy_from_slice(&0x02000001u32.to_le_bytes());
        // Set CAP_BPF (bit 39) in data[1].permitted (offset 12)
        // data[1].permitted is at bytes 12..16
        let high: u32 = 1 << (39 - 32); // bit 7 in the high word
        data[12..16].copy_from_slice(&high.to_le_bytes());
        let (permitted, _inheritable, effective) = parse_vfs_cap_data(&data).unwrap();
        assert_eq!(permitted, 1 << 39);
        assert!(effective);
        let names = cap_mask_to_names(permitted);
        assert_eq!(names, vec!["CAP_BPF"]);
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
}
