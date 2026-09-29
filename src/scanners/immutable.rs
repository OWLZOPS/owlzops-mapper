//! FS_IOC_GETFLAGS on trust anchors. ext4/xfs/btrfs/f2fs implement the ioctl;
//! tmpfs/overlay/nfs answer ENOTTY and are reported as "no attribute support",
//! not as clean.
use crate::coverage;
use crate::models::ImmutableFlag;
use std::path::Path;

const TRUST_ANCHORS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/ld.so.preload",
    "/etc/ld.so.conf",
    "/etc/pam.d/common-auth",
    "/etc/pam.d/sshd",
    "/etc/pam.d/sudo",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/root/.ssh/authorized_keys",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/profile",
    "/etc/bash.bashrc",
];

// linux/fs.h — stable ABI values; kept local so a libc constant gap on the
// musl target cannot break the build.
const FS_IMMUTABLE_FL: libc::c_int = 0x0000_0010;
const FS_APPEND_FL: libc::c_int = 0x0000_0020;
#[cfg(target_pointer_width = "64")]
const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601; // _IOR('f', 1, long)
#[cfg(target_pointer_width = "32")]
const FS_IOC_GETFLAGS: libc::c_ulong = 0x8004_6601;

pub(crate) fn locked_bits(flags: libc::c_int) -> (bool, bool) {
    (flags & FS_IMMUTABLE_FL != 0, flags & FS_APPEND_FL != 0)
}

/// `Ok(None)` = the filesystem has no inode attributes; `Err` = could not look.
#[cfg(target_os = "linux")]
pub(crate) fn inode_flags(path: &Path) -> std::io::Result<Option<libc::c_int>> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    // CAPPED_IO_OK: the descriptor serves one ioctl(2) and is never read.
    // O_NONBLOCK|O_NOFOLLOW: a planted FIFO cannot hang us, a planted symlink
    // cannot redirect us (the caller resolves symlinks explicitly first).
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)?;
    let mut flags: libc::c_int = 0;
    // SAFETY: FS_IOC_GETFLAGS writes exactly one c_int through the pointer;
    // the fd is open for the duration. `as _` bridges gnu (c_ulong) and musl
    // (c_int) request types.
    let rc = unsafe { libc::ioctl(f.as_raw_fd(), FS_IOC_GETFLAGS as _, &mut flags) };
    if rc == -1 {
        let e = std::io::Error::last_os_error();
        return match e.raw_os_error() {
            Some(libc::ENOTTY) | Some(libc::EOPNOTSUPP) | Some(libc::EINVAL) => Ok(None),
            _ => Err(e),
        };
    }
    Ok(Some(flags))
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn inode_flags(_path: &Path) -> std::io::Result<Option<libc::c_int>> {
    Ok(None)
}

pub fn scan_immutable_anchors() -> Vec<ImmutableFlag> {
    scan_immutable_from(TRUST_ANCHORS.iter().map(Path::new))
}

pub(crate) fn scan_immutable_from<'a>(
    anchors: impl Iterator<Item = &'a Path>,
) -> Vec<ImmutableFlag> {
    let mut out = Vec::new();
    for anchor in anchors {
        let resolved = match std::fs::canonicalize(anchor) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                coverage::record(format!(
                    "immutable: {} unresolvable ({}) — attributes NOT read",
                    anchor.display(),
                    e.kind()
                ));
                continue;
            }
        };
        match inode_flags(&resolved) {
            Ok(Some(flags)) => {
                let (immutable, append_only) = locked_bits(flags);
                if immutable || append_only {
                    out.push(ImmutableFlag {
                        path: anchor.display().to_string(),
                        resolved: resolved.display().to_string(),
                        immutable,
                        append_only,
                    });
                }
            }
            Ok(None) => {} // no attribute support on this fs
            Err(e) => coverage::record(format!(
                "immutable: {} ({}) — attributes NOT read; +i/+a state UNKNOWN",
                anchor.display(),
                e.kind()
            )),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_decoding() {
        assert_eq!(locked_bits(0), (false, false));
        assert_eq!(locked_bits(FS_IMMUTABLE_FL), (true, false));
        assert_eq!(locked_bits(FS_APPEND_FL | 0x80), (false, true));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_fresh_file_is_never_locked_and_the_ioctl_is_well_formed() {
        // ext4 answers Some(0); tmpfs answers None. Both are "not locked".
        let tmp = tempfile::NamedTempFile::new().unwrap();
        if let Some(flags) = inode_flags(tmp.path()).expect("open + ioctl must not error") {
            assert_eq!(locked_bits(flags), (false, false));
        }
        let missing = tmp.path().with_extension("absent");
        assert!(scan_immutable_from(std::iter::once(missing.as_path())).is_empty());
    }
}
