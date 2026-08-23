use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;

/// Read a KERNEL PSEUDO-FILE into a String, capping at `max_bytes`.
/// Returns (content, truncated).
///
/// `/proc`, `/sys` and `/dev` ONLY. These cannot be replaced with a FIFO by a
/// host attacker, so a plain blocking `File::open` is safe there. For anything
/// on a host-controlled filesystem use `read_file_capped_regular` — see R26-02.
/// The name carries the constraint on purpose: `read_procfs_capped("/etc/sudoers")`
/// is wrong on sight (R26-31).
///
/// R26-33: capped-I/O guard no longer uses context separators; the new guard
/// is exact and checks renamed procfs APIs. See .github/workflows/ci.yml.
#[cfg_attr(not(feature = "local-scan"), allow(dead_code))]
pub fn read_procfs_capped(path: &str, max_bytes: usize) -> io::Result<(String, bool)> {
    let mut f = std::fs::File::open(path)?;
    let mut buf = Vec::with_capacity(max_bytes.min(64 * 1024));
    let read = f
        .by_ref()
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut buf)?;
    let truncated = read > max_bytes;
    if truncated {
        buf.truncate(max_bytes);
    }
    let text = String::from_utf8(buf)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
    Ok((text, truncated))
}

/// Read a KERNEL PSEUDO-FILE into raw bytes, capping at `max_bytes`.
/// Returns (bytes, truncated).
///
/// Same constraints as `read_procfs_capped`: `/proc`, `/sys`, `/dev` ONLY.
/// Host-controlled paths must use `read_file_capped_regular` (R26-31/R26-36).
#[cfg_attr(not(feature = "local-scan"), allow(dead_code))]
pub fn read_procfs_bytes_capped(path: &str, max_bytes: usize) -> io::Result<(Vec<u8>, bool)> {
    let mut f = std::fs::File::open(path)?;
    let mut buf = Vec::with_capacity(max_bytes.min(64 * 1024));
    let read = f
        .by_ref()
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut buf)?;
    let truncated = read > max_bytes;
    if truncated {
        buf.truncate(max_bytes);
    }
    Ok((buf, truncated))
}

/// Read from a reader, capping at `max_bytes` and draining the rest.
pub fn read_reader_capped<R: Read>(mut reader: R, max_bytes: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::with_capacity(max_bytes.min(64 * 1024));
    let mut limited = (&mut reader).take(max_bytes as u64);
    let _ = limited.read_to_end(&mut buf);

    let mut probe = [0u8; 1];
    let truncated = matches!(reader.read(&mut probe), Ok(n) if n > 0);
    if truncated {
        let _ = io::copy(&mut reader, &mut io::sink());
    }
    (buf, truncated)
}

/// Shared implementation for regular-file capped reads.
///
/// Opens with `O_NONBLOCK | O_NOCTTY`, verifies the file is regular, reads up
/// to `max_bytes + 1` bytes, and returns `(bytes, truncated)`.
fn read_regular_capped(path: &str, max_bytes: usize) -> io::Result<(Vec<u8>, bool)> {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)?;

    if !f.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a regular file (FIFO or device on a scanner path)",
        ));
    }

    let mut buf = Vec::with_capacity(max_bytes.min(64 * 1024));
    let read = f
        .by_ref()
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut buf)?;
    let truncated = read > max_bytes;
    if truncated {
        buf.truncate(max_bytes);
    }
    Ok((buf, truncated))
}

// ── R23-10: safe open for host-controlled paths (FIFO/device resistant) ──

/// Like `read_procfs_capped`, but opens the file with `O_NONBLOCK | O_NOCTTY`
/// and verifies that the resulting file descriptor is a regular file.
///
/// Paths under scanner control (`/etc/ld.so.preload`, unit files, cron files)
/// are writable by root.  An attacker can replace any of them with a FIFO or
/// device node; `File::open` on a FIFO blocks until a writer appears, hanging
/// the scanner forever.  `O_NONBLOCK` makes the open non‑blocking, and the
/// subsequent `fstat` check ensures we only read regular files.  Other errors
/// (e.g. `ENOENT`, `EACCES`) are returned normally so the caller can decide
/// whether to record a coverage warning.
///
/// This function MUST be used for every scanner path that lives on a host‑
/// controlled filesystem (i.e. not `/proc`, `/sys`, or `/dev`).
#[cfg_attr(not(feature = "local-scan"), allow(dead_code))]
pub fn read_file_capped_regular(path: &str, max_bytes: usize) -> io::Result<(String, bool)> {
    let (buf, truncated) = read_regular_capped(path, max_bytes)?;
    let text = String::from_utf8(buf)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
    Ok((text, truncated))
}

/// Like `read_file_capped_regular`, but rejects invalid UTF-8 instead of
/// replacing it with U+FFFD. Trust stores must fail closed: a corrupted byte
/// silently turns into a different key and can cause TOFU or a false
/// HostKeyChanged (R25-72).
///
/// Returns the file contents directly; truncation is an ERROR, so there is
/// no `truncated` boolean that could only ever be `false` (R25-90).
pub fn read_file_capped_regular_strict(path: &str, max_bytes: usize) -> io::Result<String> {
    let (buf, truncated) = read_regular_capped(path, max_bytes)?;

    // R25-80: report truncation BEFORE attempting UTF-8 conversion. The cut
    // lands on a byte boundary and can split a multi-byte sequence, so a
    // truncated trust store would otherwise be misreported as corrupt.
    if truncated {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file exceeds {max_bytes} bytes and was truncated"),
        ));
    }

    String::from_utf8(buf).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file contains invalid UTF-8: {e}"),
        )
    })
}

#[cfg(feature = "local-scan")]
pub const CAP_PROC_NET: usize = 16 * 1024 * 1024;
#[cfg(feature = "local-scan")]
pub const CAP_PROC_ENVIRON: usize = 256 * 1024;
pub const CAP_CHILD_STDOUT: usize = 32 * 1024 * 1024;

#[cfg(feature = "local-scan")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn read_procfs_capped_normal() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "hello world").unwrap();
        let path = tmp.path().to_str().unwrap();
        let (content, truncated) = read_procfs_capped(path, 100).unwrap();
        assert_eq!(content, "hello world");
        assert!(!truncated);
    }

    #[test]
    fn read_procfs_capped_truncated() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        let data = vec![b'A'; 200];
        tmp.write_all(&data).unwrap();
        let path = tmp.path().to_str().unwrap();
        let (content, truncated) = read_procfs_capped(path, 100).unwrap();
        assert_eq!(content.len(), 100);
        assert!(truncated);
    }

    #[test]
    fn read_procfs_capped_exact() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        let data = vec![b'B'; 100];
        tmp.write_all(&data).unwrap();
        let path = tmp.path().to_str().unwrap();
        let (content, truncated) = read_procfs_capped(path, 100).unwrap();
        assert_eq!(content.len(), 100);
        assert!(!truncated);
    }

    #[test]
    fn read_procfs_capped_invalid_utf8() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&[0xFF, 0xFE, 0xFD]).unwrap();
        let path = tmp.path().to_str().unwrap();
        let (content, truncated) = read_procfs_capped(path, 10).unwrap();
        assert!(content.contains('\u{FFFD}'));
        assert!(!truncated);
    }

    #[test]
    fn read_reader_capped_truncated() {
        let data = vec![0u8; 200];
        let cursor = std::io::Cursor::new(data);
        let (buf, truncated) = read_reader_capped(cursor, 100);
        assert_eq!(buf.len(), 100);
        assert!(truncated);
    }

    #[test]
    fn read_reader_capped_exact() {
        let data = vec![1u8; 100];
        let cursor = std::io::Cursor::new(data);
        let (buf, truncated) = read_reader_capped(cursor, 100);
        assert_eq!(buf.len(), 100);
        assert!(!truncated);
    }
}
