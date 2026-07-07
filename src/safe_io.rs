//! Capped I/O helpers to prevent OOM from untrusted inputs.
//! All reads enforce a maximum size; truncation is reported via coverage.

use std::io::{self, Read};

/// Read a file, capping at `max_bytes`. Returns (content, truncated).
/// Never panics; invalid UTF-8 is handled via lossy conversion.
pub fn read_file_capped(path: &str, max_bytes: usize) -> io::Result<(String, bool)> {
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
    Ok((String::from_utf8_lossy(&buf).into_owned(), truncated))
}

/// Read from a reader (e.g. child stdout), capping at `max_bytes` and draining
/// the rest to prevent child blocking on full pipe. Returns (data, truncated).
pub fn read_reader_capped<R: Read>(mut reader: R, max_bytes: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::with_capacity(max_bytes.min(64 * 1024));
    let mut limited = (&mut reader).take(max_bytes as u64);
    let _ = limited.read_to_end(&mut buf);

    // Check if there is more data beyond the cap
    let mut probe = [0u8; 1];
    let truncated = matches!(reader.read(&mut probe), Ok(n) if n > 0);
    if truncated {
        let _ = io::copy(&mut reader, &mut io::sink()); // drain the rest
    }
    (buf, truncated)
}

// Reasonable caps for various sources
pub const CAP_PROC_NET: usize = 16 * 1024 * 1024; // /proc/net/tcp on busy LB
#[allow(dead_code)]
pub const CAP_PROC_ENVIRON: usize = 256 * 1024; // ARG_MAX ~2 MiB, env usually smaller
pub const CAP_CHILD_STDOUT: usize = 32 * 1024 * 1024; // dmesg / rpm -qa
