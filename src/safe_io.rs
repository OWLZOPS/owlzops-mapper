use std::io::{self, Read};

/// Read a file into a String, capping at `max_bytes`. Returns (content, truncated).
#[cfg(feature = "local-scan")]
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
    let text = String::from_utf8(buf)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
    Ok((text, truncated))
}

/// Read a file into raw bytes, capping at `max_bytes`. Returns (bytes, truncated).
#[cfg(feature = "local-scan")]
pub fn read_file_bytes_capped(path: &str, max_bytes: usize) -> io::Result<(Vec<u8>, bool)> {
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

#[cfg(feature = "local-scan")]
pub const CAP_PROC_NET: usize = 16 * 1024 * 1024;
#[cfg(feature = "local-scan")]
pub const CAP_PROC_ENVIRON: usize = 256 * 1024;
pub const CAP_CHILD_STDOUT: usize = 32 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn read_file_capped_normal() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "hello world").unwrap();
        let path = tmp.path().to_str().unwrap();
        let (content, truncated) = read_file_capped(path, 100).unwrap();
        assert_eq!(content, "hello world");
        assert!(!truncated);
    }

    #[test]
    fn read_file_capped_truncated() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        let data = vec![b'A'; 200];
        tmp.write_all(&data).unwrap();
        let path = tmp.path().to_str().unwrap();
        let (content, truncated) = read_file_capped(path, 100).unwrap();
        assert_eq!(content.len(), 100);
        assert!(truncated);
    }

    #[test]
    fn read_file_capped_exact() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        let data = vec![b'B'; 100];
        tmp.write_all(&data).unwrap();
        let path = tmp.path().to_str().unwrap();
        let (content, truncated) = read_file_capped(path, 100).unwrap();
        assert_eq!(content.len(), 100);
        assert!(!truncated);
    }

    #[test]
    fn read_file_capped_invalid_utf8() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&[0xFF, 0xFE, 0xFD]).unwrap();
        let path = tmp.path().to_str().unwrap();
        let (content, truncated) = read_file_capped(path, 10).unwrap();
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
