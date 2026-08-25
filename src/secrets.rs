//! Long-lived secrets with OS-level memory protection.
//!
//! `Zeroizing<String>` guarantees zeroization on drop, but does not prevent
//! the OS from paging the buffer to swap or including it in a core dump.
//! `SecretString` adds `mlock(2)` and `madvise(MADV_DONTDUMP)` on Linux,
//! degrading silently (with a coverage note) when the kernel refuses.

use zeroize::Zeroizing;

/// A secret string protected from being written to swap or included in core
/// dumps on Linux. Falls back to `Zeroizing<String>` on other platforms.
#[derive(Debug, Clone)]
pub struct SecretString {
    inner: Zeroizing<String>,
}

impl SecretString {
    /// Wrap a secret string. On Linux, attempts to `mlock` and `madvise` the
    /// backing memory; if either fails, records a coverage warning but still
    /// returns the secret. The secret is never copied — ownership moves here.
    pub fn new(s: String) -> Self {
        Self::from_zeroizing(Zeroizing::new(s))
    }

    /// Wrap an already zeroizing secret. This allows callers that already have
    /// a `Zeroizing<String>` to upgrade it without an extra copy.
    pub fn from_zeroizing(inner: Zeroizing<String>) -> Self {
        #[cfg(target_os = "linux")]
        {
            let ptr = inner.as_ptr();
            let len = inner.len();
            if !ptr.is_null() && len > 0 {
                let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
                if page_size > 0 {
                    let addr = ptr as usize;
                    let aligned = addr & !(page_size - 1);
                    let offset = addr - aligned;
                    let aligned_len = offset + len;
                    let aligned_len = aligned_len.next_multiple_of(page_size);

                    unsafe {
                        // Try mlock first; if it fails, still attempt madvise.
                        if libc::mlock(aligned as *const libc::c_void, aligned_len) != 0 {
                            let err = std::io::Error::last_os_error();
                            crate::coverage::record(format!(
                                "secrets: mlock failed ({err}) — sudo password may be written to swap"
                            ));
                        }
                        // Always try to exclude from core dumps.
                        if libc::madvise(
                            aligned as *mut libc::c_void,
                            aligned_len,
                            libc::MADV_DONTDUMP,
                        ) != 0
                        {
                            let err = std::io::Error::last_os_error();
                            crate::coverage::record(format!(
                                "secrets: madvise(MADV_DONTDUMP) failed ({err}) — sudo password may be included in core dumps"
                            ));
                        }
                    }
                }
            }
        }
        Self { inner }
    }

    /// Get the secret as a string slice.
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Get the length in bytes.
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl std::ops::Deref for SecretString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl AsRef<str> for SecretString {
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_string_holds_value_and_derefs() {
        let s = SecretString::new("hunter2".to_string());
        assert_eq!(s.as_str(), "hunter2");
        assert_eq!(&*s, "hunter2");
    }

    #[test]
    fn from_zeroizing_preserves_value() {
        let z = Zeroizing::new("password123".to_string());
        let s = SecretString::from_zeroizing(z);
        assert_eq!(s.as_str(), "password123");
    }
}
