//! Long-lived secrets with OS-level memory protection.
//!
//! `Zeroizing<String>` guarantees zeroization on drop, but does not prevent
//! the OS from paging the buffer to swap or including it in a core dump.
//! `SecretString` adds `mlock(2)` and `madvise(MADV_DONTDUMP)` on Linux,
//! degrading with a stderr warning and coverage note when the kernel refuses.

use zeroize::Zeroizing;

/// A secret string protected from being written to swap or included in core
/// dumps on Linux. Falls back to `Zeroizing<String>` on other platforms.
// No Clone (R27-19): a cloned Zeroizing<String> is a fresh allocation that
// from_zeroizing's mlock/madvise never touched, so the copy would silently
// lack the protection the type promises. Share with Arc<SecretString> —
// main.rs already does.
pub struct SecretString {
    inner: Zeroizing<String>,
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Zeroizing<String> derives Debug and forwards to String; a derived
        // impl would print the password verbatim (R27-17). Length is withheld
        // as well — it is a small but real disclosure.
        f.write_str("SecretString([REDACTED])")
    }
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
    ///
    /// # Invariant
    /// Exactly one `SecretString` exists per process (enforced by the absence
    /// of `Clone`). There is no `Drop`/`munlock`: the locked page is held until
    /// exit, costing one page of `RLIMIT_MEMLOCK`. `mlock`/`madvise` are
    /// page-granular, so the page is shared with unrelated heap objects; a
    /// naive `munlock` on drop could unlock a page holding another live secret.
    /// If a second secret is ever introduced, move to a dedicated `mmap` region
    /// first.
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
                            // Duplicate to stderr: coverage may not reach a report
                            // in fleet mode without a local host (R27-20).
                            eprintln!(
                                "warning: mlock failed ({err}) — sudo password may reach swap"
                            );
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
                            eprintln!(
                                "warning: madvise(MADV_DONTDUMP) failed ({err}) — sudo password may be included in core dumps"
                            );
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

    // No inherent `len`/`is_empty`: `Deref<Target = str>` provides both.
    // An inherent `len` alone trips clippy::len_without_is_empty (the lint
    // scans inherent impls only and does not credit Deref); adding an
    // inherent `is_empty` alongside it trips dead_code in a binary crate.
    // Owning neither dissolves the pair.
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

    #[test]
    fn debug_never_renders_the_secret() {
        let s = SecretString::new("hunter2".to_string());
        let d = format!("{s:?}");
        assert!(!d.contains("hunter2"), "Debug leaked the secret: {d}");
        assert!(!d.contains('7'), "Debug leaked the length");
        assert_eq!(d, "SecretString([REDACTED])");
    }
}
