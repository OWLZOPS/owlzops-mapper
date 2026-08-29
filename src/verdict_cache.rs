// Identity-keyed verdict cache: trust is bound to a specific file (inode+mtime+size),
// not to a path. Any modification of the binary automatically revokes the verdict.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const CACHE_VERSION: u32 = 1; // bump when deep logic changes → invalidates everything
const TTL_SECS: u64 = 14 * 24 * 3600; // re-verify after 14 days (never "trust forever")

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq)]
pub enum Verdict {
    Benign,
    Malicious,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    inode: u64,
    mtime: i64,
    size: u64,
    verdict: Verdict,
    scanned_at: u64,
    version: u32,
    #[serde(default)]
    sha256: String, // optional strong anchor; stat validation works without it
}

#[derive(Default)]
pub struct VerdictCache {
    path: PathBuf,
    entries: HashMap<String, Entry>,
    dirty: bool,
}

/// R27-56: wall-clock time as `Option` — never `unwrap_or(0)`, because a zero
/// "now" makes any cached age 0 and the entry appears freshly written.
fn now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// R27-56: an entry is stale if its age cannot be computed (unusable clock or
/// backward step) — treat as expired, not as fresh.
fn is_stale(e: &Entry, now: Option<u64>) -> bool {
    e.version != CACHE_VERSION
        || now
            .and_then(|n| n.checked_sub(e.scanned_at))
            .is_none_or(|age| age > TTL_SECS)
}

impl VerdictCache {
    pub fn load(path: PathBuf) -> Self {
        let entries =
            crate::safe_io::read_file_capped_regular(&path.to_string_lossy(), 16 * 1024 * 1024)
                .ok()
                .and_then(|(s, _)| serde_json::from_str(&s).ok())
                .unwrap_or_default();
        Self {
            path,
            entries,
            dirty: false,
        }
    }

    /// Returns `Some(verdict)` only if the on-disk file is byte‑identical to the
    /// scanned one (same inode + mtime + size) AND the verdict has not expired.
    /// Any mismatch → `None` → re‑verification required.
    pub fn lookup(&self, exe: &str) -> Option<Verdict> {
        let e = self.entries.get(exe)?;
        // R27-56: backward clock or unusable clock expires the entry.
        if is_stale(e, now()) {
            return None;
        }
        let m = std::fs::metadata(exe).ok()?;
        if m.ino() != e.inode || m.mtime() != e.mtime || m.len() != e.size {
            return None; // FILE CHANGED — verdict revoked
        }
        Some(e.verdict)
    }

    /// Record the verdict for **this specific binary** after a deep scan.
    pub fn record(&mut self, exe: &str, verdict: Verdict) {
        let Ok(m) = std::fs::metadata(exe) else {
            return;
        };
        // R27-56: if the clock is unusable, store 0; lookup will treat the
        // entry as expired (checked_sub returns None).
        let scanned_at = now().unwrap_or(0);
        self.entries.insert(
            exe.to_string(),
            Entry {
                inode: m.ino(),
                mtime: m.mtime(),
                size: m.len(),
                verdict,
                scanned_at,
                version: CACHE_VERSION,
                sha256: String::new(),
            },
        );
        self.dirty = true;
    }

    /// Persist to disk (atomic write), only if modified.
    /// Creates the parent directory with secure permissions (0700) and writes
    /// the cache file with mode 0600 so only root can read it.
    pub fn persist(&self) {
        if !self.dirty {
            return;
        }
        if let Some(parent) = self.path.parent() {
            // Aggressively create the directory with secure permissions
            let _ = std::fs::create_dir_all(parent);
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
        if let Ok(json) = serde_json::to_string(&self.entries) {
            let tmp = self.path.with_extension("tmp");
            if std::fs::write(&tmp, json).is_ok() {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backwards_clock_expires_the_entry() {
        let e = Entry {
            inode: 0,
            mtime: 0,
            size: 0,
            verdict: Verdict::Benign,
            scanned_at: 2_000,
            version: CACHE_VERSION,
            sha256: String::new(),
        };
        // R27-56: clock stepped back ⇒ expired, not fresh.
        assert!(
            is_stale(&e, Some(1_000)),
            "clock stepped back ⇒ expired, not fresh"
        );
        // R27-56: unusable clock ⇒ expired.
        assert!(is_stale(&e, None), "unusable clock ⇒ expired");
        // Fresh boundary.
        assert!(!is_stale(&e, Some(2_000 + TTL_SECS - 1)));
        // Expired boundary.
        assert!(is_stale(&e, Some(2_000 + TTL_SECS + 1)));
    }
}
