// src/scanners/integrity.rs
//! Shared "who controls these bytes" primitives for SEC-043 / SEC-051 / SEC-052.
//! One source of truth: the policy must not drift between subsystems — same
//! rationale as SUDO_PRIVESC_MARKER and scoring::core_pattern_is_trusted.

use crate::models::ExecWritability;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// A path is unsafe if a non-root principal can write to it.
/// Sticky bit intentionally ignored: it prevents deleting foreign files but
/// not creating new ones — which is all an injection needs.
pub(crate) fn unsafe_mode(mode: u32, uid: u32, gid: u32) -> bool {
    mode & 0o002 != 0 || (uid != 0 && mode & 0o200 != 0) || (gid != 0 && mode & 0o020 != 0)
}

/// Who controls the bytes at `path`: the file itself *and* the directory that
/// holds it (a writable parent means the file can be replaced wholesale).
/// This is a single source of truth; exec_provenance and generators use it.
pub(crate) fn assess_writability(path: &Path) -> ExecWritability {
    let Ok(md) = std::fs::metadata(path) else {
        return ExecWritability::Missing;
    };
    let file_unsafe = unsafe_mode(md.permissions().mode(), md.uid(), md.gid());
    let parent_unsafe = path
        .parent()
        .and_then(|p| std::fs::metadata(p).ok())
        .map(|m| unsafe_mode(m.permissions().mode(), m.uid(), m.gid()));
    match (file_unsafe, parent_unsafe) {
        (true, _) | (_, Some(true)) => ExecWritability::NonRootWritable,
        (false, Some(false)) => ExecWritability::RootOnly,
        (false, None) => ExecWritability::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_mode_matrix() {
        assert!(!unsafe_mode(0o755, 0, 0), "root:root 755 — normal");
        assert!(unsafe_mode(0o777, 0, 0), "world-writable even for root");
        assert!(unsafe_mode(0o755, 1000, 0), "owner not root");
        assert!(
            unsafe_mode(0o775, 0, 1000),
            "group not root and group-write"
        );
        assert!(
            !unsafe_mode(0o755, 0, 1000),
            "group not root, but without w — normal"
        );
        assert!(
            unsafe_mode(0o1777, 0, 0),
            "sticky does not protect library path"
        );
    }
}
