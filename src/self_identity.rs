//! Unforgeable self-identification (R12).
//!
//! Deployment is unlink-on-exec: upload to an ephemeral path, run under sudo,
//! unlink while running. That is byte-for-byte the SEC-017/SEC-019 fileless
//! signature, so the scanner detects itself. It cannot be made *invisible* to
//! its own heuristics — footprintlessness IS the signature. It is made
//! *identifiable* instead.
//!
//! The anchor is the PID and only the PID. `comm`/`argv[0]` are attacker
//! controlled (`prctl(PR_SET_NAME)`, forged `argv[0]`) and an env nonce is
//! copyable by any root reader of `/proc/<pid>/environ` — both hand out a
//! rename-to-bypass. No live process holds our PID in our PID namespace, and
//! `std::process::id()` is read from the same namespace we readdir `/proc`
//! from, so the comparison is total. musl does not cache getpid(), so the
//! anchor stays honest across a fork.
//!
//! Identity answers exactly ONE question: "is this record literally me?".
//! It is not a licence to skip the PID.

#![allow(dead_code)] // Fields/methods used in upcoming R12-03 and integrity report

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::OnceLock;

use crate::models::{SelfIntegrityReport, SuspiciousProcess};

const SELF_REASON: &str = "scanner self-image: ephemeral privileged exec is the expected \
     footprint of unlink-on-exec deployment (identity anchored on PID, not process name)";

#[derive(Debug, Clone)]
pub struct SelfIdentity {
    /// The only unforgeable anchor.
    pid: u32,
    /// (dev, ino) of our exec image. Corroboration and per-region discrimination
    /// in /proc/self/maps — NOT an identity gate (a hardlink shares it).
    exe_id: Option<(u64, u64)>,
    exe_path: Option<String>,
    /// st_nlink == 0 — authoritative unlink proof. The readlink " (deleted)"
    /// suffix is not: a file may legitimately be named `x (deleted)`.
    unlinked: bool,
}

static SELF: OnceLock<SelfIdentity> = OnceLock::new();

/// Established once per process. `pid` is constant for our lifetime, so this is
/// order-independent and unraceable — no plumbing through scanner signatures.
pub fn identity() -> &'static SelfIdentity {
    SELF.get_or_init(SelfIdentity::establish)
}

/// Only strip the kernel's marker when st_nlink corroborates it.
fn strip_deleted_marker(raw: &str, unlinked: bool) -> &str {
    match raw.strip_suffix(" (deleted)") {
        Some(stripped) if unlinked => stripped,
        _ => raw,
    }
}

fn dir_is_world_writable(dir: &Path) -> bool {
    fs::metadata(dir)
        .map(|m| m.permissions().mode() & 0o002 != 0)
        .unwrap_or(false)
}

impl SelfIdentity {
    fn establish() -> Self {
        let pid = std::process::id();

        // stat() THROUGH the magic link: the kernel jumps to the exe_file's
        // struct path, so dev/ino resolve even with zero links left. read_link()
        // by contrast returns d_path text with the " (deleted)" suffix.
        let meta = fs::metadata("/proc/self/exe").ok();
        let exe_id = meta.as_ref().map(|m| (m.dev(), m.ino()));
        let unlinked = meta.as_ref().is_some_and(|m| m.nlink() == 0);

        let exe_path = fs::read_link("/proc/self/exe").ok().map(|p| {
            let s = p.to_string_lossy().into_owned();
            strip_deleted_marker(&s, unlinked).to_string()
        });

        Self {
            pid,
            exe_id,
            exe_path,
            unlinked,
        }
    }

    /// The only identity question.
    #[inline]
    pub fn is_self(&self, pid: u32) -> bool {
        pid == self.pid
    }

    /// True when a `/proc/<pid>/maps` region is backed by our own exec image.
    /// Callers must build `dev` with `libc::makedev()` from the hex `major:minor`
    /// maps field. Fails OPEN: unknown exe_id ⇒ false ⇒ region stays a live
    /// injection candidate (demotion requires corroboration).
    #[inline]
    pub fn is_own_image(&self, dev: u64, ino: u64) -> bool {
        self.exe_id == Some((dev, ino))
    }

    /// Mark — never drop — our own records.
    pub fn attribute(&self, procs: &mut [SuspiciousProcess]) {
        for p in procs.iter_mut().filter(|p| self.is_self(p.pid)) {
            p.self_attributed = Some(SELF_REASON.to_string());
        }
    }

    /// Feeds `AgentReport.self_integrity`. Self-attribution is only sound if the
    /// exec image is provably ours; when it isn't, say so rather than assert trust.
    pub fn integrity_report(&self) -> SelfIntegrityReport {
        let mut warnings = Vec::new();
        match &self.exe_path {
            Some(path) => {
                if self.unlinked {
                    warnings.push(format!(
                        "exec image {path} is unlinked (nlink=0); SEC-017/SEC-019 self-attribution \
                         active for pid {}",
                        self.pid
                    ));
                }
                if let Some(dir) = Path::new(path).parent()
                    && dir_is_world_writable(dir)
                {
                    warnings.push(format!(
                        "exec image loaded from world-writable directory {} — image provenance is \
                         NOT verifiable from inside this process, and any NOPASSWD sudo rule naming \
                         {path} grants an unrestricted root shell (see SEC-005)",
                        dir.display()
                    ));
                }
            }
            None => warnings.push(
                "/proc/self/exe unreadable — self-attribution degrades to PID-only".to_string(),
            ),
        }
        // `compromised` stays false: we can warn about an unverifiable premise,
        // we cannot prove tamper from inside a possibly-tampered process.
        SelfIntegrityReport {
            compromised: false,
            warnings,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(pid: u32) -> Self {
        Self {
            pid,
            exe_id: None,
            exe_path: None,
            unlinked: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: u32, name: &str) -> SuspiciousProcess {
        SuspiciousProcess {
            pid,
            name: name.into(),
            is_deleted: true,
            euid: 0,
            ..Default::default()
        }
    }

    #[test]
    fn attributes_only_our_own_pid() {
        let me = SelfIdentity::for_test(4242);
        let mut v = vec![proc(4242, "owlzops-mapper"), proc(1337, "kdevtmpfsi")];
        me.attribute(&mut v);
        assert!(v[0].self_attributed.is_some());
        assert!(v[1].self_attributed.is_none(), "foreign pid must stay live");
    }

    #[test]
    fn rename_to_scanner_name_is_not_self() {
        // The whole point: a miner that prctl()s its comm to ours gets nothing.
        let me = SelfIdentity::for_test(4242);
        let mut v = vec![proc(31337, "owlzops-mapper")];
        me.attribute(&mut v);
        assert!(v[0].self_attributed.is_none(), "name is not an identity");
    }

    #[test]
    fn records_are_marked_never_dropped() {
        let me = SelfIdentity::for_test(7);
        let mut v = vec![proc(7, "owlzops-mapper")];
        me.attribute(&mut v);
        assert_eq!(v.len(), 1, "Raw Truth: suppression marks, never removes");
    }

    #[test]
    fn deleted_marker_needs_nlink_corroboration() {
        assert_eq!(strip_deleted_marker("/tmp/x (deleted)", true), "/tmp/x");
        // A file legitimately named "x (deleted)" with links intact.
        assert_eq!(
            strip_deleted_marker("/opt/x (deleted)", false),
            "/opt/x (deleted)"
        );
        assert_eq!(
            strip_deleted_marker("/usr/local/bin/owlzops-mapper", true),
            "/usr/local/bin/owlzops-mapper"
        );
    }

    #[test]
    fn own_image_match_fails_open_without_exe_id() {
        let me = SelfIdentity::for_test(7);
        assert!(
            !me.is_own_image(0xfd01, 12345),
            "unknown image ⇒ treat region as injection"
        );
    }
}
