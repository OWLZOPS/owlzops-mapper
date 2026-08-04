// src/scanners/generators.rs
// SEC-052/053/054: systemd generator persistence.

use crate::models::{ExecWritability, GeneratorFinding, GeneratorKind, GeneratorOrigin};
use crate::scanners::integrity::{assess_writability, unsafe_mode};
use crate::{coverage, models::ProvenanceSource};
use std::collections::HashSet;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

const MAX_GENERATORS: usize = 256;

const GENERATOR_DIRS: &[(&str, GeneratorOrigin)] = &[
    ("/run/systemd/system-generators", GeneratorOrigin::Runtime),
    ("/etc/systemd/system-generators", GeneratorOrigin::Admin),
    (
        "/usr/local/lib/systemd/system-generators",
        GeneratorOrigin::LocalAdmin,
    ),
    (
        "/usr/lib/systemd/system-generators",
        GeneratorOrigin::Vendor,
    ),
    ("/run/systemd/user-generators", GeneratorOrigin::Runtime),
    ("/etc/systemd/user-generators", GeneratorOrigin::Admin),
    (
        "/usr/local/lib/systemd/user-generators",
        GeneratorOrigin::LocalAdmin,
    ),
    ("/usr/lib/systemd/user-generators", GeneratorOrigin::Vendor),
];

// ── Pure decision layer ────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GeneratorVerdict {
    Ioc,
    Unpackaged,
    Unverifiable,
    Benign,
}

pub(crate) fn is_volatile_escape(resolved: &str) -> bool {
    crate::utils::is_volatile_exec_path(resolved) && !resolved.starts_with("/run/systemd/")
}

pub(crate) fn classify_generator(
    kind: GeneratorKind,
    origin: GeneratorOrigin,
    writability: ExecWritability,
    volatile_escape: bool,
    package: Option<&str>,
    provenance: ProvenanceSource,
) -> GeneratorVerdict {
    if kind == GeneratorKind::SearchDir {
        return GeneratorVerdict::Ioc;
    }
    if writability == ExecWritability::NonRootWritable || volatile_escape {
        return GeneratorVerdict::Ioc;
    }
    if origin == GeneratorOrigin::Vendor || package.is_some() {
        return GeneratorVerdict::Benign;
    }
    if provenance == ProvenanceSource::Unavailable {
        return GeneratorVerdict::Unverifiable;
    }
    GeneratorVerdict::Unpackaged
}

pub(crate) fn describe(g: &GeneratorFinding) -> String {
    let mut s = g.path.clone();
    if let Some(t) = &g.symlink_target {
        s.push_str(&format!(" → {t}"));
    }
    if g.writability == ExecWritability::NonRootWritable {
        s.push_str(&format!(" (writable, uid {})", g.uid));
    }
    if g.writability == ExecWritability::Missing {
        s.push_str(" (dangling link — target can be created)");
    }
    s
}

// ── I/O layer ─────────────────────────────────────────────────

fn is_executable(mode: u32) -> bool {
    mode & 0o111 != 0
}

fn inspect_entry(path: &Path, origin: GeneratorOrigin) -> Option<GeneratorFinding> {
    let lmd = std::fs::symlink_metadata(path).ok()?;
    if lmd.is_dir() {
        return None;
    }
    let symlink_target = lmd
        .file_type()
        .is_symlink()
        .then(|| std::fs::read_link(path).ok())
        .flatten()
        .map(|p| p.to_string_lossy().into_owned());

    let resolved = std::fs::canonicalize(path).ok();
    let (writability, uid, gid, executable) = match resolved.as_deref() {
        Some(r) => match std::fs::metadata(r) {
            Ok(md) => (
                assess_writability(r),
                md.uid(),
                md.gid(),
                is_executable(md.permissions().mode()),
            ),
            Err(_) => (ExecWritability::Unknown, lmd.uid(), lmd.gid(), true),
        },
        None => (ExecWritability::Missing, lmd.uid(), lmd.gid(), true),
    };

    if !executable {
        return None;
    }

    Some(GeneratorFinding {
        path: path.to_string_lossy().into_owned(),
        kind: GeneratorKind::Executable,
        origin,
        package: None,
        writability,
        symlink_target,
        resolved_path: resolved.map(|p| p.to_string_lossy().into_owned()),
        uid,
        gid,
    })
}

fn inspect_dir(dir: &Path, origin: GeneratorOrigin) -> Option<GeneratorFinding> {
    let md = std::fs::metadata(dir).ok()?;
    unsafe_mode(md.permissions().mode(), md.uid(), md.gid()).then(|| GeneratorFinding {
        path: dir.to_string_lossy().into_owned(),
        kind: GeneratorKind::SearchDir,
        origin,
        package: None,
        writability: ExecWritability::NonRootWritable,
        symlink_target: None,
        resolved_path: None,
        uid: md.uid(),
        gid: md.gid(),
    })
}

pub fn scan_generators() -> Vec<GeneratorFinding> {
    let mut out: Vec<GeneratorFinding> = Vec::new();
    let mut over_cap = 0usize;

    for (dir, origin) in GENERATOR_DIRS {
        let dir_path = Path::new(dir);
        if let Some(f) = inspect_dir(dir_path, *origin) {
            out.push(f);
        }
        match std::fs::read_dir(dir_path) {
            Ok(entries) => {
                for e in entries.flatten() {
                    if out.len() >= MAX_GENERATORS {
                        over_cap += 1;
                        continue;
                    }
                    if let Some(f) = inspect_entry(&e.path(), *origin) {
                        out.push(f);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => coverage::record(format!(
                "{dir} unreadable ({e}); SEC-052 generator surface NOT verified"
            )),
        }
    }

    if over_cap > 0 {
        coverage::record(format!(
            "generators: cap ({MAX_GENERATORS}) reached; {over_cap} entr(ies) NOT inspected"
        ));
    }

    let candidates: HashSet<String> = out
        .iter()
        .filter(|g| g.kind == GeneratorKind::Executable)
        .map(|g| {
            crate::utils::canon_path(g.resolved_path.as_deref().unwrap_or(&g.path)).into_owned()
        })
        .collect();
    if !candidates.is_empty() {
        let prov = crate::scanners::provenance::resolve_batch(&candidates);
        for g in &mut out {
            let key = crate::utils::canon_path(g.resolved_path.as_deref().unwrap_or(&g.path));
            g.package = prov.lookup(key.as_ref());
        }
    }

    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v() -> ProvenanceSource {
        ProvenanceSource::Dpkg
    }

    #[test]
    fn writable_search_dir_is_always_ioc() {
        assert_eq!(
            classify_generator(
                GeneratorKind::SearchDir,
                GeneratorOrigin::Admin,
                ExecWritability::NonRootWritable,
                false,
                None,
                v()
            ),
            GeneratorVerdict::Ioc
        );
    }

    #[test]
    fn vendor_generator_is_silent() {
        assert_eq!(
            classify_generator(
                GeneratorKind::Executable,
                GeneratorOrigin::Vendor,
                ExecWritability::RootOnly,
                false,
                None,
                v()
            ),
            GeneratorVerdict::Benign
        );
    }

    #[test]
    fn admin_generator_tiers_by_provenance() {
        let call = |p, src| {
            classify_generator(
                GeneratorKind::Executable,
                GeneratorOrigin::Admin,
                ExecWritability::RootOnly,
                false,
                p,
                src,
            )
        };
        assert_eq!(call(Some("systemd"), v()), GeneratorVerdict::Benign);
        assert_eq!(call(None, v()), GeneratorVerdict::Unpackaged);
        assert_eq!(
            call(None, ProvenanceSource::Unavailable),
            GeneratorVerdict::Unverifiable
        );
    }

    #[test]
    fn writability_trumps_everything() {
        assert_eq!(
            classify_generator(
                GeneratorKind::Executable,
                GeneratorOrigin::Vendor,
                ExecWritability::NonRootWritable,
                false,
                Some("systemd"),
                v()
            ),
            GeneratorVerdict::Ioc
        );
    }

    #[test]
    fn run_systemd_is_not_an_escape() {
        assert!(!is_volatile_escape("/run/systemd/system-generators/foo"));
        assert!(is_volatile_escape("/dev/shm/gen"));
        assert!(is_volatile_escape("/tmp/gen"));
    }

    #[test]
    fn non_executable_entry_is_skipped() {
        let dir = tempfile::TempDir::new().unwrap();
        let f = dir.path().join("README");
        std::fs::write(&f, b"notes").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(inspect_entry(&f, GeneratorOrigin::Admin).is_none());
    }

    #[test]
    fn dangling_symlink_is_missing_not_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        let link = dir.path().join("gen");
        std::os::unix::fs::symlink("/nonexistent/payload", &link).unwrap();
        let f = inspect_entry(&link, GeneratorOrigin::Admin).unwrap();
        assert_eq!(f.writability, ExecWritability::Missing);
        assert_eq!(f.symlink_target.as_deref(), Some("/nonexistent/payload"));
    }
}
