//! Userspace rootkit / library-injection detection (SEC-023).
//!
//! Flags processes with a shared object injected from a writable/ephemeral
//! path. Two independent sources, correlated per-pid:
//!   * `/proc/<pid>/environ` — LD_PRELOAD / LD_LIBRARY_PATH / LD_AUDIT /
//!     LD_PROFILE pointing at an ephemeral path;
//!   * `/proc/<pid>/maps`    — a file-backed .so actually mapped from an
//!     ephemeral path (catches ptrace/dlopen implants even after the env var
//!     is scrubbed). A "(deleted)" mapped object is treated as a stronger IoC.
//!     Anonymous executable mappings (r‑xp without a file) and
//!     writable+executable file‑backed mappings (rwxp) are now also flagged
//!     as potential code injection / shellcode.
//!
//! Additionally, the scan now flags `LD_AUDIT` and `LD_PROFILE`, two less
//! known but equally powerful dynamic linker variables that can force the
//! loading of a shared object into every process started by the affected
//! binary (MITRE T1574.006).
//!
//! FP control is by funnel, reusing the existing `is_ephemeral_exec_path`
//! contract (the same /tmp,/var/tmp,/dev/shm,/home,/memfd: set that already
//! drives SEC-013/015). Legit software does not preload .so from these paths.
//!
//! Kernel-rootkit caveat: like every readdir-based scanner this is blind to a
//! PID hidden at the getdents layer — it targets the userspace class, where it
//! is near-zero-FP.

use std::fs;

use crate::coverage;
use crate::models::LibraryInjectionFinding;
use crate::safe_io;

/// maps can be large for JIT/DB processes; cap defensively.
const CAP_PROC_MAPS: usize = 4 * 1024 * 1024;
/// Hard cap on stored findings.
const MAX_FINDINGS: usize = 64;
/// LD_* keys whose ephemeral value indicates injection.
const INJECT_ENV_KEYS: [&str; 4] = ["LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_PROFILE"];

pub fn scan_library_injections() -> Vec<LibraryInjectionFinding> {
    detect_from_proc("/proc")
}

fn detect_from_proc(proc_root: &str) -> Vec<LibraryInjectionFinding> {
    let mut findings = Vec::new();
    let mut denied = 0usize;

    let entries = match fs::read_dir(proc_root) {
        Ok(e) => e,
        Err(_) => {
            coverage::record(format!(
                "library-injection scan skipped: {proc_root} unreadable"
            ));
            return findings;
        }
    };

    for entry in entries.flatten() {
        if findings.len() >= MAX_FINDINGS {
            break;
        }
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };

        let comm = match safe_io::read_file_capped(&format!("{proc_root}/{pid}/comm"), 4096) {
            Ok((c, _)) => c.trim().to_string(),
            Err(_) => continue,
        };

        let mut pid_hits = 0usize;

        // ── Source 1: environ (LD_PRELOAD / LD_LIBRARY_PATH / LD_AUDIT / LD_PROFILE) ──
        match safe_io::read_file_bytes_capped(
            &format!("{proc_root}/{pid}/environ"),
            safe_io::CAP_PROC_ENVIRON,
        ) {
            Ok((data, truncated)) => {
                if truncated {
                    coverage::record(format!("/proc/{pid}/environ truncated"));
                }
                for chunk in data.split(|&b| b == 0) {
                    if chunk.is_empty() {
                        continue;
                    }
                    let Ok(kv) = std::str::from_utf8(chunk) else {
                        continue;
                    };
                    let Some((key, value)) = kv.split_once('=') else {
                        continue;
                    };
                    let Some(&matched_key) =
                        INJECT_ENV_KEYS.iter().find(|k| key.eq_ignore_ascii_case(k))
                    else {
                        continue;
                    };
                    for path in value.split([':', ' ']).filter(|p| !p.is_empty()) {
                        if crate::utils::is_ephemeral_exec_path(path) {
                            findings.push(LibraryInjectionFinding {
                                pid,
                                process: comm.clone(),
                                object_path: path.to_string(),
                                source: matched_key.to_string(),
                                is_deleted: false,
                            });
                            pid_hits += 1;
                            if findings.len() >= MAX_FINDINGS {
                                break;
                            }
                        }
                    }
                }
            }
            Err(_) => denied += 1,
        }

        // ── Source 2: maps (file-backed .so from ephemeral path + anon exec) ──
        if findings.len() < MAX_FINDINGS {
            match safe_io::read_file_capped(&format!("{proc_root}/{pid}/maps"), CAP_PROC_MAPS) {
                Ok((content, truncated)) => {
                    if truncated {
                        coverage::record(format!("/proc/{pid}/maps truncated"));
                    }
                    scan_maps(&content, pid, &comm, &mut findings);
                }
                Err(_) => {
                    if pid_hits == 0 {
                        denied += 1;
                    }
                }
            }
        }
    }

    if denied > 0 {
        let hint = if !crate::is_running_as_root() {
            " — run as root for full visibility"
        } else {
            ""
        };
        coverage::record(format!(
            "library-injection scan: {denied} process(es) with unreadable environ/maps{hint}"
        ));
    }

    findings
}

/// Returns true if the maps line describes an anonymous executable region
/// (potential code injection) or a writable+executable file-backed region
/// (weaker, but still suspicious).
fn is_anon_exec(perms: &str, backing: Option<&str>) -> bool {
    let x = perms.as_bytes().get(2) == Some(&b'x');
    if !x {
        return false;
    }
    match backing {
        Some(path) if path.starts_with('/') => {
            // file-backed and executable – only flag if also writable
            perms.as_bytes().get(1) == Some(&b'w')
        }
        Some(_) => false, // [heap], [stack], etc.
        None => true,     // anonymous executable (no path)
    }
}

fn scan_maps(content: &str, pid: u32, comm: &str, findings: &mut Vec<LibraryInjectionFinding>) {
    let mut seen: Vec<String> = Vec::new();
    for line in content.lines() {
        if findings.len() >= MAX_FINDINGS {
            break;
        }

        // Original /proc/<pid>/maps parsing (six columns)
        let mut it = line.splitn(6, char::is_whitespace);
        let (addr, perms, _off, _dev, _inode, path) = (
            it.next(),
            it.next(),
            it.next(),
            it.next(),
            it.next(),
            it.next(),
        );
        // Skip malformed lines that don't have a proper address range
        let Some(addr) = addr else { continue };
        if !addr.contains('-') {
            continue;
        }
        let Some(perms) = perms else { continue };
        let path = path.map(str::trim).filter(|p| !p.is_empty());

        // --- File-backed ephemeral .so check ---
        let mut found_ephemeral = false;
        if let Some(p) = path
            && !p.starts_with('[')
        {
            let (clean, is_deleted) = match p.strip_suffix(" (deleted)") {
                Some(base) => (base, true),
                None => (p, false),
            };
            let looks_like_so = clean.ends_with(".so") || clean.contains(".so.");
            if looks_like_so && crate::utils::is_ephemeral_exec_path(clean) {
                let clean_str = clean.to_string();
                if !seen.contains(&clean_str) {
                    seen.push(clean_str);
                    findings.push(LibraryInjectionFinding {
                        pid,
                        process: comm.to_string(),
                        object_path: clean.to_string(),
                        source: "maps".to_string(),
                        is_deleted,
                    });
                    found_ephemeral = true;
                }
            }
        }

        // If we already flagged this line, skip the anon check
        if found_ephemeral {
            continue;
        }

        // --- Anonymous executable detection ---
        if is_anon_exec(perms, path) {
            let description = match path {
                Some(p) if p.starts_with('[') => format!("{p} (anon rwx)"),
                Some(p) => format!("{p} (rwx file-backed)"),
                None => "anonymous executable (r-xp)".to_string(),
            };
            if !seen.contains(&description) {
                seen.push(description.clone());
                findings.push(LibraryInjectionFinding {
                    pid,
                    process: comm.to_string(),
                    object_path: description,
                    source: "maps-anon-exec".to_string(),
                    is_deleted: false,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    // ── maps parsing ─────────────────────────────────────────

    fn find(content: &str) -> Vec<LibraryInjectionFinding> {
        let mut f = Vec::new();
        scan_maps(content, 1, "victim", &mut f);
        f
    }

    #[test]
    fn maps_flags_so_from_tmp() {
        let m = "\
7f00-7f10 r-xp 00000000 08:01 100 /usr/lib/x86_64-linux-gnu/libc.so.6
7f20-7f30 r-xp 00000000 08:01 200 /tmp/evil.so
7f40-7f50 rw-p 00000000 00:00 0 [heap]
";
        let out = find(m);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].object_path, "/tmp/evil.so");
        assert_eq!(out[0].source, "maps");
        assert!(!out[0].is_deleted);
    }

    #[test]
    fn maps_flags_deleted_so_from_dev_shm() {
        let m = "7f20-7f30 r-xp 0 08:01 200 /dev/shm/impl.so (deleted)\n";
        let out = find(m);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].object_path, "/dev/shm/impl.so");
        assert!(out[0].is_deleted, "deleted mapping must be flagged");
    }

    #[test]
    fn maps_ignores_system_so_and_anon() {
        let m = "\
7f00-7f10 r-xp 0 08:01 100 /usr/lib/libssl.so.3
7f40-7f50 rw-p 0 00:00 0 [stack]
7f60-7f70 r--p 0 08:01 300 /lib/ld-linux.so.2
";
        assert!(find(m).is_empty(), "system libraries must not flag");
    }

    #[test]
    fn maps_dedups_multi_segment_so() {
        // Same .so mapped as 4 segments → one finding.
        let m = "\
7f20-7f21 r-xp 0 08:01 200 /tmp/x.so
7f21-7f22 r--p 0 08:01 200 /tmp/x.so
7f22-7f23 rw-p 0 08:01 200 /tmp/x.so
7f23-7f24 ---p 0 08:01 200 /tmp/x.so
";
        assert_eq!(find(m).len(), 1);
    }

    #[test]
    fn maps_versioned_so_matches() {
        let m = "7f20-7f30 r-xp 0 08:01 200 /var/tmp/libfoo.so.1.2\n";
        let out = find(m);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].object_path, "/var/tmp/libfoo.so.1.2");
    }

    #[test]
    fn maps_non_so_executable_from_tmp_is_ignored_here() {
        let m = "7f20-7f30 r-xp 0 08:01 200 /tmp/dropper\n";
        // Not a .so, and not writable, so neither ephemeral nor anon exec fires.
        assert!(find(m).is_empty());
    }

    #[test]
    fn maps_malformed_lines_do_not_panic() {
        let m = "garbage\n\n7f20 r-xp\n7f20-7f30 r-xp 0 08:01 200 /tmp/ok.so\n";
        let out = find(m);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].object_path, "/tmp/ok.so");
    }

    // ── NEW: anon exec tests ──────────────────────────────────

    #[test]
    fn maps_flags_anon_exec() {
        let m = "7f20-7f30 r-xp 00000000 00:00 0\n";
        let out = find(m);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].object_path, "anonymous executable (r-xp)");
        assert_eq!(out[0].source, "maps-anon-exec");
    }

    #[test]
    fn maps_flags_rwx_file_backed() {
        let m = "7f20-7f30 rwxp 0 08:01 200 /tmp/suspicious\n";
        let out = find(m);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].object_path, "/tmp/suspicious (rwx file-backed)");
        assert_eq!(out[0].source, "maps-anon-exec");
    }

    #[test]
    fn maps_anon_rw_ignored() {
        // writable but not executable → not flagged
        let m = "7f20-7f30 rw-p 00000000 00:00 0\n";
        assert!(find(m).is_empty());
    }

    // ── environ + end-to-end over a fake /proc ──────────────

    /// Build a fake /proc/<pid> with comm, environ (NUL-separated), and maps.
    fn fake_pid(pid: u32, comm: &str, environ: &[&str], maps: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join(pid.to_string());
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("comm"), format!("{comm}\n")).unwrap();
        let mut env_bytes = Vec::new();
        for e in environ {
            env_bytes.extend_from_slice(e.as_bytes());
            env_bytes.push(0);
        }
        fs::write(base.join("environ"), env_bytes).unwrap();
        fs::write(base.join("maps"), maps).unwrap();
        tmp
    }

    #[test]
    fn environ_ld_preload_from_tmp_is_flagged() {
        let proc = fake_pid(
            1337,
            "nginx",
            &["PATH=/usr/bin", "LD_PRELOAD=/tmp/hide.so", "HOME=/root"],
            "",
        );
        let out = detect_from_proc(proc.path().to_str().unwrap());
        let hit = out
            .iter()
            .find(|f| f.source == "LD_PRELOAD")
            .expect("LD_PRELOAD flagged");
        assert_eq!(hit.pid, 1337);
        assert_eq!(hit.object_path, "/tmp/hide.so");
    }

    #[test]
    fn environ_ld_preload_from_system_path_is_not_flagged() {
        let proc = fake_pid(
            1338,
            "redis-server",
            &["LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so.2"],
            "",
        );
        let out = detect_from_proc(proc.path().to_str().unwrap());
        assert!(out.is_empty(), "system-path preload is legitimate");
    }

    #[test]
    fn environ_ld_library_path_list_flags_ephemeral_entry() {
        let proc = fake_pid(
            1339,
            "app",
            &["LD_LIBRARY_PATH=/usr/lib:/opt/app/lib:/dev/shm/x"],
            "",
        );
        let out = detect_from_proc(proc.path().to_str().unwrap());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].object_path, "/dev/shm/x");
        assert_eq!(out[0].source, "LD_LIBRARY_PATH");
    }

    #[test]
    fn environ_ld_audit_from_tmp_is_flagged() {
        let proc = fake_pid(1342, "sshd", &["LD_AUDIT=/dev/shm/audit.so"], "");
        let out = detect_from_proc(proc.path().to_str().unwrap());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].object_path, "/dev/shm/audit.so");
        assert_eq!(out[0].source, "LD_AUDIT");
    }

    #[test]
    fn environ_ld_profile_from_tmp_is_flagged() {
        let proc = fake_pid(1343, "java", &["LD_PROFILE=/tmp/prof.so"], "");
        let out = detect_from_proc(proc.path().to_str().unwrap());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].object_path, "/tmp/prof.so");
        assert_eq!(out[0].source, "LD_PROFILE");
    }

    #[test]
    fn environ_and_maps_both_contribute() {
        let proc = fake_pid(
            1340,
            "sshd",
            &["LD_PRELOAD=/tmp/a.so"],
            "7f20-7f30 r-xp 0 08:01 200 /dev/shm/b.so\n",
        );
        let out = detect_from_proc(proc.path().to_str().unwrap());
        assert_eq!(out.len(), 2);
        assert!(
            out.iter()
                .any(|f| f.source == "LD_PRELOAD" && f.object_path == "/tmp/a.so")
        );
        assert!(
            out.iter()
                .any(|f| f.source == "maps" && f.object_path == "/dev/shm/b.so")
        );
    }

    #[test]
    fn clean_process_yields_nothing() {
        let proc = fake_pid(
            1341,
            "bash",
            &["PATH=/usr/bin", "HOME=/home/user"],
            "7f00-7f10 r-xp 0 08:01 100 /usr/lib/libc.so.6\n7f40-7f50 rw-p 0 00:00 0 [heap]\n",
        );
        assert!(detect_from_proc(proc.path().to_str().unwrap()).is_empty());
    }

    #[test]
    fn unreadable_pid_is_skipped_not_fatal() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("9999")).unwrap();
        let out = detect_from_proc(tmp.path().to_str().unwrap());
        assert!(out.is_empty());
    }

    #[test]
    fn non_numeric_proc_entries_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("net")).unwrap();
        fs::write(tmp.path().join("net").join("tcp"), "junk").unwrap();
        symlink("/x", tmp.path().join("self")).ok();
        let out = detect_from_proc(tmp.path().to_str().unwrap());
        assert!(out.is_empty());
    }
}
