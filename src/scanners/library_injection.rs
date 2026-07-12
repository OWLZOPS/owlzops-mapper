//! Userspace rootkit / library-injection detection (SEC-023) and
//! Anomalous Executable Memory detection (SEC-026).
//!
//! Based on Fable's R11 architectural guidance: suppression by VMA topology,
//! not by process identity.
//!
//! Key concepts:
//! - ExecTier: classifies memory regions (e.g. AnonRx, AnonRwx, ExecStack).
//! - RuntimeTrust: assesses if the process matches a legitimate JIT runtime
//!   topology (exe validity, system runtime .so) to safely suppress JIT-native
//!   anonymous r-x regions without ignoring real injections or isolated RWX regions.

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
/// Known runtime libraries that indicate a legitimate JIT/interpreter environment.
const RT_LIBS: &[&str] = &["libjvm.so", "libnode.so", "libpython3", "libv8"];

/// Tier of the executable region. Replaces the binary `is_anon_exec`.
#[derive(Debug, PartialEq)]
enum ExecTier {
    Ignore,        // [vdso]/[vvar]/[vsyscall] or non-executable
    AnonRx,        // Anonymous r-xp (suppressible if JIT topology matches)
    AnonRwx,       // Anonymous RWX (stronger, hard to justify even for JIT)
    RwxFileBacked, // rwx file-backed from ephemeral paths (strong IOC)
    ExecStack,     // rwx/r-x on [stack] (Buffer overflow / ROP IOC)
    ExecHeap,      // rwx/r-x on [heap] (Heap spray IOC)
}

/// Expensive-to-fake signals that validate a process is a legitimate JIT runtime.
struct RuntimeTrust {
    exe_ok: bool,
    runtime_libs: bool,
}

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
                    // Assess Runtime Trust BEFORE parsing VMA lines
                    let exe_path = fs::read_link(format!("{proc_root}/{pid}/exe"))
                        .map(|p| p.to_string_lossy().to_string())
                        .ok();
                    let trust = assess_runtime(&content, exe_path.as_deref());

                    scan_maps(&content, pid, &comm, &trust, &mut findings);
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

/// Assess if the process exhibits structural traits of a legitimate runtime.
fn assess_runtime(maps: &str, exe_path: Option<&str>) -> RuntimeTrust {
    let exe_ok = exe_path.is_some_and(|e| {
        !e.ends_with(" (deleted)")
            && !crate::utils::is_ephemeral_exec_path(e.trim_end_matches(" (deleted)"))
    });

    let runtime_libs = maps.lines().any(|l| {
        if let Some(path) = l.rsplit(char::is_whitespace).next() {
            path.starts_with("/usr/") && RT_LIBS.iter().any(|lib| path.contains(lib))
        } else {
            false
        }
    });

    RuntimeTrust {
        exe_ok,
        runtime_libs,
    }
}

/// Classify the VMA region based on permissions and backing.
fn classify_region(perms: &str, backing: Option<&str>) -> ExecTier {
    let b = perms.as_bytes();
    let x = b.get(2) == Some(&b'x');
    let w = b.get(1) == Some(&b'w');

    if !x {
        return ExecTier::Ignore;
    }

    match backing {
        Some("[vdso]") | Some("[vvar]") | Some("[vsyscall]") => ExecTier::Ignore,
        Some(p) if p == "[stack]" || p.starts_with("[stack:") => ExecTier::ExecStack,
        Some("[heap]") => ExecTier::ExecHeap,
        Some(p) if p.starts_with("[anon:") => {
            if w {
                ExecTier::AnonRwx
            } else {
                ExecTier::AnonRx
            }
        }
        Some(p) if p.starts_with('/') => {
            if w && crate::utils::is_ephemeral_exec_path(p) {
                ExecTier::RwxFileBacked
            } else {
                ExecTier::Ignore
            }
        }
        Some(_) => {
            if w {
                ExecTier::AnonRwx
            } else {
                ExecTier::AnonRx
            }
        }
        None => {
            if w {
                ExecTier::AnonRwx
            } else {
                ExecTier::AnonRx
            }
        }
    }
}

fn scan_maps(
    content: &str,
    pid: u32,
    comm: &str,
    trust: &RuntimeTrust,
    findings: &mut Vec<LibraryInjectionFinding>,
) {
    let mut seen: Vec<String> = Vec::new();

    for line in content.lines() {
        if findings.len() >= MAX_FINDINGS {
            break;
        }

        let mut it = line.splitn(6, char::is_whitespace);
        let (addr, perms, _off, _dev, _inode, path) = (
            it.next(),
            it.next(),
            it.next(),
            it.next(),
            it.next(),
            it.next(),
        );

        let Some(addr) = addr else { continue };
        if !addr.contains('-') {
            continue;
        }
        let Some(perms) = perms else { continue };
        let path = path.map(str::trim).filter(|p| !p.is_empty());

        // --- 1. Classical ephemeral .so injection (SEC-023) ---
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

        if found_ephemeral {
            continue;
        }

        // --- 2. Anomalous Executable Regions (SEC-026 / SEC-023 Escalation) ---
        let tier = classify_region(perms, path);
        if tier == ExecTier::Ignore {
            continue;
        }

        // Fable logic: Suppress AnonRx if it perfectly matches JIT topology
        if tier == ExecTier::AnonRx && trust.exe_ok && trust.runtime_libs {
            continue;
        }

        let (source, desc) = match tier {
            ExecTier::ExecStack => (
                "maps-exec-stack",
                format!("{} (shellcode on stack)", path.unwrap_or("[stack]")),
            ),
            ExecTier::ExecHeap => ("maps-exec-heap", "[heap] (heap spray IOC)".to_string()),
            ExecTier::RwxFileBacked => (
                "maps-anon-rwx",
                format!("{} (rwx file-backed)", path.unwrap_or("unknown")),
            ),
            ExecTier::AnonRwx => ("maps-anon-rwx", "anonymous executable (rwxp)".to_string()),
            ExecTier::AnonRx => ("maps-anon-rx", "anonymous executable (r-xp)".to_string()),
            _ => continue,
        };

        if !seen.contains(&desc) {
            seen.push(desc.clone());
            findings.push(LibraryInjectionFinding {
                pid,
                process: comm.to_string(),
                object_path: desc,
                source: source.to_string(),
                is_deleted: false,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    // ── maps parsing ─────────────────────────────────────────

    fn find_with_trust(
        content: &str,
        exe_ok: bool,
        runtime_libs: bool,
    ) -> Vec<LibraryInjectionFinding> {
        let mut f = Vec::new();
        let trust = RuntimeTrust {
            exe_ok,
            runtime_libs,
        };
        scan_maps(content, 1, "victim", &trust, &mut f);
        f
    }

    fn find(content: &str) -> Vec<LibraryInjectionFinding> {
        // Default to untrusted for basic tests
        find_with_trust(content, false, false)
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
    fn maps_non_so_executable_from_tmp_is_ignored_by_so_check() {
        let m = "7f20-7f30 r-xp 0 08:01 200 /tmp/dropper\n";
        // It's not an .so, but it WILL be flagged as RwxFileBacked if writable.
        // Here it's only r-xp, so it falls through to Ignore (file-backed rx is ignored).
        assert!(find(m).is_empty());
    }

    #[test]
    fn maps_malformed_lines_do_not_panic() {
        let m = "garbage\n\n7f20 r-xp\n7f20-7f30 r-xp 0 08:01 200 /tmp/ok.so\n";
        let out = find(m);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].object_path, "/tmp/ok.so");
    }

    // ── NEW: anon exec & JIT suppression tests ────────────────

    #[test]
    fn maps_flags_anon_exec() {
        let m = "7f20-7f30 r-xp 00000000 00:00 0\n";
        let out = find(m);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].object_path, "anonymous executable (r-xp)");
        assert_eq!(out[0].source, "maps-anon-rx"); // Updated assertion
    }

    #[test]
    fn maps_flags_rwx_file_backed() {
        let m = "7f20-7f30 rwxp 0 08:01 200 /tmp/suspicious\n";
        let out = find(m);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].object_path, "/tmp/suspicious (rwx file-backed)");
        assert_eq!(out[0].source, "maps-anon-rwx"); // Updated assertion
    }

    #[test]
    fn maps_anon_rw_ignored() {
        // writable but not executable → not flagged
        let m = "7f20-7f30 rw-p 00000000 00:00 0\n";
        assert!(find(m).is_empty());
    }

    #[test]
    fn maps_flags_exec_stack_and_heap() {
        let m = "\
7f20-7f30 rwxp 00000000 00:00 0 [stack]
7f40-7f50 rwxp 00000000 00:00 0 [heap]
";
        let out = find(m);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].source, "maps-exec-stack");
        assert_eq!(out[1].source, "maps-exec-heap");
    }

    #[test]
    fn maps_suppresses_jit_anon_rx() {
        // A Node.js environment with libnode loaded and an anonymous r-xp region.
        let m = "\
7f00-7f10 r-xp 00000000 08:01 100 /usr/lib/libnode.so.108
7f20-7f30 r-xp 00000000 00:00 0
";
        // Assess trust realistically: exe is valid, and runtime libs are present.
        let trust = assess_runtime(m, Some("/usr/bin/node"));

        let mut f = Vec::new();
        scan_maps(m, 1, "node", &trust, &mut f);

        // The AnonRx should be successfully suppressed by Fable's logic!
        assert!(f.is_empty(), "JIT code cache should be suppressed");
    }

    // ── environ + end-to-end over a fake /proc ──────────────

    /// Build a fake /proc/<pid> with comm, environ (NUL-separated), and maps.
    fn fake_pid(
        pid: u32,
        comm: &str,
        environ: &[&str],
        maps: &str,
        exe_target: Option<&str>,
    ) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join(pid.to_string());
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("comm"), format!("{comm}\n")).unwrap();

        if let Some(target) = exe_target {
            symlink(target, base.join("exe")).ok();
        }

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
            Some("/usr/sbin/nginx"),
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
            Some("/usr/bin/redis-server"),
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
            Some("/usr/bin/app"),
        );
        let out = detect_from_proc(proc.path().to_str().unwrap());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].object_path, "/dev/shm/x");
        assert_eq!(out[0].source, "LD_LIBRARY_PATH");
    }

    #[test]
    fn environ_ld_audit_from_tmp_is_flagged() {
        let proc = fake_pid(
            1342,
            "sshd",
            &["LD_AUDIT=/dev/shm/audit.so"],
            "",
            Some("/usr/sbin/sshd"),
        );
        let out = detect_from_proc(proc.path().to_str().unwrap());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].object_path, "/dev/shm/audit.so");
        assert_eq!(out[0].source, "LD_AUDIT");
    }

    #[test]
    fn environ_ld_profile_from_tmp_is_flagged() {
        let proc = fake_pid(
            1343,
            "java",
            &["LD_PROFILE=/tmp/prof.so"],
            "",
            Some("/usr/bin/java"),
        );
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
            Some("/usr/sbin/sshd"),
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
            Some("/bin/bash"),
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
