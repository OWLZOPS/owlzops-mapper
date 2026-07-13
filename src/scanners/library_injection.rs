//! Userspace rootkit / library-injection detection (SEC-023) and
//! Anomalous Executable Memory detection (SEC-026).

use std::fs;

use crate::coverage;
use crate::models::LibraryInjectionFinding;
use crate::safe_io;

const CAP_PROC_MAPS: usize = 4 * 1024 * 1024;
const MAX_FINDINGS: usize = 64;
const INJECT_ENV_KEYS: [&str; 4] = ["LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_PROFILE"];
const RT_LIBS: &[&str] = &[
    "libjvm.so",
    "libnode.so",
    "libpython3",
    "libv8",
    "libcef.so",
];

// ── VENDOR & RUNTIME ANCHORS ───────────────────────────────

const VENDOR_ROOTS: &[&str] = &[
    "/.local/share/JetBrains/",
    "/.cache/JetBrains/",
    "/.vscode/",
    "/.vscode-server/",
    "/usr/share/code/",
    "/opt/google/chrome/",
];
const VENDOR_ANCHOR_MIN_SO: usize = 3;

/// Known static runtimes or complex interpreters that do not predictably
/// load RT_LIBS. Checked by strict binary path only.
const RUNTIME_EXE_ALLOWLIST: &[&str] = &[
    "/opt/google/chrome/chrome",
    "/usr/lib/chromium/chromium",
    "/usr/bin/php",
    "/usr/sbin/php-fpm",
    "/usr/bin/node",
    "/usr/local/bin/node",
    "/usr/bin/python",
    "/usr/bin/python3",
    "/usr/bin/unattended-upgrade",
    "/usr/local/hestia/nginx/sbin/hestia-nginx",
];

/// Volatile paths where a loaded .so is genuinely suspicious.
/// Differs from is_ephemeral_exec_path by NOT including /home,
/// because user software (IDEs, VSCode) legitimately loads .so from /home.
fn is_volatile_lib_path(p: &str) -> bool {
    p.starts_with("/tmp/")
        || p.starts_with("/var/tmp/")
        || p.starts_with("/dev/shm/")
        || p.starts_with("/run/")
        || p.starts_with("/memfd:")
}

fn exe_allowlisted(exe: Option<&str>) -> bool {
    exe.is_some_and(|e| {
        let base = e.trim_end_matches(" (deleted)");
        !e.ends_with(" (deleted)")
            && RUNTIME_EXE_ALLOWLIST
                .iter()
                .any(|p| base.starts_with(p) || base == *p)
    })
}

// ── REGION TIERING ─────────────────────────────────────────

#[derive(Debug, PartialEq, Clone, Copy)]
enum ExecTier {
    Ignore,
    AnonRx,
    AnonRwx,
    RwxFileBacked,
    ExecStack,
    ExecHeap,
}

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
            // If a writable file resides in a volatile directory -> alert
            if w && is_volatile_lib_path(p) {
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

// ── RUNTIME TRUST & TOPOLOGY ───────────────────────────────

struct RuntimeTrust {
    exe_ok: bool,
    runtime_libs: bool,
    vendor_anchored: bool,
}

fn assess_runtime(maps: &str, exe_path: Option<&str>) -> RuntimeTrust {
    let exe_ok = exe_path.is_some_and(|e| {
        let clean = e.trim_end_matches(" (deleted)");
        let is_deleted = e.ends_with(" (deleted)");

        // Allow execution from /home if it's a confirmed vendor path (e.g. JetBrains)
        let is_vendor = VENDOR_ROOTS.iter().any(|r| clean.contains(*r));

        !is_deleted && (!crate::utils::is_ephemeral_exec_path(clean) || is_vendor)
    });

    let runtime_libs = maps.lines().any(|l| {
        l.rsplit(char::is_whitespace)
            .next()
            .is_some_and(|p| p.starts_with("/usr/") && RT_LIBS.iter().any(|lib| p.contains(lib)))
    });

    let vendor_anchored = exe_path
        .and_then(|e| VENDOR_ROOTS.iter().find(|r| e.contains(**r)).copied())
        .is_some_and(|root| {
            maps.lines()
                .filter(|l| {
                    let last = l.rsplit(char::is_whitespace).next().unwrap_or("");
                    last.contains(root)
                        && !last.ends_with("(deleted)")
                        && (last.ends_with(".so") || last.contains(".so."))
                })
                .count()
                >= VENDOR_ANCHOR_MIN_SO
        });

    RuntimeTrust {
        exe_ok,
        runtime_libs,
        vendor_anchored,
    }
}

#[derive(Debug)]
struct ExecCluster {
    lo: u64,
    hi: u64,
    pages: usize,
    span: u64,
}

fn build_exec_clusters(maps: &str) -> Vec<ExecCluster> {
    const GAP: u64 = 64 * 1024;
    let mut regions: Vec<(u64, u64)> = maps
        .lines()
        .filter_map(|l| {
            let mut it = l.splitn(6, char::is_whitespace);
            let addr = it.next()?;
            if it.next()?.as_bytes().get(2) != Some(&b'x') {
                return None;
            }
            let (lo, hi) = addr.split_once('-')?;
            Some((
                u64::from_str_radix(lo, 16).ok()?,
                u64::from_str_radix(hi, 16).ok()?,
            ))
        })
        .collect();

    regions.sort_unstable();
    let mut out: Vec<ExecCluster> = Vec::new();
    for (lo, hi) in regions {
        match out.last_mut() {
            Some(c) if lo.saturating_sub(c.hi) <= GAP => {
                c.hi = hi;
                c.pages += 1;
                c.span = c.hi - c.lo;
            }
            _ => out.push(ExecCluster {
                lo,
                hi,
                pages: 1,
                span: hi - lo,
            }),
        }
    }
    out
}

fn is_inside_jit_cluster(addr_lo: u64, clusters: &[ExecCluster]) -> bool {
    clusters
        .iter()
        .any(|c| (c.span >= 8 * 1024 * 1024 || c.pages >= 16) && addr_lo >= c.lo && addr_lo <= c.hi)
}

const TRAMP_MAX_BYTES: u64 = 4 * 4096;
const TRAMP_POOL_MIN: usize = 8;

fn region_size(addr: &str) -> Option<u64> {
    let (lo, hi) = addr.split_once('-')?;
    Some(u64::from_str_radix(hi, 16).ok()? - u64::from_str_radix(lo, 16).ok()?)
}

fn is_trampoline_pool(maps: &str) -> bool {
    maps.lines()
        .filter(|l| {
            let mut it = l.splitn(6, char::is_whitespace);
            let (Some(a), Some(p)) = (it.next(), it.next()) else {
                return false;
            };
            p.as_bytes().get(2) == Some(&b'x')
                && region_size(a).is_some_and(|s| s <= TRAMP_MAX_BYTES)
        })
        .count()
        >= TRAMP_POOL_MIN
}

// ── MAIN SCANNER ───────────────────────────────────────────

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

        // --- 1. ENVIRON SCAN ---
        if let Ok((data, _)) = safe_io::read_file_bytes_capped(
            &format!("{proc_root}/{pid}/environ"),
            safe_io::CAP_PROC_ENVIRON,
        ) {
            for chunk in data.split(|&b| b == 0).filter(|c| !c.is_empty()) {
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
                    if is_volatile_lib_path(path) {
                        findings.push(LibraryInjectionFinding {
                            pid,
                            process: comm.clone(),
                            object_path: path.to_string(),
                            source: matched_key.to_string(),
                            is_deleted: false,
                            region_addr: None, // no address available from environ
                            deep_forensics: None,
                        });
                        pid_hits += 1;
                    }
                }
            }
        }

        // --- 2. MAPS SCAN ---
        if findings.len() < MAX_FINDINGS {
            if let Ok((content, _)) =
                safe_io::read_file_capped(&format!("{proc_root}/{pid}/maps"), CAP_PROC_MAPS)
            {
                let exe_path = fs::read_link(format!("{proc_root}/{pid}/exe"))
                    .map(|p| p.to_string_lossy().to_string())
                    .ok();
                let trust = assess_runtime(&content, exe_path.as_deref());
                scan_maps(
                    &content,
                    pid,
                    &comm,
                    &trust,
                    exe_path.as_deref(),
                    &mut findings,
                );
            } else if pid_hits == 0 {
                denied += 1;
            }
        }
    }

    if denied > 0 {
        coverage::record(format!(
            "library-injection scan: {denied} process(es) with unreadable maps"
        ));
    }
    findings
}

fn scan_maps(
    content: &str,
    pid: u32,
    comm: &str,
    trust: &RuntimeTrust,
    exe_path: Option<&str>,
    findings: &mut Vec<LibraryInjectionFinding>,
) {
    let mut seen: Vec<String> = Vec::new();
    let clusters = build_exec_clusters(content);
    let pool = is_trampoline_pool(content);
    let trust_met = trust.exe_ok && (trust.runtime_libs || trust.vendor_anchored);

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
        let addr_lo = addr
            .split_once('-')
            .and_then(|(lo, _)| u64::from_str_radix(lo, 16).ok())
            .unwrap_or(0);

        let Some(perms) = perms else { continue };
        let path = path.map(str::trim).filter(|p| !p.is_empty());

        // --- 2.1 Classical Ephemeral .so Injection (SEC-023) ---
        let mut found_ephemeral = false;
        if let Some(p) = path
            && !p.starts_with('[')
        {
            let (clean, is_deleted) = match p.strip_suffix(" (deleted)") {
                Some(base) => (base, true),
                None => (p, false),
            };
            if (clean.ends_with(".so") || clean.contains(".so.")) && is_volatile_lib_path(clean) {
                let source = if trust_met {
                    "maps-so-jit-extract"
                } else {
                    "maps"
                };
                let clean_str = clean.to_string();
                if !seen.contains(&clean_str) {
                    seen.push(clean_str);
                    findings.push(LibraryInjectionFinding {
                        pid,
                        process: comm.to_string(),
                        object_path: clean.to_string(),
                        source: source.to_string(),
                        is_deleted,
                        region_addr: Some(addr.to_string()),
                        deep_forensics: None,
                    });
                    found_ephemeral = true;
                }
            }
        }
        if found_ephemeral {
            continue;
        }

        // --- 2.2 Anomalous Executable Regions (SEC-026 & SEC-027) ---
        let tier = classify_region(perms, path);
        if tier == ExecTier::Ignore {
            continue;
        }

        let small = region_size(addr).is_some_and(|s| s <= TRAMP_MAX_BYTES);

        let downgrade: Option<&str> = if trust_met {
            match tier {
                ExecTier::AnonRx => Some("maps-rx-jit-suppressed"),
                ExecTier::AnonRwx if is_inside_jit_cluster(addr_lo, &clusters) => {
                    Some("maps-rwx-jit-hardening")
                }
                ExecTier::AnonRwx if small => Some(if pool {
                    "maps-rwx-jit-trampoline"
                } else {
                    "maps-rwx-jit-runtime"
                }),
                _ => None,
            }
        } else if exe_allowlisted(exe_path) && matches!(tier, ExecTier::AnonRwx | ExecTier::AnonRx)
        {
            Some("maps-rwx-runtime-allowlist")
        } else {
            None
        };

        if let Some(src) = downgrade {
            let desc = format!("{} (pid {}): suppressed via {}", comm, pid, src);
            if !seen.contains(&desc) {
                seen.push(desc.clone());
                findings.push(LibraryInjectionFinding {
                    pid,
                    process: comm.to_string(),
                    object_path: desc,
                    source: src.to_string(),
                    is_deleted: false,
                    region_addr: Some(addr.to_string()),
                    deep_forensics: None,
                });
            }
            continue;
        }

        // Active Finding (SEC-026 or SEC-023 Escalation)
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
                region_addr: Some(addr.to_string()),
                deep_forensics: None,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::InjectionClass;

    #[test]
    fn test_volatile_lib_path_excludes_home() {
        assert!(is_volatile_lib_path("/tmp/evil.so"));
        assert!(is_volatile_lib_path("/dev/shm/payload.so"));
        assert!(
            !is_volatile_lib_path("/home/user/.vscode/extensions/lib.so"),
            "Home must not be volatile for .so"
        );
    }

    #[test]
    fn test_exe_allowlist() {
        assert!(exe_allowlisted(Some("/usr/bin/node")));
        assert!(exe_allowlisted(Some("/opt/google/chrome/chrome")));
        assert!(
            !exe_allowlisted(Some("/tmp/node")),
            "Must check absolute path"
        );
    }

    #[test]
    fn test_classify_all_downgrade_sources() {
        let make = |src: &str| LibraryInjectionFinding {
            pid: 0,
            process: String::new(),
            object_path: String::new(),
            source: src.to_string(),
            is_deleted: false,
            region_addr: None,
            deep_forensics: None,
        };

        // Advisory sources must map to JitAdvisory
        for src in &[
            "maps-rwx-jit-hardening",
            "maps-rwx-jit-trampoline",
            "maps-rwx-jit-runtime",
            "maps-rx-jit-suppressed",
            "maps-so-jit-extract",
            "maps-rwx-runtime-allowlist",
        ] {
            assert_eq!(
                make(src).classify(),
                InjectionClass::JitAdvisory,
                "source '{src}' should be JitAdvisory"
            );
        }

        // Real anomaly must remain MemoryAnomaly
        assert_eq!(
            make("maps-anon-rwx").classify(),
            InjectionClass::MemoryAnomaly
        );
        // Classic injection must stay ClassicInjection
        assert_eq!(
            make("LD_PRELOAD").classify(),
            InjectionClass::ClassicInjection
        );
    }
}
