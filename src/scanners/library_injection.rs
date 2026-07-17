//! Userspace rootkit / library-injection detection (SEC-023) and
//! Anomalous Executable Memory detection (SEC-026).

use std::fs;
use std::path::PathBuf;

use super::deep;
use crate::coverage;
use crate::models::LibraryInjectionFinding;
use crate::safe_io;
use crate::verdict_cache::{Verdict, VerdictCache};

/// Configuration for the memory scanner, passed down from CLI args.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub deep: bool,
    pub target_pid: Option<u32>,
    pub verdict_cache_path: PathBuf,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            deep: false,
            target_pid: None,
            verdict_cache_path: PathBuf::from("/var/lib/owlzops/verdict-cache.json"),
        }
    }
}

impl ScanConfig {
    /// Should we perform deep memory forensics on this PID?
    #[inline]
    fn deep_for(&self, pid: u32) -> bool {
        self.deep || self.target_pid == Some(pid)
    }
}

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

        let is_vendor = VENDOR_ROOTS.iter().any(|r| clean.contains(*r));

        !is_deleted && (!crate::utils::is_ephemeral_exec_path(clean) || is_vendor)
    });

    let runtime_libs = maps.lines().any(|l| {
        let last = l.rsplit(char::is_whitespace).next().unwrap_or("");
        last.starts_with('/')
            && !last.ends_with("(deleted)")
            && !is_volatile_lib_path(last)
            && RT_LIBS.iter().any(|lib| last.contains(lib))
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

// ── Verdict derivation ─────────────────────────────────────

/// Single-region verdict for object-identity caching. Confident only.
fn verdict_of_region(d: &crate::models::DeepMemoryAnalysis) -> Option<Verdict> {
    if d.entropy >= 7.0 || d.image_header {
        return Some(Verdict::Malicious);
    }
    if d.prologue.is_some() && d.confidence >= 70 {
        return Some(Verdict::Benign);
    }
    None
}

// ── Inode family analysis (for deleted .so unlink-on-load detection) ─

#[derive(Default, Clone, Copy)]
struct InodeFamily {
    vmas: u16,
    exec: bool,
    any_wx: bool,
}

/// Segment families of DELETED volatile-path .so inodes, keyed by (dev, inode).
/// ld.so's dlopen maps one .so as 2–4 VMAs from a single inode; a manual
/// single-shot mmap stager maps exactly one. An rwx permission on ANY segment
/// of the family poisons the whole inode.
fn deleted_so_families(maps: &str) -> std::collections::HashMap<(&str, &str), InodeFamily> {
    let mut fam = std::collections::HashMap::new();
    for line in maps.lines() {
        let mut it = line.splitn(6, char::is_whitespace);
        let (Some(_a), Some(perms), Some(_o), Some(dev), Some(inode), Some(path)) = (
            it.next(),
            it.next(),
            it.next(),
            it.next(),
            it.next(),
            it.next(),
        ) else {
            continue;
        };
        let path = path.trim();
        if inode == "0" || !path.ends_with("(deleted)") {
            continue;
        }
        let clean = path.trim_end_matches(" (deleted)");
        if !((clean.ends_with(".so") || clean.contains(".so.")) && is_volatile_lib_path(clean)) {
            continue;
        }
        let e: &mut InodeFamily = fam.entry((dev, inode)).or_default();
        e.vmas = e.vmas.saturating_add(1);
        let b = perms.as_bytes();
        let w = b.get(1) == Some(&b'w');
        let x = b.get(2) == Some(&b'x');
        e.exec |= x;
        e.any_wx |= w && x;
    }
    fam
}

// ── MAIN SCANNER ───────────────────────────────────────────

pub fn scan_library_injections(cfg: &ScanConfig) -> Vec<LibraryInjectionFinding> {
    detect_from_proc("/proc", cfg)
}

fn detect_from_proc(proc_root: &str, cfg: &ScanConfig) -> Vec<LibraryInjectionFinding> {
    let mut findings = Vec::new();
    let mut denied = 0usize;
    let mut cache = VerdictCache::load(cfg.verdict_cache_path.clone());

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
                            region_addr: None,
                            deep_forensics: None,
                            exe_path: None,
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

                let start = findings.len();

                scan_maps(
                    &content,
                    pid,
                    &comm,
                    &trust,
                    exe_path.as_deref(),
                    &cache,
                    &mut findings,
                );

                // Slow path: enrich + cache verdict per object
                if cfg.deep_for(pid) && findings.len() > start {
                    let ctx = deep::ProcMemContext::build(&content);
                    deep::enrich(&mut findings[start..], pid, &ctx);
                    for f in &findings[start..] {
                        if let Some(v) = f.deep_forensics.as_ref().and_then(verdict_of_region) {
                            cache.record(&f.object_path, v);
                        }
                    }
                }
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
    cache.persist();
    findings
}

fn scan_maps(
    content: &str,
    pid: u32,
    comm: &str,
    trust: &RuntimeTrust,
    exe_path: Option<&str>,
    cache: &VerdictCache,
    findings: &mut Vec<LibraryInjectionFinding>,
) {
    let mut seen: Vec<String> = Vec::new();
    let clusters = build_exec_clusters(content);
    let pool = is_trampoline_pool(content);
    let families = deleted_so_families(content);
    let trust_met = trust.exe_ok && (trust.runtime_libs || trust.vendor_anchored);

    for line in content.lines() {
        if findings.len() >= MAX_FINDINGS {
            break;
        }

        let mut it = line.splitn(6, char::is_whitespace);
        let (addr, perms, _off, dev, inode, path) = (
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
                let pb = perms.as_bytes();
                let writable_exec = pb.get(1) == Some(&b'w') && pb.get(2) == Some(&b'x');

                let source = if writable_exec {
                    // rwx .so from a volatile path — hard signal, never demote
                    "maps"
                } else if is_deleted {
                    // Unlink-on-load (Netty/JNA jar-extract) vs fileless stager.
                    let family = dev
                        .zip(inode)
                        .and_then(|k| families.get(&k))
                        .copied()
                        .unwrap_or_default();
                    let env_ioc = findings
                        .iter()
                        .any(|f| f.pid == pid && f.source.starts_with("LD_"));
                    let real_tmp = clean.starts_with("/tmp/") || clean.starts_with("/var/tmp/");
                    if trust_met
                        && real_tmp                    // memfd / /dev/shm / /run stay hard
                        && !env_ioc                    // no LD_* co-occurrence
                        && family.vmas >= 2            // ld.so segment family
                        && family.exec
                        && !family.any_wx
                    // W^X across whole family
                    {
                        "maps-so-unlink-on-load"
                    } else {
                        "maps"
                    }
                } else if trust_met {
                    "maps-so-jit-extract"
                } else {
                    "maps-so-tmp-unverified"
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
                        exe_path: exe_path.map(|s| s.to_string()),
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

        let mut downgrade: Option<&str> = if trust_met {
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
        } else {
            None
        };

        if downgrade.is_none() && matches!(tier, ExecTier::AnonRwx | ExecTier::AnonRx) {
            downgrade = match exe_path.and_then(|e| cache.lookup(e)) {
                Some(Verdict::Benign) => Some("maps-rwx-cached-clean"),
                Some(Verdict::Malicious) => None,
                None => match exe_path.map(|p| crate::utils::exe_provenance(p, pid)) {
                    Some(crate::utils::ExeProvenance::InstalledApp)
                    | Some(crate::utils::ExeProvenance::NestedUserInstall) => {
                        Some("maps-rwx-provisional")
                    }
                    _ => None,
                },
            };
        }

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
                    exe_path: exe_path.map(|s| s.to_string()),
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
                exe_path: exe_path.map(|s| s.to_string()),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::InjectionClass;

    // Synthetic JVM maps: libjvm.so from a NON-/usr/ bundled path + JNI .so from /tmp.
    fn jvm_maps(jni_perms: &str) -> String {
        format!(
            "\
5566000000-5566001000 r-xp 00000000 08:01 100 /opt/kafka/jdk/bin/java
7f00aa000000-7f00aa400000 r-xp 00000000 08:01 201 /opt/kafka/jdk/lib/server/libjvm.so
7f00bb000000-7f00bb010000 r--p 00000000 08:01 202 /opt/kafka/jdk/lib/libjava.so
7f00cc000000-7f00cc020000 {jni_perms} 00000000 08:01 303 /tmp/liblz4-java-1121051756510130003.so
"
        )
    }

    fn scan(maps: &str, exe: Option<&str>) -> Vec<LibraryInjectionFinding> {
        let trust = assess_runtime(maps, exe);
        let cache = VerdictCache::default();
        let mut out = Vec::new();
        scan_maps(maps, 4242, "java", &trust, exe, &cache, &mut out);
        out
    }

    #[test]
    fn bundled_jvm_rx_jni_is_not_classic() {
        let maps = jvm_maps("r-xp");
        let f = scan(&maps, Some("/opt/kafka/jdk/bin/java"));
        let jni = f
            .iter()
            .find(|x| x.object_path.contains("lz4-java"))
            .unwrap();
        assert_ne!(jni.classify(), InjectionClass::ClassicInjection);
        assert_eq!(jni.source, "maps-so-jit-extract");
    }

    #[test]
    fn rwx_jni_from_tmp_stays_classic_even_in_jvm() {
        let maps = jvm_maps("rwxp");
        let f = scan(&maps, Some("/opt/kafka/jdk/bin/java"));
        let jni = f
            .iter()
            .find(|x| x.object_path.contains("lz4-java"))
            .unwrap();
        assert_eq!(jni.source, "maps");
        assert_eq!(jni.classify(), InjectionClass::ClassicInjection);
    }

    #[test]
    fn rx_tmp_so_without_runtime_is_provisional_not_classic() {
        let maps = "\
55000000-55001000 r-xp 00000000 08:01 100 /opt/app/mystery-bin
7fcc00000000-7fcc00020000 r-xp 00000000 08:01 303 /tmp/libsomething-9988.so
";
        let f = scan(maps, Some("/opt/app/mystery-bin"));
        let hit = f
            .iter()
            .find(|x| x.object_path.contains("libsomething"))
            .unwrap();
        assert_eq!(hit.source, "maps-so-tmp-unverified");
        assert_ne!(hit.classify(), InjectionClass::ClassicInjection);
    }

    #[test]
    fn runtime_libs_accepts_non_usr_paths() {
        let maps = jvm_maps("r-xp");
        let trust = assess_runtime(&maps, Some("/opt/kafka/jdk/bin/java"));
        assert!(
            trust.runtime_libs,
            "bundled/opt JDK must satisfy runtime_libs"
        );
    }

    // ── Unlink-on-load (Netty/JNA ghost inode) tests ───────

    const JVM_CTX: &str = "\
5566000000-5566001000 r-xp 00000000 08:01 100 /opt/rustrover/jbr/bin/java
7f00aa000000-7f00aa400000 r-xp 00000000 08:01 201 /opt/rustrover/jbr/lib/server/libjvm.so
7f00bb000000-7f00bb010000 r--p 00000000 08:01 202 /opt/rustrover/jbr/lib/libjava.so
";
    const EXE: Option<&str> = Some("/opt/rustrover/jbr/bin/java");
    const GHOST: &str = "/tmp/libio_grpc_netty_shaded_netty_transport_native_epoll123.so (deleted)";

    fn netty_family(text_perms: &str) -> String {
        format!(
            "{JVM_CTX}\
7f0000000000-7f0000004000 r--p 00000000 08:01 999 {GHOST}
7f0000004000-7f0000010000 {text_perms} 00004000 08:01 999 {GHOST}
7f0000010000-7f0000012000 rw-p 00010000 08:01 999 {GHOST}
"
        )
    }

    fn scan_into(maps: &str, out: &mut Vec<LibraryInjectionFinding>) {
        let trust = assess_runtime(maps, EXE);
        scan_maps(
            maps,
            4242,
            "java",
            &trust,
            EXE,
            &VerdictCache::default(),
            out,
        );
    }

    fn scan_single(maps: &str) -> Vec<LibraryInjectionFinding> {
        let mut out = Vec::new();
        scan_into(maps, &mut out);
        out
    }

    #[test]
    fn netty_unlink_on_load_reclassified_provisional() {
        let f = scan_single(&netty_family("r-xp"));
        let g = f.iter().find(|x| x.object_path.contains("netty")).unwrap();
        assert_eq!(g.source, "maps-so-unlink-on-load");
        assert!(g.is_deleted);
        assert_ne!(g.classify(), InjectionClass::ClassicInjection);
    }

    #[test]
    fn single_vma_deleted_stays_classic() {
        let maps = format!(
            "{JVM_CTX}7f0000000000-7f0000010000 r-xp 00000000 08:01 999 /tmp/evil.so (deleted)\n"
        );
        let f = scan_single(&maps);
        assert_eq!(
            f.iter()
                .find(|x| x.object_path.contains("evil"))
                .unwrap()
                .source,
            "maps"
        );
    }

    #[test]
    fn rwx_on_any_family_segment_poisons_the_inode() {
        let f = scan_single(&netty_family("rwxp"));
        assert_eq!(
            f.iter()
                .find(|x| x.object_path.contains("netty"))
                .unwrap()
                .source,
            "maps"
        );
    }

    #[test]
    fn memfd_deleted_never_demotes() {
        let maps = format!(
            "{JVM_CTX}\
7f0000000000-7f0000004000 r--p 00000000 00:01 999 /memfd:evil.so (deleted)
7f0000004000-7f0000010000 r-xp 00004000 00:01 999 /memfd:evil.so (deleted)
"
        );
        let f = scan_single(&maps);
        assert_eq!(
            f.iter()
                .find(|x| x.object_path.contains("evil"))
                .unwrap()
                .source,
            "maps"
        );
    }

    #[test]
    fn deleted_family_without_trust_stays_classic() {
        let maps = "\
55000000-55001000 r-xp 00000000 08:01 100 /opt/app/mystery-bin
7f0000000000-7f0000004000 r--p 00000000 08:01 999 /tmp/x.so (deleted)
7f0000004000-7f0000010000 r-xp 00004000 08:01 999 /tmp/x.so (deleted)
";
        let trust = assess_runtime(maps, Some("/opt/app/mystery-bin"));
        let mut out = Vec::new();
        scan_maps(
            maps,
            4242,
            "app",
            &trust,
            Some("/opt/app/mystery-bin"),
            &VerdictCache::default(),
            &mut out,
        );
        assert_eq!(
            out.iter()
                .find(|x| x.object_path.contains("/tmp/x"))
                .unwrap()
                .source,
            "maps"
        );
    }

    #[test]
    fn ld_preload_cooccurrence_disables_reclassification() {
        let mut out = vec![LibraryInjectionFinding {
            pid: 4242,
            source: "LD_PRELOAD".into(),
            object_path: "/tmp/pre.so".into(),
            ..Default::default()
        }];
        scan_into(&netty_family("r-xp"), &mut out);
        assert_eq!(
            out.iter()
                .find(|x| x.object_path.contains("netty"))
                .unwrap()
                .source,
            "maps"
        );
    }
}
