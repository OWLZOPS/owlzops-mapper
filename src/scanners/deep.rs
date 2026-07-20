#![allow(dead_code)]

use crate::coverage;
use crate::models::{
    DeepMemoryAnalysis, LibraryInjectionFinding, Origin, PointerKind, Prologue, ResolvedPointer,
};
use std::io;
use std::sync::Arc;

const DEEP_READ_LEN: usize = 256;
const MAX_DEEP_REGIONS: usize = 64;

// ── Clustering infrastructure (mirrors library_injection.rs) ──

#[derive(Debug, Clone)]
pub struct ExecCluster {
    pub lo: u64,
    pub hi: u64,
    pub pages: usize,
    pub span: u64,
}

pub fn build_exec_clusters(maps: &str) -> Vec<ExecCluster> {
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

fn is_runtime_reservation(c: &ExecCluster) -> bool {
    c.span >= 8 * 1024 * 1024 || c.pages >= 16
}

// ── Memory context and pointer resolver ──

pub struct ProcMemContext {
    pub clusters: Vec<ExecCluster>,
    pub resolver: PointerResolver,
}

impl ProcMemContext {
    pub fn build(maps: &str) -> Self {
        let clusters = build_exec_clusters(maps);
        let resolver = PointerResolver::build(maps, &clusters);
        Self { clusters, resolver }
    }
}

struct Interval {
    lo: u64,
    hi: u64,
    tag: PointerKind,
    label: Arc<str>,
}

pub struct PointerResolver {
    intervals: Vec<Interval>,
}

/// Extract the basename from a file path (the part after the last '/').
fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

impl PointerResolver {
    fn build(maps: &str, clusters: &[ExecCluster]) -> Self {
        let mut ivs = Vec::new();
        for l in maps.lines() {
            let mut it = l.splitn(6, char::is_whitespace);
            let (Some(addr), Some(perms), _, _, _, path) = (
                it.next(),
                it.next(),
                it.next(),
                it.next(),
                it.next(),
                it.next(),
            ) else {
                continue;
            };
            let Some((lo, hi)) = addr.split_once('-').and_then(|(a, b)| {
                Some((
                    u64::from_str_radix(a, 16).ok()?,
                    u64::from_str_radix(b, 16).ok()?,
                ))
            }) else {
                continue;
            };

            let x = perms.as_bytes().get(2) == Some(&b'x');
            let file = path.map(str::trim).filter(|p| p.starts_with('/'));

            let (tag, label): (PointerKind, Arc<str>) = match (x, file) {
                (true, Some(p)) => (PointerKind::LibText, basename(p).into()),
                (false, Some(p)) => (PointerKind::LibData, basename(p).into()),
                (true, None) => (PointerKind::JitCluster, "anon-jit".into()),
                (false, None) => continue,
            };
            ivs.push(Interval { lo, hi, tag, label });
        }

        // Demote fake JIT regions (anonymous exec outside runtime reservation)
        for iv in ivs.iter_mut() {
            if iv.tag == PointerKind::JitCluster
                && !clusters
                    .iter()
                    .any(|c| is_runtime_reservation(c) && iv.lo >= c.lo && iv.lo <= c.hi)
            {
                iv.tag = PointerKind::Unmapped;
            }
        }
        ivs.sort_unstable_by_key(|iv| iv.lo);
        Self { intervals: ivs }
    }

    fn resolve(&self, addr: u64) -> (PointerKind, Arc<str>) {
        let i = self.intervals.partition_point(|iv| iv.lo <= addr);
        if i > 0 {
            let iv = &self.intervals[i - 1];
            if addr < iv.hi {
                return (iv.tag.clone(), iv.label.clone());
            }
        }
        (PointerKind::Unmapped, "unmapped".into())
    }
}

// ── Process memory reader (process_vm_readv) ──

pub trait MemoryReader {
    fn read_at(&self, addr: u64, len: usize) -> io::Result<Vec<u8>>;
}

pub struct ProcMemReader {
    pid: libc::pid_t,
}

impl ProcMemReader {
    pub fn open(pid: u32) -> io::Result<Self> {
        Ok(Self {
            pid: pid as libc::pid_t,
        })
    }
}

impl MemoryReader for ProcMemReader {
    fn read_at(&self, addr: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: len,
        };
        let remote = libc::iovec {
            iov_base: addr as *mut _,
            iov_len: len,
        };

        let n = unsafe { libc::process_vm_readv(self.pid, &local, 1, &remote, 1, 0) };
        if n >= 0 {
            buf.truncate(n as usize);
            return Ok(buf);
        }

        // Fallback via /proc/pid/mem can be added here if needed.
        // For now, EPERM typically means YAMA LSM restriction; stop.
        Err(io::Error::last_os_error())
    }
}

// ── Analysis helpers (entropy, prologue, pointers) ──

fn shannon(buf: &[u8]) -> f32 {
    if buf.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in buf {
        counts[b as usize] += 1;
    }
    let len = buf.len() as f32;
    let mut entropy = 0.0f32;
    for &c in &counts {
        if c > 0 {
            let p = c as f32 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn detect_prologue(buf: &[u8]) -> Option<Prologue> {
    if buf.starts_with(&[0xF3, 0x0F, 0x1E, 0xFA]) {
        Some(Prologue::Endbr64)
    } else if buf.starts_with(&[0x55, 0x48, 0x89, 0xE5]) {
        Some(Prologue::PushRbp)
    } else {
        None
    }
}

fn scan_pointers(buf: &[u8], r: &PointerResolver) -> Vec<ResolvedPointer> {
    buf.chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .filter(|&v| (0x1_0000..0x0000_8000_0000_0000).contains(&v))
        .map(|v| {
            let (kind, label) = r.resolve(v);
            ResolvedPointer {
                value: format!("{v:#x}"),
                target: label.to_string(),
                kind,
            }
        })
        .filter(|rp| rp.kind != PointerKind::Unmapped)
        .collect()
}

// ── Multi‑tier attribution funnel (replaces flat ConfidenceEngine) ──

/// L0: image header detection
fn has_image_header(b: &[u8]) -> bool {
    b.starts_with(b"MZ")
        || b.starts_with(&[0x7F, b'E', b'L', b'F'])
        || b.windows(4).take(64).any(|w| w == b"PE\0\0")
}

/// Empty/sparse reserved region: JIT code buffer not yet filled
/// (entropy ≈ 0, mostly zeros). No payload → nothing to attribute as malware.
/// Content fact, not reputation — NOT evadable by renaming the process.
fn attribute_reserved_buffer(buf: &[u8]) -> Option<(Origin, u8)> {
    if buf.is_empty() {
        return None;
    }
    let zeros = buf.iter().filter(|&&b| b == 0).count();
    // ≥95% zeros AND no prologue = reserved-but-not-written. Real payload ≠ zeros.
    (zeros * 100 >= buf.len() * 95 && detect_prologue(buf).is_none())
        .then_some((Origin::ReservedBuffer, 70))
}

/// L1a: pointer‑table attribution (dynamically linked engines)
const POINTER_SIGS: &[(&str, Origin, u8)] = &[
    ("libffi", Origin::FfiClosure, 70),
    ("libjvm", Origin::HotSpot, 75),
    ("libpcre2", Origin::Pcre2Jit, 75),
    ("_gi", Origin::GObjectCallback, 70),
    ("gobject", Origin::GObjectCallback, 70),
];

fn attribute_by_pointer(ptrs: &[ResolvedPointer]) -> Option<(Origin, u8)> {
    POINTER_SIGS
        .iter()
        .find(|(n, _, _)| ptrs.iter().any(|p| p.target.contains(*n)))
        .map(|&(_, ref o, c)| (o.clone(), c))
}

/// Check whether an address falls inside a runtime JIT reservation.
fn is_inside_jit_cluster(region_lo: u64, clusters: &[ExecCluster]) -> bool {
    clusters.iter().any(|c| {
        (c.span >= 8 * 1024 * 1024 || c.pages >= 16) && region_lo >= c.lo && region_lo <= c.hi
    })
}

/// L1b: engine‑agnostic managed‑JIT shape (V8, JSC, Zend, PCRE2)
fn attribute_managed_jit(
    buf: &[u8],
    region_lo: u64,
    ctx: &ProcMemContext,
    ptrs: &[ResolvedPointer],
) -> Option<(Origin, u8)> {
    let in_reservation = is_inside_jit_cluster(region_lo, &ctx.clusters);
    let self_ref = ptrs
        .iter()
        .any(|p| matches!(p.kind, PointerKind::LibText | PointerKind::JitCluster));
    let native = detect_prologue(buf).is_some() && shannon(buf) < 6.5;

    let signals = [in_reservation, self_ref, native]
        .into_iter()
        .filter(|b| *b)
        .count();

    (signals >= 2).then_some((Origin::ManagedJit, 70 + 15 * (signals as u8 - 2)))
}

/// L1c: libffi trampoline stub signature
fn attribute_ffi_trampoline(buf: &[u8]) -> Option<(Origin, u8)> {
    const FFI_STUB: &[&[u8]] = &[
        &[0x49, 0xBB], // movabs r11, <closure> — unix64 classic stub
        &[0x49, 0xBA], // movabs r10, <closure> — alternative
    ];
    FFI_STUB
        .iter()
        .any(|s| buf.windows(s.len()).take(8).any(|w| w == *s))
        .then_some((Origin::FfiClosure, 60))
}

/// Ordered attribution funnel: cheaper/more reliable layers first, short‑circuit.
fn attribute(
    buf: &[u8],
    region_lo: u64,
    ctx: &ProcMemContext,
    ptrs: &[ResolvedPointer],
    _has_prologue: bool,
) -> (Origin, u8) {
    // L0 — trumping veto: positive malware overrides ANY benign attribution
    if shannon(buf) >= 7.0 || has_image_header(buf) {
        return (Origin::UnknownPayload, 65);
    }
    // L1-0 — content = "no payload" (zero/sparse reserved buffers)
    if let Some(v) = attribute_reserved_buffer(buf) {
        return v;
    }
    // L1a — dynamic engines via pointer table
    if let Some(v) = attribute_by_pointer(ptrs) {
        return v;
    }
    // L1b — generic managed‑JIT shape
    if let Some(v) = attribute_managed_jit(buf, region_lo, ctx, ptrs) {
        return v;
    }
    // L1c — libffi stub signature
    if let Some(v) = attribute_ffi_trampoline(buf) {
        return v;
    }

    (Origin::Inconclusive, 0)
}

/// Top‑level analysis: collects raw signals and runs the attribution funnel.
fn analyze(buf: &[u8], region_lo: u64, ctx: &ProcMemContext) -> DeepMemoryAnalysis {
    let entropy = shannon(buf);
    let prologue = detect_prologue(buf);
    let ptrs = scan_pointers(buf, &ctx.resolver);
    let image_header = has_image_header(buf);

    let (origin, confidence) = attribute(buf, region_lo, ctx, &ptrs, prologue.is_some());

    DeepMemoryAnalysis {
        origin,
        confidence,
        entropy,
        prologue,
        resolved_pointers: ptrs,
        bytes_examined: buf.len(),
        image_header,
    }
}

fn is_rwx_candidate(src: &str) -> bool {
    src.contains("rwx") || src.contains("exec-") || src == "maps-anon-rx"
}

pub fn enrich(findings: &mut [LibraryInjectionFinding], pid: u32, ctx: &ProcMemContext) {
    let reader = match ProcMemReader::open(pid) {
        Ok(r) => r,
        Err(e) => {
            coverage::record(format!("deep: cannot attach pid {pid} ({e})"));
            return;
        }
    };
    let mut budget = MAX_DEEP_REGIONS;

    for f in findings
        .iter_mut()
        .filter(|f| is_rwx_candidate(&f.source) && f.deep_forensics.is_none())
    {
        if budget == 0 {
            break;
        }

        let Some(addr_str) = f.region_addr.as_deref() else {
            continue;
        };
        let lo_str = addr_str.split('-').next().unwrap_or("");
        let Some(lo) = u64::from_str_radix(lo_str, 16).ok() else {
            continue;
        };

        f.deep_forensics = Some(match reader.read_at(lo, DEEP_READ_LEN) {
            Ok(buf) => analyze(&buf, lo, ctx),
            Err(_) => DeepMemoryAnalysis::inconclusive(),
        });
        budget -= 1;
    }
}

// ── Sixth Gate: unlink-on-load ghost inode recovery via /proc/<pid>/map_files ──
//
// Reads the *whole backing file* (offset 0, all sections) that survives unlink
// because the VMA keeps the inode alive. Streaming, single-pass, O(1) memory:
// a fixed 64 KiB buffer + a 256-entry histogram, regardless of file or fleet size.

use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::sync::OnceLock;

const GHOST_CHUNK: usize = 64 * 1024; // fixed streaming buffer
const GHOST_MAX_BYTES: u64 = 32 * 1024 * 1024; // TIME safety cap (memory is already O(1))
const GHOST_ENTROPY_SUSPECT: f32 = 7.0; // >= → packed/encrypted (aligns with Layer 1)
const GHOST_ENTROPY_CLEAN: f32 = 6.5; // <  → structurally quiet (aligns with is_benign_shape)

/// Streaming Shannon accumulator — global histogram over all chunks (mathematically
/// identical to one-shot entropy, but constant memory).
struct EntropyAcc {
    counts: [u64; 256],
    total: u64,
}
impl EntropyAcc {
    fn new() -> Self {
        Self {
            counts: [0; 256],
            total: 0,
        }
    }
    fn feed(&mut self, b: &[u8]) {
        for &x in b {
            self.counts[x as usize] += 1;
        }
        self.total += b.len() as u64;
    }
    fn shannon(&self) -> f32 {
        if self.total == 0 {
            return 0.0;
        }
        let len = self.total as f32;
        let mut h = 0.0f32;
        for &c in &self.counts {
            if c > 0 {
                let p = c as f32 / len;
                h -= p * p.log2();
            }
        }
        h
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum ElfKind {
    Dyn,
    Exec,
    OtherType(u16),
    NotElf,
}

/// e_ident magic + e_type at offset 16. Endianness honored defensively via EI_DATA,
/// though the musl x86_64 target is little-endian.
fn classify_elf_head(head: &[u8]) -> ElfKind {
    if head.len() < 18 || &head[0..4] != b"\x7FELF" {
        return ElfKind::NotElf;
    }
    let le = head.get(5) != Some(&2); // EI_DATA: 1=LE (default), 2=BE
    let e_type = if le {
        u16::from_le_bytes([head[16], head[17]])
    } else {
        u16::from_be_bytes([head[16], head[17]])
    };
    match e_type {
        2 => ElfKind::Exec,
        3 => ElfKind::Dyn,
        other => ElfKind::OtherType(other),
    }
}

struct GhostScan {
    entropy: f32,
    kind: ElfKind,
    bytes_read: u64,
    truncated: bool, // did NOT reach EOF within GHOST_MAX_BYTES (or file grew)
}

/// fstat facts extracted eagerly so `ghost_analysis` is a pure, unit-testable function.
struct GhostMeta {
    nlink: u64,
    uid: u32,
    mtime: i64,
}
impl GhostMeta {
    fn from_meta(m: &std::fs::Metadata) -> Self {
        Self {
            nlink: m.nlink(),
            uid: m.uid(),
            mtime: m.mtime(),
        }
    }
}

/// Chunked read of a (possibly deleted) inode. `max_bytes` is a parameter for DI/testability.
/// EINTR-safe; refuses non-regular targets.
fn scan_ghost_file(path: &str, max_bytes: u64) -> io::Result<(GhostScan, GhostMeta)> {
    let mut f = std::fs::File::open(path)?;
    let meta = f.metadata()?;
    if !meta.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "map_files target is not a regular file",
        ));
    }
    let size = meta.len();

    let mut buf = vec![0u8; GHOST_CHUNK]; // single allocation, reused every iteration
    let mut acc = EntropyAcc::new();
    let mut head = [0u8; 18];
    let mut head_len = 0usize;
    let mut read_total: u64 = 0;

    loop {
        if read_total >= max_bytes {
            break;
        }
        let want = ((max_bytes - read_total) as usize).min(buf.len());
        let n = match f.read(&mut buf[..want]) {
            Ok(0) => break, // EOF
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if head_len < head.len() {
            let take = (head.len() - head_len).min(n);
            head[head_len..head_len + take].copy_from_slice(&buf[..take]);
            head_len += take;
        }
        acc.feed(&buf[..n]);
        read_total += n as u64;
    }

    let scan = GhostScan {
        entropy: acc.shannon(),
        kind: classify_elf_head(&head[..head_len]),
        bytes_read: read_total,
        truncated: read_total < size,
    };
    Ok((scan, GhostMeta::from_meta(&meta)))
}

fn cached_euid() -> u32 {
    static EUID: OnceLock<u32> = OnceLock::new();
    *EUID.get_or_init(|| unsafe { libc::geteuid() } as u32)
}

/// CONTENT is the discriminator; metadata only sharpens an already-made call.
/// Pure function — no I/O, fully deterministic under test.
fn ghost_analysis(
    scan: &GhostScan,
    meta: &GhostMeta,
    start_epoch: Option<u64>,
) -> DeepMemoryAnalysis {
    // Edge case: empty file -> inconclusive
    if scan.bytes_read == 0 {
        return DeepMemoryAnalysis {
            origin: Origin::GhostInconclusive,
            confidence: 0,
            entropy: 0.0,
            prologue: None,
            resolved_pointers: Vec::new(),
            bytes_examined: 0,
            image_header: false,
        };
    }

    let valid_image = matches!(scan.kind, ElfKind::Dyn | ElfKind::Exec);
    let complete = !scan.truncated;

    // Three-band routing on content.
    let (origin, mut confidence) = if scan.entropy >= GHOST_ENTROPY_SUSPECT || !valid_image {
        (Origin::GhostSuspectImage, 75u8) // packed/encrypted OR not a shared object
    } else if valid_image && complete && scan.entropy < GHOST_ENTROPY_CLEAN {
        (Origin::GhostCleanImage, 85u8) // well-formed, fully read, quiet
    } else {
        (Origin::GhostInconclusive, 0u8) // mid-band (6.5..7.0) or truncated
    };

    // Confidence nudges — NEVER flip the class.
    let euid = cached_euid();
    let self_owned = meta.uid == euid && euid != 0;
    let fresh = start_epoch.is_some_and(|s| meta.mtime >= s as i64);
    match origin {
        Origin::GhostSuspectImage => {
            if self_owned {
                confidence = confidence.saturating_add(5);
            }
            if fresh {
                confidence = confidence.saturating_add(5);
            }
            if meta.nlink == 0 {
                confidence = confidence.saturating_add(5);
            }
            confidence = confidence.min(95);
        }
        Origin::GhostCleanImage => {
            // A still-linked inode (relink race / false ghost) is even stronger benign evidence.
            if meta.nlink >= 1 {
                confidence = confidence.saturating_add(5);
            }
            confidence = confidence.min(95);
        }
        _ => {}
    }

    DeepMemoryAnalysis {
        origin,
        confidence,
        entropy: scan.entropy,
        prologue: None, // file recovery: no entrypoint prologue scan
        resolved_pointers: Vec::new(),
        bytes_examined: scan.bytes_read as usize, // x86_64 target: no truncation
        image_header: false, // INVARIANT: ELF *file* header is expected & benign
    }
}

fn ghost_candidate(src: &str) -> bool {
    src == "maps-so-unlink-on-load"
}

/// Sixth Gate entry point. Sibling to `enrich`; leaves the five structural gates untouched.
/// Local-only by construction (map_files cannot be opened for remote SSH hosts).
pub fn enrich_ghosts(
    findings: &mut [LibraryInjectionFinding],
    pid: u32,
    proc_root: &str,
    start_epoch: Option<u64>,
) {
    let mut budget = MAX_DEEP_REGIONS;
    for f in findings
        .iter_mut()
        .filter(|f| ghost_candidate(&f.source) && f.deep_forensics.is_none())
    {
        if budget == 0 {
            break;
        }
        let Some(addr) = f.region_addr.as_deref() else {
            continue;
        };
        // map_files key is the exact "lo-hi" range straight from /proc/<pid>/maps.
        let path = format!("{}/{}/map_files/{}", proc_root, pid, addr);

        match scan_ghost_file(&path, GHOST_MAX_BYTES) {
            Ok((scan, meta)) => {
                f.deep_forensics = Some(ghost_analysis(&scan, &meta, start_epoch));
            }
            Err(e) => {
                // EACCES (pre-5.8 CAP_SYS_ADMIN), EPERM (YAMA/userns), ENOENT (VMA gone):
                // degrade — do NOT fabricate a verdict. Stays SEC-033 downstream.
                coverage::record(format!(
                    "deep(ghost): pid {} region {} unreadable via map_files ({})",
                    pid, addr, e
                ));
            }
        }
        budget -= 1;
    }
}

// ── starttime (wall-clock epoch) — reuses ghost_pid's field-22 idiom ──

fn clk_tck() -> u64 {
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if hz > 0 { hz as u64 } else { 100 }
}

fn boot_epoch() -> Option<u64> {
    static BOOT: OnceLock<Option<u64>> = OnceLock::new();
    *BOOT.get_or_init(|| {
        let stat = std::fs::read_to_string("/proc/stat").ok()?;
        stat.lines()
            .find_map(|l| l.strip_prefix("btime "))
            .and_then(|v| v.trim().parse::<u64>().ok())
    })
}

/// Pure parse split out for hermetic tests (comm may contain ')' and spaces).
pub fn parse_starttime_ticks(stat: &str) -> Option<u64> {
    let rparen = stat.rfind(')')?;
    let after = stat[rparen + 1..].trim_start();
    // field 22 (starttime) == index 19 of the post-')' tail (field 3 = state = index 0).
    after.split_ascii_whitespace().nth(19)?.parse().ok()
}

/// Wall-clock start (epoch secs). One 4 KiB read of /proc/<pid>/stat per deep PID; btime cached once.
pub fn proc_start_epoch(proc_root: &str, pid: u32) -> Option<u64> {
    let btime = boot_epoch()?;
    let stat = std::fs::read_to_string(format!("{}/{}/stat", proc_root, pid)).ok()?;
    Some(btime + parse_starttime_ticks(&stat)? / clk_tck())
}

#[cfg(test)]
mod ghost_tests {
    use super::*;
    use std::io::Write;

    fn tmp(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    }
    fn et_dyn(body_len: usize) -> Vec<u8> {
        let mut v = vec![0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        v.extend_from_slice(&3u16.to_le_bytes()); // e_type = ET_DYN
        v.resize(18 + body_len, 0x00); // low-entropy tail
        v
    }

    #[test]
    fn clean_et_dyn_is_ghostcleanimage() {
        let f = tmp(&et_dyn(4096));
        let (scan, meta) = scan_ghost_file(f.path().to_str().unwrap(), GHOST_MAX_BYTES).unwrap();
        let d = ghost_analysis(&scan, &meta, None);
        assert_eq!(d.origin, Origin::GhostCleanImage);
        assert!(d.confidence >= 70);
        assert!(!d.image_header, "must not trip Layer-1 trumping");
    }

    #[test]
    fn high_entropy_is_suspect() {
        let payload: Vec<u8> = (0..=255u8).cycle().take(65536).collect(); // ~8.0 bits/byte
        let f = tmp(&payload);
        let (scan, meta) = scan_ghost_file(f.path().to_str().unwrap(), GHOST_MAX_BYTES).unwrap();
        assert!(scan.entropy >= GHOST_ENTROPY_SUSPECT);
        assert_eq!(
            ghost_analysis(&scan, &meta, None).origin,
            Origin::GhostSuspectImage
        );
    }

    #[test]
    fn non_elf_low_entropy_is_suspect() {
        let f = tmp(&vec![0x90u8; 4096]); // NOP sled: low entropy, no ELF magic
        let (scan, meta) = scan_ghost_file(f.path().to_str().unwrap(), GHOST_MAX_BYTES).unwrap();
        assert_eq!(scan.kind, ElfKind::NotElf);
        assert_eq!(
            ghost_analysis(&scan, &meta, None).origin,
            Origin::GhostSuspectImage
        );
    }

    #[test]
    fn empty_file_is_inconclusive() {
        let f = tmp(&[]);
        let (scan, meta) = scan_ghost_file(f.path().to_str().unwrap(), GHOST_MAX_BYTES).unwrap();
        let d = ghost_analysis(&scan, &meta, None);
        assert_eq!(d.origin, Origin::GhostInconclusive);
        assert_eq!(d.confidence, 0);
    }

    #[test]
    fn truncated_read_is_inconclusive() {
        let f = tmp(&et_dyn(8192));
        // cap below file size ⇒ truncated ⇒ no clean downgrade even for valid ET_DYN
        let (scan, meta) = scan_ghost_file(f.path().to_str().unwrap(), 512).unwrap();
        assert!(scan.truncated);
        assert_eq!(
            ghost_analysis(&scan, &meta, None).origin,
            Origin::GhostInconclusive
        );
    }

    #[test]
    fn starttime_field22_survives_paren_in_comm() {
        let stat = "1234 (weird )name) S 1 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 998877 0";
        assert_eq!(parse_starttime_ticks(stat), Some(998877));
    }

    #[test]
    fn entropy_zero_on_uniform() {
        let mut a = EntropyAcc::new();
        a.feed(&[0u8; 1024]);
        assert!(a.shannon() < 0.01);
    }
}
