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
    src.contains("rwx") || src.contains("exec-")
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
