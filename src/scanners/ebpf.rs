//! Agentless eBPF inventory.
//! Scans /proc/<pid>/fd for BPF programs, maps, and links, and /sys/fs/bpf
//! for pinned objects. No bpf() syscall required – pure VFS reading.

use crate::models::{BpfLinkInfo, BpfMapInfo, BpfPinInfo, BpfProgInfo, EbpfInventory};
use std::fs;
use std::io;
use std::path::Path;

/// Maximum number of BPF objects to collect per category
const MAX_BPF_OBJECTS: usize = 256;
/// Maximum recursion depth for pin scanning
const MAX_PIN_DEPTH: u8 = 8;
/// Per‑PID fd limit (mirrors proc_net / reverse_shell)
const MAX_FD_PER_PID: usize = 4096;

/// Try to parse a u32 from a line like "prog_id:\t123"
fn parse_u32_field(line: &str, prefix: &str) -> Option<u32> {
    line.strip_prefix(prefix)
        .and_then(|s| s.trim().parse().ok())
}

// ── R19V‑01 + R19V‑02 ──────────────────────────────────────────────────

/// Kernel anon_inode names: "bpf-prog" / "bpf-map" (hyphen) AND
/// "bpf_link" (underscore).  Brackets are optional in some kernels.
fn is_bpf_fd(link_target: &str) -> bool {
    let Some(rest) = link_target.strip_prefix("anon_inode:") else {
        return false;
    };
    let rest = rest.strip_prefix('[').unwrap_or(rest);
    rest.starts_with("bpf-") || rest.starts_with("bpf_")
}

/// Aggregated BPF fdinfo fields.
struct BpfFdInfo {
    obj_type: &'static str,
    id: u32,
    type_or_name: Option<String>,
    prog_tag: String,
    prog_id: u32, // for links: the program they reference
}

/// Parse an fdinfo block, correctly handling links that also carry a prog_id.
fn parse_bpf_fdinfo(fdinfo: &str) -> Option<BpfFdInfo> {
    let (mut prog_id, mut map_id, mut link_id) = (None, None, None);
    let (mut prog_type, mut map_type, mut link_type, mut prog_name) = (None, None, None, None);
    let mut prog_tag = String::new();

    for line in fdinfo.lines() {
        if let Some(v) = parse_u32_field(line, "prog_id:") {
            prog_id = Some(v);
        } else if let Some(v) = parse_u32_field(line, "map_id:") {
            map_id = Some(v);
        } else if let Some(v) = parse_u32_field(line, "link_id:") {
            link_id = Some(v);
        } else if let Some(v) = line.strip_prefix("prog_type:") {
            prog_type = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("map_type:") {
            map_type = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("link_type:") {
            link_type = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("prog_name:") {
            prog_name = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("prog_tag:") {
            prog_tag = v.trim().to_string();
        }
    }

    // Priority: link > map > prog. A link's fdinfo contains *both* link_id and prog_id.
    if let Some(id) = link_id {
        return Some(BpfFdInfo {
            obj_type: "link",
            id,
            type_or_name: link_type,
            prog_tag,
            prog_id: prog_id.unwrap_or(0),
        });
    }
    if let Some(id) = map_id {
        return Some(BpfFdInfo {
            obj_type: "map",
            id,
            type_or_name: map_type,
            prog_tag,
            prog_id: 0,
        });
    }
    let id = prog_id?;
    Some(BpfFdInfo {
        obj_type: "prog",
        id,
        type_or_name: prog_name.or(prog_type),
        prog_tag,
        prog_id: id,
    })
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Read the contents of a /proc/<pid>/fd/<fdnum> symlink
fn read_fd_link(pid: u32, fdnum: u32) -> io::Result<String> {
    let path = format!("/proc/{}/fd/{}", pid, fdnum);
    std::fs::read_link(&path).map(|p| p.to_string_lossy().into_owned())
}

fn push_capped<T>(vec: &mut Vec<T>, item: T, dropped: &mut usize) {
    if vec.len() < MAX_BPF_OBJECTS {
        vec.push(item);
    } else {
        *dropped += 1;
    }
}

// ── /proc scanner ───────────────────────────────────────────────────────

fn scan_proc_bpf() -> (Vec<BpfProgInfo>, Vec<BpfMapInfo>, Vec<BpfLinkInfo>, usize) {
    let mut programs = Vec::new();
    let mut maps = Vec::new();
    let mut links = Vec::new();
    let mut dropped = 0usize;

    let proc_dir = match fs::read_dir("/proc") {
        Ok(dir) => dir,
        Err(_) => return (programs, maps, links, dropped),
    };

    for entry in proc_dir.flatten() {
        if programs.len() >= MAX_BPF_OBJECTS
            && maps.len() >= MAX_BPF_OBJECTS
            && links.len() >= MAX_BPF_OBJECTS
        {
            break;
        }

        let pid_str = entry.file_name();
        let pid = match pid_str.to_str().and_then(|s| s.parse::<u32>().ok()) {
            Some(p) => p,
            None => continue,
        };

        // Capped comm
        let comm = crate::safe_io::read_file_capped(&format!("/proc/{}/comm", pid), 4096)
            .map(|(s, _)| s.trim().to_string())
            .unwrap_or_default();

        let fd_dir = match fs::read_dir(format!("/proc/{}/fd", pid)) {
            Ok(d) => d,
            Err(_) => continue,
        };

        let mut fds_scanned = 0usize;
        for fd_entry in fd_dir.flatten() {
            fds_scanned += 1;
            if fds_scanned > MAX_FD_PER_PID {
                crate::coverage::record(format!(
                    "ebpf: pid {} fd budget exhausted at {} — inventory INCOMPLETE for this PID",
                    pid, MAX_FD_PER_PID
                ));
                break;
            }

            if programs.len() >= MAX_BPF_OBJECTS
                && maps.len() >= MAX_BPF_OBJECTS
                && links.len() >= MAX_BPF_OBJECTS
            {
                break;
            }

            let fdnum = match fd_entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            {
                Some(n) => n,
                None => continue,
            };

            let link_target = match read_fd_link(pid, fdnum) {
                Ok(t) => t,
                Err(_) => continue,
            };

            if !is_bpf_fd(&link_target) {
                continue;
            }

            // Capped fdinfo
            let fdinfo_path = format!("/proc/{}/fdinfo/{}", pid, fdnum);
            let fdinfo = match crate::safe_io::read_file_capped(&fdinfo_path, 8192) {
                Ok((s, _)) => s,
                Err(_) => continue,
            };

            let info = match parse_bpf_fdinfo(&fdinfo) {
                Some(i) => i,
                None => continue,
            };

            match info.obj_type {
                "prog" => push_capped(
                    &mut programs,
                    BpfProgInfo {
                        prog_id: info.id,
                        prog_type: info.type_or_name.unwrap_or_default(),
                        prog_name: None,
                        prog_tag: info.prog_tag,
                        pid,
                        comm: comm.clone(),
                    },
                    &mut dropped,
                ),
                "map" => push_capped(
                    &mut maps,
                    BpfMapInfo {
                        map_id: info.id,
                        map_type: info.type_or_name.unwrap_or_default(),
                        pid,
                        comm: comm.clone(),
                    },
                    &mut dropped,
                ),
                "link" => push_capped(
                    &mut links,
                    BpfLinkInfo {
                        link_id: info.id,
                        prog_id: info.prog_id,
                        attach_type: info.type_or_name.unwrap_or_default(),
                        pid,
                        comm: comm.clone(),
                    },
                    &mut dropped,
                ),
                _ => {}
            }
        }
    }

    (programs, maps, links, dropped)
}

// ── Pin scanner ─────────────────────────────────────────────────────────

fn scan_bpf_pins() -> Vec<BpfPinInfo> {
    let mut pins = Vec::new();
    scan_bpf_dir(Path::new("/sys/fs/bpf"), MAX_PIN_DEPTH, &mut pins);
    pins
}

fn scan_bpf_dir(dir: &Path, depth: u8, pins: &mut Vec<BpfPinInfo>) {
    if pins.len() >= MAX_BPF_OBJECTS || depth == 0 {
        if depth == 0 {
            crate::coverage::record(format!("ebpf: pin scan depth limit at {}", dir.display()));
        }
        return;
    }

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        if pins.len() >= MAX_BPF_OBJECTS {
            return;
        }

        let path = entry.path();
        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };

        if ft.is_symlink() {
            continue;
        }

        if ft.is_dir() {
            scan_bpf_dir(&path, depth - 1, pins);
            continue;
        }

        pins.push(BpfPinInfo {
            path: path.to_string_lossy().into_owned(),
            obj_type: "unknown".into(),
            obj_id: 0,
        });
    }
}

// ── Main entry point ────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub fn gather_ebpf_inventory() -> EbpfInventory {
    let (programs, maps, links, dropped) = scan_proc_bpf();
    let pins = scan_bpf_pins();

    if dropped > 0 {
        crate::coverage::record(format!(
            "ebpf: {dropped} object(s) dropped at MAX_BPF_OBJECTS — inventory INCOMPLETE"
        ));
    }

    // Collect unique, sorted program tags for drift comparison (R19V‑10).
    let mut tags: Vec<String> = programs
        .iter()
        .map(|p| p.prog_tag.clone())
        .filter(|t| !t.is_empty())
        .collect();
    tags.sort_unstable();
    tags.dedup();

    EbpfInventory {
        programs,
        maps,
        pins,
        links,
        prog_tags: tags,
    }
}

#[cfg(not(target_os = "linux"))]
pub fn gather_ebpf_inventory() -> EbpfInventory {
    EbpfInventory::default()
}
