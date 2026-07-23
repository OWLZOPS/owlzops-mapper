//! Agentless eBPF inventory.
//! Scans /proc/<pid>/fd for BPF programs, maps, and links, and /sys/fs/bpf
//! for pinned objects. No bpf() syscall required – pure VFS reading.

use crate::models::{BpfLinkInfo, BpfMapInfo, BpfPinInfo, BpfProgInfo, EbpfInventory};
use std::fs;
use std::io;
use std::path::Path;

/// Maximum number of BPF objects to collect per category
const MAX_BPF_OBJECTS: usize = 256;
/// Maximum recursion depth for pin scanning (R19-08)
const MAX_PIN_DEPTH: u8 = 8;

/// Try to parse a u32 from a line like "prog_id:\t123"
fn parse_u32_field(line: &str, prefix: &str) -> Option<u32> {
    line.strip_prefix(prefix)
        .and_then(|s| s.trim().parse().ok())
}

/// Parse fdinfo content for a BPF file descriptor.
/// Returns (obj_type, id, type_or_name, prog_tag).
fn parse_bpf_fdinfo(fdinfo: &str) -> Option<(String, u32, Option<String>, String)> {
    let mut obj_type = String::new();
    let mut id: Option<u32> = None;
    let mut name: Option<String> = None;
    let mut prog_tag = String::new();

    for line in fdinfo.lines() {
        if let Some(prog_id) = parse_u32_field(line, "prog_id:") {
            obj_type = "prog".into();
            id = Some(prog_id);
        } else if let Some(map_id) = parse_u32_field(line, "map_id:") {
            obj_type = "map".into();
            id = Some(map_id);
        } else if let Some(link_id) = parse_u32_field(line, "link_id:") {
            obj_type = "link".into();
            id = Some(link_id);
        } else if let Some(prog_type) = line.strip_prefix("prog_type:") {
            name = Some(prog_type.trim().to_string());
        } else if let Some(map_type) = line.strip_prefix("map_type:") {
            name = Some(map_type.trim().to_string());
        } else if let Some(prog_name) = line.strip_prefix("prog_name:") {
            name = Some(prog_name.trim().to_string());
        } else if let Some(tag) = line.strip_prefix("prog_tag:") {
            prog_tag = tag.trim().to_string();
        }
    }

    match (id, obj_type.as_str()) {
        (Some(id), "prog") | (Some(id), "map") | (Some(id), "link") => {
            Some((obj_type, id, name, prog_tag))
        }
        _ => None,
    }
}

/// Check if a symlink target points to an anon_inode:bpf-*
fn is_bpf_fd(link_target: &str) -> bool {
    link_target.starts_with("anon_inode:[bpf-") || link_target.starts_with("anon_inode:bpf-")
}

/// Read the contents of a /proc/<pid>/fd/<fdnum> symlink
fn read_fd_link(pid: u32, fdnum: u32) -> io::Result<String> {
    let path = format!("/proc/{}/fd/{}", pid, fdnum);
    std::fs::read_link(&path).map(|p| p.to_string_lossy().into_owned())
}

/// Push an item into a collection, respecting the global cap.
/// Records dropped objects for later coverage reporting.
fn push_capped<T>(vec: &mut Vec<T>, item: T, dropped: &mut usize) {
    if vec.len() < MAX_BPF_OBJECTS {
        vec.push(item);
    } else {
        *dropped += 1;
    }
}

/// Scan all PIDs for BPF file descriptors
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

        // Read comm
        let comm = fs::read_to_string(format!("/proc/{}/comm", pid))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        let fd_dir = match fs::read_dir(format!("/proc/{}/fd", pid)) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for fd_entry in fd_dir.flatten() {
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

            // Check if FD points to BPF object
            let link_target = match read_fd_link(pid, fdnum) {
                Ok(t) => t,
                Err(_) => continue,
            };

            if !is_bpf_fd(&link_target) {
                continue;
            }

            // Read fdinfo
            let fdinfo_path = format!("/proc/{}/fdinfo/{}", pid, fdnum);
            let fdinfo = match fs::read_to_string(&fdinfo_path) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let (obj_type, id, type_or_name, prog_tag) = match parse_bpf_fdinfo(&fdinfo) {
                Some(info) => info,
                None => continue,
            };

            match obj_type.as_str() {
                "prog" => push_capped(
                    &mut programs,
                    BpfProgInfo {
                        prog_id: id,
                        prog_type: type_or_name.unwrap_or_default(),
                        prog_name: None,
                        prog_tag,
                        pid,
                        comm: comm.clone(),
                    },
                    &mut dropped,
                ),
                "map" => push_capped(
                    &mut maps,
                    BpfMapInfo {
                        map_id: id,
                        map_type: type_or_name.unwrap_or_default(),
                        pid,
                        comm: comm.clone(),
                    },
                    &mut dropped,
                ),
                "link" => push_capped(
                    &mut links,
                    BpfLinkInfo {
                        link_id: id,
                        prog_id: 0, // link fdinfo doesn't expose prog_id via current parser
                        attach_type: type_or_name.unwrap_or_default(),
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

/// Recursively scan /sys/fs/bpf for pinned objects
fn scan_bpf_pins() -> Vec<BpfPinInfo> {
    let mut pins = Vec::new();
    scan_bpf_dir(Path::new("/sys/fs/bpf"), MAX_PIN_DEPTH, &mut pins);
    pins
}

/// Depth‑limited, symlink‑safe pin scanner (R19‑08)
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

        // Symlinks inside bpffs are anomalous – skip and treat as signal
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

/// Main entry point
#[cfg(target_os = "linux")]
pub fn gather_ebpf_inventory() -> EbpfInventory {
    let (programs, maps, links, dropped) = scan_proc_bpf();
    let pins = scan_bpf_pins();

    if dropped > 0 {
        crate::coverage::record(format!(
            "ebpf: {dropped} object(s) dropped at MAX_BPF_OBJECTS — inventory INCOMPLETE"
        ));
    }

    EbpfInventory {
        programs,
        maps,
        pins,
        links,
    }
}

/// Stub for non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub fn gather_ebpf_inventory() -> EbpfInventory {
    EbpfInventory::default()
}
