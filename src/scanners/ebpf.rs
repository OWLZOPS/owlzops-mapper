//! Agentless eBPF inventory.
//! Scans /proc/<pid>/fd for BPF programs, maps, and links, and /sys/fs/bpf
//! for pinned objects. No bpf() syscall required – pure VFS reading.

use crate::models::{BpfMapInfo, BpfPinInfo, BpfProgInfo, EbpfInventory};
use std::fs;
use std::io;
use std::path::Path;

/// Maximum number of BPF objects to collect per category
const MAX_BPF_OBJECTS: usize = 256;

/// Try to parse a u32 from a line like "prog_id:\t123"
fn parse_u32_field(line: &str, prefix: &str) -> Option<u32> {
    line.strip_prefix(prefix)
        .and_then(|s| s.trim().parse().ok())
}

/// Parse fdinfo content for a BPF file descriptor
fn parse_bpf_fdinfo(fdinfo: &str) -> Option<(String, u32, Option<String>)> {
    let mut obj_type = String::new();
    let mut id: Option<u32> = None;
    let mut name: Option<String> = None;

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
            // Prefer prog_name over prog_type for the name field
            name = Some(prog_name.trim().to_string());
        }
    }

    match (id, obj_type.as_str()) {
        (Some(id), "prog") | (Some(id), "map") | (Some(id), "link") => Some((obj_type, id, name)),
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

/// Scan all PIDs for BPF file descriptors
fn scan_proc_bpf() -> (Vec<BpfProgInfo>, Vec<BpfMapInfo>) {
    let mut programs = Vec::new();
    let mut maps = Vec::new();

    let proc_dir = match fs::read_dir("/proc") {
        Ok(dir) => dir,
        Err(_) => return (programs, maps),
    };

    for entry in proc_dir.flatten() {
        if programs.len() >= MAX_BPF_OBJECTS && maps.len() >= MAX_BPF_OBJECTS {
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
            if programs.len() >= MAX_BPF_OBJECTS && maps.len() >= MAX_BPF_OBJECTS {
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

            let (obj_type, id, type_or_name) = match parse_bpf_fdinfo(&fdinfo) {
                Some(info) => info,
                None => continue,
            };

            match obj_type.as_str() {
                "prog" if programs.len() < MAX_BPF_OBJECTS => {
                    programs.push(BpfProgInfo {
                        prog_id: id,
                        prog_type: type_or_name.unwrap_or_default(),
                        prog_name: None,
                        prog_tag: String::new(),
                        pid,
                        comm: comm.clone(),
                    });
                }
                "map" if maps.len() < MAX_BPF_OBJECTS => {
                    maps.push(BpfMapInfo {
                        map_id: id,
                        map_type: type_or_name.unwrap_or_default(),
                        pid,
                        comm: comm.clone(),
                    });
                }
                _ => {}
            }
        }
    }

    (programs, maps)
}

/// Recursively scan /sys/fs/bpf for pinned objects
fn scan_bpf_pins() -> Vec<BpfPinInfo> {
    let mut pins = Vec::new();
    scan_bpf_dir(Path::new("/sys/fs/bpf"), &mut pins);
    pins
}

fn scan_bpf_dir(dir: &Path, pins: &mut Vec<BpfPinInfo>) {
    if pins.len() >= MAX_BPF_OBJECTS {
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

        if path.is_dir() {
            scan_bpf_dir(&path, pins);
            continue;
        }

        // Record any file in /sys/fs/bpf as a pinned BPF object.
        // Detailed type/id extraction can be added later if needed.
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
    let (programs, maps) = scan_proc_bpf();
    let pins = scan_bpf_pins();
    EbpfInventory {
        programs,
        maps,
        pins,
    }
}

/// Stub for non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub fn gather_ebpf_inventory() -> EbpfInventory {
    EbpfInventory::default()
}
