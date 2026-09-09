use std::collections::HashSet;
use std::fs;

use crate::coverage;
use crate::models::MountNamespaceAnomaly;
use crate::safe_io;

const MAX_PIDS: usize = 4096;

fn mnt_ns_inode(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/ns/mnt"))
        .ok()?
        .to_str()
        .map(str::to_string)
}

pub fn scan_mount_namespace_anomalies(
    known_container_pids: &HashSet<u32>,
) -> Vec<MountNamespaceAnomaly> {
    let host_ns = match mnt_ns_inode(1) {
        Some(ns) => ns,
        None => {
            coverage::record("mount namespace scan: /proc/1/ns/mnt unreadable".to_string());
            return Vec::new();
        }
    };

    let mut pids: Vec<u32> = match fs::read_dir("/proc") {
        Ok(entries) => entries
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
            .collect(),
        Err(e) => {
            coverage::record(format!("mount namespace scan: /proc unreadable ({e})"));
            return Vec::new();
        }
    };
    pids.sort_unstable();

    let mut result = Vec::new();
    let mut denied = 0usize;

    for pid in pids.into_iter().take(MAX_PIDS) {
        let Some(ns) = mnt_ns_inode(pid) else {
            denied += 1;
            continue;
        };
        if ns == host_ns || known_container_pids.contains(&pid) {
            continue;
        }

        let comm = safe_io::read_procfs_capped(&format!("/proc/{pid}/comm"), 4096)
            .ok()
            .map(|(c, _)| c.trim().to_string())
            .unwrap_or_else(|| "?".to_string());

        let exe_path = std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());

        result.push(MountNamespaceAnomaly {
            pid,
            comm,
            exe_path,
            mnt_ns: ns,
            known_container: false,
        });
    }

    result.sort_by_key(|a| a.pid);

    if denied > 0 {
        coverage::record(format!(
            "mount namespace scan: /proc/<pid>/ns/mnt unreadable for {denied} process(es)"
        ));
    }

    result
}
