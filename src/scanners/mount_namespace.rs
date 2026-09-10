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

/// True when the process is managed by systemd. Modern systemd runs most
/// services in their own mount namespace as a hardening measure
/// (`ProtectSystem`, `PrivateMounts`, `DynamicUser`). Flagging those would
/// drown the report in noise — they are the platform, not a drift.
fn is_systemd_managed(pid: u32) -> bool {
    let Ok((cgroup, _)) = safe_io::read_procfs_capped(&format!("/proc/{pid}/cgroup"), 8192) else {
        return false;
    };
    cgroup.contains("system.slice/")
        || cgroup.contains("user.slice/")
        || cgroup.contains("machine.slice/")
}

/// True when the executable lives in a path owned by the package manager
/// or a known sandbox runtime. Such a binary can only be placed there by
/// root or by the platform itself, so a namespace anomaly around it is not
/// the signal we are hunting.
fn is_system_path(exe: &str) -> bool {
    const ROOTS: &[&str] = &[
        "/usr/",
        "/opt/",
        "/nix/store/",
        "/app/",             // Flatpak /app prefix
        "/snap/",            // Snap
        "/var/lib/flatpak/", // Flatpak store on the host
        "/run/wrappers/",    // NixOS setuid/capability wrappers
    ];
    ROOTS.iter().any(|p| exe.starts_with(p))
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
        if is_systemd_managed(pid) {
            continue;
        }

        let comm = safe_io::read_procfs_capped(&format!("/proc/{pid}/comm"), 4096)
            .ok()
            .map(|(c, _)| c.trim().to_string())
            .unwrap_or_else(|| "?".to_string());

        let exe_path = std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());

        // Kernel worker threads have no user-space image: readlink on
        // /proc/<pid>/exe returns ENOENT. They cannot execute attacker code
        // and their mount namespace is inherited from the kernel at boot,
        // so they are noise in this list. `kdevtmpfs` is the canonical
        // example seen on every Fedora/Ubuntu host.
        let Some(exe_path) = exe_path else {
            continue;
        };

        // Variant B: skip processes whose binary lives in a system-managed
        // prefix. Anything else here — /tmp, /dev/shm, /home, /run/user,
        // memfd — is what the scanner is actually for.
        if is_system_path(&exe_path) {
            continue;
        }

        result.push(MountNamespaceAnomaly {
            pid,
            comm,
            exe_path: Some(exe_path),
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
