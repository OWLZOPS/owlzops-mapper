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

/// The systemd unit or scope owning this pid, taken from its cgroup path.
/// cgroup v2 line: "0::/system.slice/nginx.service".
fn systemd_unit(pid: u32) -> Option<String> {
    let (cgroup, _) = safe_io::read_procfs_capped(&format!("/proc/{pid}/cgroup"), 8192).ok()?;
    cgroup
        .lines()
        .filter_map(|l| l.rsplit(':').next())
        .flat_map(|p| p.rsplit('/'))
        .find(|c| c.ends_with(".service") || c.ends_with(".scope"))
        .map(str::to_string)
}

/// True when the executable lives in a path owned by the package manager
/// or a known sandbox runtime. Reported as a label, never used to drop
/// the row: `unshare -m` from a shell runs /usr/bin/bash.
fn is_system_path(exe: &str) -> bool {
    const ROOTS: &[&str] = &[
        "/usr/",
        // Aligned with utils.rs::SYSTEM_BIN. On usrmerge systems /bin and
        // /sbin are symlinks into /usr, but a container's namespace may
        // predate that — the paths here are namespace-relative.
        "/bin/",
        "/sbin/",
        "/opt/",
        "/nix/store/",
        "/app/",
        "/snap/",
        "/var/lib/flatpak/",
        "/run/wrappers/",
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

    let total_pids = pids.len();
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

        // Kernel worker threads have no user-space image: readlink on
        // /proc/<pid>/exe returns ENOENT. They cannot execute attacker code
        // and their mount namespace is inherited from the kernel at boot,
        // so they are noise in this list.
        let Some(exe_path) = std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
        else {
            continue;
        };

        // R31-01: label system-managed prefixes and systemd units, never
        // drop them. `unshare -m` from a shell runs /usr/bin/bash under
        // session-N.scope — the case this scanner exists for. Consumers
        // filter by policy (ui.rs default; JSON always carries all).
        result.push(MountNamespaceAnomaly {
            pid,
            comm,
            exe_path: Some(exe_path.clone()),
            mnt_ns: ns,
            systemd_unit: systemd_unit(pid),
            system_path: is_system_path(&exe_path),
        });
    }

    result.sort_by_key(|a| a.pid);

    if denied > 0 {
        coverage::record(format!(
            "mount namespace scan: /proc/<pid>/ns/mnt unreadable for {denied} process(es)"
        ));
    }
    if total_pids > MAX_PIDS {
        // R31-02: pids are ascending, so take() drops the NEWEST processes —
        // exactly where a fresh `unshare` lands. Report the cap; the list
        // is a lower bound.
        coverage::record(format!(
            "mount namespace scan: {total_pids} processes, cap is {MAX_PIDS} — the \
             {} newest were NOT examined; this list is a LOWER BOUND",
            total_pids - MAX_PIDS
        ));
    }

    result
}
