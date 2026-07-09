use crate::models::{DiskInfo, StorageInfo};
use sysinfo::Disks;

pub fn gather_storage_info() -> StorageInfo {
    let mut disks = Vec::new();
    for disk in Disks::new_with_refreshed_list().list() {
        let fs_type = disk.file_system().to_string_lossy().to_lowercase();
        if fs_type.contains("squashfs") || fs_type.contains("tmpfs") || fs_type.contains("overlay")
        {
            continue;
        }

        let mount_point = disk.mount_point().to_string_lossy().to_string();
        let mut inode_usage = None;

        // Use run_with_timeout to avoid hanging on NFS or stuck mounts
        if let Some(stdout_str) = crate::utils::run_with_timeout("df", &["-Pi", &mount_point], 5) {
            let lines: Vec<&str> = stdout_str.lines().collect();
            if lines.len() > 1 {
                let parts: Vec<&str> = lines[1].split_whitespace().collect();
                if parts.len() >= 5 {
                    inode_usage = Some(parts[4].to_string());
                }
            }
        }

        // Compute exact sizes in MiB and percentage from raw bytes
        let total_space = disk.total_space();
        let available = disk.available_space();
        let used = total_space.saturating_sub(available);
        let usage_pct = if total_space > 0 {
            (used as f64 / total_space as f64) * 100.0
        } else {
            0.0
        };

        disks.push(DiskInfo {
            mount_point,
            total_mb: total_space / (1024 * 1024),
            used_mb: used / (1024 * 1024),
            usage_pct,
            inode_usage_percent: inode_usage,
        });
    }

    StorageInfo { disks }
}
