use crate::models::{DiskInfo, StorageInfo};
use crate::scanners::Scanner;
use std::error::Error;
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
        if let Some(stdout_str) = crate::utils::run_with_timeout("df", &["-i", &mount_point], 5) {
            let lines: Vec<&str> = stdout_str.lines().collect();
            if lines.len() > 1 {
                let parts: Vec<&str> = lines[1].split_whitespace().collect();
                if parts.len() >= 5 {
                    inode_usage = Some(parts[4].to_string());
                }
            }
        }

        disks.push(DiskInfo {
            mount_point,
            total_gb: disk.total_space() / (1024 * 1024 * 1024),
            used_gb: (disk.total_space() - disk.available_space()) / (1024 * 1024 * 1024),
            inode_usage_percent: inode_usage,
        });
    }

    StorageInfo { disks }
}

pub struct StorageScanner;

impl Scanner for StorageScanner {
    fn name(&self) -> &'static str {
        "storage"
    }

    fn scan(&self) -> Result<Box<dyn std::any::Any + Send>, Box<dyn Error + Send>> {
        let info = gather_storage_info();
        Ok(Box::new(info))
    }
}
