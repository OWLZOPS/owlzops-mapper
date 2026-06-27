use crate::models::{PackageManager, PackagesInfo, UpgradablePackage};
use std::process::Command;

fn command_exists(bin: &str) -> bool {
    Command::new("which")
        .arg(bin)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn detect_package_manager() -> PackageManager {
    if command_exists("apt-get") {
        return PackageManager::Apt;
    }
    if command_exists("zypper") {
        return PackageManager::Zypper;
    }
    if command_exists("dnf") {
        return PackageManager::Dnf;
    }
    if command_exists("yum") {
        return PackageManager::Yum;
    }
    if command_exists("pacman") {
        return PackageManager::Pacman;
    }
    PackageManager::Unknown
}

// =====================================================================
// APT (Debian / Ubuntu)
// =====================================================================

fn apt_installed_count() -> usize {
    if let Ok(output) = Command::new("dpkg-query")
        .args(["-f", "${binary:Package}\n", "-W"])
        .output()
    {
        return String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count();
    }
    0
}

fn apt_refresh_cache() -> bool {
    crate::utils::run_with_timeout("apt-get", &["update", "-qq"], 30).is_some()
}

fn apt_upgradable() -> Vec<UpgradablePackage> {
    let mut result = Vec::new();
    if let Some(stdout) = crate::utils::run_with_timeout("apt", &["list", "--upgradable"], 30) {
        for line in stdout.lines() {
            if line.starts_with("Listing...") || line.trim().is_empty() {
                continue;
            }
            let Some((name_repo, rest)) = line.split_once(' ') else {
                continue;
            };
            let Some((name, repo_part)) = name_repo.split_once('/') else {
                continue;
            };
            let new_version = rest
                .split_whitespace()
                .next()
                .unwrap_or("unknown")
                .to_string();
            let current_version = line
                .find("upgradable from: ")
                .map(|idx| {
                    let after = &line[idx + "upgradable from: ".len()..];
                    after.trim_end_matches(']').trim().to_string()
                })
                .unwrap_or_else(|| "unknown".to_string());
            let is_security = repo_part.to_lowercase().contains("security");
            result.push(UpgradablePackage {
                name: name.to_string(),
                current_version,
                new_version,
                is_security,
            });
        }
    }
    result
}

// =====================================================================
// DNF / YUM (RHEL / Fedora / CentOS)
// =====================================================================

fn rpm_installed_count() -> usize {
    if let Ok(output) = Command::new("rpm").arg("-qa").output() {
        return String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count();
    }
    0
}

fn dnf_like_refresh_cache(bin: &str) -> bool {
    crate::utils::run_with_timeout(bin, &["makecache", "-q"], 60).is_some()
}

fn dnf_like_upgradable(bin: &str) -> Vec<UpgradablePackage> {
    let mut result = Vec::new();
    if let Some(stdout) = crate::utils::run_with_timeout(bin, &["check-update"], 30) {
        for line in stdout.lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() == 3 && cols[0].contains('.') {
                let name = cols[0]
                    .rsplit_once('.')
                    .map(|(n, _)| n)
                    .unwrap_or(cols[0])
                    .to_string();
                result.push(UpgradablePackage {
                    name,
                    current_version: "unknown".to_string(),
                    new_version: cols[1].to_string(),
                    is_security: cols[2].to_lowercase().contains("security"),
                });
            }
        }
    }
    result
}

// =====================================================================
// Pacman (Arch)
// =====================================================================

fn pacman_installed_count() -> usize {
    if let Ok(output) = Command::new("pacman").arg("-Q").output() {
        return String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count();
    }
    0
}

fn pacman_refresh_cache() -> bool {
    crate::utils::run_with_timeout("pacman", &["-Sy", "--noconfirm"], 60).is_some()
}

fn pacman_upgradable() -> Vec<UpgradablePackage> {
    let mut result = Vec::new();
    if let Some(stdout) = crate::utils::run_with_timeout("pacman", &["-Qu"], 30) {
        for line in stdout.lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 4 && cols[2] == "->" {
                result.push(UpgradablePackage {
                    name: cols[0].to_string(),
                    current_version: cols[1].to_string(),
                    new_version: cols[3].to_string(),
                    is_security: false,
                });
            }
        }
    }
    result
}

// =====================================================================
// Zypper (openSUSE / SLES)
// =====================================================================

fn zypper_installed_count() -> usize {
    rpm_installed_count()
}

fn zypper_refresh_cache() -> bool {
    crate::utils::run_with_timeout("zypper", &["-n", "-q", "refresh"], 60).is_some()
}

fn zypper_security_package_names() -> std::collections::HashSet<String> {
    use rayon::prelude::*;

    let output = match crate::utils::run_with_timeout(
        "zypper",
        &["-n", "-q", "list-patches", "--category", "security"],
        30,
    ) {
        Some(stdout) => stdout,
        None => return std::collections::HashSet::new(),
    };

    let patch_names: Vec<String> = output
        .lines()
        .filter(|l| l.trim().starts_with("security"))
        .filter_map(|line| {
            let cols: Vec<&str> = line.trim().splitn(6, '|').collect();
            if cols.len() >= 3 {
                let patch = cols[2].trim().to_string();
                if !patch.is_empty() { Some(patch) } else { None }
            } else {
                None
            }
        })
        .collect();

    let results: Vec<std::collections::HashSet<String>> = patch_names
        .into_par_iter()
        .take(50)
        .map(|patch| {
            let mut names = std::collections::HashSet::new();
            let Some(info_out) = crate::utils::run_with_timeout(
                "zypper",
                &["-q", "info", "-t", "patch", &patch],
                10,
            ) else {
                return names;
            };
            for line in info_out.lines() {
                let l = line.trim();
                if (l.starts_with("Provides:") || l.starts_with("package:"))
                    && let Some(pkg) = l.split_whitespace().nth(1)
                {
                    names.insert(pkg.to_string());
                }
            }
            names
        })
        .collect();

    let mut pkg_names = std::collections::HashSet::new();
    for set in results {
        pkg_names.extend(set);
    }
    pkg_names
}

fn zypper_upgradable() -> Vec<UpgradablePackage> {
    let mut result = Vec::new();

    let upd_output =
        match crate::utils::run_with_timeout("zypper", &["-n", "-q", "list-updates"], 30) {
            Some(stdout) => stdout,
            None => return result,
        };

    let has_updates = upd_output.lines().any(|l| l.trim().starts_with('v'));
    if !has_updates {
        return result;
    }

    let security_pkgs = zypper_security_package_names();

    for line in upd_output.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('v') {
            continue;
        }
        let cols: Vec<&str> = trimmed.splitn(7, '|').collect();
        if cols.len() < 5 {
            continue;
        }
        let name = cols[2].trim().to_string();
        let current_version = cols[3].trim().to_string();
        let new_version = cols[4].trim().to_string();
        let is_security =
            security_pkgs.contains(&name) || cols[1].trim().to_lowercase().contains("security");
        result.push(UpgradablePackage {
            name,
            current_version,
            new_version,
            is_security,
        });
    }

    result
}

// =====================================================================
// Entry point
// =====================================================================

pub fn gather_packages_info(refresh_cache: bool) -> PackagesInfo {
    let manager = detect_package_manager();
    let mut cache_refreshed = false;

    let (installed_count, upgradable) = match manager {
        PackageManager::Apt => {
            if refresh_cache {
                cache_refreshed = apt_refresh_cache();
            }
            (apt_installed_count(), apt_upgradable())
        }
        PackageManager::Dnf => {
            if refresh_cache {
                cache_refreshed = dnf_like_refresh_cache("dnf");
            }
            (rpm_installed_count(), dnf_like_upgradable("dnf"))
        }
        PackageManager::Yum => {
            if refresh_cache {
                cache_refreshed = dnf_like_refresh_cache("yum");
            }
            (rpm_installed_count(), dnf_like_upgradable("yum"))
        }
        PackageManager::Pacman => {
            if refresh_cache {
                cache_refreshed = pacman_refresh_cache();
            }
            (pacman_installed_count(), pacman_upgradable())
        }
        PackageManager::Zypper => {
            if refresh_cache {
                cache_refreshed = zypper_refresh_cache();
            }
            (zypper_installed_count(), zypper_upgradable())
        }
        PackageManager::Unknown => (0, Vec::new()),
    };

    PackagesInfo {
        manager,
        installed_count,
        upgradable,
        cache_refreshed,
    }
}
