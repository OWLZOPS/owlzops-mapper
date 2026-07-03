use crate::models::{PackageManager, PackagesInfo, UpgradablePackage};
use crate::scanners::Scanner;
use std::collections::HashSet;
use std::error::Error;

/// Parse the stdout of `dnf check-update` (or `yum check-update`).
/// Format: "pkg.arch  version  repo" (three columns, repo may contain "security")
fn parse_dnf_check_update(stdout: &str) -> Vec<UpgradablePackage> {
    stdout
        .lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() == 3 && cols[0].contains('.') {
                let name = cols[0]
                    .rsplit_once('.')
                    .map(|(n, _)| n)
                    .unwrap_or(cols[0])
                    .to_string();
                Some(UpgradablePackage {
                    name,
                    current_version: "unknown".to_string(),
                    new_version: cols[1].to_string(),
                    is_security: cols[2].to_lowercase().contains("security"),
                })
            } else {
                None
            }
        })
        .collect()
}

/// Parse the stdout of `apt list --upgradable`.
/// Lines look like: "pkg/jammy-updates,jammy-security 1.0.1 amd64 [upgradable from: 1.0.0]"
fn parse_apt_upgradable(stdout: &str) -> Vec<UpgradablePackage> {
    stdout
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with("Listing...") || line.starts_with("WARNING:") {
                return None;
            }
            let name_end = line.find('/')?;
            let name = line[..name_end].to_string();
            let rest = &line[name_end + 1..];
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() < 3 {
                return None;
            }
            let repo = parts[0].to_lowercase(); // repository field
            let new_version = parts[1].to_string(); // new version
            let is_security = repo.contains("security");
            // Extract current version from "[upgradable from: X]"
            let current_version = line
                .split("upgradable from:")
                .nth(1)
                .and_then(|s| s.trim().split(']').next())
                .unwrap_or("unknown")
                .to_string();
            Some(UpgradablePackage {
                name,
                current_version,
                new_version,
                is_security,
            })
        })
        .collect()
}

/// Parse the stdout of `zypper list-updates`.
/// Lines: "S | Repository | Name | Current Version | Available Version | Arch"
/// We parse only lines starting with 'v' (patch) or containing security keywords.
fn parse_zypper_updates(stdout: &str) -> Vec<UpgradablePackage> {
    stdout
        .lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
            if cols.len() < 6 {
                return None;
            }
            // First column: status (v = vulnerability patch)
            let is_security = cols[0].contains('v') || cols[0].to_lowercase().contains("security");
            let name = cols[2].to_string();
            let current_version = cols[3].to_string();
            let new_version = cols[4].to_string();
            if name.is_empty() || name == "Name" {
                return None;
            }
            Some(UpgradablePackage {
                name,
                current_version,
                new_version,
                is_security,
            })
        })
        .collect()
}

/// Parse the stdout of `pacman -Qu`.
/// Lines: "pkg 1.0.0-1 -> 1.0.1-1"
fn parse_pacman_updates(stdout: &str) -> Vec<UpgradablePackage> {
    stdout
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                return None;
            }
            let name = parts[0].to_string();
            let current_version = parts[1].to_string();
            let new_version = parts[3].to_string();
            Some(UpgradablePackage {
                name,
                current_version,
                new_version,
                is_security: false, // pacman does not have a security channel
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Scanner wrappers (call external commands and delegate to parsers)
// ---------------------------------------------------------------------------

fn dnf_like_upgradable(bin: &str) -> Vec<UpgradablePackage> {
    crate::utils::run_with_timeout_any_exit(bin, &["check-update"], 30)
        .map(|out| parse_dnf_check_update(&out))
        .unwrap_or_default()
}

fn apt_upgradable() -> Vec<UpgradablePackage> {
    crate::utils::run_with_timeout("apt", &["list", "--upgradable"], 30)
        .map(|out| parse_apt_upgradable(&out))
        .unwrap_or_default()
}

fn zypper_upgradable() -> Vec<UpgradablePackage> {
    crate::utils::run_with_timeout("zypper", &["list-updates"], 30)
        .map(|out| parse_zypper_updates(&out))
        .unwrap_or_default()
}

fn pacman_upgradable() -> Vec<UpgradablePackage> {
    crate::utils::run_with_timeout("pacman", &["-Qu"], 15)
        .map(|out| parse_pacman_updates(&out))
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Helpers for zypper security patch inspection
// ---------------------------------------------------------------------------

fn zypper_security_package_names() -> HashSet<String> {
    const MAX_PATCHES_TO_INSPECT: usize = 50;
    let mut pkg_names = HashSet::new();

    let Some(list_out) =
        crate::utils::run_with_timeout("zypper", &["list-patches", "--category", "security"], 30)
    else {
        return pkg_names;
    };

    let patch_names: Vec<String> = list_out
        .lines()
        .skip_while(|l| !l.starts_with("---"))
        .skip(1)
        .filter_map(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            parts.first().map(|s| s.to_string())
        })
        .collect();

    for patch in patch_names.iter().take(MAX_PATCHES_TO_INSPECT) {
        let Some(info_out) =
            crate::utils::run_with_timeout("zypper", &["-q", "info", "-t", "patch", patch], 15)
        else {
            continue;
        };
        for line in info_out.lines() {
            let l = line.trim();
            if (l.starts_with("Provides:") || l.starts_with("package:"))
                && let Some(pkg) = l.split_whitespace().nth(1)
            {
                pkg_names.insert(pkg.to_string());
            }
        }
    }

    pkg_names
}

// ---------------------------------------------------------------------------
// Package manager detection
// ---------------------------------------------------------------------------

fn detect_package_manager() -> (PackageManager, Option<String>) {
    let bins = &[
        (PackageManager::Dnf, "dnf"),
        (PackageManager::Yum, "yum"),
        (PackageManager::Apt, "apt"),
        (PackageManager::Pacman, "pacman"),
        (PackageManager::Zypper, "zypper"),
    ];

    for (pm, bin) in bins {
        let found = crate::utils::run_with_timeout("which", &[bin], 2)
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        if found {
            return (*pm, Some(bin.to_string()));
        }
    }
    (PackageManager::Unknown, None)
}

// ---------------------------------------------------------------------------
// Cache refresh
// ---------------------------------------------------------------------------

fn refresh_cache(manager: PackageManager, bin: Option<&str>) -> bool {
    match manager {
        PackageManager::Apt => crate::utils::run_with_timeout("apt-get", &["update"], 30).is_some(),
        PackageManager::Dnf | PackageManager::Yum => {
            let b = bin.unwrap_or("dnf");
            crate::utils::run_with_timeout(b, &["makecache"], 30).is_some()
        }
        PackageManager::Pacman => crate::utils::run_with_timeout("pacman", &["-Sy"], 15).is_some(),
        PackageManager::Zypper => {
            crate::utils::run_with_timeout("zypper", &["refresh"], 30).is_some()
        }
        PackageManager::Unknown => false,
    }
}

fn installed_count(manager: PackageManager, bin: Option<&str>) -> usize {
    match manager {
        PackageManager::Apt => crate::utils::run_with_timeout("dpkg-query", &["-W"], 10)
            .map(|s| s.lines().count())
            .unwrap_or(0),
        PackageManager::Dnf | PackageManager::Yum => {
            let b = bin.unwrap_or("rpm");
            crate::utils::run_with_timeout(b, &["-qa"], 15)
                .map(|s| s.lines().count())
                .unwrap_or(0)
        }
        PackageManager::Pacman => crate::utils::run_with_timeout("pacman", &["-Q"], 10)
            .map(|s| s.lines().count())
            .unwrap_or(0),
        PackageManager::Zypper => crate::utils::run_with_timeout("rpm", &["-qa"], 15)
            .map(|s| s.lines().count())
            .unwrap_or(0),
        PackageManager::Unknown => 0,
    }
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

pub fn gather_packages_info(refresh: bool) -> PackagesInfo {
    let (manager, bin) = detect_package_manager();
    let cache_refreshed = if refresh {
        refresh_cache(manager, bin.as_deref())
    } else {
        false
    };
    let installed = installed_count(manager, bin.as_deref());

    let mut upgradable = match manager {
        PackageManager::Dnf | PackageManager::Yum => {
            dnf_like_upgradable(bin.as_deref().unwrap_or("dnf"))
        }
        PackageManager::Apt => apt_upgradable(),
        PackageManager::Pacman => pacman_upgradable(),
        PackageManager::Zypper => zypper_upgradable(),
        PackageManager::Unknown => Vec::new(),
    };

    // For zypper, enhance security flags by inspecting individual patches
    if manager == PackageManager::Zypper {
        let sec_pkgs = zypper_security_package_names();
        for pkg in &mut upgradable {
            if sec_pkgs.contains(&pkg.name) {
                pkg.is_security = true;
            }
        }
    }

    PackagesInfo {
        manager,
        installed_count: installed,
        upgradable,
        cache_refreshed,
    }
}

#[allow(dead_code)]
pub struct PackagesScanner {
    pub refresh: bool,
}

impl Scanner for PackagesScanner {
    fn name(&self) -> &'static str {
        "packages"
    }

    fn scan(&self) -> Result<Box<dyn std::any::Any + Send>, Box<dyn Error + Send>> {
        let info = gather_packages_info(self.refresh);
        Ok(Box::new(info))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dnf_security_line() {
        let stdout = "bash.x86_64  5.1.8-4.fc36  updates-security\n";
        let pkgs = parse_dnf_check_update(stdout);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "bash");
        assert_eq!(pkgs[0].new_version, "5.1.8-4.fc36");
        assert!(pkgs[0].is_security);
    }

    #[test]
    fn parse_apt_security_line() {
        let stdout =
            "curl/jammy-security 7.81.0-1ubuntu1.20 amd64 [upgradable from: 7.81.0-1ubuntu1.19]\n";
        let pkgs = parse_apt_upgradable(stdout);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "curl");
        assert_eq!(pkgs[0].current_version, "7.81.0-1ubuntu1.19");
        assert_eq!(pkgs[0].new_version, "7.81.0-1ubuntu1.20");
        assert!(pkgs[0].is_security);
    }

    #[test]
    fn parse_pacman_output() {
        let stdout = "bash 5.1.16-1 -> 5.1.16-2\n";
        let pkgs = parse_pacman_updates(stdout);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "bash");
        assert_eq!(pkgs[0].current_version, "5.1.16-1");
        assert_eq!(pkgs[0].new_version, "5.1.16-2");
        assert!(!pkgs[0].is_security);
    }

    #[test]
    fn parse_zypper_security_patch() {
        let stdout = "v | security    | bash | 5.0-1 | 5.1-1 | x86_64\n";
        let pkgs = parse_zypper_updates(stdout);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "bash");
        assert_eq!(pkgs[0].current_version, "5.0-1");
        assert_eq!(pkgs[0].new_version, "5.1-1");
        assert!(pkgs[0].is_security);
    }
}
