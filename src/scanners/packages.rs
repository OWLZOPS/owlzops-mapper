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
    // Requires root. Network call — only runs when explicitly requested via
    // --refresh-packages (see main.rs); packages.rs itself doesn't decide
    // whether network access is allowed, it just executes when asked to.
    Command::new("apt-get")
        .args(["update", "-qq"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn apt_upgradable() -> Vec<UpgradablePackage> {
    let mut result = Vec::new();
    if let Ok(output) = Command::new("apt").arg("list").arg("--upgradable").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            // Format: "pkgname/repo,repo2 newversion arch [upgradable from: oldversion]"
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
    Command::new(bin)
        .args(["makecache", "-q"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn dnf_like_upgradable(bin: &str) -> Vec<UpgradablePackage> {
    let mut result = Vec::new();
    // check-update returns exit code 100 when updates are available — not an execution error.
    if let Ok(output) = Command::new(bin).arg("check-update").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            // Line format: "pkgname.arch  new-version  repo"
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
    Command::new("pacman")
        .args(["-Sy", "--noconfirm"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn pacman_upgradable() -> Vec<UpgradablePackage> {
    let mut result = Vec::new();
    if let Ok(output) = Command::new("pacman").arg("-Qu").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            // Формат: "pkgname oldversion -> newversion"
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 4 && cols[2] == "->" {
                result.push(UpgradablePackage {
                    name: cols[0].to_string(),
                    current_version: cols[1].to_string(),
                    new_version: cols[3].to_string(),
                    is_security: false, // pacman не маркирует security-апдейты отдельно
                });
            }
        }
    }
    result
}

// =====================================================================
// Entry point
// =====================================================================

/// `refresh_cache` - refresh the repository's local cache before checking for updates.
/// This is the only potentially network-related call in this module, and it is
/// performed only when explicitly requested by the caller (see the
/// --refresh-packages flag and its interaction with --offline in main.rs).
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
        PackageManager::Unknown => (0, Vec::new()),
    };

    PackagesInfo {
        manager,
        installed_count,
        upgradable,
        cache_refreshed,
    }
}
