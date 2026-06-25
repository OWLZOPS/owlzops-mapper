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
    // Check zypper before dnf: some SLES systems ship both, zypper is authoritative.
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
            // Format: "pkgname oldversion -> newversion"
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
    // zypper is RPM-based — rpm -qa works on all zypper systems.
    rpm_installed_count()
}

fn zypper_refresh_cache() -> bool {
    // -n = non-interactive, -q = quiet. Requires root.
    Command::new("zypper")
        .args(["-n", "-q", "refresh"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Returns the set of package names covered by pending security patches.
fn zypper_security_package_names() -> std::collections::HashSet<String> {
    let mut pkg_names = std::collections::HashSet::new();

    let Ok(output) = Command::new("zypper")
        .args(["-n", "-q", "list-patches", "--category", "security"])
        .output()
    else {
        return pkg_names;
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut patch_names: Vec<String> = Vec::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("security") {
            continue;
        }
        let cols: Vec<&str> = trimmed.splitn(6, '|').collect();
        if cols.len() >= 3 {
            let patch = cols[2].trim().to_string();
            if !patch.is_empty() {
                patch_names.push(patch);
            }
        }
    }

    for patch in patch_names.into_iter().take(50) {
        let Ok(info_out) = Command::new("zypper")
            .args(["-q", "info", "-t", "patch", &patch])
            .output()
        else {
            continue;
        };
        // The "Provides:" block lists the affected packages.
        for line in String::from_utf8_lossy(&info_out.stdout).lines() {
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

fn zypper_upgradable() -> Vec<UpgradablePackage> {
    let mut result = Vec::new();

    let Ok(upd_output) = Command::new("zypper")
        .args(["-n", "-q", "list-updates"])
        .output()
    else {
        return result;
    };

    let stdout = String::from_utf8_lossy(&upd_output.stdout);

    let has_updates = stdout.lines().any(|l| l.trim().starts_with('v'));
    if !has_updates {
        return result;
    }

    let security_pkgs = zypper_security_package_names();

    for line in stdout.lines() {
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
