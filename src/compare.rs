use crate::models::{AgentReport, Change, DiffReport, MultiHostDiff, Severity};
use std::collections::{HashMap, HashSet};

/// Compare two AgentReports and produce a DiffReport
pub fn compare_reports(before: &AgentReport, after: &AgentReport) -> DiffReport {
    let mut changes = Vec::new();

    // --- risk_score ---
    if before.risk_score != after.risk_score {
        let sev = if after.risk_score > before.risk_score {
            Severity::Degraded
        } else {
            Severity::Improved
        };
        changes.push(Change {
            field: "risk_score".into(),
            before: Some(before.risk_score.to_string()),
            after: Some(after.risk_score.to_string()),
            severity: sev,
        });
    }

    // --- host fields ---
    if before.host.hostname != after.host.hostname {
        changes.push(Change {
            field: "host.hostname".into(),
            before: Some(before.host.hostname.clone()),
            after: Some(after.host.hostname.clone()),
            severity: Severity::Changed,
        });
    }
    if before.host.uptime_days != after.host.uptime_days {
        changes.push(Change {
            field: "host.uptime_days".into(),
            before: Some(before.host.uptime_days.to_string()),
            after: Some(after.host.uptime_days.to_string()),
            severity: Severity::Changed,
        });
    }
    if before.host.reboot_required != after.host.reboot_required {
        let sev = if after.host.reboot_required {
            Severity::Degraded
        } else {
            Severity::Improved
        };
        changes.push(Change {
            field: "host.reboot_required".into(),
            before: Some(before.host.reboot_required.to_string()),
            after: Some(after.host.reboot_required.to_string()),
            severity: sev,
        });
    }

    // --- Security-critical boolean drifts (H-5) ---
    macro_rules! compare_bool {
        ($changes:expr, $before:expr, $after:expr, $field:literal, $degraded_when:literal) => {
            if $before != $after {
                let sev = if $after == $degraded_when {
                    Severity::Degraded
                } else {
                    Severity::Improved
                };
                $changes.push(Change {
                    field: $field.into(),
                    before: Some($before.to_string()),
                    after: Some($after.to_string()),
                    severity: sev,
                });
            }
        };
    }

    compare_bool!(
        changes,
        before.network.firewall_active,
        after.network.firewall_active,
        "network.firewall_active",
        false
    );
    compare_bool!(
        changes,
        before.security.ssh_root_login_enabled,
        after.security.ssh_root_login_enabled,
        "security.ssh_root_login_enabled",
        true
    );
    compare_bool!(
        changes,
        before.security.ssh_password_auth_enabled,
        after.security.ssh_password_auth_enabled,
        "security.ssh_password_auth_enabled",
        true
    );
    compare_bool!(
        changes,
        before.security.fail2ban_active,
        after.security.fail2ban_active,
        "security.fail2ban_active",
        false
    );
    compare_bool!(
        changes,
        before.security.auditd_active,
        after.security.auditd_active,
        "security.auditd_active",
        false
    );
    compare_bool!(
        changes,
        before.host.ntp_synchronized,
        after.host.ntp_synchronized,
        "host.ntp_synchronized",
        false
    );

    // OS / kernel changes (unexpected downgrades)
    if before.host.os_version != after.host.os_version {
        changes.push(Change {
            field: "host.os_version".into(),
            before: Some(before.host.os_version.clone()),
            after: Some(after.host.os_version.clone()),
            severity: Severity::Changed,
        });
    }
    if before.host.kernel != after.host.kernel {
        changes.push(Change {
            field: "host.kernel".into(),
            before: Some(before.host.kernel.clone()),
            after: Some(after.host.kernel.clone()),
            severity: Severity::Changed,
        });
    }

    // Sudden package count change (possible supply-chain signal)
    if before.packages.installed_count != after.packages.installed_count {
        let sev = if after.packages.installed_count > before.packages.installed_count + 50 {
            Severity::Degraded // large unexpected increase
        } else {
            Severity::Changed
        };
        changes.push(Change {
            field: "packages.installed_count".into(),
            before: Some(before.packages.installed_count.to_string()),
            after: Some(after.packages.installed_count.to_string()),
            severity: sev,
        });
    }

    // SSL certificates – crossing critical/warning threshold
    let before_certs: Vec<_> = before.network.ssl_certificates.iter().collect();
    let after_certs: Vec<_> = after.network.ssl_certificates.iter().collect();
    for after_cert in &after_certs {
        if let Some(before_cert) = before_certs.iter().find(|c| c.domain == after_cert.domain)
            && before_cert.is_critical != after_cert.is_critical
        {
            let sev = if after_cert.is_critical {
                Severity::Degraded
            } else {
                Severity::Improved
            };
            changes.push(Change {
                field: format!("network.ssl_certificates.{}.is_critical", after_cert.domain),
                before: Some(before_cert.is_critical.to_string()),
                after: Some(after_cert.is_critical.to_string()),
                severity: sev,
            });
        }
    }

    // Detect removed certificates
    for before_cert in &before_certs {
        if !after_certs.iter().any(|c| c.domain == before_cert.domain) {
            changes.push(Change {
                field: format!("network.ssl_certificates.{}.removed", before_cert.domain),
                before: Some(before_cert.domain.clone()),
                after: None,
                severity: Severity::Changed,
            });
        }
    }

    // --- network.listening_ports (key: protocol:bind_address:port) ---
    let before_ports: HashSet<(String, String, String)> = before
        .network
        .listening_ports
        .iter()
        .map(|p| (p.protocol.clone(), p.bind_address.clone(), p.port.clone()))
        .collect();
    let after_ports: HashSet<(String, String, String)> = after
        .network
        .listening_ports
        .iter()
        .map(|p| (p.protocol.clone(), p.bind_address.clone(), p.port.clone()))
        .collect();

    for added in after_ports.difference(&before_ports) {
        changes.push(Change {
            field: "network.listening_ports".into(),
            before: None,
            after: Some(format!("{}:{}:{}", added.0, added.1, added.2)),
            severity: Severity::Degraded,
        });
    }
    for removed in before_ports.difference(&after_ports) {
        changes.push(Change {
            field: "network.listening_ports".into(),
            before: Some(format!("{}:{}:{}", removed.0, removed.1, removed.2)),
            after: None,
            severity: Severity::Improved,
        });
    }

    // Detect process changes on unchanged ports
    for after_p in &after.network.listening_ports {
        if let Some(before_p) = before.network.listening_ports.iter().find(|p| {
            p.protocol == after_p.protocol
                && p.bind_address == after_p.bind_address
                && p.port == after_p.port
        }) && before_p.process != after_p.process
        {
            changes.push(Change {
                field: format!(
                    "network.listening_ports.{}.{}.{}.process",
                    after_p.protocol, after_p.bind_address, after_p.port
                ),
                before: Some(before_p.process.clone()),
                after: Some(after_p.process.clone()),
                severity: Severity::Degraded,
            });
        }
    }

    // --- packages.upgradable (key: package name) ---
    let before_pkgs: HashSet<&str> = before
        .packages
        .upgradable
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    let after_pkgs: HashSet<&str> = after
        .packages
        .upgradable
        .iter()
        .map(|p| p.name.as_str())
        .collect();

    for added in after_pkgs.difference(&before_pkgs) {
        changes.push(Change {
            field: "packages.upgradable".into(),
            before: None,
            after: Some(added.to_string()),
            severity: Severity::Degraded,
        });
    }
    for removed in before_pkgs.difference(&after_pkgs) {
        changes.push(Change {
            field: "packages.upgradable".into(),
            before: Some(removed.to_string()),
            after: None,
            severity: Severity::Improved,
        });
    }

    // --- security.shell_users (compare authorized_keys_count) ---
    let before_users: HashMap<&str, u64> = before
        .security
        .shell_users
        .iter()
        .map(|u| (u.username.as_str(), u.authorized_keys_count as u64))
        .collect();
    let after_users: HashMap<&str, u64> = after
        .security
        .shell_users
        .iter()
        .map(|u| (u.username.as_str(), u.authorized_keys_count as u64))
        .collect();

    let all_users: HashSet<&str> = before_users
        .keys()
        .chain(after_users.keys())
        .copied()
        .collect();
    for user in all_users {
        let before_count = before_users.get(user).copied().unwrap_or(0);
        let after_count = after_users.get(user).copied().unwrap_or(0);

        if before_count != after_count {
            let sev = if after_count > before_count {
                Severity::Degraded
            } else {
                Severity::Improved
            };
            changes.push(Change {
                field: format!("security.shell_users.{}.authorized_keys_count", user),
                before: Some(before_count.to_string()),
                after: Some(after_count.to_string()),
                severity: sev,
            });
        }
    }

    // --- topology.containers (use container name as key) ---
    let before_containers: HashSet<&str> = before
        .topology
        .containers
        .iter()
        .map(|c| c.name.as_str())
        .collect();
    let after_containers: HashSet<&str> = after
        .topology
        .containers
        .iter()
        .map(|c| c.name.as_str())
        .collect();

    for added in after_containers.difference(&before_containers) {
        changes.push(Change {
            field: "topology.containers".into(),
            before: None,
            after: Some(added.to_string()),
            severity: Severity::Degraded,
        });
    }
    for removed in before_containers.difference(&after_containers) {
        changes.push(Change {
            field: "topology.containers".into(),
            before: Some(removed.to_string()),
            after: None,
            severity: Severity::Improved,
        });
    }

    // Detect image changes on unchanged containers
    for after_c in &after.topology.containers {
        if let Some(before_c) = before
            .topology
            .containers
            .iter()
            .find(|c| c.name == after_c.name)
            && before_c.image != after_c.image
        {
            changes.push(Change {
                field: format!("topology.containers.{}.image", after_c.name),
                before: Some(before_c.image.clone()),
                after: Some(after_c.image.clone()),
                severity: Severity::Degraded,
            });
        }
    }

    // --- security.sysctl_issues (text description) ---
    let before_sysctl: HashSet<&str> = before
        .security
        .sysctl_issues
        .iter()
        .map(|s| s.as_str())
        .collect();
    let after_sysctl: HashSet<&str> = after
        .security
        .sysctl_issues
        .iter()
        .map(|s| s.as_str())
        .collect();

    for added in after_sysctl.difference(&before_sysctl) {
        changes.push(Change {
            field: "security.sysctl_issues".into(),
            before: None,
            after: Some(added.to_string()),
            severity: Severity::Degraded,
        });
    }
    for removed in before_sysctl.difference(&after_sysctl) {
        changes.push(Change {
            field: "security.sysctl_issues".into(),
            before: Some(removed.to_string()),
            after: None,
            severity: Severity::Improved,
        });
    }

    // --- host.failed_services ---
    let before_failed: HashSet<&str> = before
        .host
        .failed_services
        .iter()
        .map(|s| s.as_str())
        .collect();
    let after_failed: HashSet<&str> = after
        .host
        .failed_services
        .iter()
        .map(|s| s.as_str())
        .collect();

    for added in after_failed.difference(&before_failed) {
        changes.push(Change {
            field: "host.failed_services".into(),
            before: None,
            after: Some(added.to_string()),
            severity: Severity::Degraded,
        });
    }
    for removed in before_failed.difference(&after_failed) {
        changes.push(Change {
            field: "host.failed_services".into(),
            before: Some(removed.to_string()),
            after: None,
            severity: Severity::Improved,
        });
    }

    // --- host.backup_tools ---
    let before_backup: HashSet<&str> = before
        .host
        .backup_tools
        .iter()
        .map(|t| t.as_str())
        .collect();
    let after_backup: HashSet<&str> = after.host.backup_tools.iter().map(|t| t.as_str()).collect();

    for added in after_backup.difference(&before_backup) {
        changes.push(Change {
            field: "host.backup_tools".into(),
            before: None,
            after: Some(added.to_string()),
            severity: Severity::Improved,
        });
    }
    for removed in before_backup.difference(&after_backup) {
        changes.push(Change {
            field: "host.backup_tools".into(),
            before: Some(removed.to_string()),
            after: None,
            severity: Severity::Degraded,
        });
    }

    // Sort by severity: Degraded first, then Changed, then Improved
    changes.sort_unstable_by_key(|c| match c.severity {
        Severity::Degraded => 0,
        Severity::Changed => 1,
        Severity::Improved => 2,
    });

    DiffReport { changes }
}

pub fn compare_multi(before: &[AgentReport], after: &[AgentReport]) -> Vec<MultiHostDiff> {
    let before_map: HashMap<&str, &AgentReport> = before
        .iter()
        .map(|r| (r.host.hostname.as_str(), r))
        .collect();
    let after_map: HashMap<&str, &AgentReport> = after
        .iter()
        .map(|r| (r.host.hostname.as_str(), r))
        .collect();

    let all_hostnames: HashSet<&str> = before_map.keys().chain(after_map.keys()).copied().collect();
    let mut diffs = Vec::new();

    for hostname in all_hostnames {
        match (before_map.get(hostname), after_map.get(hostname)) {
            (Some(b), Some(a)) => {
                let diff = compare_reports(b, a);
                if !diff.changes.is_empty() {
                    diffs.push(MultiHostDiff {
                        hostname: hostname.to_string(),
                        diff,
                    });
                }
            }
            (Some(_), None) => {
                let changes = vec![Change {
                    field: "host.removed".into(),
                    before: Some(hostname.to_string()),
                    after: None,
                    severity: Severity::Degraded,
                }];
                diffs.push(MultiHostDiff {
                    hostname: hostname.to_string(),
                    diff: DiffReport { changes },
                });
            }
            (None, Some(_)) => {
                let changes = vec![Change {
                    field: "host.added".into(),
                    before: None,
                    after: Some(hostname.to_string()),
                    severity: Severity::Changed,
                }];
                diffs.push(MultiHostDiff {
                    hostname: hostname.to_string(),
                    diff: DiffReport { changes },
                });
            }
            (None, None) => unreachable!(),
        }
    }

    diffs.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    diffs
}

/// Terminal output with colored table (using comfy_table)
pub fn print_diff_terminal(report: &DiffReport) {
    use comfy_table::presets::UTF8_FULL;
    use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};

    if report.changes.is_empty() {
        println!("No differences found.");
        return;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("Field").add_attribute(Attribute::Bold),
            Cell::new("Before").fg(Color::Red),
            Cell::new("After").fg(Color::Green),
            Cell::new("Severity").add_attribute(Attribute::Bold),
        ]);

    for change in &report.changes {
        let before = change.before.as_deref().unwrap_or("-");
        let after = change.after.as_deref().unwrap_or("-");

        let severity_cell = match change.severity {
            Severity::Degraded => Cell::new("↓ Degraded").fg(Color::Red),
            Severity::Improved => Cell::new("↑ Improved").fg(Color::Green),
            Severity::Changed => Cell::new("~ Changed").fg(Color::Yellow),
        };

        table.add_row(vec![
            Cell::new(&change.field),
            Cell::new(before),
            Cell::new(after),
            severity_cell,
        ]);
    }

    println!("{table}");
}

/// Export diff as JSON string
pub fn diff_to_json(report: &DiffReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

/// Export diff to Excel using the dedicated function in exporters/xlsx
pub fn write_diff_xlsx(report: &DiffReport, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    crate::exporters::xlsx::write_diff_sheet(report, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::*;

    fn test_report() -> AgentReport {
        AgentReport {
            scan_id: "test".into(),
            timestamp: "2025-01-01T00:00:00Z".into(),
            version: "0.4.3".into(),
            duration_secs: 1.0,
            risk_score: 0,
            is_root_execution: true,
            scan_warnings: Vec::new(),
            host: HostInfo::default(),
            databases: vec![],
            network: NetworkInfo::default(),
            storage: StorageInfo::default(),
            topology: TopologyInfo::default(),
            security: SecurityInfo::default(),
            packages: PackagesInfo::default(),
        }
    }

    #[test]
    fn detect_firewall_disabled() {
        let mut before = test_report();
        before.network.firewall_active = true;

        let mut after = test_report();
        after.network.firewall_active = false;

        let diff = compare_reports(&before, &after);
        let change = diff
            .changes
            .iter()
            .find(|c| c.field == "network.firewall_active")
            .expect("Firewall change not detected");

        assert_eq!(change.before.as_deref(), Some("true"));
        assert_eq!(change.after.as_deref(), Some("false"));
        assert_eq!(change.severity, Severity::Degraded);
    }

    #[test]
    fn detect_risk_score_increase() {
        let mut before = test_report();
        before.risk_score = 20;

        let mut after = test_report();
        after.risk_score = 50;

        let diff = compare_reports(&before, &after);
        let change = diff
            .changes
            .iter()
            .find(|c| c.field == "risk_score")
            .expect("Risk score change not detected");

        assert_eq!(change.before.as_deref(), Some("20"));
        assert_eq!(change.after.as_deref(), Some("50"));
        assert_eq!(change.severity, Severity::Degraded);
    }

    #[test]
    fn detect_ssh_root_login_enabled() {
        let mut before = test_report();
        before.security.ssh_root_login_enabled = false;

        let mut after = test_report();
        after.security.ssh_root_login_enabled = true;

        let diff = compare_reports(&before, &after);
        let change = diff
            .changes
            .iter()
            .find(|c| c.field == "security.ssh_root_login_enabled")
            .expect("SSH root login change not detected");

        assert_eq!(change.before.as_deref(), Some("false"));
        assert_eq!(change.after.as_deref(), Some("true"));
        assert_eq!(change.severity, Severity::Degraded);
    }

    #[test]
    fn no_changes_returns_empty() {
        let before = test_report();
        let after = test_report();
        let diff = compare_reports(&before, &after);
        assert!(diff.changes.is_empty(), "Expected no changes");
    }
}
