use crate::models::{
    AgentReport, Change, DiffReport, HostDiffStatus, MultiHostDiff, PortInfo, Severity,
    SnapshotMeta,
};
use std::collections::{HashMap, HashSet};

fn sev_rank(s: &Severity) -> u8 {
    match s {
        Severity::Degraded => 0,
        Severity::Changed => 1,
        Severity::Improved => 2,
    }
}

/// Compare two AgentReports and produce a DiffReport
pub fn compare_reports(before: &AgentReport, after: &AgentReport) -> DiffReport {
    let mut changes = Vec::new();

    // --- risk_score ---
    if before.risk_score != after.risk_score {
        let formula_changed = before.scoring_version != after.scoring_version;
        let severity = if formula_changed {
            Severity::Changed
        } else if after.risk_score > before.risk_score {
            Severity::Degraded
        } else {
            Severity::Improved
        };
        let field_label = if formula_changed {
            format!(
                "risk_score (scoring v{}→v{}, not directly comparable)",
                before.scoring_version, after.scoring_version
            )
        } else {
            "risk_score".into()
        };
        changes.push(Change {
            field: field_label,
            before: Some(before.risk_score.to_string()),
            after: Some(after.risk_score.to_string()),
            severity,
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
            Severity::Degraded
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

    // SSL certificates – crossing critical/warning threshold + added/removed
    let before_certs: Vec<_> = before.network.ssl_certificates.iter().collect();
    let after_certs: Vec<_> = after.network.ssl_certificates.iter().collect();

    for after_cert in &after_certs {
        if let Some(before_cert) = before_certs.iter().find(|c| c.domain == after_cert.domain) {
            if before_cert.is_critical != after_cert.is_critical {
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
            if before_cert.is_warning != after_cert.is_warning {
                let sev = if after_cert.is_warning {
                    Severity::Degraded
                } else {
                    Severity::Improved
                };
                changes.push(Change {
                    field: format!("network.ssl_certificates.{}.is_warning", after_cert.domain),
                    before: Some(before_cert.is_warning.to_string()),
                    after: Some(after_cert.is_warning.to_string()),
                    severity: sev,
                });
            }
        } else {
            // New certificate
            changes.push(Change {
                field: format!("network.ssl_certificates.{}.added", after_cert.domain),
                before: None,
                after: Some(after_cert.domain.clone()),
                severity: Severity::Degraded,
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
    type PortKey<'a> = (&'a str, &'a str, &'a str);
    let before_ports: HashMap<PortKey<'_>, &PortInfo> = before
        .network
        .listening_ports
        .iter()
        .map(|p| {
            (
                (
                    p.protocol.as_str(),
                    p.bind_address.as_str(),
                    p.port.as_str(),
                ),
                p,
            )
        })
        .collect();
    let after_ports: HashMap<PortKey<'_>, &PortInfo> = after
        .network
        .listening_ports
        .iter()
        .map(|p| {
            (
                (
                    p.protocol.as_str(),
                    p.bind_address.as_str(),
                    p.port.as_str(),
                ),
                p,
            )
        })
        .collect();

    for k in after_ports.keys() {
        if !before_ports.contains_key(k) {
            changes.push(Change {
                field: "network.listening_ports".into(),
                before: None,
                after: Some(format!("{}:{}:{}", k.0, k.1, k.2)),
                severity: Severity::Degraded,
            });
        }
    }
    for k in before_ports.keys() {
        if !after_ports.contains_key(k) {
            changes.push(Change {
                field: "network.listening_ports".into(),
                before: Some(format!("{}:{}:{}", k.0, k.1, k.2)),
                after: None,
                severity: Severity::Improved,
            });
        }
    }

    // Detect process changes on unchanged ports (O(n) via HashMap lookup)
    for (k, a) in &after_ports {
        if let Some(b) = before_ports.get(k)
            && b.process != a.process
        {
            changes.push(Change {
                field: format!("network.listening_ports.{}.{}.{}.process", k.0, k.1, k.2),
                before: Some(b.process.clone()),
                after: Some(a.process.clone()),
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

    // Deterministic sort: Degraded first, then Changed, then Improved;
    // within same severity, stable order by field/before/after
    changes.sort_unstable_by(|a, b| {
        sev_rank(&a.severity)
            .cmp(&sev_rank(&b.severity))
            .then_with(|| a.field.cmp(&b.field))
            .then_with(|| a.before.cmp(&b.before))
            .then_with(|| a.after.cmp(&b.after))
    });

    DiffReport {
        before: Some(SnapshotMeta::from_report(before)),
        after: Some(SnapshotMeta::from_report(after)),
        changes,
    }
}

pub fn compare_multi(before: &[AgentReport], after: &[AgentReport]) -> Vec<MultiHostDiff> {
    let mut before_map: HashMap<&str, &AgentReport> = HashMap::with_capacity(before.len());
    for r in before {
        if before_map.insert(r.host.hostname.as_str(), r).is_some() {
            tracing::warn!(
                host = %r.host.hostname,
                "duplicate hostname in 'before' set — using the last entry"
            );
        }
    }

    let mut after_map: HashMap<&str, &AgentReport> = HashMap::with_capacity(after.len());
    for r in after {
        if after_map.insert(r.host.hostname.as_str(), r).is_some() {
            tracing::warn!(
                host = %r.host.hostname,
                "duplicate hostname in 'after' set — using the last entry"
            );
        }
    }

    let mut hostnames: Vec<&str> = before_map.keys().chain(after_map.keys()).copied().collect();
    hostnames.sort_unstable();
    hostnames.dedup();

    let mut diffs = Vec::new();
    for hostname in hostnames {
        match (before_map.get(hostname), after_map.get(hostname)) {
            (Some(b), Some(a)) => diffs.push(MultiHostDiff {
                hostname: hostname.to_string(),
                status: HostDiffStatus::Compared,
                diff: compare_reports(b, a),
            }),
            (Some(b), None) => diffs.push(MultiHostDiff {
                hostname: hostname.to_string(),
                status: HostDiffStatus::Removed,
                diff: DiffReport {
                    before: Some(SnapshotMeta::from_report(b)),
                    after: None,
                    changes: vec![Change {
                        field: "host.removed".into(),
                        before: Some(hostname.to_string()),
                        after: None,
                        severity: Severity::Degraded,
                    }],
                },
            }),
            (None, Some(a)) => diffs.push(MultiHostDiff {
                hostname: hostname.to_string(),
                status: HostDiffStatus::Added,
                diff: DiffReport {
                    before: None,
                    after: Some(SnapshotMeta::from_report(a)),
                    changes: vec![Change {
                        field: "host.added".into(),
                        before: None,
                        after: Some(format!("{} (risk {})", hostname, a.risk_score)),
                        severity: Severity::Changed,
                    }],
                },
            }),
            (None, None) => unreachable!(),
        }
    }
    diffs
}

// ── Terminal helpers ─────────────────────────────────────────────────────

fn fmt_ts(raw: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(raw)
        .map(|dt| {
            dt.with_timezone(&chrono::Utc)
                .format("%Y-%m-%d %H:%M UTC")
                .to_string()
        })
        .unwrap_or_else(|_| raw.to_string())
}

fn human_span(before: &str, after: &str) -> Option<(String, bool)> {
    let b = chrono::DateTime::parse_from_rfc3339(before).ok()?;
    let a = chrono::DateTime::parse_from_rfc3339(after).ok()?;
    let secs = (a - b).num_seconds();
    let neg = secs < 0;
    let s = secs.unsigned_abs();
    let (d, h, m) = (s / 86400, s % 86400 / 3600, s % 3600 / 60);
    let text = if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    };
    Some((text, neg))
}

/// Terminal output with colored table (using comfy_table)
pub fn print_diff_terminal(report: &DiffReport) {
    // Metadata header
    if let (Some(b), Some(a)) = (&report.before, &report.after) {
        println!("  host:    {}", b.hostname);
        println!(
            "  before: {}  (v{}, risk {})",
            fmt_ts(&b.timestamp),
            b.version,
            b.risk_score
        );
        println!(
            "  after:  {}  (v{}, risk {})",
            fmt_ts(&a.timestamp),
            a.version,
            a.risk_score
        );
        match human_span(&b.timestamp, &a.timestamp) {
            Some((_, true)) => println!(
                "  \x1b[1;33m[!] 'after' is OLDER than 'before' — arguments swapped?\x1b[0m"
            ),
            Some((span, false)) => println!("  span:   {span}"),
            None => {}
        }
        if b.hostname != a.hostname {
            println!(
                "  \x1b[1;33m[!] comparing different hosts: {} vs {}\x1b[0m",
                b.hostname, a.hostname
            );
        }
    }

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
            scoring_version: 1,
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
