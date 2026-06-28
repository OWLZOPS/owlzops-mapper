use crate::models::{AgentReport, Change, DiffReport, Severity};
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
    changes.sort_unstable_by_key(|c| match c.severity {
        Severity::Degraded => 0,
        Severity::Changed => 1,
        Severity::Improved => 2,
    });

    // --- network.listening_ports (key: bind_address:port) ---
    // port is a String in the model, so we keep it as String
    let before_ports: HashSet<(String, String)> = before
        .network
        .listening_ports
        .iter()
        .map(|p| (p.bind_address.clone(), p.port.clone()))
        .collect();
    let after_ports: HashSet<(String, String)> = after
        .network
        .listening_ports
        .iter()
        .map(|p| (p.bind_address.clone(), p.port.clone()))
        .collect();

    for added in after_ports.difference(&before_ports) {
        changes.push(Change {
            field: "network.listening_ports".into(),
            before: None,
            after: Some(format!("{}:{}", added.0, added.1)),
            severity: Severity::Degraded,
        });
    }
    for removed in before_ports.difference(&after_ports) {
        changes.push(Change {
            field: "network.listening_ports".into(),
            before: Some(format!("{}:{}", removed.0, removed.1)),
            after: None,
            severity: Severity::Improved,
        });
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
    // authorized_keys_count is usize, we store as u64 for comparison
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

    DiffReport { changes }
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
