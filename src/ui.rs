//! Terminal dashboard renderer.
//!
//! All strings originating from an audited host pass through
//! [`sanitize_terminal`] before being printed, mitigating
//! terminal escape sequence injection (C0/C1 control characters
//! beyond `\t` are replaced with U+FFFD).

use std::collections::HashMap;

use crate::models::{AgentReport, PackageManager};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, Color, Table};

// ---------------------------------------------------------------------------
// Sanitisation helper
// ---------------------------------------------------------------------------

/// Replace control characters (except `\t`) with the Unicode
/// replacement character so that attacker-controlled strings
/// cannot inject ANSI escape sequences into the terminal.
pub fn sanitize_terminal(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() && c != '\t' {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

/// Common patterns that indicate a suspicious cron job
/// (executables from writable locations, hidden directories, etc.).
const SUSPICIOUS_CRON_PATTERNS: &[&str] = &[
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/home/",
    "curl",
    "wget",
    "base64 -d",
    "sh -c",
    "bash -c",
];

fn is_suspicious_cron(line: &str) -> bool {
    let lower = line.to_lowercase();
    SUSPICIOUS_CRON_PATTERNS.iter().any(|p| lower.contains(p))
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

pub fn render_dashboard(report: &AgentReport) {
    render_header(report);
    render_system_overview(report);
    render_top_memory(report);
    render_databases(report);
    render_security_health(report);
    render_storage(report);
    render_network_listeners(report);
    render_ssl_certificates(report);
    render_shell_users(report);
    render_system_internals(report);
    render_packages(report);
    render_docker(report);
    render_capability_audit(report);

    if !report.coverage_warnings.is_empty() {
        println!("\n⚠ Coverage Warnings (incomplete data):");
        for w in &report.coverage_warnings {
            println!("   - {}", sanitize_terminal(w));
        }
    }

    render_footer();
}

pub fn render_multi_host_summary(reports: &[AgentReport]) {
    if reports.is_empty() {
        println!("No reports to display.");
        return;
    }

    let mut t = Table::new();
    t.load_preset(UTF8_FULL).apply_modifier(UTF8_ROUND_CORNERS);
    t.set_header(vec![
        Cell::new("Host")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Risk Score").add_attribute(Attribute::Bold),
        Cell::new("Firewall").add_attribute(Attribute::Bold),
        Cell::new("SSH Root").add_attribute(Attribute::Bold),
        Cell::new("Security Updates").add_attribute(Attribute::Bold),
    ]);

    for r in reports {
        let score_cell = if r.risk_score >= 70 {
            Cell::new(r.risk_score.to_string()).fg(Color::Red)
        } else if r.risk_score >= 40 {
            Cell::new(r.risk_score.to_string()).fg(Color::Yellow)
        } else {
            Cell::new(r.risk_score.to_string()).fg(Color::Green)
        };

        t.add_row(vec![
            Cell::new(sanitize_terminal(&r.host.hostname)),
            score_cell,
            Cell::new(if r.network.firewall_active {
                "on"
            } else {
                "OFF"
            }),
            Cell::new(if r.security.ssh_root_login_enabled {
                "OPEN"
            } else {
                "disabled"
            }),
            Cell::new(if r.packages.upgradable.iter().any(|p| p.is_security) {
                "YES"
            } else {
                "no"
            }),
        ]);
    }

    println!("🦉 Owlzops Multi‑Host Audit Summary\n");
    println!("{t}\n");
}

// ---------------------------------------------------------------------------
// Private render helpers
// ---------------------------------------------------------------------------

fn render_header(report: &AgentReport) {
    use std::io::IsTerminal;
    let is_tty = std::io::stdout().is_terminal();

    let (icon_owl, icon_spy, icon_shield, color_reset) = if is_tty {
        ("\u{1F989}  ", "\u{1F50D}  ", "\u{1F512}  ", "\x1b[0m")
    } else {
        ("", "", "", "")
    };

    // ---------- Risk Score with visual penalty notation ----------
    let risk_label = if report.risk_score < 40 {
        "Healthy"
    } else if report.risk_score < 70 {
        "At Risk"
    } else {
        "Critical"
    };

    let risk_color = if is_tty {
        if report.risk_score >= 70 {
            "\x1b[1;31m"
        } else if report.risk_score >= 40 {
            "\x1b[1;33m"
        } else {
            "\x1b[1;32m"
        }
    } else {
        ""
    };

    println!("{}Owlzops Mapper v{}", icon_owl, report.version);
    println!("{}Scan completed in {:.2}s", icon_spy, report.duration_secs);
    println!(
        "{}Risk Score: {}{}/100{}  ({}) \n",
        icon_shield, risk_color, report.risk_score, color_reset, risk_label
    );

    let scored = crate::scoring::score(crate::scoring::evaluate(report));
    println!(
        "  Security −{}  Reliability −{}  Hygiene −{}",
        scored.security, scored.reliability, scored.hygiene
    );

    let active_findings: Vec<&crate::scoring::Finding> = scored
        .findings
        .iter()
        .filter(|f| f.suppressed.is_none())
        .collect();

    if !active_findings.is_empty() {
        println!("Breakdown:");
        for f in &active_findings {
            let cis_note = if let Some(cis) = f.cis_ref {
                format!(" [{}]", cis)
            } else {
                String::new()
            };
            println!("  • {} (+{}){}", f.title, f.weight, cis_note);
            if !f.evidence.is_empty() {
                println!("    └─ {}", sanitize_terminal(&f.evidence));
            }
        }
    }

    if !report.is_root_execution {
        println!(
            "\x1b[1;31m[!] WARNING: Script not run as root. Data is incomplete. Please use `sudo`.\x1b[0m\n"
        );
    }

    if report.host.reboot_required {
        let pkgs = &report.host.reboot_required_pkgs;
        let suffix = if pkgs.is_empty() {
            String::new()
        } else {
            let first: Vec<_> = pkgs.iter().take(5).map(|s| sanitize_terminal(s)).collect();
            let more = if pkgs.len() > 5 {
                format!(", +{}", pkgs.len() - 5)
            } else {
                String::new()
            };
            format!(" ({}{})", first.join(", "), more)
        };
        println!(
            "\x1b[1;41;37m[CRITICAL] SYSTEM REBOOT REQUIRED{}\x1b[0m\n",
            suffix
        );
    }

    if !report.scan_warnings.is_empty() {
        println!(
            "\x1b[1;31m[!] Scan incomplete — {} scanner(s) failed. Report may be unreliable.\x1b[0m\n",
            report.scan_warnings.len()
        );
    }
}

fn render_system_overview(report: &AgentReport) {
    let mut t_sys = Table::new();
    t_sys
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS);
    t_sys.set_header(vec![
        Cell::new("System Overview")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Details").add_attribute(Attribute::Bold),
    ]);
    t_sys.add_row(vec![
        "Hostname",
        sanitize_terminal(&report.host.hostname).as_str(),
    ]);
    t_sys.add_row(vec![
        "Provider",
        sanitize_terminal(&report.host.hosting_provider).as_str(),
    ]);
    t_sys.add_row(vec![
        "External IP",
        sanitize_terminal(&report.host.external_ipv4).as_str(),
    ]);
    t_sys.add_row(vec![
        "OS & Kernel",
        &format!(
            "{} ({})",
            sanitize_terminal(&report.host.os_version),
            sanitize_terminal(&report.host.kernel)
        ),
    ]);
    t_sys.add_row(vec!["Uptime", &format!("{} days", report.host.uptime_days)]);
    t_sys.add_row(vec!["CPU Cores", &report.host.cpu_cores.to_string()]);
    t_sys.add_row(vec![
        "RAM (Total/Swap)",
        &format!(
            "{:.2} GB / {:.2} GB",
            report.host.total_ram_mb as f64 / 1024.0,
            report.host.swap_total_mb as f64 / 1024.0
        ),
    ]);
    t_sys.add_row(vec![
        "Load Average",
        &format!(
            "{:.2}, {:.2}, {:.2}",
            report.host.load_average.0, report.host.load_average.1, report.host.load_average.2
        ),
    ]);

    let tech_stack_str = if report.host.tech_stack.is_empty() {
        "None detected".to_string()
    } else {
        report
            .host
            .tech_stack
            .iter()
            .map(|s| sanitize_terminal(s))
            .collect::<Vec<_>>()
            .join(", ")
    };
    t_sys.add_row(vec![
        Cell::new("Detected Tech Stack").fg(Color::Yellow),
        Cell::new(tech_stack_str),
    ]);

    let dns_str = if report.network.dns_resolvers.is_empty() {
        "Unknown".to_string()
    } else {
        report
            .network
            .dns_resolvers
            .iter()
            .map(|s| sanitize_terminal(s))
            .collect::<Vec<_>>()
            .join(", ")
    };

    let dns_cell = if !report.network.dns_upstreams.is_empty() {
        let upstreams = report
            .network
            .dns_upstreams
            .iter()
            .map(|s| sanitize_terminal(s))
            .collect::<Vec<_>>()
            .join(", ");
        Cell::new(format!("{}  →  {}", dns_str, sanitize_terminal(&upstreams)))
    } else {
        Cell::new(dns_str)
    };
    t_sys.add_row(vec![Cell::new("DNS Resolvers"), dns_cell]);

    let sec_mod_str = if report.host.security_modules.is_empty() {
        "None".to_string()
    } else {
        report
            .host
            .security_modules
            .iter()
            .map(|s| sanitize_terminal(s))
            .collect::<Vec<_>>()
            .join(", ")
    };
    t_sys.add_row(vec![
        Cell::new("Security Modules (LSM)"),
        Cell::new(sec_mod_str),
    ]);

    println!("{t_sys}\n");
}

fn render_top_memory(report: &AgentReport) {
    if report.host.top_memory_processes.is_empty() {
        return;
    }
    let mut t_mem = Table::new();
    t_mem
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS);
    t_mem.set_header(vec![
        Cell::new("Top 5 Memory Consumers")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("PID").add_attribute(Attribute::Bold),
        Cell::new("RAM (MB)").add_attribute(Attribute::Bold),
    ]);
    for proc in &report.host.top_memory_processes {
        let mut mem_cell = Cell::new(proc.memory_mb.to_string());
        if proc.memory_mb > 1024 {
            mem_cell = mem_cell.fg(Color::Yellow);
        }
        let name = if proc.instances > 1 {
            format!(
                "{} (×{} workers)",
                sanitize_terminal(&proc.name),
                proc.instances
            )
        } else {
            sanitize_terminal(&proc.name)
        };
        t_mem.add_row(vec![
            Cell::new(name),
            Cell::new(proc.pid.to_string()),
            mem_cell,
        ]);
    }
    println!("{t_mem}\n");
}

fn render_databases(report: &AgentReport) {
    if report.databases.is_empty() {
        return;
    }
    let mut t_dbs = Table::new();
    t_dbs
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS);
    t_dbs.set_header(vec![
        Cell::new("Host Databases")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Version").add_attribute(Attribute::Bold),
        Cell::new("Data Directory").add_attribute(Attribute::Bold),
        Cell::new("Size (GB)").add_attribute(Attribute::Bold),
    ]);
    for db in &report.databases {
        let db_size_gb = db.size_mb as f64 / 1024.0;
        t_dbs.add_row(vec![
            sanitize_terminal(&db.engine).as_str(),
            sanitize_terminal(&db.version).as_str(),
            sanitize_terminal(&db.data_dir).as_str(),
            &format!("{:.2}", db_size_gb),
        ]);
    }
    println!("{t_dbs}\n");
}

fn render_security_health(report: &AgentReport) {
    let scored = crate::scoring::score(crate::scoring::evaluate(report));
    let suppressed_evidence: std::collections::HashSet<&str> = scored
        .findings
        .iter()
        .filter(|f| f.suppressed.is_some())
        .map(|f| f.evidence.as_str())
        .collect();

    let mut t_risk = Table::new();
    t_risk
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS);
    t_risk.set_header(vec![
        Cell::new("Security & Health Checks")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Status").add_attribute(Attribute::Bold),
    ]);

    let fw_cell = if report.network.firewall_active {
        Cell::new("Enabled").fg(Color::Green)
    } else {
        Cell::new("Disabled (CRITICAL)")
            .fg(Color::Red)
            .add_attribute(Attribute::Bold)
    };
    t_risk.add_row(vec![Cell::new("Host Firewall"), fw_cell]);

    let root_cell = if report.security.ssh_root_login_enabled {
        Cell::new("Permitted (HIGH RISK)")
            .fg(Color::Red)
            .add_attribute(Attribute::Bold)
    } else {
        Cell::new("Disabled").fg(Color::Green)
    };
    t_risk.add_row(vec![Cell::new("SSH Root Login"), root_cell]);

    t_risk.add_row(vec![
        Cell::new("SSH Config Source"),
        Cell::new(sanitize_terminal(&report.security.ssh_config_source)),
    ]);

    let f2b = if report.security.fail2ban_active {
        Cell::new("Active").fg(Color::Green)
    } else {
        Cell::new("Inactive").fg(Color::Red)
    };
    t_risk.add_row(vec![Cell::new("Fail2Ban"), f2b]);

    let audit = if report.security.auditd_active {
        Cell::new("Active").fg(Color::Green)
    } else {
        Cell::new("Inactive").fg(Color::Red)
    };
    t_risk.add_row(vec![Cell::new("Auditd"), audit]);

    let ntp_cell = match (report.host.ntp_synchronized, report.host.time_offset_ms) {
        (true, Some(ms)) if ms > 100.0 => {
            Cell::new(format!("Synced ({:.1}ms — high offset)", ms)).fg(Color::Yellow)
        }
        (true, Some(ms)) => Cell::new(format!("Synced ({:.1}ms)", ms)).fg(Color::Green),
        (true, None) => Cell::new("Synced").fg(Color::Green),
        (false, Some(ms)) if ms > 1000.0 => {
            Cell::new(format!("NOT SYNCED ({:.0}ms — CRITICAL)", ms))
                .fg(Color::Red)
                .add_attribute(Attribute::Bold)
        }
        (false, Some(ms)) => Cell::new(format!("NOT SYNCED ({:.1}ms)", ms)).fg(Color::Red),
        (false, None) => Cell::new("NOT SYNCED")
            .fg(Color::Red)
            .add_attribute(Attribute::Bold),
    };
    t_risk.add_row(vec![Cell::new("NTP / Time Sync"), ntp_cell]);

    if !report.security.sudo_nopasswd_entries.is_empty() {
        t_risk.add_row(vec![
            Cell::new("Sudo NOPASSWD"),
            Cell::new(format!(
                "{} entries",
                report.security.sudo_nopasswd_entries.len()
            ))
            .fg(Color::Red)
            .add_attribute(Attribute::Bold),
        ]);
    }
    if let Some(mode) = report.security.sudoers_mode {
        let sudo_perm = if mode != 0o440 {
            Cell::new(format!("{:o} (expected 0440)", mode))
                .fg(Color::Red)
                .add_attribute(Attribute::Bold)
        } else {
            Cell::new(format!("{:o}", mode)).fg(Color::Green)
        };
        t_risk.add_row(vec![Cell::new("Sudoers Permissions"), sudo_perm]);
    }

    let visible_sysctl: Vec<&str> = report
        .security
        .sysctl_issues
        .iter()
        .filter(|issue| !suppressed_evidence.contains(issue.as_str()))
        .map(|s| s.as_str())
        .collect();
    if !visible_sysctl.is_empty() {
        t_risk.add_row(vec![
            Cell::new("Sysctl Issues"),
            Cell::new(
                visible_sysctl
                    .iter()
                    .map(|s| sanitize_terminal(s))
                    .collect::<Vec<_>>()
                    .join("; "),
            )
            .fg(Color::Red)
            .add_attribute(Attribute::Bold),
        ]);
    }

    let oom_cell = if report.host.oom_kills > 0 {
        Cell::new(format!("{} Kills (HIGH RISK)", report.host.oom_kills)).fg(Color::Red)
    } else {
        Cell::new("0").fg(Color::Green)
    };
    t_risk.add_row(vec![Cell::new("OOM Kills (Memory)"), oom_cell]);

    // Zombie processes with parent grouping
    let zombie_cell = if report.host.zombie_processes > 0 {
        let details = &report.host.zombie_details;
        if details.is_empty() {
            Cell::new(format!("{} (WARNING)", report.host.zombie_processes)).fg(Color::Yellow)
        } else {
            // Group by parent
            let mut parent_counts: HashMap<(&str, u32), usize> = HashMap::new();
            for z in details {
                let key = (z.parent_name.as_str(), z.ppid);
                *parent_counts.entry(key).or_insert(0) += 1;
            }
            let mut parents: Vec<_> = parent_counts.into_iter().collect();
            parents.sort_by_key(|b| std::cmp::Reverse(b.1)); // most zombies first
            let parts: Vec<_> = parents
                .iter()
                .take(3)
                .map(|((name, ppid), count)| {
                    if *count > 1 {
                        format!("{}[{}] ×{}", sanitize_terminal(name), ppid, count)
                    } else {
                        format!("{}[{}]", sanitize_terminal(name), ppid)
                    }
                })
                .collect();
            let more = if parents.len() > 3 {
                format!(", +{} more", parents.len() - 3)
            } else {
                String::new()
            };
            Cell::new(format!(
                "{} (WARNING: unreaped by: {}{})",
                report.host.zombie_processes,
                parts.join(", "),
                more
            ))
            .fg(Color::Yellow)
        }
    } else {
        Cell::new("0").fg(Color::Green)
    };
    t_risk.add_row(vec![Cell::new("Zombie Processes"), zombie_cell]);

    let backup_status = if report.host.backup_tools.is_empty() {
        Cell::new("None (CRITICAL)")
            .fg(Color::Red)
            .add_attribute(Attribute::Bold)
    } else {
        Cell::new(
            report
                .host
                .backup_tools
                .iter()
                .map(|t| sanitize_terminal(t))
                .collect::<Vec<_>>()
                .join(", "),
        )
        .fg(Color::Green)
    };
    t_risk.add_row(vec![Cell::new("Backup Tools"), backup_status]);

    if !report.host.failed_services.is_empty() {
        t_risk.add_row(vec![
            Cell::new("Failed Services"),
            Cell::new(
                report
                    .host
                    .failed_services
                    .iter()
                    .map(|s| sanitize_terminal(s))
                    .collect::<Vec<_>>()
                    .join(", "),
            )
            .fg(Color::Red),
        ]);
    }

    println!("{t_risk}\n");
    if !report.host.dmesg_errors.is_empty() {
        println!("\x1b[1;31m[!] Critical Kernel Logs (dmesg):\x1b[0m");
        for err in &report.host.dmesg_errors {
            println!("    {}", sanitize_terminal(err));
        }
        println!();
    }
}

fn render_storage(report: &AgentReport) {
    let mut t_store = Table::new();
    t_store
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS);
    t_store.set_header(vec![
        Cell::new("Mount")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Total (GB)").add_attribute(Attribute::Bold),
        Cell::new("Used (GB)").add_attribute(Attribute::Bold),
        Cell::new("Usage %").add_attribute(Attribute::Bold),
        Cell::new("Inodes %").add_attribute(Attribute::Bold),
    ]);
    for disk in &report.storage.disks {
        if disk.total_mb == 0 {
            continue;
        }
        let size_gb = disk.total_mb as f64 / 1024.0;
        let used_gb = disk.used_mb as f64 / 1024.0;
        let mut usage_cell = Cell::new(format!("{:.1}%", disk.usage_pct));
        if disk.usage_pct > 90.0 {
            usage_cell = usage_cell.fg(Color::Red).add_attribute(Attribute::Bold);
        } else if disk.usage_pct > 75.0 {
            usage_cell = usage_cell.fg(Color::Yellow);
        }
        let inode_val = disk
            .inode_usage_percent
            .clone()
            .unwrap_or_else(|| "-".to_string());
        t_store.add_row(vec![
            Cell::new(sanitize_terminal(&disk.mount_point)),
            Cell::new(format!("{:.2}", size_gb)),
            Cell::new(format!("{:.2}", used_gb)),
            usage_cell,
            Cell::new(sanitize_terminal(&inode_val)),
        ]);
    }
    println!("{t_store}\n");
}

fn render_network_listeners(report: &AgentReport) {
    if report.network.listening_ports.is_empty() {
        return;
    }
    let mut t_ports = Table::new();
    t_ports
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS);
    t_ports.set_header(vec![
        Cell::new("Proto")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Bind Address").add_attribute(Attribute::Bold),
        Cell::new("Port").add_attribute(Attribute::Bold),
        Cell::new("Process").add_attribute(Attribute::Bold),
    ]);
    for p in &report.network.listening_ports {
        if p.port == "0" || p.port == "*" {
            continue;
        }
        let exposed = p.bind_address == "0.0.0.0" || p.bind_address == "::";
        let mut addr_cell = Cell::new(sanitize_terminal(&p.bind_address));
        let mut port_cell = Cell::new(&p.port);
        let mut proto_cell = Cell::new(&p.protocol);
        let mut proc_cell = Cell::new(sanitize_terminal(&p.process));
        if exposed {
            addr_cell = addr_cell.fg(Color::Red);
            port_cell = port_cell.fg(Color::Red);
            proto_cell = proto_cell.fg(Color::Red);
            proc_cell = proc_cell.fg(Color::Red);
        }
        t_ports.add_row(vec![proto_cell, addr_cell, port_cell, proc_cell]);
    }
    println!("Active Network Listeners (red = exposed on 0.0.0.0/::):");
    println!("{t_ports}\n");
}

fn render_ssl_certificates(report: &AgentReport) {
    if report.network.ssl_certificates.is_empty() {
        return;
    }
    let mut t_ssl = Table::new();
    t_ssl
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS);
    t_ssl.set_header(vec![
        Cell::new("Domain")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Expires").add_attribute(Attribute::Bold),
        Cell::new("Days Left").add_attribute(Attribute::Bold),
    ]);
    for cert in &report.network.ssl_certificates {
        let days_cell = match cert.days_remaining {
            Some(d) if cert.is_critical => Cell::new(format!("{} (CRITICAL)", d))
                .fg(Color::Red)
                .add_attribute(Attribute::Bold),
            Some(d) if cert.is_warning => Cell::new(format!("{} (WARNING)", d)).fg(Color::Yellow),
            Some(d) if d < 0 => Cell::new(format!("Expired {} days ago", -d))
                .fg(Color::Red)
                .add_attribute(Attribute::Bold),
            Some(d) => Cell::new(d.to_string()).fg(Color::Green),
            None => Cell::new("unknown").fg(Color::DarkGrey),
        };
        t_ssl.add_row(vec![
            Cell::new(sanitize_terminal(&cert.domain)),
            Cell::new(sanitize_terminal(&cert.expiry_date)),
            days_cell,
        ]);
    }
    println!("SSL Certificates (Let's Encrypt):");
    println!("{t_ssl}\n");
}

fn render_shell_users(report: &AgentReport) {
    if report.security.shell_users.is_empty() {
        return;
    }
    let mut t_users = Table::new();
    t_users
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS);
    t_users.set_header(vec![
        Cell::new("User")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Last Login").add_attribute(Attribute::Bold),
        Cell::new("Last Remote SSH").add_attribute(Attribute::Bold),
        Cell::new("SSH Keys").add_attribute(Attribute::Bold),
    ]);
    for u in &report.security.shell_users {
        let mut keys_cell = Cell::new(u.authorized_keys_count.to_string());
        if u.authorized_keys_count > 0 {
            keys_cell = keys_cell.fg(Color::Yellow);
        }
        t_users.add_row(vec![
            Cell::new(sanitize_terminal(&u.username)),
            Cell::new(sanitize_terminal(&u.last_login)),
            Cell::new(sanitize_terminal(&u.last_ssh_login)),
            keys_cell,
        ]);
    }
    println!("Shell Users & SSH Access:");
    println!("{t_users}\n");
}

fn render_system_internals(report: &AgentReport) {
    let mut t_internals = Table::new();
    t_internals
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS);
    t_internals.set_header(vec![
        Cell::new("System Internals")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Count").add_attribute(Attribute::Bold),
    ]);
    t_internals.add_row(vec![
        "System & Custom Cronjobs",
        &report.host.cron_jobs.len().to_string(),
    ]);
    t_internals.add_row(vec![
        "Systemd Timers",
        &report.host.systemd_timers.len().to_string(),
    ]);
    t_internals.add_row(vec![
        "Custom /etc/hosts overrides",
        &report.network.custom_host_overrides.len().to_string(),
    ]);
    println!("{t_internals}\n");

    if !report.network.custom_host_overrides.is_empty() {
        println!("\x1b[1;33m[!] Found Custom /etc/hosts Overrides:\x1b[0m");
        for host in &report.network.custom_host_overrides {
            println!("    - {}", sanitize_terminal(host));
        }
        println!();
    }
    if !report.host.cron_jobs.is_empty() {
        println!("System & Custom Cronjobs:");
        for cron in &report.host.cron_jobs {
            let safe_cron = sanitize_terminal(cron);
            if is_suspicious_cron(&safe_cron) {
                println!("\x1b[1;31m[!]  {}\x1b[0m", safe_cron);
            } else {
                println!("    - {}", safe_cron);
            }
        }
        println!();
    }
}

fn render_packages(report: &AgentReport) {
    if !report.packages.manager.is_known() {
        return;
    }
    let manager_str = match report.packages.manager {
        PackageManager::Apt => "apt (Debian/Ubuntu)",
        PackageManager::Dnf => "dnf (Fedora/RHEL)",
        PackageManager::Yum => "yum (RHEL/CentOS)",
        PackageManager::Pacman => "pacman (Arch)",
        PackageManager::Zypper => "zypper (openSUSE/SLES)",
        PackageManager::Unknown => "Unknown",
    };
    let mut t_pkg = Table::new();
    t_pkg
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS);
    t_pkg.set_header(vec![
        Cell::new("Packages")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Value").add_attribute(Attribute::Bold),
    ]);
    t_pkg.add_row(vec!["Package Manager", manager_str]);
    t_pkg.add_row(vec![
        "Installed Packages",
        &report.packages.installed_count.to_string(),
    ]);

    let security_count = report
        .packages
        .upgradable
        .iter()
        .filter(|p| p.is_security)
        .count();
    let mut upgradable_cell = Cell::new(report.packages.upgradable.len().to_string());
    if security_count > 0 {
        upgradable_cell = upgradable_cell
            .fg(Color::Red)
            .add_attribute(Attribute::Bold);
    } else if !report.packages.upgradable.is_empty() {
        upgradable_cell = upgradable_cell.fg(Color::Yellow);
    }
    t_pkg.add_row(vec![Cell::new("Upgradable Packages"), upgradable_cell]);
    if security_count > 0 {
        t_pkg.add_row(vec![
            Cell::new("  ...of which Security"),
            Cell::new(security_count.to_string())
                .fg(Color::Red)
                .add_attribute(Attribute::Bold),
        ]);
    }
    let cache_str = if report.packages.cache_refreshed {
        "Yes (just refreshed)"
    } else {
        "No (may be stale — use --refresh-packages)"
    };
    t_pkg.add_row(vec![
        Cell::new("Cache Freshly Refreshed"),
        Cell::new(cache_str),
    ]);
    println!("{t_pkg}\n");

    if !report.packages.upgradable.is_empty() {
        let mut t_upg = Table::new();
        t_upg
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS);
        t_upg.set_header(vec![
            Cell::new("Package")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
            Cell::new("Current").add_attribute(Attribute::Bold),
            Cell::new("Available").add_attribute(Attribute::Bold),
            Cell::new("Security").add_attribute(Attribute::Bold),
        ]);
        let mut sorted_upgradable: Vec<_> = report.packages.upgradable.iter().collect();
        sorted_upgradable.sort_by_key(|b| std::cmp::Reverse(b.is_security));
        for pkg in sorted_upgradable.iter().take(20) {
            let sec_cell = if pkg.is_security {
                Cell::new("YES")
                    .fg(Color::Red)
                    .add_attribute(Attribute::Bold)
            } else {
                Cell::new("-")
            };
            t_upg.add_row(vec![
                Cell::new(sanitize_terminal(&pkg.name)),
                Cell::new(sanitize_terminal(&pkg.current_version)),
                Cell::new(sanitize_terminal(&pkg.new_version)),
                sec_cell,
            ]);
        }
        println!("Upgradable Packages (top 20):");
        println!("{t_upg}\n");
        if report.packages.upgradable.len() > 20 {
            println!(
                "    ... and {} more (see --format json for the full list)\n",
                report.packages.upgradable.len() - 20
            );
        }
    }
}

/// Truncate each Docker mount string to at most `max_width` characters,
/// appending "..." if truncated. Keeps the beginning of the path intact.
fn truncate_docker_mounts(mounts: &[String], max_width: usize) -> String {
    mounts
        .iter()
        .map(|m| {
            let safe = sanitize_terminal(m);
            if safe.len() > max_width {
                let trunc_len = max_width.saturating_sub(3);
                let truncated: String = safe.chars().take(trunc_len).collect();
                format!("{}...", truncated)
            } else {
                safe
            }
        })
        .collect::<Vec<String>>()
        .join("\n")
}

fn render_docker(report: &AgentReport) {
    if !report.topology.docker_active {
        return;
    }
    let total_img_gb = report.topology.total_images_size_mb as f64 / 1024.0;
    let reclaimable_gb = report.topology.images_reclaimable_mb as f64 / 1024.0;
    let build_cache_gb = report.topology.build_cache_reclaimable_mb as f64 / 1024.0;

    let mut t_dock_sum = Table::new();
    t_dock_sum
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS);
    t_dock_sum.set_header(vec![
        Cell::new("Docker Storage Summary")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Value").add_attribute(Attribute::Bold),
    ]);
    t_dock_sum.add_row(vec![
        "Total Images",
        &report.topology.images_count.to_string(),
    ]);
    t_dock_sum.add_row(vec![
        "Real Disk Size (Images)",
        &format!("{:.2} GB", total_img_gb),
    ]);

    if reclaimable_gb > 0.0 || build_cache_gb > 0.0 {
        t_dock_sum.add_row(vec![
            "Reclaimable Space (Prune)",
            &format!("{:.2} GB", reclaimable_gb),
        ]);
        t_dock_sum.add_row(vec![
            "Build Cache Reclaimable",
            &format!("{:.2} GB", build_cache_gb),
        ]);
    } else {
        // Fallback to dangling count for systems without system_df support
        let dang_img_gb = report.topology.total_dangling_size_mb as f64 / 1024.0;
        let mut dang_count_cell = Cell::new(report.topology.dangling_images_count.to_string());
        let mut dang_size_cell = Cell::new(format!("{:.2} GB", dang_img_gb));
        if report.topology.dangling_images_count > 0 {
            dang_count_cell = dang_count_cell
                .fg(Color::Yellow)
                .add_attribute(Attribute::Bold);
            if dang_img_gb > 5.0 {
                dang_size_cell = dang_size_cell.fg(Color::Red).add_attribute(Attribute::Bold);
            } else {
                dang_size_cell = dang_size_cell
                    .fg(Color::Yellow)
                    .add_attribute(Attribute::Bold);
            }
        }
        t_dock_sum.add_row(vec![Cell::new("Dangling (Unused) Images"), dang_count_cell]);
        t_dock_sum.add_row(vec![Cell::new("Dangling Wasted Space"), dang_size_cell]);
    }

    t_dock_sum.add_row(vec![
        "Dangling Volumes",
        &report.topology.dangling_volumes_count.to_string(),
    ]);
    println!("Docker Images & Volumes:");
    println!("{t_dock_sum}\n");

    // Dangling images list remains unchanged
    if !report.topology.dangling_images.is_empty() {
        let mut t_dang = Table::new();
        t_dang
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS);
        t_dang.set_header(vec![
            Cell::new("Dangling Image ID")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
            Cell::new("Virtual Size (GB)").add_attribute(Attribute::Bold),
        ]);
        for d in &report.topology.dangling_images {
            let d_size_gb = d.size_mb as f64 / 1024.0;
            let mut size_cell = Cell::new(format!("{:.2}", d_size_gb));
            if d_size_gb > 1.0 {
                size_cell = size_cell.fg(Color::Yellow);
            }
            t_dang.add_row(vec![Cell::new(sanitize_terminal(&d.id)), size_cell]);
        }
        println!("Top Dangling Images:");
        println!(
            "\x1b[1;31m[!] WARNING: Before running `docker image prune`, ensure these images are truly unused and you have required backups!\x1b[0m"
        );
        println!("{t_dang}\n");
    }

    // Containers with RW size
    if !report.topology.containers.is_empty() {
        let mut t_docker = Table::new();
        t_docker
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS);
        t_docker.set_header(vec![
            Cell::new("Container Name")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
            Cell::new("Uptime / Status").add_attribute(Attribute::Bold),
            Cell::new("Size (GB)").add_attribute(Attribute::Bold),
            Cell::new("RW Size (MB)").add_attribute(Attribute::Bold),
            Cell::new("Log Size (GB)").add_attribute(Attribute::Bold),
            Cell::new("Security Issues").add_attribute(Attribute::Bold),
            Cell::new("Data Mounts (Host -> Container)").add_attribute(Attribute::Bold),
        ]);
        for c in &report.topology.containers {
            let mut status_cell = Cell::new(sanitize_terminal(&c.status));
            if c.state == "running" {
                status_cell = status_cell.fg(Color::Green);
            } else if c.state == "exited" {
                status_cell = status_cell.fg(Color::Yellow);
            }
            let c_size_gb = c.size_mb as f64 / 1024.0;
            let rw_size_mb = c.rw_size_mb;
            let c_log_gb = c.log_size_mb as f64 / 1024.0;
            let mut log_cell = Cell::new(format!("{:.2}", c_log_gb));
            if c_log_gb > 1.0 {
                log_cell = log_cell.fg(Color::Red);
            }

            let issue_list = c.security_issues();
            let issue_str = if issue_list.is_empty() {
                "-".to_string()
            } else {
                issue_list.join(", ")
            };
            let issue_cell = if issue_str == "-" {
                Cell::new(issue_str)
            } else {
                Cell::new(sanitize_terminal(&issue_str))
                    .fg(Color::Red)
                    .add_attribute(Attribute::Bold)
            };

            let mounts_display = truncate_docker_mounts(&c.mounts, 80);
            let mounts_cell = Cell::new(mounts_display).fg(Color::DarkGrey);

            t_docker.add_row(vec![
                Cell::new(sanitize_terminal(&c.name)),
                status_cell,
                Cell::new(format!("{:.2}", c_size_gb)),
                Cell::new(rw_size_mb.to_string()),
                log_cell,
                issue_cell,
                mounts_cell,
            ]);
        }
        println!("Docker Containers & Data Persistency:");
        println!("{t_docker}\n");
    }
}

fn render_capability_audit(report: &AgentReport) {
    if report.security.capability_audit.is_empty() {
        return;
    }
    println!("\nNon‑root processes with elevated capabilities:");
    for f in &report.security.capability_audit {
        let cap_list = if f.critical_caps.is_empty() {
            let ambient_names = crate::scanners::capabilities::decode_mask(f.ambient);
            format!("ambient: {}", ambient_names.join(", "))
        } else {
            f.critical_caps.join(", ")
        };
        println!(
            "  • {} (pid {}, euid {}) — {}",
            sanitize_terminal(&f.comm),
            f.pid,
            f.euid,
            cap_list
        );
    }
    println!();
}

fn render_footer() {
    println!(
        "\x1b[3mRun `owlzops-mapper --format json` to export full payload for Blueprint Engine.\x1b[0m\n"
    );
}
