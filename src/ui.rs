//! Terminal dashboard renderer.
//!
//! All strings originating from an audited host pass through
//! [`sanitize_terminal`] before being printed, mitigating
//! terminal escape sequence injection (C0/C1 control characters
//! beyond `\t` are replaced with U+FFFD).

use std::collections::HashMap;

use crate::models::{
    AgentReport, CronSeverity, InjectionClass, LibraryInjectionFinding, Origin, PackageManager,
};
use crate::scoring::{classify_cap_binary, classify_setuid};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};

// ---------------------------------------------------------------------------
// Sanitisation helper
// ---------------------------------------------------------------------------

/// Replace control characters, bidi overrides, and zero-width characters
/// with the Unicode replacement character (U+FFFD).
/// Tabs (\t) are converted to 4 spaces to fix comfy_table border alignment calculations.
pub fn sanitize_terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\t' => out.push_str("    "),
            c if c.is_control() => out.push('\u{FFFD}'),          // C0, C1, DEL
            '\u{202A}'..='\u{202E}'   // bidi overrides (LRE, RLE, PDF, LRO, RLO)
            | '\u{2066}'..='\u{2069}' // bidi isolates (LRI, RLI, FSI, PDI)
            | '\u{200B}'..='\u{200D}' // zero-width space, non-joiner, joiner
            | '\u{2060}'             // word joiner
            | '\u{FEFF}'             // BOM / zero-width no-break space
            => out.push('\u{FFFD}'),
            c => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Helper: table with dynamic column width (no forced width)
// ---------------------------------------------------------------------------

/// Create a `Table` preset for sections that contain potentially long text.
/// Uses `ContentArrangement::Dynamic` so columns resize to fit the content,
/// while `comfy_table`'s internal fallback (80 columns) guarantees no runaway
/// lines when no terminal is present (e.g. automated SSH calls).
fn create_dynamic_table() -> Table {
    let mut t = Table::new();
    t.load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);
    t
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

pub fn render_dashboard(report: &AgentReport, verbose: bool) {
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
    render_mount_masking(report);
    render_reverse_shells(report);
    render_library_injections(report, verbose);
    render_ghost_pids(report);

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
        let scored = crate::scoring::score(crate::scoring::evaluate(r));
        let risk_score = scored.total;

        let score_cell = if risk_score >= 70 {
            Cell::new(risk_score.to_string()).fg(Color::Red)
        } else if risk_score >= 40 {
            Cell::new(risk_score.to_string()).fg(Color::Yellow)
        } else {
            Cell::new(risk_score.to_string()).fg(Color::Green)
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

    println!("\u{1F989} Owlzops Multi‑Host Audit Summary\n");
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

    // Always compute the score locally to avoid depending on a possibly
    // stale `risk_score` from an older remote agent.
    let scored = crate::scoring::score(crate::scoring::evaluate(report));
    let risk_score = scored.total;

    let risk_label = if risk_score < 40 {
        "Healthy"
    } else if risk_score < 70 {
        "At Risk"
    } else {
        "Critical"
    };

    let risk_color = if is_tty {
        if risk_score >= 70 {
            "\x1b[1;31m"
        } else if risk_score >= 40 {
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
        icon_shield, risk_color, risk_score, color_reset, risk_label
    );

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
        println!("\nRisk Breakdown:");

        let (icon_sec, icon_rel, icon_hyg) = if is_tty {
            ("\u{1F6E1} ", "\u{2699} ", "\u{1F9F9} ")
        } else {
            ("", "", "")
        };

        let categories = [
            (
                crate::scoring::Category::Security,
                format!("{}Security Findings", icon_sec),
            ),
            (
                crate::scoring::Category::Reliability,
                format!("{}Reliability Findings", icon_rel),
            ),
            (
                crate::scoring::Category::Hygiene,
                format!("{}Hygiene Findings", icon_hyg),
            ),
        ];

        for (cat, label) in categories {
            let cat_findings: Vec<_> = active_findings
                .iter()
                .filter(|f| f.category == cat)
                .collect();

            if !cat_findings.is_empty() {
                println!("\n  {}", label);

                let mut t_cat = create_dynamic_table();
                t_cat.set_header(vec![
                    Cell::new("CIS / Ref")
                        .add_attribute(Attribute::Bold)
                        .fg(Color::Cyan),
                    Cell::new("Penalty")
                        .add_attribute(Attribute::Bold)
                        .fg(Color::Red),
                    Cell::new("Finding").add_attribute(Attribute::Bold),
                    Cell::new("Evidence").add_attribute(Attribute::Bold),
                ]);

                for f in cat_findings {
                    let cis_note = f.cis_ref.unwrap_or("-");
                    t_cat.add_row(vec![
                        Cell::new(cis_note).fg(Color::DarkGrey),
                        Cell::new(format!("-{}", f.weight)).fg(Color::Red),
                        Cell::new(&f.title),
                        Cell::new(sanitize_terminal(&f.evidence)),
                    ]);
                }
                println!("{t_cat}");
            }
        }
        println!();
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

    // ── Shadow IT & Suspicious Listeners ───────────────────────────────
    let mut shadow_it_ports = Vec::new();
    let mut devtool_ports = Vec::new();
    let mut prov_ports = Vec::new();

    for port in &report.network.listening_ports {
        if let Some(exe) = &port.exe_path
            && crate::utils::is_ephemeral_exec_path(exe)
        {
            let loopback = crate::utils::is_loopback_bind(&port.bind_address);
            let label = format!(
                "{}/{} on {} ({})",
                port.port, port.protocol, port.bind_address, exe
            );

            let prov = port
                .pid
                .map(|p| crate::utils::exe_provenance(exe, p))
                .unwrap_or(crate::utils::ExeProvenance::LoneDropped);

            match (loopback, prov) {
                // Root-owned tree: path alone is sufficient (need root to place binary).
                (true, crate::utils::ExeProvenance::InstalledApp) => devtool_ports.push(label),
                // User-writable tree: path does NOT clear; parentage needed later.
                // For now — provisional trust.
                (true, crate::utils::ExeProvenance::NestedUserInstall) => prov_ports.push(label),
                // Lone/deleted binary OR exposed to the world → keep alert.
                _ => shadow_it_ports.push(label),
            }
        }
    }

    if !shadow_it_ports.is_empty() {
        let shadow_cell = Cell::new(format!("{} listener(s)", shadow_it_ports.len()))
            .fg(Color::Red)
            .add_attribute(Attribute::Bold);
        t_risk.add_row(vec![
            Cell::new("Shadow IT / Suspicious Listener"),
            shadow_cell,
        ]);
    }

    if !devtool_ports.is_empty() {
        let dev_cell =
            Cell::new(format!("{} loopback IPC port(s)", devtool_ports.len())).fg(Color::Green);
        t_risk.add_row(vec![Cell::new("Developer Tools (IPC)"), dev_cell]);
    }

    if !prov_ports.is_empty() {
        let prov_cell =
            Cell::new(format!("{} user-space IPC port(s)", prov_ports.len())).fg(Color::Yellow);
        t_risk.add_row(vec![Cell::new("User Tools (Provisional)"), prov_cell]);
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
        let exposed = crate::utils::is_wildcard_bind(&p.bind_address);
        let loopback = crate::utils::is_loopback_bind(&p.bind_address);

        let mut addr_cell = Cell::new(sanitize_terminal(&p.bind_address));
        let mut port_cell = Cell::new(&p.port);
        let mut proto_cell = Cell::new(&p.protocol);
        let mut proc_cell = Cell::new(sanitize_terminal(&p.process));

        if exposed {
            addr_cell = addr_cell.fg(Color::Red).add_attribute(Attribute::Bold);
            port_cell = port_cell.fg(Color::Red).add_attribute(Attribute::Bold);
            proto_cell = proto_cell.fg(Color::Red).add_attribute(Attribute::Bold);
            proc_cell = proc_cell.fg(Color::Red).add_attribute(Attribute::Bold);
        } else if let Some(exe) = &p.exe_path
            && crate::utils::is_ephemeral_exec_path(exe)
            && loopback
        {
            let prov = p
                .pid
                .map(|pid| crate::utils::exe_provenance(exe, pid))
                .unwrap_or(crate::utils::ExeProvenance::LoneDropped);

            match prov {
                crate::utils::ExeProvenance::InstalledApp => {
                    proc_cell = proc_cell.fg(Color::Green);
                }
                crate::utils::ExeProvenance::NestedUserInstall => {
                    proc_cell = proc_cell.fg(Color::Yellow);
                }
                _ => {
                    proc_cell = proc_cell.fg(Color::Red);
                }
            }
        }

        t_ports.add_row(vec![proto_cell, addr_cell, port_cell, proc_cell]);
    }
    println!("Active Network Listeners (Red = Exposed, Yellow = User IPC, Green = System IPC):");
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
        let mut t_hosts = create_dynamic_table();
        t_hosts.set_header(vec![
            Cell::new("Custom /etc/hosts Overrides")
                .add_attribute(Attribute::Bold)
                .fg(Color::Yellow),
        ]);
        for host in &report.network.custom_host_overrides {
            t_hosts.add_row(vec![Cell::new(sanitize_terminal(host))]);
        }
        println!("{t_hosts}\n");
    }

    if !report.host.cron_jobs.is_empty() {
        let mut t_cron = create_dynamic_table();
        t_cron.set_header(vec![
            Cell::new("Cronjob Rule")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
            Cell::new("Status").add_attribute(Attribute::Bold),
        ]);

        for cron in &report.host.cron_jobs {
            let safe_cmd = sanitize_terminal(&cron.command);
            let (status_cell, cmd_cell) = match cron.severity {
                CronSeverity::Critical => (
                    Cell::new("Suspicious!")
                        .fg(Color::Red)
                        .add_attribute(Attribute::Bold),
                    Cell::new(safe_cmd).fg(Color::Red),
                ),
                CronSeverity::Warning => (
                    Cell::new("Review").fg(Color::Yellow),
                    Cell::new(safe_cmd).fg(Color::Yellow),
                ),
                CronSeverity::Ok => (Cell::new("OK").fg(Color::Green), Cell::new(safe_cmd)),
            };
            t_cron.add_row(vec![cmd_cell, status_cell]);
        }

        println!("System & Custom Cronjobs:");
        println!("{t_cron}\n");
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

    if !report.topology.containers.is_empty() {
        let mut t_docker = create_dynamic_table();
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

    let mut t_caps = create_dynamic_table();
    t_caps.set_header(vec![
        Cell::new("Process")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("PID / EUID").add_attribute(Attribute::Bold),
        Cell::new("Capabilities").add_attribute(Attribute::Bold),
        Cell::new("Security Flags").add_attribute(Attribute::Bold),
    ]);

    for f in &report.security.capability_audit {
        let cap_list = if f.critical_caps.is_empty() {
            let ambient_names = crate::scanners::capabilities::decode_mask(f.ambient);
            format!("ambient: {}", ambient_names.join(", "))
        } else {
            f.critical_caps.join(", ")
        };

        let nnp = match f.no_new_privs {
            Some(false) => "NNP=open",
            Some(true) => "NNP=1",
            None => "-",
        };
        let secc = match f.seccomp {
            Some(2) => "Seccomp=2",
            Some(0) => "Seccomp=off",
            Some(1) => "Seccomp=strict",
            _ => "-",
        };

        let mut flags = Vec::new();
        if nnp != "-" {
            flags.push(nnp);
        }
        if secc != "-" {
            flags.push(secc);
        }

        let flags_display = if flags.is_empty() {
            String::from("-")
        } else {
            flags.join("\n")
        };

        t_caps.add_row(vec![
            Cell::new(sanitize_terminal(&f.comm)),
            Cell::new(format!("{} / {}", f.pid, f.euid)),
            Cell::new(cap_list).fg(Color::Red),
            Cell::new(flags_display).fg(Color::DarkGrey),
        ]);
    }

    println!("Non-root processes with elevated capabilities:");
    println!("{t_caps}\n");
}

// ── SEC-021: Bind‑Mount Masking ───────────────────────────────────────────

fn render_mount_masking(report: &AgentReport) {
    if report.security.mount_masking.is_empty() {
        return;
    }
    let mut t = create_dynamic_table();
    t.set_header(vec![
        Cell::new("Masked Path")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Source / FS").add_attribute(Attribute::Bold),
        Cell::new("Reason").add_attribute(Attribute::Bold),
    ]);
    for m in &report.security.mount_masking {
        t.add_row(vec![
            Cell::new(sanitize_terminal(&m.target_path)),
            Cell::new(format!(
                "{} ({})",
                sanitize_terminal(&m.mount_source),
                sanitize_terminal(&m.fstype)
            )),
            Cell::new(sanitize_terminal(&m.reason)),
        ]);
    }
    println!("⚠ Bind‑Mount Masking Detected (SEC‑021):");
    println!("{t}\n");
}

// ── SEC-022: Reverse Shells / C2 ──────────────────────────────────────────

fn render_reverse_shells(report: &AgentReport) {
    if report.security.reverse_shells.is_empty() {
        return;
    }
    let mut t = create_dynamic_table();
    t.set_header(vec![
        Cell::new("PID")
            .add_attribute(Attribute::Bold)
            .fg(Color::Cyan),
        Cell::new("Process").add_attribute(Attribute::Bold),
        Cell::new("Remote C2").add_attribute(Attribute::Bold),
        Cell::new("Stdio").add_attribute(Attribute::Bold),
    ]);
    for r in &report.security.reverse_shells {
        let fd = match r.stdio_fd {
            Some(0) => "stdin".to_string(),
            Some(1) => "stdout".to_string(),
            Some(2) => "stderr".to_string(),
            Some(n) => format!("fd {n}"),
            None => "—".to_string(),
        };
        t.add_row(vec![
            Cell::new(r.pid.to_string()),
            Cell::new(sanitize_terminal(&r.process)),
            Cell::new(sanitize_terminal(&r.remote_address)),
            Cell::new(fd),
        ]);
    }
    println!("🚨 Reverse Shell / C2 Connections (SEC‑022):");
    println!("{t}\n");
}

/// Short label for a forensic origin.
fn origin_label(o: &Origin) -> &'static str {
    match o {
        Origin::FfiClosure => "libffi",
        Origin::GObjectCallback => "GObject",
        Origin::JitCode => "JIT",
        Origin::RuntimeTrampoline => "trampoline",
        Origin::HotSpot => "Java JIT",
        Origin::Pcre2Jit => "PCRE2 JIT",
        Origin::UnknownPayload => "Unknown",
        Origin::Inconclusive => "n/a",
        Origin::ManagedJit => "Managed JIT",
        Origin::ReservedBuffer => "Empty JIT",
        Origin::GhostCleanImage => "Clean Ghost ELF",
        Origin::GhostSuspectImage => "Suspect Ghost Payload",
        Origin::GhostInconclusive => "Inconclusive Ghost",
    }
}

// ── SEC-023 / SEC-026 / SEC-027 / SEC-028 / SEC-029: Library Injection & Memory Anomalies ─────

fn render_library_injections(report: &AgentReport, verbose: bool) {
    let inj = &report.security.library_injections;
    if inj.is_empty() {
        return;
    }

    // Classic injections (SEC-023)
    let classic: Vec<_> = inj
        .iter()
        .filter(|l| l.classify() == InjectionClass::ClassicInjection)
        .collect();
    if !classic.is_empty() {
        let mut t = create_dynamic_table();
        t.set_header(vec![
            Cell::new("PID")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
            Cell::new("Process").add_attribute(Attribute::Bold),
            Cell::new("Injected Object").add_attribute(Attribute::Bold),
            Cell::new("Source").add_attribute(Attribute::Bold),
            Cell::new("Deleted").add_attribute(Attribute::Bold),
        ]);
        for l in classic {
            t.add_row(vec![
                Cell::new(l.pid.to_string()),
                Cell::new(sanitize_terminal(&l.process)),
                Cell::new(sanitize_terminal(&l.object_path)),
                Cell::new(&l.source).fg(Color::Red),
                Cell::new(if l.is_deleted { "yes" } else { "no" }),
            ]);
        }
        println!("🧬 Userspace Rootkit / Library Injection (SEC‑023):");
        println!("{t}\n");
    }

    // Memory anomalies (SEC-026 & SEC-028)
    let memory_anomalies: Vec<_> = inj
        .iter()
        .filter(|l| {
            if l.classify() != InjectionClass::MemoryAnomaly {
                return false;
            }
            if let Some(d) = &l.deep_forensics {
                let is_benign = matches!(
                    d.origin,
                    Origin::FfiClosure
                        | Origin::GObjectCallback
                        | Origin::HotSpot
                        | Origin::RuntimeTrampoline
                        | Origin::Pcre2Jit
                        | Origin::ManagedJit
                        | Origin::ReservedBuffer
                );
                if is_benign && d.confidence >= 70 {
                    return false;
                }
            }
            true
        })
        .collect();

    if !memory_anomalies.is_empty() {
        let has_deep = memory_anomalies.iter().any(|l| l.deep_forensics.is_some());

        if verbose {
            let mut t = create_dynamic_table();
            t.set_header(vec![
                Cell::new("PID")
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Cyan),
                Cell::new("Process").add_attribute(Attribute::Bold),
                Cell::new("Type").add_attribute(Attribute::Bold),
                Cell::new("Address").add_attribute(Attribute::Bold),
                Cell::new("Detail").add_attribute(Attribute::Bold),
            ]);
            let mut all: Vec<_> = memory_anomalies.iter().collect();
            all.sort_by_key(|l| std::cmp::Reverse(region_kind(&l.source).1));
            for l in all {
                let (kind, rank) = region_kind(&l.source);
                let c = if rank >= 3 { Color::Red } else { Color::Yellow };
                t.add_row(vec![
                    Cell::new(l.pid.to_string()),
                    Cell::new(sanitize_terminal(&l.process)),
                    Cell::new(kind).fg(c),
                    Cell::new(l.region_addr.as_deref().unwrap_or("?")),
                    Cell::new(sanitize_terminal(&l.object_path)),
                ]);
            }
            println!("⚠️  Anomalous Executable Memory (SEC‑026) — verbose:");
            println!("{t}\n");
        } else {
            struct Row {
                process: String,
                pids: Vec<u32>,
                kinds: String,
                anchor: String,
                rank: u8,
                origin: Option<String>,
            }

            let mut groups: std::collections::BTreeMap<
                (&str, u32),
                Vec<&&LibraryInjectionFinding>,
            > = std::collections::BTreeMap::new();
            for l in &memory_anomalies {
                groups
                    .entry((l.process.as_str(), l.pid))
                    .or_default()
                    .push(l);
            }

            let mut per_pid: Vec<Row> = groups
                .into_iter()
                .map(|((proc_name, pid), regs)| {
                    let mut counts: std::collections::BTreeMap<&str, usize> = Default::default();
                    let mut rank = 0u8;
                    for r in &regs {
                        let (k, rk) = region_kind(&r.source);
                        *counts.entry(k).or_default() += 1;
                        rank = rank.max(rk);
                    }
                    let kinds = counts
                        .iter()
                        .map(|(k, n)| format!("{n}× {k}"))
                        .collect::<Vec<_>>()
                        .join(", ");

                    let extra = if regs.len() > 1 {
                        format!(" (+{})", regs.len() - 1)
                    } else {
                        String::new()
                    };
                    let anchor = regs[0].region_addr.clone().unwrap_or_else(|| "?".into()) + &extra;

                    let origin = regs
                        .iter()
                        .filter_map(|r| r.deep_forensics.as_ref())
                        .min_by_key(|d| match d.origin {
                            Origin::UnknownPayload => 0,
                            Origin::Inconclusive => 9,
                            _ => 1,
                        })
                        .map(|d| format!("{} ({}%)", origin_label(&d.origin), d.confidence));

                    Row {
                        process: proc_name.to_string(),
                        pids: vec![pid],
                        kinds,
                        anchor,
                        rank,
                        origin,
                    }
                })
                .collect();

            let mut merged: std::collections::BTreeMap<(String, String, Option<String>), Row> =
                Default::default();
            for r in per_pid.drain(..) {
                merged
                    .entry((r.process.clone(), r.kinds.clone(), r.origin.clone()))
                    .and_modify(|m| m.pids.extend(&r.pids))
                    .or_insert(r);
            }

            let mut rows: Vec<Row> = merged.into_values().collect();
            rows.sort_by_key(|r| std::cmp::Reverse(r.rank));

            let mut t = create_dynamic_table();
            let mut header = vec![
                Cell::new("Process")
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Yellow),
                Cell::new("PID(s)").add_attribute(Attribute::Bold),
                Cell::new("Regions").add_attribute(Attribute::Bold),
                Cell::new("Address").add_attribute(Attribute::Bold),
            ];
            if has_deep {
                header.push(
                    Cell::new("Origin")
                        .add_attribute(Attribute::Bold)
                        .fg(Color::Cyan),
                );
            }
            t.set_header(header);

            const CAP: usize = 15;
            for r in rows.iter().take(CAP) {
                let pids = if r.pids.len() <= 4 {
                    r.pids
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                } else {
                    format!(
                        "{},…(+{})",
                        r.pids
                            .iter()
                            .take(3)
                            .map(u32::to_string)
                            .collect::<Vec<_>>()
                            .join(","),
                        r.pids.len() - 3
                    )
                };
                let c = if r.rank >= 3 {
                    Color::Red
                } else {
                    Color::Yellow
                };

                let mut cells = vec![
                    Cell::new(sanitize_terminal(&r.process)),
                    Cell::new(pids),
                    Cell::new(&r.kinds).fg(c),
                    Cell::new(&r.anchor),
                ];

                if has_deep {
                    let (lbl, col) = match r.origin.as_deref() {
                        Some(o) if o.starts_with("Unknown") => (o.to_string(), Color::Red),
                        Some(o) => (o.to_string(), Color::Green),
                        None => ("—".to_string(), Color::DarkGrey),
                    };
                    cells.push(Cell::new(lbl).fg(col));
                }
                t.add_row(cells);
            }
            println!("⚠️  Anomalous Executable Memory (SEC‑026 / SEC-028):");
            println!("{t}");
            if rows.len() > CAP {
                println!(
                    "    …and {} more (process,pid) group(s) — run with -v or see JSON export",
                    rows.len() - CAP
                );
            }

            // HINT: only show if deep scan was NOT requested (fast path)
            if !verbose {
                let deep_requested = std::env::args().any(|arg| arg == "--deep");
                if !deep_requested {
                    println!(
                        "\n    \x1b[1;36m💡 HINT: Run `owlzops-mapper audit --deep` to perform memory forensics and verify legitimate JIT compilers.\x1b[0m\n"
                    );
                } else {
                    println!();
                }
            } else {
                println!();
            }
        }

        let traced: Vec<_> = memory_anomalies
            .iter()
            .filter(|l| {
                l.deep_forensics
                    .as_ref()
                    .is_some_and(|d| !d.resolved_pointers.is_empty())
            })
            .collect();

        if !traced.is_empty() {
            println!("  🔍 Pointer resolution trace (deep forensics):");
            for l in traced.iter().take(5) {
                let d = l.deep_forensics.as_ref().unwrap();
                println!(
                    "    pid {} @ {}  origin={} ({}%)  entropy={:.1}",
                    l.pid,
                    l.region_addr.as_deref().unwrap_or("?"),
                    origin_label(&d.origin),
                    d.confidence,
                    d.entropy
                );
                for p in d.resolved_pointers.iter().take(4) {
                    println!("        → {:<16} {}", p.value, sanitize_terminal(&p.target));
                }
                if d.resolved_pointers.len() > 4 {
                    println!(
                        "        … (+{} more pointers, see JSON)",
                        d.resolved_pointers.len() - 4
                    );
                }
            }
            if traced.len() > 5 {
                println!(
                    "    …and {} more regions analyzed (see JSON)\n",
                    traced.len() - 5
                );
            } else {
                println!();
            }
        }
    }

    // JIT Advisories (SEC-027) – suppressed, single line
    let jit_advisories: Vec<_> = inj
        .iter()
        .filter(|l| l.classify() == InjectionClass::JitAdvisory)
        .collect();
    if !jit_advisories.is_empty() {
        println!(
            "🛡  JIT writable-code advisory (SEC‑027): {} suppressed finding(s) with verified runtime topology.\n",
            jit_advisories.len()
        );
    }

    // Provisional Trust (SEC-029)
    let prov_trust: Vec<_> = inj
        .iter()
        .filter(|l| {
            l.source == "maps-rwx-provisional"
                || l.source == "maps-rwx-cached-clean"
                || l.source == "maps-rwx-runtime-allowlist"
        })
        .collect();
    if !prov_trust.is_empty() {
        println!(
            "🛡  Provisional Trust (SEC‑029): {} region(s) in allowlisted binaries (JIT shape unverified).\n",
            prov_trust.len()
        );
    }

    // SEC‑034 / SEC‑036 – File capabilities with risk-tiering
    let file_caps = &report.security.file_capabilities;
    if !file_caps.is_empty() {
        let src = &report.security.provenance_source;
        let suppressed: Vec<_> = file_caps
            .iter()
            .filter(|fc| classify_cap_binary(fc, src).0 == 0)
            .collect();
        let active: Vec<_> = file_caps
            .iter()
            .filter(|fc| classify_cap_binary(fc, src).0 != 0)
            .collect();

        if !suppressed.is_empty() {
            println!(
                "🛡  Files with expected capabilities (SEC‑034): {} suppressed finding(s).\n",
                suppressed.len()
            );
        }
        if !active.is_empty() {
            println!(
                "🛡  Unexpected file capabilities (SEC‑036): {} active finding(s) — review required.\n",
                active.len()
            );
        }
    }

    // SEC‑037 – Setuid/setgid files with risk-tiering
    let setuid_files = &report.security.setuid_files;
    if !setuid_files.is_empty() {
        let src = &report.security.provenance_source;
        let (suppressed_su, active_su): (Vec<_>, Vec<_>) = setuid_files
            .iter()
            .partition(|f| classify_setuid(f, src).0 == 0);

        if !suppressed_su.is_empty() {
            println!(
                "🛡  Expected setuid/setgid files (SEC‑037): {} suppressed finding(s).\n",
                suppressed_su.len()
            );
        }
        if !active_su.is_empty() {
            println!(
                "🛡  Unexpected setuid/setgid files (SEC‑037): {} active finding(s) — review required.\n",
                active_su.len()
            );
        }
    }

    // SEC‑035 – eBPF inventory (suppressed, informational)
    let ebpf = &report.security.ebpf_inventory;
    let ebpf_total = ebpf.programs.len() + ebpf.maps.len() + ebpf.links.len() + ebpf.pins.len();
    if ebpf_total > 0 {
        println!(
            "🛡  eBPF inventory (SEC‑035): {} program(s), {} map(s), {} link(s), {} pin(s).",
            ebpf.programs.len(),
            ebpf.maps.len(),
            ebpf.links.len(),
            ebpf.pins.len(),
        );
    }
}

/// Short label + severity rank from the source string.
fn region_kind(source: &str) -> (&'static str, u8) {
    match source {
        s if s.contains("exec-stack") => ("rwx-stack", 4),
        s if s.contains("exec-heap") => ("rwx-heap", 4),
        s if s.contains("file-backed") => ("rwx-file", 3),
        s if s.contains("rwx") => ("rwxp", 2),
        _ => ("r-xp", 1),
    }
}

// ── SEC-024/025: True Ghost PID / LKM Rootkit ─────────────────────────────

fn render_ghost_pids(report: &AgentReport) {
    if report.security.ghost_pids.is_empty() {
        return;
    }

    let (hard, soft): (Vec<_>, Vec<_>) = report
        .security
        .ghost_pids
        .iter()
        .partition(|g| g.confirmed_ioc);

    if !hard.is_empty() {
        let mut t = create_dynamic_table();
        t.set_header(vec![
            Cell::new("PID")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
            Cell::new("State").add_attribute(Attribute::Bold),
            Cell::new("Age").add_attribute(Attribute::Bold),
            Cell::new("Confirmed via").add_attribute(Attribute::Bold),
            Cell::new("Socket").add_attribute(Attribute::Bold),
        ]);
        for g in hard {
            let state = g.state.as_deref().unwrap_or("?");
            let age = g
                .age_secs
                .map(|a| format!("{a}s"))
                .unwrap_or_else(|| "age?".to_string());
            t.add_row(vec![
                Cell::new(g.pid.to_string()),
                Cell::new(state),
                Cell::new(age),
                Cell::new(&g.confirmed_via),
                Cell::new(if g.holds_socket { "yes" } else { "no" }),
            ]);
        }
        println!("👻 Hidden Process Detected (LKM Rootkit) (SEC‑024):");
        println!("{t}\n");
    }

    if !soft.is_empty() {
        let mut t = create_dynamic_table();
        t.set_header(vec![
            Cell::new("PID")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
            Cell::new("State").add_attribute(Attribute::Bold),
            Cell::new("Age").add_attribute(Attribute::Bold),
            Cell::new("Confirmed via").add_attribute(Attribute::Bold),
            Cell::new("Socket").add_attribute(Attribute::Bold),
        ]);
        for g in soft {
            let state = g.state.as_deref().unwrap_or("?");
            let age = g
                .age_secs
                .map(|a| format!("{a}s"))
                .unwrap_or_else(|| "age?".to_string());
            t.add_row(vec![
                Cell::new(g.pid.to_string()),
                Cell::new(state),
                Cell::new(age),
                Cell::new(&g.confirmed_via),
                Cell::new(if g.holds_socket { "yes" } else { "no" }),
            ]);
        }
        println!("👻 Suspicious PID Visibility Mismatch (downgraded) (SEC‑025):");
        println!("{t}\n");
    }
}

fn render_footer() {
    println!();
    println!(
        "\x1b[3mRun `owlzops-mapper --format json` to export full payload for Blueprint Engine.\x1b[0m\n"
    );
}
