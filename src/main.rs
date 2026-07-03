mod cli;
mod compare;
mod exporters;
mod models;
mod output;
mod runner;
mod scanners;
mod scoring;
mod ui;
mod utils;

use clap::Parser;
use cli::{AuditArgs, Cli, Commands};
use models::AgentReport;
use runner::{is_local_host, run_local_scan_async, run_remote_scan, snapshot_run};
use scoring::*;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::Semaphore;
use tracing::warn;

// =====================================================================
// Helper Functions
// =====================================================================

fn is_running_as_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

fn compute_risk_score(report: &AgentReport) -> u8 {
    CriticalFlags::from_report(report).risk_penalty()
}

fn compute_exit_code(report: &AgentReport) -> i32 {
    let flags = CriticalFlags::from_report(report);

    if !report.is_root_execution {
        if flags.has_critical() {
            warn!(
                "not running as root AND critical issues detected - results may be incomplete, re-run with sudo."
            );
        } else {
            warn!("not running as root - results may be incomplete.");
        }
        return 2;
    }

    if !report.scan_warnings.is_empty() {
        warn!(warnings = ?report.scan_warnings, "one or more scanners failed - report may be incomplete");
        return 2;
    }

    if flags.has_critical() { 1 } else { 0 }
}
async fn run_remote_scan_with_timeout(
    host: String,
    args: AuditArgs,
) -> Result<Option<AgentReport>, tokio::task::JoinError> {
    let host_for_log = host.clone();
    match tokio::time::timeout(
        std::time::Duration::from_secs(600),
        tokio::task::spawn_blocking(move || run_remote_scan(&host, &args)),
    )
    .await
    {
        Ok(inner) => inner,
        Err(_elapsed) => {
            warn!(host = %host_for_log, "remote scan timed out after 600s");
            Ok(None)
        }
    }
}
// =====================================================================
// Main command runner (returns exit code)
// =====================================================================

async fn run_command(cli: Cli) -> i32 {
    match cli.command {
        Commands::Audit(args) => {
            let mut hosts: Vec<String> = Vec::new();
            for h in &args.host {
                hosts.push(h.clone());
            }
            if let Some(ref path) = args.hosts
                && let Ok(contents) = std::fs::read_to_string(path)
            {
                for line in contents.lines() {
                    let h = line.trim();
                    if !h.is_empty() && !h.starts_with('#') {
                        hosts.push(h.to_string());
                    }
                }
            }

            // Remove duplicate hosts
            let mut seen = HashSet::new();
            hosts.retain(|h| seen.insert(h.clone()));

            if !hosts.is_empty() {
                let mut remote = Vec::new();
                let mut local = Vec::new();
                let mut local_seen = false;
                for h in hosts {
                    if is_local_host(&h) {
                        if !local_seen {
                            local.push(h);
                            local_seen = true;
                        }
                    } else {
                        remote.push(h);
                    }
                }

                let mut handles: Vec<
                    tokio::task::JoinHandle<Result<Option<AgentReport>, tokio::task::JoinError>>,
                > = Vec::new();
                for _host in local {
                    let a = AuditArgs {
                        hosts: None,
                        host: Vec::new(),
                        ssh_user: String::new(),
                        ssh_key: String::new(),
                        copy_binary: false,
                        remote_path: String::new(),
                        local_binary: None,
                        ..args.clone()
                    };
                    handles.push(tokio::spawn(async move {
                        Ok(Some(run_local_scan_async(&a).await))
                    }));
                }
                const MAX_CONCURRENT_SCANS: usize = 10;
                let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_SCANS));

                for host in remote {
                    let sem = semaphore.clone();
                    let a = AuditArgs {
                        hosts: None,
                        host: Vec::new(),
                        ..args.clone()
                    };
                    handles.push(tokio::spawn(async move {
                        let _permit = match sem.acquire().await {
                            Ok(p) => p,
                            Err(_) => return Ok(None),
                        };
                        run_remote_scan_with_timeout(host, a).await
                    }));
                }

                let mut reports = Vec::new();
                for (i, handle) in handles.into_iter().enumerate() {
                    match handle.await {
                        Ok(inner_result) => match inner_result {
                            Ok(Some(report)) => reports.push(report),
                            Ok(None) => warn!(host_index = i, "scan returned no data"),
                            Err(e) => warn!(host_index = i, "scan task failed: {e}"),
                        },
                        Err(e) if e.is_panic() => warn!(host_index = i, "scan task panicked: {e}"),
                        Err(e) => warn!(host_index = i, "scan task failed: {e}"),
                    }
                }

                output::output_multi(&reports, &args.format, args.output);
                // Compute overall exit code for fleet scans
                let worst = reports.iter().map(compute_exit_code).max().unwrap_or(0);
                return if worst >= 1 { worst.min(2) } else { 0 };
            }

            // Single local scan
            let report = run_local_scan_async(&args).await;
            let exit_code = compute_exit_code(&report);
            output::output_single(&report, &args.format, args.output);
            exit_code
        }

        Commands::Snapshot(args) => snapshot_run(args).await,

        Commands::DirCompare(args) => {
            let mut files: Vec<PathBuf> = match std::fs::read_dir(&args.dir) {
                Ok(entries) => entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.path())
                    .filter(|p| p.extension().map(|e| e == "json").unwrap_or(false))
                    .collect(),
                Err(_) => {
                    eprintln!("Cannot read directory: {}", args.dir.display());
                    return 1;
                }
            };
            files.sort();
            if files.len() < 2 {
                eprintln!("Need at least 2 snapshots in directory");
                return 1;
            }
            let before_path = files[files.len() - 2].clone();
            let after_path = files[files.len() - 1].clone();
            let before_data = std::fs::read_to_string(&before_path).unwrap_or_else(|e| {
                eprintln!("Failed to read '{}': {}", before_path.display(), e);
                std::process::exit(1);
            });
            let after_data = std::fs::read_to_string(&after_path).unwrap_or_else(|e| {
                eprintln!("Failed to read '{}': {}", after_path.display(), e);
                std::process::exit(1);
            });
            let before: AgentReport = serde_json::from_str(&before_data).unwrap_or_else(|e| {
                eprintln!("Invalid JSON in '{}': {}", before_path.display(), e);
                std::process::exit(1);
            });
            let after: AgentReport = serde_json::from_str(&after_data).unwrap_or_else(|e| {
                eprintln!("Invalid JSON in '{}': {}", after_path.display(), e);
                std::process::exit(1);
            });
            let diff = compare::compare_reports(&before, &after);

            match args.format.as_str() {
                "terminal" => compare::print_diff_terminal(&diff),
                "json" => {
                    let json = compare::diff_to_json(&diff).unwrap_or_else(|e| {
                        eprintln!("Failed to serialize diff JSON: {e}");
                        std::process::exit(1);
                    });
                    if let Some(path) = args.output {
                        std::fs::write(&path, json).unwrap_or_else(|e| {
                            eprintln!("Failed to write JSON output: {e}");
                            std::process::exit(1);
                        });
                        println!("Diff JSON written to {}", path.display());
                    } else {
                        println!("{}", json);
                    }
                }
                "excel" => {
                    let path = args.output.unwrap_or_else(|| {
                        eprintln!("Error: --output is required for Excel format");
                        std::process::exit(1);
                    });
                    compare::write_diff_xlsx(&diff, path.to_str().unwrap()).unwrap_or_else(|e| {
                        eprintln!("Failed to write Excel diff: {e}");
                        std::process::exit(1);
                    });
                    println!("Diff Excel written to {}", path.display());
                }
                _ => {
                    eprintln!(
                        "Unknown format '{}'. Supported: terminal, json, excel",
                        args.format
                    );
                    return 1;
                }
            }
            0
        }

        Commands::Compare(cmp_args) => {
            // Read both JSON reports
            let before_data = std::fs::read_to_string(&cmp_args.before).unwrap_or_else(|e| {
                eprintln!("Failed to read 'before' file: {e}");
                std::process::exit(1);
            });
            let after_data = std::fs::read_to_string(&cmp_args.after).unwrap_or_else(|e| {
                eprintln!("Failed to read 'after' file: {e}");
                std::process::exit(1);
            });

            // Multi-host mode
            if cmp_args.multi_host {
                let parse_array = |data: &str, label: &str| -> Vec<AgentReport> {
                    if let Ok(reports) = serde_json::from_str::<Vec<AgentReport>>(data) {
                        return reports;
                    }
                    // If single object, wrap in array
                    if let Ok(report) = serde_json::from_str::<AgentReport>(data) {
                        return vec![report];
                    }
                    eprintln!("Invalid JSON in '{}' file", label);
                    std::process::exit(1);
                };
                let before = parse_array(&before_data, "before");
                let after = parse_array(&after_data, "after");
                let diffs = compare::compare_multi(&before, &after);

                match cmp_args.format.as_str() {
                    "terminal" => {
                        for mh in &diffs {
                            println!("\nHost: {}", mh.hostname);
                            compare::print_diff_terminal(&mh.diff);
                        }
                    }
                    "json" => {
                        let json = serde_json::to_string_pretty(&diffs).unwrap_or_else(|e| {
                            eprintln!("Failed to serialize multi-host diff: {e}");
                            std::process::exit(1);
                        });
                        if let Some(path) = cmp_args.output {
                            std::fs::write(&path, json).unwrap_or_else(|e| {
                                eprintln!("Failed to write JSON output: {e}");
                                std::process::exit(1);
                            });
                            println!("Multi-host diff JSON written to {}", path.display());
                        } else {
                            println!("{}", json);
                        }
                    }
                    "excel" => {
                        let path = cmp_args.output.unwrap_or_else(|| {
                            eprintln!("Error: --output is required for Excel format");
                            std::process::exit(1);
                        });
                        crate::exporters::xlsx::write_multi_diff_xlsx(
                            &diffs,
                            path.to_str().unwrap(),
                        )
                        .unwrap_or_else(|e| {
                            eprintln!("Failed to write multi-host Excel diff: {e}");
                            std::process::exit(1);
                        });
                        println!("Multi-host diff Excel written to {}", path.display());
                    }
                    _ => {
                        eprintln!(
                            "Unknown format '{}'. Supported: terminal, json, excel",
                            cmp_args.format
                        );
                        return 1;
                    }
                }
                return 0;
            }

            // Accept either a single AgentReport or an array of them (take the first)
            let parse_report = |data: &str, label: &str| -> AgentReport {
                // Try to parse as a single object
                if let Ok(report) = serde_json::from_str::<AgentReport>(data) {
                    return report;
                }
                // If that fails, try as a Vec<AgentReport>
                if let Ok(mut reports) = serde_json::from_str::<Vec<AgentReport>>(data) {
                    if reports.is_empty() {
                        eprintln!("Error: '{}' file contains an empty array", label);
                        std::process::exit(1);
                    }
                    return reports.remove(0);
                }
                eprintln!("Invalid JSON in '{}' file", label);
                std::process::exit(1);
            };

            let before_report = parse_report(&before_data, "before");
            let after_report = parse_report(&after_data, "after");

            let diff = compare::compare_reports(&before_report, &after_report);

            match cmp_args.format.as_str() {
                "terminal" => compare::print_diff_terminal(&diff),
                "json" => {
                    let json = compare::diff_to_json(&diff).unwrap_or_else(|e| {
                        eprintln!("Failed to serialize diff JSON: {e}");
                        std::process::exit(1);
                    });
                    if let Some(path) = cmp_args.output {
                        std::fs::write(&path, json).unwrap_or_else(|e| {
                            eprintln!("Failed to write JSON output: {e}");
                            std::process::exit(1);
                        });
                        println!("Diff JSON written to {}", path.display());
                    } else {
                        println!("{}", json);
                    }
                }
                "excel" => {
                    let path = cmp_args.output.unwrap_or_else(|| {
                        eprintln!("Error: --output is required for Excel format");
                        std::process::exit(1);
                    });
                    compare::write_diff_xlsx(&diff, path.to_str().unwrap()).unwrap_or_else(|e| {
                        eprintln!("Failed to write Excel diff: {e}");
                        std::process::exit(1);
                    });
                    println!("Diff Excel written to {}", path.display());
                }
                other => {
                    eprintln!(
                        "Unknown format '{}'. Supported: terminal, json, excel",
                        other
                    );
                    std::process::exit(1);
                }
            }
            0
        }
    }
}

// =====================================================================
// Entry point with graceful shutdown
// =====================================================================

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("owlzops_mapper=warn")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    let exit_code = tokio::select! {
        code = run_command(cli) => code,
        _ = signal::ctrl_c() => {
            eprintln!("Interrupted — partial results discarded.");
            130
        }
    };

    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::*;

    fn minimal_report() -> AgentReport {
        AgentReport {
            scan_id: "test-id".to_string(),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            version: "0.4.0".to_string(),
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
    fn risk_score_never_exceeds_100() {
        let mut r = minimal_report();
        r.network.firewall_active = false;
        r.security.ssh_root_login_enabled = true;
        r.security.ssh_password_auth_enabled = true;
        r.host.backup_tools = vec![];
        r.host.oom_kills = 5;
        r.host.ntp_synchronized = false;
        r.security.sudo_nopasswd_entries = vec!["ALL".to_string()];
        r.security.sysctl_issues = vec!["a".to_string(); 10];
        for _ in 0..5 {
            r.packages.upgradable.push(UpgradablePackage {
                name: "pkg".to_string(),
                current_version: "1.0".to_string(),
                new_version: "1.1".to_string(),
                is_security: true,
            });
        }
        assert!(compute_risk_score(&r) <= 100);
    }

    #[test]
    fn exit_code_2_when_not_root() {
        let mut r = minimal_report();
        r.is_root_execution = false;
        assert_eq!(compute_exit_code(&r), 2);
    }

    #[test]
    fn exit_code_0_when_clean() {
        let mut r = minimal_report();
        r.network.firewall_active = true;
        r.security.ssh_root_login_enabled = false;
        r.host.backup_tools = vec!["restic".to_string()];
        r.host.ntp_synchronized = true;
        assert_eq!(compute_exit_code(&r), 0);
    }

    #[test]
    fn exit_code_1_on_missing_firewall() {
        let mut r = minimal_report();
        r.network.firewall_active = false;
        r.host.backup_tools = vec!["restic".to_string()];
        r.host.ntp_synchronized = true;
        assert_eq!(compute_exit_code(&r), 1);
    }

    #[test]
    fn exit_code_1_on_missing_backup() {
        let mut r = minimal_report();
        r.network.firewall_active = true;
        r.host.backup_tools = vec![];
        r.host.ntp_synchronized = true;
        assert_eq!(compute_exit_code(&r), 1);
    }
}
