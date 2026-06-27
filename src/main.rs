mod exporters;
mod models;
mod scanners;
mod ui;

use chrono::Utc;
use clap::{Parser, ValueEnum};
use models::AgentReport;
use std::process::Command;

// =====================================================================
// CLI Arguments Setup
// =====================================================================

#[derive(Parser, Debug)]
#[command(author = "Owlzops", version, about = "Infrastructure Discovery Agent")]
struct Args {
    #[arg(short, long, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    #[arg(short, long)]
    output: Option<String>,

    #[arg(long, default_value_t = false)]
    external_ip: bool,

    #[arg(long, default_value_t = false)]
    offline: bool,

    #[arg(long, default_value_t = false)]
    refresh_packages: bool,

    // ---- remote scan options -------------------------------------------------
    /// Single hostname/IP, or comma-separated list, for remote scanning.
    /// Use "localhost" or "127.0.0.1" to scan the local machine without SSH.
    /// Can be specified multiple times.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    host: Vec<String>,

    /// File with one hostname/IP per line for remote scanning.
    #[arg(long)]
    hosts: Option<String>,

    #[arg(long, default_value = "root")]
    ssh_user: String,

    #[arg(long, default_value = "~/.ssh/id_rsa")]
    ssh_key: String,

    /// Copy the local binary to the remote host before scanning.
    /// Requires a statically linked (musl) build. Release binaries are static.
    #[arg(long, default_value_t = false)]
    copy_binary: bool,

    #[arg(long, default_value = "/tmp/owlzops-mapper")]
    remote_path: String,

    /// Path to a local static (musl) binary to copy instead of /proc/self/exe.
    #[arg(long)]
    local_binary: Option<String>,
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
enum OutputFormat {
    Text,
    Json,
    Xlsx,
    #[value(alias = "excel")]
    Xlsx2,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Text => write!(f, "text"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Xlsx | OutputFormat::Xlsx2 => write!(f, "xlsx"),
        }
    }
}

// =====================================================================
// Helper Functions
// =====================================================================

fn is_running_as_root() -> bool {
    // Safety: getuid is always safe to call.
    unsafe { libc::getuid() == 0 }
}

fn compute_risk_score(report: &AgentReport) -> u8 {
    let mut score = 0u8;
    if !report.network.firewall_active {
        score += 30;
    }
    if report.security.ssh_root_login_enabled {
        score += 25;
    }
    if report.packages.upgradable.iter().any(|p| p.is_security) {
        score += 20;
    }
    let critical_certs = report
        .network
        .ssl_certificates
        .iter()
        .filter(|c| c.is_critical)
        .count() as u8;
    score += std::cmp::min(critical_certs * 15, 15);
    if report
        .host
        .failed_services
        .iter()
        .any(|s| s.contains(".service"))
    {
        score += 10;
    }
    if report.security.ssh_password_auth_enabled {
        score += 10;
    }
    if report.host.oom_kills > 0 {
        score += 10;
    }
    if report.host.backup_tools.is_empty() {
        score += 20;
    }
    if !report.host.ntp_synchronized {
        score += 10;
    }
    if !report.security.sudo_nopasswd_entries.is_empty() {
        score += 10;
    }
    if let Some(mode) = report.security.sudoers_mode
        && mode != 0o440
    {
        score += 5;
    }
    let sysctl_penalty = std::cmp::min(report.security.sysctl_issues.len() as u8 * 5, 15);
    score += sysctl_penalty;
    score.min(100)
}

fn compute_exit_code(report: &AgentReport) -> i32 {
    let has_critical = !report.network.firewall_active
        || report.security.ssh_root_login_enabled
        || report.packages.upgradable.iter().any(|p| p.is_security)
        || report
            .network
            .ssl_certificates
            .iter()
            .any(|c| c.is_critical)
        || report
            .host
            .failed_services
            .iter()
            .any(|s| s.contains(".service"))
        || report.host.backup_tools.is_empty()
        || !report.security.sudo_nopasswd_entries.is_empty()
        || !report.host.ntp_synchronized;

    if !report.is_root_execution {
        if has_critical {
            eprintln!(
                "WARNING: not running as root AND critical issues detected – results may be incomplete, re-run with sudo."
            );
        } else {
            eprintln!("WARNING: not running as root – results may be incomplete.");
        }
        return 2;
    }
    if has_critical { 1 } else { 0 }
}

fn is_local_host(host: &str) -> bool {
    let host_lower = host.to_lowercase();
    if host_lower == "localhost" || host_lower == "127.0.0.1" || host_lower == "::1" {
        return true;
    }
    if let Some(system_hostname) = sysinfo::System::host_name()
        && host_lower == system_hostname.to_lowercase()
    {
        return true;
    }
    false
}

/// Async local scan – used when no remote hosts are given or when `--host localhost` is present.
async fn run_local_scan_async(args: &Args) -> AgentReport {
    let start = std::time::Instant::now();
    let is_root = is_running_as_root();

    let want_external_ip = if args.offline && args.external_ip {
        false
    } else {
        args.external_ip
    };
    let want_refresh_packages = if args.offline && args.refresh_packages {
        false
    } else {
        args.refresh_packages
    };

    let mut sys = sysinfo::System::new_all();
    let host_info = scanners::host::gather_host_info(&mut sys, want_external_ip);

    let dbs_task = tokio::task::spawn_blocking(scanners::host::gather_databases_info);
    let network_task = tokio::task::spawn_blocking(scanners::network::gather_network_info);
    let storage_task = tokio::task::spawn_blocking(scanners::storage::gather_storage_info);
    let security_task = tokio::task::spawn_blocking(scanners::security::gather_security_info);
    let packages_task = tokio::task::spawn_blocking(move || {
        scanners::packages::gather_packages_info(want_refresh_packages)
    });

    let (dbs_res, network_res, storage_res, security_res, topology_info, packages_res) = tokio::join!(
        dbs_task,
        network_task,
        storage_task,
        security_task,
        scanners::docker::gather_docker_topology(),
        packages_task,
    );

    let dbs = dbs_res.expect("databases scanner panicked");
    let network_info = network_res.expect("network scanner panicked");
    let storage_info = storage_res.expect("storage scanner panicked");
    let security_info = security_res.expect("security scanner panicked");
    let packages_info = packages_res.expect("packages scanner panicked");

    let duration_secs = start.elapsed().as_secs_f64();

    let mut report = AgentReport {
        scan_id: uuid::Uuid::new_v4().to_string(),
        timestamp: Utc::now().to_rfc3339(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        duration_secs,
        risk_score: 0,
        is_root_execution: is_root,
        host: host_info,
        databases: dbs,
        network: network_info,
        storage: storage_info,
        topology: topology_info,
        security: security_info,
        packages: packages_info,
    };
    report.risk_score = compute_risk_score(&report);
    report
}

/// Remote scan – performs an actual SSH call, or returns None on failure.
fn run_remote_scan(host: &str, args: &Args) -> Option<AgentReport> {
    let remote_path = &args.remote_path;
    let ssh_user = &args.ssh_user;
    let ssh_key = shellexpand::tilde(&args.ssh_key).to_string();

    if args.copy_binary {
        let local_bin = args.local_binary.as_deref().unwrap_or("/proc/self/exe");
        let status = Command::new("scp")
            .args([
                "-i",
                &ssh_key,
                "-o",
                "StrictHostKeyChecking=accept-new",
                local_bin,
                &format!("{}@{}:{}", ssh_user, host, remote_path),
            ])
            .status()
            .ok()?;
        if !status.success() {
            eprintln!("[!] Failed to copy binary to {host}");
            return None;
        }
    }

    let output = Command::new("ssh")
        .args([
            "-i",
            &ssh_key,
            "-o",
            "StrictHostKeyChecking=accept-new",
            &format!("{}@{}", ssh_user, host),
            "--",
            "sudo",
            remote_path,
            "--format",
            "json",
            "--offline",
        ])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Ok(report) = serde_json::from_str::<AgentReport>(&stdout) {
        return Some(report);
    }

    eprintln!("[!] Remote scan failed on {host}");
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    if !stderr_str.trim().is_empty() {
        eprintln!("    stderr: {}", stderr_str.trim());
    } else if !stdout.trim().is_empty() {
        eprintln!(
            "    stdout (truncated): {}",
            &stdout.trim()[..stdout.trim().len().min(200)]
        );
    }
    None
}

// =====================================================================
// Main Coordination
// =====================================================================

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // --- collect all hosts -------------------------------------------
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

    if !hosts.is_empty() {
        let mut remote = Vec::new();
        let mut local = Vec::new();

        for h in hosts {
            if is_local_host(&h) {
                local.push(h);
            } else {
                remote.push(h);
            }
        }

        let mut handles = Vec::new();

        // Local scans (async)
        for _host in local {
            let a = Args {
                format: args.format.clone(),
                output: args.output.clone(),
                external_ip: args.external_ip,
                offline: args.offline,
                refresh_packages: args.refresh_packages,
                hosts: None,
                host: Vec::new(),
                ssh_user: String::new(),
                ssh_key: String::new(),
                copy_binary: false,
                remote_path: String::new(),
                local_binary: None,
            };
            handles.push(tokio::spawn(
                async move { Some(run_local_scan_async(&a).await) },
            ));
        }

        // Remote scans (spawn_blocking)
        for host in remote {
            let args_owned = Args {
                format: args.format.clone(),
                output: args.output.clone(),
                external_ip: args.external_ip,
                offline: args.offline,
                refresh_packages: args.refresh_packages,
                hosts: None,
                host: Vec::new(),
                ssh_user: args.ssh_user.clone(),
                ssh_key: args.ssh_key.clone(),
                copy_binary: args.copy_binary,
                remote_path: args.remote_path.clone(),
                local_binary: args.local_binary.clone(),
            };
            handles.push(tokio::task::spawn_blocking(move || {
                run_remote_scan(&host, &args_owned)
            }));
        }

        let mut reports = Vec::new();
        for handle in handles {
            if let Ok(Some(report)) = handle.await {
                reports.push(report);
            }
        }

        match args.format {
            OutputFormat::Text => {
                if reports.len() == 1 {
                    ui::render_dashboard(&reports[0]);
                } else {
                    ui::render_multi_host_summary(&reports);
                }
            }
            OutputFormat::Json => {
                if let Ok(json) = serde_json::to_string_pretty(&reports) {
                    println!("{json}");
                } else {
                    eprintln!("Error serializing multi‑host report");
                }
            }
            OutputFormat::Xlsx | OutputFormat::Xlsx2 => {
                let filename = args.output.unwrap_or_else(|| {
                    format!(
                        "owlzops-multi-{}.xlsx",
                        chrono::Local::now().format("%Y-%m-%d_%H-%M-%S")
                    )
                });
                match exporters::xlsx::write_multi_host_report(&reports, &filename) {
                    Ok(_) => println!("✅ Multi‑host Excel report: {filename}"),
                    Err(e) => eprintln!("❌ Failed to generate Excel report: {e}"),
                }
            }
        }
        return;
    }

    // --- pure local scan (no hosts at all) --------------------------
    let report = run_local_scan_async(&args).await;
    let exit_code = compute_exit_code(&report);

    match args.format {
        OutputFormat::Json => match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("Error serializing Owlzops report: {e}"),
        },
        OutputFormat::Text => ui::render_dashboard(&report),
        OutputFormat::Xlsx | OutputFormat::Xlsx2 => {
            let filename = args.output.unwrap_or_else(|| {
                format!(
                    "owlzops-report-{}-{}.xlsx",
                    report.host.hostname,
                    chrono::Local::now().format("%Y-%m-%d_%H-%M-%S")
                )
            });
            match exporters::xlsx::write_report(&report, &filename) {
                Ok(_) => println!("✅ Excel report successfully generated: {filename}"),
                Err(e) => eprintln!("❌ Failed to generate Excel report: {e}"),
            }
        }
    }

    std::process::exit(exit_code);
}
