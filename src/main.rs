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
    if let Ok(output) = Command::new("id").arg("-u").output()
        && let Ok(uid_str) = std::str::from_utf8(&output.stdout[..])
    {
        return uid_str.trim() == "0";
    }
    false
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
    score = score.min(100);
    score
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
            .any(|s| s.contains(".service"));

    if !report.is_root_execution {
        if has_critical {
            eprintln!(
                "WARNING: not running as root AND critical issues detected – \
                 results may be incomplete, re-run with sudo."
            );
        } else {
            eprintln!("WARNING: not running as root – results may be incomplete.");
        }
        return 2;
    }

    if has_critical { 1 } else { 0 }
}

// =====================================================================
// Main Coordination
// =====================================================================

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let start = std::time::Instant::now();
    let is_root = is_running_as_root();

    if args.format == OutputFormat::Json && !is_root {
        eprintln!("WARNING: Script is NOT running as root/sudo! JSON data will be incomplete.");
    }

    let want_external_ip = if args.offline && args.external_ip {
        eprintln!("WARNING: --offline overrides --external-ip; no outbound request will be made.");
        false
    } else {
        args.external_ip
    };
    let want_refresh_packages = if args.offline && args.refresh_packages {
        eprintln!(
            "WARNING: --offline overrides --refresh-packages; package cache will not be refreshed."
        );
        false
    } else {
        args.refresh_packages
    };

    let mut sys = sysinfo::System::new_all();

    // Host info first (requires mutable sys)
    let host_info = scanners::host::gather_host_info(&mut sys, want_external_ip);

    // Parallel execution of remaining scanners using spawn_blocking
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
        risk_score: 0, // placeholder, will be recalculated
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
    let exit_code = compute_exit_code(&report);

    match args.format {
        OutputFormat::Json => match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{}", json),
            Err(e) => eprintln!("Error serializing Owlzops report: {}", e),
        },
        OutputFormat::Text => {
            ui::render_dashboard(&report);
        }
        OutputFormat::Xlsx | OutputFormat::Xlsx2 => {
            let filename = args.output.unwrap_or_else(|| {
                format!(
                    "owlzops-report-{}-{}.xlsx",
                    report.host.hostname,
                    chrono::Local::now().format("%Y-%m-%d_%H-%M-%S")
                )
            });
            match exporters::xlsx::write_report(&report, &filename) {
                Ok(_) => println!("✅ Excel report successfully generated: {}", filename),
                Err(e) => eprintln!("❌ Failed to generate Excel report: {}", e),
            }
        }
    }

    std::process::exit(exit_code);
}
