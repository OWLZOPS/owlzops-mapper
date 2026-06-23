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
    /// Format of the output report
    #[arg(short, long, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Output file path for xlsx reports (default: owlzops-report-<hostname>.xlsx)
    #[arg(short, long)]
    output: Option<String>,

    /// Detect external/public IP via an outbound request to ifconfig.me.
    /// Off by default — the agent stays fully offline unless you opt in.
    #[arg(long, default_value_t = false)]
    external_ip: bool,

    /// Hard guarantee of no outbound network calls, regardless of other flags.
    /// If combined with --external-ip or --refresh-packages, --offline wins and
    /// those flags are ignored (with a warning), so this flag can be relied on
    /// as a strict safety switch — e.g. on an air-gapped host or restricted network zone.
    #[arg(long, default_value_t = false)]
    offline: bool,

    /// Refresh the local package manager cache (apt-get update / dnf makecache /
    /// pacman -Sy) before checking for upgradable packages. This is an outbound
    /// network call, so it's opt-in. Without this flag, upgradable packages are
    /// computed from whatever is already in the local cache (may be stale).
    #[arg(long, default_value_t = false)]
    refresh_packages: bool,
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
enum OutputFormat {
    Text,
    Json,
    Xlsx,
    /// Alias for xlsx — accepted as --format excel
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

    // --offline — guarantees that no outbound network requests will be made.
    // Overrides --external-ip and --refresh-packages when used together.
    // This allows the flag to be treated as a reliable safety switch,
    // regardless of any other options passed on the command line.
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

    // Triggering modular scanners
    let dbs = scanners::host::gather_databases_info();
    let host_info = scanners::host::gather_host_info(&mut sys, want_external_ip);
    let network_info = scanners::network::gather_network_info();
    let storage_info = scanners::storage::gather_storage_info();
    let security_info = scanners::security::gather_security_info();
    let topology_info = scanners::docker::gather_docker_topology().await;
    let packages_info = scanners::packages::gather_packages_info(want_refresh_packages);

    let duration_secs = start.elapsed().as_secs_f64();

    let report = AgentReport {
        scan_id: uuid::Uuid::new_v4().to_string(),
        timestamp: Utc::now().to_rfc3339(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        duration_secs,
        is_root_execution: is_root,
        host: host_info,
        databases: dbs,
        network: network_info,
        storage: storage_info,
        topology: topology_info,
        security: security_info,
        packages: packages_info,
    };

    match args.format {
        OutputFormat::Json => match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{}", json),
            Err(e) => eprintln!("Error serializing Owlzops report: {}", e),
        },
        OutputFormat::Text => {
            ui::render_dashboard(&report);
        }
        OutputFormat::Xlsx | OutputFormat::Xlsx2 => {
            let filename = args
                .output
                .unwrap_or_else(|| format!("owlzops-report-{}.xlsx", report.host.hostname));
            match exporters::xlsx::write_report(&report, &filename) {
                Ok(_) => println!("✅ Excel report successfully generated: {}", filename),
                Err(e) => eprintln!("❌ Failed to generate Excel report: {}", e),
            }
        }
    }
}
