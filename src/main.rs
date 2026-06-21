mod models;
mod scanners;
mod ui;

use clap::{Parser, ValueEnum};
use chrono::Utc;
use std::process::Command;
use models::AgentReport;

// =====================================================================
// CLI Arguments Setup
// =====================================================================

#[derive(Parser, Debug)]
#[command(author = "Owlzops", version = "0.1.1", about = "Infrastructure Discovery Agent")]
struct Args {
    /// Format of the output report
    #[arg(short, long, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Detect external/public IP via an outbound request to ifconfig.me.
    /// Off by default — the agent stays fully offline unless you opt in.
    #[arg(long, default_value_t = false)]
    external_ip: bool,
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
enum OutputFormat {
    Text,
    Json
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Text => write!(f, "text"),
            OutputFormat::Json => write!(f, "json"),
        }
    }
}

// =====================================================================
// Helper Functions
// =====================================================================

fn is_running_as_root() -> bool {
    if let Ok(output) = Command::new("id").arg("-u").output() {
        let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return uid == "0";
    }
    false
}

// =====================================================================
// Main Coordination
// =====================================================================

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let is_root = is_running_as_root();

    if args.format == OutputFormat::Json && !is_root {
        eprintln!("WARNING: Script is NOT running as root/sudo! JSON data will be incomplete.");
    }

    let mut sys = sysinfo::System::new_all();

    // Triggering modular scanners
    let dbs = scanners::host::gather_databases_info();
    let host_info = scanners::host::gather_host_info(&mut sys, args.external_ip);
    let network_info = scanners::network::gather_network_info();
    let storage_info = scanners::storage::gather_storage_info();
    let security_info = scanners::security::gather_security_info();
    let topology_info = scanners::docker::gather_docker_topology().await;

    let report = AgentReport {
        scan_id: uuid::Uuid::new_v4().to_string(),
        timestamp: Utc::now().to_rfc3339(),
        is_root_execution: is_root,
        host: host_info,
        databases: dbs,
        network: network_info,
        storage: storage_info,
        topology: topology_info,
        security: security_info,
    };

    match args.format {
        OutputFormat::Json => {
            match serde_json::to_string_pretty(&report) {
                Ok(json) => println!("{}", json),
                Err(e) => eprintln!("Error serializing Owlzops report: {}", e),
            }
        }
        OutputFormat::Text => {
            ui::render_dashboard(&report);
        }
    }
}