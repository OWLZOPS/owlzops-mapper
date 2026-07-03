use crate::cli::{AuditArgs, SnapshotArgs};
use crate::models::AgentReport;
use chrono::Utc;
use std::path::PathBuf;
use tracing::{info, warn};

// ── Validation helpers (public – also used in main) ────────

/// Validate that a remote path looks safe to pass to SSH exec.
pub fn validate_remote_path(path: &str) -> Result<(), String> {
    if path.contains(|c: char| !c.is_ascii_alphanumeric() && !"-_./".contains(c)) {
        return Err(format!(
            "remote path contains unexpected characters: '{path}'"
        ));
    }
    if !path.starts_with('/') {
        return Err("remote path must be absolute".to_string());
    }
    Ok(())
}

/// Validate that an SSH username looks safe.
pub fn validate_ssh_user(user: &str) -> Result<(), String> {
    if user.is_empty()
        || user.starts_with('-')
        || user.contains(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
    {
        return Err(format!("invalid ssh user: '{user}'"));
    }
    Ok(())
}

/// Validate that a hostname/IP is safe for SSH arguments.
pub fn validate_host(host: &str) -> Result<(), String> {
    if host.is_empty() || host.starts_with('-') {
        return Err(format!("invalid host: '{host}'"));
    }
    if host.contains(|c: char| !c.is_ascii_alphanumeric() && !"-_.:".contains(c)) {
        return Err(format!("host contains unexpected characters: '{host}'"));
    }
    Ok(())
}

pub fn is_local_host(host: &str) -> bool {
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

// ── Scan execution ─────────────────────────────────────────

pub async fn run_local_scan_async(args: &AuditArgs) -> AgentReport {
    let scan_id = uuid::Uuid::new_v4().to_string();
    let span = tracing::info_span!("scan", scan_id = %scan_id, host = "local");
    let _enter = span.enter();

    let start = std::time::Instant::now();
    let is_root = crate::is_running_as_root();

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

    info!("scan started");

    // Build a dynamic list of scanners
    let scanners: Vec<Box<dyn crate::scanners::Scanner>> = vec![
        Box::new(crate::scanners::host::HostScanner {
            fetch_external_ip: want_external_ip,
        }),
        Box::new(crate::scanners::storage::StorageScanner),
        Box::new(crate::scanners::network::NetworkScanner),
        Box::new(crate::scanners::security::SecurityScanner),
        Box::new(crate::scanners::packages::PackagesScanner {
            refresh: want_refresh_packages,
        }),
        Box::new(crate::scanners::docker::DockerScanner),
    ];

    let mut handles = Vec::new();
    for scanner in scanners {
        let name = scanner.name().to_string();
        handles.push(tokio::task::spawn_blocking(move || (name, scanner.scan())));
    }

    // Databases are collected separately (they are in host.rs)
    let dbs_handle = tokio::task::spawn_blocking(|| {
        ("databases".to_string(), {
            let info = crate::scanners::host::gather_databases_info();
            Ok::<Box<dyn std::any::Any + Send>, Box<dyn std::error::Error + Send>>(Box::new(info))
        })
    });

    let mut scan_warnings = Vec::new();
    let mut host_info = None;
    let mut dbs = Vec::new();
    let mut network_info = None;
    let mut storage_info = None;
    let mut security_info = None;
    let mut packages_info = None;
    let mut topology_info = None;

    // Collect results
    for handle in handles {
        match handle.await {
            Ok((name, Ok(result))) => match name.as_str() {
                "host" => {
                    if let Some(info) = result.downcast_ref::<crate::models::HostInfo>() {
                        host_info = Some(info.clone());
                    }
                }
                "network" => {
                    if let Some(info) = result.downcast_ref::<crate::models::NetworkInfo>() {
                        network_info = Some(info.clone());
                    }
                }
                "storage" => {
                    if let Some(info) = result.downcast_ref::<crate::models::StorageInfo>() {
                        storage_info = Some(info.clone());
                    }
                }
                "security" => {
                    if let Some(info) = result.downcast_ref::<crate::models::SecurityInfo>() {
                        security_info = Some(info.clone());
                    }
                }
                "packages" => {
                    if let Some(info) = result.downcast_ref::<crate::models::PackagesInfo>() {
                        packages_info = Some(info.clone());
                    }
                }
                "docker" => {
                    if let Some(info) = result.downcast_ref::<crate::models::TopologyInfo>() {
                        topology_info = Some(info.clone());
                    }
                }
                _ => {}
            },
            Ok((name, Err(e))) => {
                warn!(scanner = %name, error = %e, "scanner failed");
                scan_warnings.push(format!("{} scanner failed: {}", name, e));
            }
            Err(e) => {
                warn!(scanner = "unknown", error = %e, "scanner panicked");
                scan_warnings.push("a scanner panicked".to_string());
            }
        }
    }

    // Collect databases
    match dbs_handle.await {
        Ok((_, Ok(result))) => {
            if let Some(db_list) = result.downcast_ref::<Vec<crate::models::DatabaseInfo>>() {
                dbs = db_list.clone();
            }
        }
        Ok((name, Err(e))) => {
            warn!(scanner = %name, error = %e, "scanner failed");
            scan_warnings.push(format!("{} scanner failed: {}", name, e));
        }
        Err(e) => {
            warn!(scanner = "databases", error = %e, "scanner panicked");
            scan_warnings.push("databases scanner panicked".to_string());
        }
    }

    // Fill defaults for any scanner that didn't return
    let host_info = host_info.unwrap_or_else(|| {
        scan_warnings.push("host scanner did not return data".to_string());
        crate::models::HostInfo {
            hostname: "unknown".to_string(),
            ..Default::default()
        }
    });
    let network_info = network_info.unwrap_or_else(|| {
        scan_warnings.push("network scanner did not return data".to_string());
        crate::models::NetworkInfo::default()
    });
    let storage_info = storage_info.unwrap_or_else(|| {
        scan_warnings.push("storage scanner did not return data".to_string());
        crate::models::StorageInfo::default()
    });
    let security_info = security_info.unwrap_or_else(|| {
        scan_warnings.push("security scanner did not return data".to_string());
        crate::models::SecurityInfo::default()
    });
    let packages_info = packages_info.unwrap_or_else(|| {
        scan_warnings.push("packages scanner did not return data".to_string());
        crate::models::PackagesInfo::default()
    });
    let topology_info = topology_info.unwrap_or_else(|| {
        scan_warnings.push("docker scanner did not return data".to_string());
        crate::models::TopologyInfo::default()
    });

    let duration_secs = start.elapsed().as_secs_f64();

    let mut report = AgentReport {
        scan_id,
        timestamp: Utc::now().to_rfc3339(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        duration_secs,
        risk_score: 0,
        is_root_execution: is_root,
        scan_warnings,
        host: host_info,
        databases: dbs,
        network: network_info,
        storage: storage_info,
        topology: topology_info,
        security: security_info,
        packages: packages_info,
    };
    report.risk_score = crate::compute_risk_score(&report);
    info!(
        scan_id = %report.scan_id,
        duration_secs = report.duration_secs,
        risk_score = report.risk_score,
        "scan completed"
    );
    report
}

pub fn run_remote_scan(host: &str, args: &AuditArgs) -> Option<AgentReport> {
    let remote_path = &args.remote_path;
    let ssh_user = &args.ssh_user;
    let ssh_key = shellexpand::tilde(&args.ssh_key).to_string();

    // Validate inputs before using them in shell commands
    if let Err(e) = validate_remote_path(remote_path) {
        warn!("{e}");
        return None;
    }
    if let Err(e) = validate_ssh_user(ssh_user) {
        warn!("{e}");
        return None;
    }
    if let Err(e) = validate_host(host) {
        warn!("{e}");
        return None;
    }

    if args.copy_binary {
        let local_bin = args.local_binary.as_deref().unwrap_or("/proc/self/exe");
        let status = match crate::utils::run_child_with_timeout(
            "scp",
            &[
                "-i",
                &ssh_key,
                "-o",
                "StrictHostKeyChecking=accept-new",
                local_bin,
                &format!("{}@{}:{}", ssh_user, host, remote_path),
            ],
            args.remote_timeout_secs / 2,
        ) {
            Some(s) => s,
            None => {
                warn!(host = %host, "SCP timed out or failed");
                return None;
            }
        };
        if !status.status.success() {
            warn!(host = %host, "SCP returned non-zero exit code");
            return None;
        }
    }

    let output = crate::utils::run_child_with_timeout(
        "ssh",
        &[
            "-i",
            &ssh_key,
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=30",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=3",
            &format!("{}@{}", ssh_user, host),
            "--",
            "sudo",
            remote_path,
            "audit",
            "--format",
            "json",
            "--offline",
        ],
        args.remote_timeout_secs,
    );

    let output = match output {
        Some(out) => out,
        None => {
            warn!(host = %host, "SSH command timed out after {}s", args.remote_timeout_secs);
            return None;
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Ok(report) = serde_json::from_str::<AgentReport>(&stdout) {
        return Some(report);
    }

    warn!(host = %host, "remote scan failed");
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    if !stderr_str.trim().is_empty() {
        warn!(host = %host, stderr = %stderr_str.trim(), "remote scan stderr");
    } else if !stdout.trim().is_empty() {
        let truncated: String = stdout.trim().chars().take(200).collect();
        warn!(host = %host, stdout_truncated = %truncated, "remote scan stdout");
    }
    None
}

pub async fn snapshot_run(args: SnapshotArgs) -> i32 {
    let output_dir = shellexpand::tilde(&args.output_dir).to_string();
    let output_dir = PathBuf::from(output_dir);

    // Perform audit using the embedded AuditArgs (always JSON, but we serialize ourselves)
    let report = if !args.audit.host.is_empty() {
        let host = &args.audit.host[0];
        match run_remote_scan(host, &args.audit) {
            Some(report) => report,
            None => {
                eprintln!("Failed to scan remote host: {host}");
                return 1;
            }
        }
    } else if let Some(ref hosts_path) = args.audit.hosts {
        let contents = std::fs::read_to_string(hosts_path).unwrap_or_default();
        let first_host = contents
            .lines()
            .find(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .map(|l| l.trim().to_string());
        if let Some(host) = first_host {
            match run_remote_scan(&host, &args.audit) {
                Some(report) => report,
                None => {
                    eprintln!("Failed to scan remote host: {host}");
                    return 1;
                }
            }
        } else {
            run_local_scan_async(&args.audit).await
        }
    } else {
        run_local_scan_async(&args.audit).await
    };

    let hostname = &report.host.hostname;
    let timestamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
    let filename = format!("{}.json", timestamp);
    let dir_path = output_dir.join(hostname);
    let file_path = dir_path.join(&filename);

    if args.audit.format != crate::cli::OutputFormat::Json || args.audit.output.is_some() {
        eprintln!(
            "note: `snapshot` always writes JSON under --output-dir; --format/--output are ignored here."
        );
    }
    if let Err(e) = std::fs::create_dir_all(&dir_path) {
        eprintln!("Failed to create directory {}: {}", dir_path.display(), e);
        return 1;
    }

    let json = serde_json::to_string_pretty(&report).unwrap_or_else(|e| {
        eprintln!("Failed to serialize report: {e}");
        std::process::exit(1);
    });

    if let Err(e) = std::fs::write(&file_path, &json) {
        eprintln!("Failed to write snapshot {}: {}", file_path.display(), e);
        return 1;
    }

    println!("Snapshot saved to {}", file_path.display());
    0
}
