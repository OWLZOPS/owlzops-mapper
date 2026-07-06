use crate::cli::{AuditArgs, SnapshotArgs};
use crate::models::AgentReport;
use chrono::Utc;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use tracing::{Instrument, info, warn};

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

    async move {
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

        let host_task = tokio::task::spawn_blocking(move || {
            let sys = sysinfo::System::new_all();
            crate::scanners::host::gather_host_info(&sys, want_external_ip)
        });

        let dbs_task = tokio::task::spawn_blocking(crate::scanners::host::gather_databases_info);
        let network_task =
            tokio::task::spawn_blocking(crate::scanners::network::gather_network_info);
        let storage_task =
            tokio::task::spawn_blocking(crate::scanners::storage::gather_storage_info);
        let security_task =
            tokio::task::spawn_blocking(crate::scanners::security::gather_security_info);
        let packages_task = tokio::task::spawn_blocking(move || {
            crate::scanners::packages::gather_packages_info(want_refresh_packages)
        });

        let (
            host_res,
            dbs_res,
            network_res,
            storage_res,
            security_res,
            topology_info,
            packages_res,
        ) = tokio::join!(
            host_task,
            dbs_task,
            network_task,
            storage_task,
            security_task,
            tokio::spawn(crate::scanners::docker::gather_docker_topology()),
            packages_task,
        );

        let mut scan_warnings = Vec::new();

        let host_info = host_res.unwrap_or_else(|e| {
            warn!(scanner = "host", error = ?e, "scanner panicked");
            scan_warnings.push("host scanner panicked".to_string());
            crate::models::HostInfo {
                hostname: "unknown".to_string(),
                ..Default::default()
            }
        });
        let dbs = dbs_res.unwrap_or_else(|e| {
            warn!(scanner = "databases", error = ?e, "scanner panicked");
            scan_warnings.push("databases scanner panicked".to_string());
            vec![]
        });
        let network_info = network_res.unwrap_or_else(|e| {
            warn!(scanner = "network", error = ?e, "scanner panicked");
            scan_warnings.push("network scanner panicked".to_string());
            crate::models::NetworkInfo::default()
        });
        let storage_info = storage_res.unwrap_or_else(|e| {
            warn!(scanner = "storage", error = ?e, "scanner panicked");
            scan_warnings.push("storage scanner panicked".to_string());
            crate::models::StorageInfo::default()
        });
        let security_info = security_res.unwrap_or_else(|e| {
            warn!(scanner = "security", error = ?e, "scanner panicked");
            scan_warnings.push(
                "security scanner panicked — SSH/sudo/sysctl fields NOT verified".to_string(),
            );
            crate::models::SecurityInfo::default()
        });
        let packages_info = packages_res.unwrap_or_else(|e| {
            warn!(scanner = "packages", error = ?e, "scanner panicked");
            scan_warnings.push("packages scanner panicked".to_string());
            crate::models::PackagesInfo::default()
        });

        let topology_info = topology_info.unwrap_or_else(|e| {
            warn!(scanner = "docker", error = ?e, "docker scanner panicked");
            scan_warnings.push("docker scanner panicked".to_string());
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
            scoring_version: crate::scoring::SCORING_VERSION,
        };
        report.risk_score = crate::scoring::score(crate::scoring::evaluate(&report)).total;

        info!(
            scan_id = %report.scan_id,
            duration_secs = report.duration_secs,
            risk_score = report.risk_score,
            "scan completed"
        );
        report
    }
    .instrument(span)
    .await
}

pub fn run_remote_scan(host: &str, args: &AuditArgs) -> Option<AgentReport> {
    let remote_path = &args.remote_path;
    let ssh_user = &args.ssh_user;
    let ssh_key = shellexpand::tilde(&args.ssh_key).to_string();

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
        let current_exe = std::env::current_exe()
            .unwrap_or_else(|_| std::path::PathBuf::from("./owlzops-mapper"));

        let local_bin = args
            .local_binary
            .as_deref()
            .unwrap_or(current_exe.to_str().expect("Path contains invalid unicode"));

        // Determine file size for progress bar
        let file_size = std::fs::metadata(local_bin).map(|m| m.len()).unwrap_or(0);

        let pb = ProgressBar::new(file_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {bytes}/{total_bytes} ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );
        pb.set_message(format!("Uploading to {host}"));

        let tmp_remote = format!("{}.tmp", remote_path);

        // 1. Remove old temporary file (ignore errors)
        let _ = crate::utils::run_child_with_timeout(
            "ssh",
            &[
                "-i",
                &ssh_key,
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                "ConnectTimeout=10",
                &format!("{}@{}", ssh_user, host),
                "rm",
                "-f",
                &tmp_remote,
            ],
            10,
        );

        // 2. Upload the fresh binary to a temporary name
        let status = match crate::utils::run_child_with_timeout(
            "scp",
            &[
                "-i",
                &ssh_key,
                "-o",
                "StrictHostKeyChecking=accept-new",
                local_bin,
                &format!("{}@{}:{}", ssh_user, host, tmp_remote),
            ],
            args.remote_timeout_secs / 2,
        ) {
            Some(s) => s,
            None => {
                pb.finish_with_message("Upload timed out");
                warn!(host = %host, "SCP timed out or failed");
                return None;
            }
        };
        if !status.status.success() {
            pb.finish_with_message("Upload failed");
            warn!(host = %host, "SCP returned non-zero exit code");
            return None;
        }

        // 3. Make the temporary binary executable
        let _ = crate::utils::run_child_with_timeout(
            "ssh",
            &[
                "-i",
                &ssh_key,
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                "ConnectTimeout=10",
                &format!("{}@{}", ssh_user, host),
                "chmod",
                "+x",
                &tmp_remote,
            ],
            10,
        );

        // 4. Atomically replace the old binary with the new one
        let _ = crate::utils::run_child_with_timeout(
            "ssh",
            &[
                "-i",
                &ssh_key,
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                "ConnectTimeout=10",
                &format!("{}@{}", ssh_user, host),
                "mv",
                "-f",
                &tmp_remote,
                remote_path,
            ],
            10,
        );

        pb.finish_with_message("Uploaded");
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

    // Clean up the binary on the remote host unless --keep-binary is set
    if !args.keep_binary {
        let _ = crate::utils::run_child_with_timeout(
            "ssh",
            &[
                "-i",
                &ssh_key,
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                "ConnectTimeout=10",
                &format!("{}@{}", ssh_user, host),
                "rm",
                "-f",
                remote_path,
            ],
            10,
        );
    }

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
    let output_dir = if args.output_dir == "~/.owlzops/snapshots" && crate::is_running_as_root() {
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            let home = read_user_home(&sudo_user).unwrap_or_else(|| format!("/home/{}", sudo_user));
            shellexpand::tilde(&format!("{}/.owlzops/snapshots", home)).to_string()
        } else {
            shellexpand::tilde(&args.output_dir).to_string()
        }
    } else {
        shellexpand::tilde(&args.output_dir).to_string()
    };
    let output_dir = PathBuf::from(output_dir);

    let mut report = if !args.audit.host.is_empty() {
        let host = args.audit.host[0].clone();
        let host_for_msg = host.clone();
        let audit_args = args.audit.clone();
        match tokio::task::spawn_blocking(move || run_remote_scan(&host, &audit_args)).await {
            Ok(Some(report)) => report,
            Ok(None) => {
                eprintln!("Failed to scan remote host: {host_for_msg}");
                return 1;
            }
            Err(e) => {
                eprintln!("Remote scan task panicked: {e} (host: {host_for_msg})");
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
            let host_clone = host.clone();
            let audit_args = args.audit.clone();
            match tokio::task::spawn_blocking(move || run_remote_scan(&host_clone, &audit_args))
                .await
            {
                Ok(Some(report)) => report,
                Ok(None) => {
                    eprintln!("Failed to scan remote host: {host}");
                    return 1;
                }
                Err(e) => {
                    eprintln!("Remote scan task panicked: {e} (host: {host})");
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

    report.scoring_version = crate::scoring::SCORING_VERSION;
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

fn read_user_home(username: &str) -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut parts = line.splitn(7, ':');
        if parts.next()? == username {
            let home = parts.nth(4)?;
            Some(home.to_string())
        } else {
            None
        }
    })
}
