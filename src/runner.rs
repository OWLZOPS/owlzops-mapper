use crate::cli::{AuditArgs, SnapshotArgs};
use crate::models::AgentReport;
#[cfg(feature = "local-scan")]
use chrono::Utc;
#[cfg(feature = "local-scan")]
use std::collections::BTreeMap;
use std::path::PathBuf;
#[cfg(feature = "local-scan")]
use tracing::{Instrument, info, warn};

// ── Validation helpers (public – also used in main) ────────

/// Validate that a remote path looks safe to pass to SSH exec.
///
/// Rejects:
/// - unexpected characters
/// - relative paths
/// - paths containing `..`
/// - paths under world-writable directories (`/tmp`, `/var/tmp`, `/dev/shm`)
pub fn validate_remote_path(path: &str) -> Result<(), String> {
    if path.contains(|c: char| !c.is_ascii_alphanumeric() && !"-_./".contains(c)) {
        return Err(format!(
            "remote path contains unexpected characters: '{path}'"
        ));
    }
    if !path.starts_with('/') {
        return Err("remote path must be absolute".to_string());
    }
    if path.split('/').any(|seg| seg == "..") {
        return Err("remote path must not contain '..'".to_string());
    }
    let dir = path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
    for bad in ["/tmp", "/var/tmp", "/dev/shm"] {
        if dir == bad || dir.starts_with(&format!("{bad}/")) {
            return Err(format!(
                "--remote-path {path} lives under {bad} (mode 1777): anyone on the target \
                 could replace the binary between upload and the sudo exec"
            ));
        }
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
/// Allows square brackets to support IPv6 addresses like `[::1]:2222`.
pub fn validate_host(host: &str) -> Result<(), String> {
    if host.is_empty() || host.starts_with('-') {
        return Err(format!("invalid host: '{host}'"));
    }
    if host.contains(|c: char| !c.is_ascii_alphanumeric() && !"-_.:[]".contains(c)) {
        return Err(format!("host contains unexpected characters: '{host}'"));
    }
    Ok(())
}

#[cfg(feature = "local-scan")]
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

#[cfg(feature = "local-scan")]
/// Aggregate of the persistence-family scanners. A struct rather than a tuple
/// so adding a scanner is a one-field change instead of widening four call
/// sites; `Default` doubles as the panic fallback.
#[derive(Default)]
struct PersistenceScan {
    preload: Vec<crate::models::PreloadFinding>,
    core_pattern: Option<String>,
    modules_disabled: Option<bool>,
    lockdown: Option<String>,
    exec_start: Vec<crate::models::ExecStartFinding>,
    ld_so_conf: Vec<crate::models::LdSoConfInjection>,
    generators: Vec<crate::models::GeneratorFinding>,
    one_way_switches: BTreeMap<String, Option<u8>>,
    pam: Vec<crate::models::PamFinding>,
}

#[cfg(feature = "local-scan")]
/// Single source for the panic warning — the message cannot drift from the
/// scanner set again (R23-34).
const PERSISTENCE_IDS: &str = "SEC-042/043/044/049/050/051/052/053/054/055/056/057";

#[cfg(feature = "local-scan")]
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

        let deep = args.deep;
        let verdict_cache = args.verdict_cache.clone();
        let security_task = tokio::task::spawn_blocking(move || {
            crate::scanners::security::gather_security_info(deep, verdict_cache)
        });

        let packages_task = tokio::task::spawn_blocking(move || {
            crate::scanners::packages::gather_packages_info(want_refresh_packages)
        });

        // Persistence family – see PERSISTENCE_IDS.
        let persistence_task = tokio::task::spawn_blocking(move || {
            let (core_pattern, modules_disabled, lockdown) =
                crate::scanners::kernel_facts::gather_kernel_facts();
            let one_way_switches = crate::scanners::kernel_facts::gather_one_way_switches();
            PersistenceScan {
                preload: crate::scanners::preload::scan_ld_preload(),
                core_pattern,
                modules_disabled,
                lockdown,
                exec_start: crate::scanners::exec_provenance::scan_exec_provenance(deep),
                ld_so_conf: crate::scanners::ld_so_conf::scan_ld_so_conf(),
                generators: crate::scanners::generators::scan_generators(),
                one_way_switches,
                pam: crate::scanners::pam::scan_pam(),
            }
        });

        let (
            host_res,
            dbs_res,
            network_res,
            storage_res,
            security_res,
            topology_info,
            packages_res,
            persistence_res,
        ) = tokio::join!(
            host_task,
            dbs_task,
            network_task,
            storage_task,
            security_task,
            tokio::spawn(crate::scanners::runtime::gather_runtime_topology()),
            packages_task,
            persistence_task,
        );

        let mut scan_warnings = Vec::new();
        let mut failed_scanners = Vec::new();

        let host_info = host_res.unwrap_or_else(|e| {
            warn!(scanner = "host", error = ?e, "scanner panicked");
            scan_warnings.push("host scanner panicked".to_string());
            failed_scanners.push("host".to_string());
            crate::models::HostInfo {
                hostname: "unknown".to_string(),
                ..Default::default()
            }
        });
        let dbs = dbs_res.unwrap_or_else(|e| {
            warn!(scanner = "databases", error = ?e, "scanner panicked");
            scan_warnings.push("databases scanner panicked".to_string());
            failed_scanners.push("databases".to_string());
            vec![]
        });
        let network_info = network_res.unwrap_or_else(|e| {
            warn!(scanner = "network", error = ?e, "scanner panicked");
            scan_warnings.push("network scanner panicked".to_string());
            failed_scanners.push("network".to_string());
            crate::models::NetworkInfo::default()
        });
        let storage_info = storage_res.unwrap_or_else(|e| {
            warn!(scanner = "storage", error = ?e, "scanner panicked");
            scan_warnings.push("storage scanner panicked".to_string());
            failed_scanners.push("storage".to_string());
            crate::models::StorageInfo::default()
        });
        let security_info = security_res.unwrap_or_else(|e| {
            warn!(scanner = "security", error = ?e, "scanner panicked");
            scan_warnings.push(
                "security scanner panicked — SSH/sudo/sysctl fields NOT verified".to_string(),
            );
            failed_scanners.push("security".to_string());
            crate::models::SecurityInfo::default()
        });
        let packages_info = packages_res.unwrap_or_else(|e| {
            warn!(scanner = "packages", error = ?e, "scanner panicked");
            scan_warnings.push("packages scanner panicked".to_string());
            failed_scanners.push("packages".to_string());
            crate::models::PackagesInfo::default()
        });

        let topology_info = topology_info.unwrap_or_else(|e| {
            warn!(scanner = "docker", error = ?e, "docker scanner panicked");
            scan_warnings.push("docker scanner panicked".to_string());
            failed_scanners.push("docker".to_string());
            crate::models::TopologyInfo::default()
        });

        let p = persistence_res.unwrap_or_else(|e| {
            warn!(scanner = "persistence", error = ?e, "persistence scanner panicked");
            scan_warnings.push(format!(
                "persistence scanner panicked — {PERSISTENCE_IDS} NOT verified"
            ));
            failed_scanners.push("persistence".to_string());
            PersistenceScan::default()
        });

        // Drain coverage after all scanners finished – scope is attached here,
        // not in the scanners, because they run on arbitrary blocking threads.
        let coverage_warnings = crate::coverage::drain_scoped(&scan_id);

        let duration_secs = start.elapsed().as_secs_f64();

        let mut report = AgentReport {
            scan_id,
            timestamp: Utc::now().to_rfc3339(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            duration_secs,
            risk_score: 0,
            is_root_execution: is_root,
            scan_warnings,
            coverage_warnings,
            failed_scanners,
            remote_privileged: None,
            host: host_info,
            databases: dbs,
            network: network_info,
            storage: storage_info,
            topology: topology_info,
            security: security_info,
            packages: packages_info,
            scoring_version: crate::scoring::SCORING_VERSION,
            self_integrity: None,
        };

        report.security.preload_injections = p.preload;
        report.security.core_pattern = p.core_pattern;
        report.security.modules_disabled = p.modules_disabled;
        report.security.lockdown = p.lockdown;
        report.security.exec_start_injections = p.exec_start;
        report.security.ld_so_conf_injections = p.ld_so_conf;
        report.security.generators = p.generators;
        report.security.one_way_switches = p.one_way_switches;
        report.security.pam_injections = p.pam;

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

// ── Snapshot run (now fully russh‑based) ───────────────────

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

        match run_remote_scan_russh(&host, &audit_args).await {
            Ok(report) => report,
            Err(e) => {
                eprintln!("Failed to scan remote host {host_for_msg}: {e}");
                return 1;
            }
        }
    } else if let Some(ref hosts_path) = args.audit.hosts {
        let contents = match std::fs::read_to_string(hosts_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "Failed to read hosts file {:?}: {} — refusing to silently fall back to a LOCAL scan",
                    hosts_path, e
                );
                return 1;
            }
        };
        let first_host = contents
            .lines()
            .find(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .map(|l| l.trim().to_string());
        if let Some(host) = first_host {
            let host_clone = host.clone();
            let audit_args = args.audit.clone();
            match run_remote_scan_russh(&host_clone, &audit_args).await {
                Ok(report) => report,
                Err(e) => {
                    eprintln!("Failed to scan remote host {host}: {e}");
                    return 1;
                }
            }
        } else {
            eprintln!(
                "hosts file {:?} contains no usable host entries",
                hosts_path
            );
            return 1;
        }
    } else {
        #[cfg(feature = "local-scan")]
        {
            run_local_scan_async(&args.audit).await
        }
        #[cfg(not(feature = "local-scan"))]
        {
            eprintln!(
                "Local audit is not supported on this platform. Please provide a remote host."
            );
            return 1;
        }
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

// ── Helper: remote scan via russh (used by snapshot) ──────

async fn run_remote_scan_russh(host: &str, args: &AuditArgs) -> Result<AgentReport, String> {
    let ssh_key_expanded = shellexpand::tilde(&args.ssh_key).to_string();

    let (stdout, coverage) = crate::ssh_engine::run_remote_scan_russh(
        host,
        &args.ssh_user,
        &ssh_key_expanded,
        args.remote_path.as_deref(),
        None, // sudo_pass
        args.copy_binary,
        args.keep_binary,
        args.local_binary.as_deref(),
        args.deep,
        args.remote_timeout_secs,
        None, // upload_pb
    )
    .await
    .map_err(|e| format!("russh scan failed: {e}"))?;

    let mut report = serde_json::from_slice::<AgentReport>(&stdout)
        .map_err(|e| format!("remote output is not a valid AgentReport: {e}"))?;
    report.coverage_warnings.extend(coverage.notes);
    Ok(report)
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
