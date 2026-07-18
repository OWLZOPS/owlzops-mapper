mod cli;
mod compare;
mod coverage;
mod exporters;
mod known_hosts;
mod models;
mod output;
mod runner;
mod safe_io;
mod scanners;
mod scoring;
mod self_identity;
mod ssh_engine;
mod ui;
mod utils;
mod verdict_cache;

use crate::utils::host_budget_secs;
use clap::Parser;
use cli::{AuditArgs, Cli, Commands, OutputFormat};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use models::{AgentReport, HostDiffStatus, SelfIntegrityReport};
use runner::{is_local_host, run_local_scan_async, snapshot_run};
use scoring::*;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::signal;
use tokio::sync::{Notify, Semaphore};
use tracing::warn;
use zeroize::Zeroizing;

// sanitize hostname when printing to terminal in compare paths
use crate::ui::sanitize_terminal as st;

fn is_running_as_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

fn compute_exit_code(report: &AgentReport) -> i32 {
    let flags = CriticalFlags::from_report(report);

    if flags.compromised_host {
        warn!(
            "ACTIVE COMPROMISE indicators detected — see SEC-015/016/017/019/020/021/022/023/024 or DOCK-010; exiting 3"
        );
        return 3;
    }

    if !report.is_root_execution {
        if flags.has_critical() {
            warn!(
                "not running as root AND critical issues detected – results may be incomplete, re-run with sudo."
            );
        } else {
            warn!("not running as root – results may be incomplete.");
        }
        return 2;
    }

    if !report.scan_warnings.is_empty() {
        warn!(warnings = ?report.scan_warnings, "one or more scanners failed – report may be incomplete");
        return 2;
    }

    if flags.has_critical() { 1 } else { 0 }
}

fn raise_nofile_limit() {
    let soft_desired = 4096u64;
    let hard_desired = 65536u64;
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) } == 0
        && limits.rlim_cur < soft_desired
    {
        limits.rlim_cur = soft_desired;
        if limits.rlim_max < hard_desired && limits.rlim_cur > limits.rlim_max {
            limits.rlim_max = hard_desired;
        }
        unsafe {
            libc::setrlimit(libc::RLIMIT_NOFILE, &limits);
        }
    }
}

async fn run_command(cli: Cli, shutdown: Arc<AtomicBool>, shutdown_notify: Arc<Notify>) -> i32 {
    let verbose = cli.verbose; // carry verbose flag into output functions
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

                // Resolve sudo password once (before any progress bars)
                let sudo_pass: Option<Arc<Zeroizing<String>>> = if args.ask_sudo_pass {
                    match ssh_engine::resolve_sudo_password() {
                        Ok(p) => Some(Arc::new(p)),
                        Err(e) => {
                            eprintln!("Error: {e}");
                            return 2;
                        }
                    }
                } else {
                    None
                };

                let use_streaming = args.format == OutputFormat::Json && args.output.is_some();

                let mut reports: Vec<AgentReport> = Vec::new();
                let (tx, rx_chan) = if use_streaming {
                    let (tx, rx) = tokio::sync::mpsc::channel::<AgentReport>(256);
                    (Some(tx), Some(rx))
                } else {
                    (None, None)
                };

                // Fail-fast: create the output file before launching any scan
                let output_path = args.output.clone();
                let mut jsonl_file = if use_streaming {
                    match std::fs::File::create(output_path.as_deref().unwrap_or("report.jsonl")) {
                        Ok(f) => Some(f),
                        Err(e) => {
                            eprintln!("Cannot create output file: {e}");
                            return 2;
                        }
                    }
                } else {
                    None
                };

                let writer_task = if let (Some(rx), Some(file)) = (rx_chan, jsonl_file.take()) {
                    Some(tokio::task::spawn_blocking(move || {
                        use std::io::Write;
                        let mut file = std::io::BufWriter::new(file);
                        let mut rx = rx;
                        let mut written = 0usize;
                        let mut io_errors = 0usize;
                        let mut worst = 0i32;
                        while let Some(report) = rx.blocking_recv() {
                            worst = worst.max(compute_exit_code(&report));
                            match serde_json::to_string(&report) {
                                Ok(json) => match writeln!(file, "{json}") {
                                    Ok(()) => written += 1,
                                    Err(e) => {
                                        io_errors += 1;
                                        warn!(error = %e, "JSONL write failed — report lost");
                                    }
                                },
                                Err(e) => warn!(error = %e, "skipping unserializable report"),
                            }
                        }
                        if let Err(e) = file.flush() {
                            io_errors += 1;
                            warn!(error = %e, "JSONL flush failed — tail records may be lost");
                        }
                        (written, worst, io_errors)
                    }))
                } else {
                    None
                };

                // Process local hosts synchronously (no SSH needed)
                for _host in local {
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }

                    let local_spinner = ProgressBar::new_spinner();
                    local_spinner.set_style(
                        ProgressStyle::with_template("{spinner:.cyan} {msg} [{elapsed_precise}]")
                            .unwrap()
                            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"]),
                    );
                    if args.deep {
                        local_spinner
                            .set_message("Deep forensic scan in progress (may take 10–30s)");
                    } else {
                        local_spinner.set_message("Auditing local system...");
                    }
                    local_spinner.enable_steady_tick(Duration::from_millis(100));

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

                    // Self‑integrity preflight
                    let integrity = scanners::self_integrity::run_self_integrity_check();
                    let mut local_report = run_local_scan_async(&a).await;
                    local_report.self_integrity = Some(SelfIntegrityReport {
                        compromised: integrity.compromised,
                        warnings: integrity.warnings,
                    });

                    local_spinner.finish_and_clear();

                    if let Some(tx) = &tx {
                        let _ = tx.send(local_report).await;
                    } else {
                        reports.push(local_report);
                    }
                }

                // Process remote hosts with JoinSet + Semaphore + global timeout
                if !remote.is_empty() {
                    // ========== MULTIPROGRESS SETUP ==========
                    let multi = MultiProgress::new();

                    // 1. Upload progress bar (only when we copy a binary)
                    let upload_bar = if sudo_pass.is_some() && args.copy_binary {
                        let pb = multi.add(ProgressBar::new(0));
                        pb.set_style(
                            ProgressStyle::default_bar()
                                .template(
                                    "{bytes:>9}/{total_bytes:9} [{wide_bar:.cyan/blue}] {msg}",
                                )
                                .unwrap()
                                .progress_chars("##-"),
                        );
                        pb.set_message("uploading binary");
                        Some(pb)
                    } else {
                        None
                    };

                    // 2. Scan spinner
                    let scan_bar = multi.add(ProgressBar::new_spinner());
                    scan_bar.set_style(
                        ProgressStyle::with_template("{spinner:.cyan} {msg} [{elapsed_precise}]")
                            .unwrap()
                            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"]),
                    );
                    if args.deep {
                        scan_bar.set_message("Deep forensic scan in progress (may take 10–30s)");
                    } else {
                        scan_bar.set_message("Auditing systems...");
                    }
                    scan_bar.enable_steady_tick(Duration::from_millis(100));
                    let start_time = Instant::now();
                    // ==========================================

                    let semaphore = Arc::new(Semaphore::new(args.max_concurrent));
                    let mut join_set = tokio::task::JoinSet::new();

                    for host in remote {
                        if shutdown.load(Ordering::Relaxed) {
                            break;
                        }
                        let sem = semaphore.clone();
                        let a = AuditArgs {
                            hosts: None,
                            host: Vec::new(),
                            ..args.clone()
                        };
                        let pass = sudo_pass.clone();
                        let host_for_log = host.clone();
                        let upload_pb = upload_bar.clone();

                        join_set.spawn(async move {
                            // R13-03: explicit permit error handling.
                            // If the semaphore has been closed (future shutdown), bail out.
                            let Ok(_permit) = sem.acquire_owned().await else {
                                return None;
                            };

                            if pass.is_some() {
                                if let Err(e) = runner::validate_host(&host) {
                                    warn!("{e}");
                                    return None;
                                }
                                if let Err(e) = runner::validate_ssh_user(&a.ssh_user) {
                                    warn!("{e}");
                                    return None;
                                }
                                if let Err(e) = runner::validate_remote_path(&a.remote_path) {
                                    warn!("{e}");
                                    return None;
                                }
                            }

                            // R13-02: grace budget for teardown after timeout
                            let overall =
                                Duration::from_secs(host_budget_secs(a.remote_timeout_secs) + 35);

                            let result = tokio::time::timeout(overall, async {
                                let ssh_key_expanded = shellexpand::tilde(&a.ssh_key).to_string();

                                match ssh_engine::run_remote_scan_russh(
                                    &host,
                                    &a.ssh_user,
                                    &ssh_key_expanded,
                                    &a.remote_path,
                                    pass.as_deref(),
                                    a.copy_binary,
                                    a.keep_binary,
                                    a.local_binary.as_deref(),
                                    a.deep,
                                    a.remote_timeout_secs,
                                    upload_pb,
                                )
                                .await
                                {
                                    Ok(stdout) => {
                                        match serde_json::from_slice::<AgentReport>(&stdout) {
                                            Ok(report) => Some(report),
                                            Err(e) => {
                                                let preview: String =
                                                    String::from_utf8_lossy(&stdout)
                                                        .chars()
                                                        .take(200)
                                                        .collect();
                                                warn!(
                                                    host = %host,
                                                    error = %e,
                                                    preview = %preview,
                                                    "remote output is not a valid AgentReport"
                                                );
                                                None
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!(host = %host, error = %e, "russh scan failed");
                                        None
                                    }
                                }
                            })
                            .await;

                            match result {
                                Ok(Some(report)) => Some(report),
                                Ok(None) => None,
                                Err(_elapsed) => {
                                    warn!(host = %host_for_log, "global timeout for host");
                                    None
                                }
                            }
                        });
                    }

                    // Process results with immediate abort on shutdown signal
                    loop {
                        tokio::select! {
                            biased;
                            _ = shutdown_notify.notified() => {
                                join_set.abort_all();
                                scan_bar.finish_and_clear();
                                if let Some(pb) = &upload_bar { pb.finish_and_clear(); }
                                break;
                            }
                            res = join_set.join_next() => {
                                match res {
                                    Some(result) => {
                                        match result {
                                            Ok(Some(report)) => {
                                                if let Some(sender) = &tx {
                                                    let _ = sender.send(report).await;
                                                } else {
                                                    reports.push(report);
                                                }
                                            }
                                            Ok(None) => {}
                                            Err(e) if e.is_panic() => warn!("scan task panicked: {e}"),
                                            Err(e) => warn!("scan task failed: {e}"),
                                        }
                                    }
                                    None => {
                                        let _elapsed = start_time.elapsed();
                                        scan_bar.finish_and_clear();
                                        if let Some(pb) = &upload_bar { pb.finish_and_clear(); }
                                        break;
                                    }
                                }
                                crate::coverage::drain_and_log("fleet-orchestrator");
                            }
                        }
                    }
                }

                if let Some(tx) = tx {
                    drop(tx);
                }
                if let Some(writer) = writer_task {
                    let joined = if shutdown.load(Ordering::Relaxed) {
                        match tokio::time::timeout(Duration::from_secs(2), writer).await {
                            Ok(r) => r,
                            Err(_) => {
                                warn!(
                                    "JSONL writer timed out during shutdown, output may be incomplete"
                                );
                                return 2;
                            }
                        }
                    } else {
                        writer.await
                    };
                    match joined {
                        Ok((written, worst, io_errors)) => {
                            if io_errors > 0 {
                                warn!(
                                    written,
                                    io_errors,
                                    "JSONL output incomplete — returning degraded exit code"
                                );
                                return 2;
                            }
                            return if written == 0 { 2 } else { worst };
                        }
                        Err(_) => {
                            warn!("JSONL writer task failed");
                            return 2;
                        }
                    }
                }

                // Fallback to legacy multi-host output
                if reports.is_empty() {
                    warn!("fleet scan produced no reports — all hosts failed");
                    if let Err(e) = output::output_multi(
                        &reports,
                        &args.format,
                        args.output.as_deref().map(std::path::Path::new),
                        verbose,
                    ) {
                        warn!("output error: {e}");
                    }
                    return 2;
                }

                if let Err(e) = output::output_multi(
                    &reports,
                    &args.format,
                    args.output.as_deref().map(std::path::Path::new),
                    verbose,
                ) {
                    warn!("output error: {e}");
                    return 2;
                }

                let worst = reports.iter().map(compute_exit_code).max().unwrap_or(0);
                return worst;
            }

            // Single local scan (no hosts file or empty hosts)
            let local_spinner = ProgressBar::new_spinner();
            local_spinner.set_style(
                ProgressStyle::with_template("{spinner:.cyan} {msg} [{elapsed_precise}]")
                    .unwrap()
                    .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"]),
            );
            if args.deep {
                local_spinner.set_message("Deep forensic scan in progress (may take 10–30s)");
            } else {
                local_spinner.set_message("Auditing local system...");
            }
            local_spinner.enable_steady_tick(Duration::from_millis(100));

            // Self‑integrity preflight
            let integrity = scanners::self_integrity::run_self_integrity_check();
            let mut report = run_local_scan_async(&args).await;
            report.self_integrity = Some(SelfIntegrityReport {
                compromised: integrity.compromised,
                warnings: integrity.warnings,
            });

            local_spinner.finish_and_clear();

            let exit_code = compute_exit_code(&report);
            if let Err(e) = output::output_single(
                &report,
                &args.format,
                args.output.as_deref().map(std::path::Path::new),
                verbose,
            ) {
                warn!("output error: {e}");
                return 2;
            }
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

            match args.format {
                OutputFormat::Text => compare::print_diff_terminal(&diff),
                OutputFormat::Json => {
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
                OutputFormat::Xlsx => {
                    let path = args.output.unwrap_or_else(|| {
                        eprintln!("Error: --output is required for Excel format");
                        std::process::exit(1);
                    });
                    compare::write_diff_xlsx(&diff, &path.to_string_lossy()).unwrap_or_else(|e| {
                        eprintln!("Failed to write Excel diff: {e}");
                        std::process::exit(1);
                    });
                    println!("Diff Excel written to {}", path.display());
                }
            }
            0
        }

        Commands::Compare(cmp_args) => {
            let before_data = std::fs::read_to_string(&cmp_args.before).unwrap_or_else(|e| {
                eprintln!("Failed to read 'before' file: {e}");
                std::process::exit(1);
            });
            let after_data = std::fs::read_to_string(&cmp_args.after).unwrap_or_else(|e| {
                eprintln!("Failed to read 'after' file: {e}");
                std::process::exit(1);
            });

            if cmp_args.multi_host {
                let parse_array = |data: &str, label: &str| -> Vec<AgentReport> {
                    if let Ok(reports) = serde_json::from_str::<Vec<AgentReport>>(data) {
                        return reports;
                    }
                    if let Ok(report) = serde_json::from_str::<AgentReport>(data) {
                        return vec![report];
                    }
                    let jsonl: Vec<AgentReport> = data
                        .lines()
                        .filter(|l| !l.trim().is_empty())
                        .filter_map(|l| serde_json::from_str(l).ok())
                        .collect();
                    if !jsonl.is_empty() {
                        return jsonl;
                    }
                    eprintln!("Invalid JSON in '{}' file", label);
                    std::process::exit(1);
                };
                let before = parse_array(&before_data, "before");
                let after = parse_array(&after_data, "after");
                let diffs = compare::compare_multi(&before, &after);

                match cmp_args.format {
                    OutputFormat::Text => {
                        let changed: Vec<_> = diffs
                            .iter()
                            .filter(|d| !d.diff.changes.is_empty())
                            .collect();
                        let unchanged = diffs.len() - changed.len();
                        println!(
                            "Fleet drift: {} host(s) — {} changed, {} unchanged",
                            diffs.len(),
                            changed.len(),
                            unchanged
                        );
                        for mh in &changed {
                            let tag = match mh.status {
                                HostDiffStatus::Added => " [+ added]",
                                HostDiffStatus::Removed => " [− removed]",
                                HostDiffStatus::Compared => "",
                            };
                            println!("\nHost: {}{}", st(&mh.hostname), tag);
                            compare::print_diff_terminal(&mh.diff);
                        }
                    }
                    OutputFormat::Json => {
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
                    OutputFormat::Xlsx => {
                        let path = cmp_args.output.unwrap_or_else(|| {
                            eprintln!("Error: --output is required for Excel format");
                            std::process::exit(1);
                        });
                        crate::exporters::xlsx::write_multi_diff_xlsx(
                            &diffs,
                            &path.to_string_lossy(),
                        )
                        .unwrap_or_else(|e| {
                            eprintln!("Failed to write multi-host Excel diff: {e}");
                            std::process::exit(1);
                        });
                        println!("Multi-host diff Excel written to {}", path.display());
                    }
                }
                return 0;
            }

            let parse_report = |data: &str, label: &str| -> AgentReport {
                if let Ok(report) = serde_json::from_str::<AgentReport>(data) {
                    return report;
                }
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

            match cmp_args.format {
                OutputFormat::Text => compare::print_diff_terminal(&diff),
                OutputFormat::Json => {
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
                OutputFormat::Xlsx => {
                    let path = cmp_args.output.unwrap_or_else(|| {
                        eprintln!("Error: --output is required for Excel format");
                        std::process::exit(1);
                    });
                    compare::write_diff_xlsx(&diff, &path.to_string_lossy()).unwrap_or_else(|e| {
                        eprintln!("Failed to write Excel diff: {e}");
                        std::process::exit(1);
                    });
                    println!("Diff Excel written to {}", path.display());
                }
            }
            0
        }
    }
}

#[tokio::main]
async fn main() {
    raise_nofile_limit();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("owlzops_mapper=warn")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_notify = Arc::new(Notify::new());
    let shutdown_clone = shutdown.clone();
    let shutdown_notify_clone = shutdown_notify.clone();

    let mut cmd_handle = tokio::spawn(run_command(cli, shutdown_clone, shutdown_notify_clone));

    // Listen for SIGINT (Ctrl+C) and SIGTERM
    let mut sig_int = signal::unix::signal(signal::unix::SignalKind::interrupt())
        .expect("failed to install SIGINT handler");
    let mut sig_term = signal::unix::signal(signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");

    let exit_code = tokio::select! {
        res = &mut cmd_handle => {
            match res {
                Ok(code) => code,
                Err(join_err) => {
                    if join_err.is_panic() {
                        eprintln!("Main task panicked");
                        130
                    } else {
                        1
                    }
                }
            }
        }
        _ = sig_int.recv() => {
            eprintln!("Received interrupt signal, shutting down gracefully...");
            shutdown.store(true, Ordering::Relaxed);
            shutdown_notify.notify_one();
            crate::utils::terminate_registered_children();
            match tokio::time::timeout(Duration::from_secs(5), &mut cmd_handle).await {
                Ok(Ok(code)) => code,
                _ => {
                    eprintln!("Graceful shutdown timed out, forcing exit.");
                    130
                }
            }
        }
        _ = sig_term.recv() => {
            eprintln!("Received termination signal, shutting down gracefully...");
            shutdown.store(true, Ordering::Relaxed);
            shutdown_notify.notify_one();
            crate::utils::terminate_registered_children();
            match tokio::time::timeout(Duration::from_secs(5), &mut cmd_handle).await {
                Ok(Ok(code)) => code,
                _ => {
                    eprintln!("Graceful shutdown timed out, forcing exit.");
                    130
                }
            }
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
            coverage_warnings: Vec::new(),
            scoring_version: 1,
            self_integrity: None,
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
        assert!(scoring::score(scoring::evaluate(&r)).total <= 100);
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

    #[test]
    fn exit_code_3_on_compromise() {
        use crate::models::SuspiciousProcess;
        let mut r = minimal_report();
        r.security.suspicious_processes = vec![SuspiciousProcess {
            pid: 1337,
            name: "xmrig".into(),
            exe_path: Some("/tmp/xmrig".into()),
            ..Default::default()
        }];
        assert_eq!(compute_exit_code(&r), 3);
    }
}
