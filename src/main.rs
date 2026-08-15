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
#[cfg(feature = "local-scan")]
mod verdict_cache;

use crate::utils::host_budget_secs;
use clap::{CommandFactory, FromArgMatches};
use cli::{AuditArgs, Cli, Commands, OutputFormat};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
#[cfg(feature = "local-scan")]
use models::SelfIntegrityReport;
use models::{AgentReport, HostDiffStatus};
use runner::snapshot_run;
#[cfg(feature = "local-scan")]
use runner::{is_local_host, run_local_scan_async};
use scoring::*;
use std::collections::HashSet;
use std::io::Write;
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

// ---------------------------------------------------------------------------
// Fleet teardown constants (R19V2‑01 / R19V2‑04)
// ---------------------------------------------------------------------------
/// Grace period for fleet teardown after first Ctrl‑C.
pub(crate) const FLEET_TEARDOWN_GRACE: Duration = Duration::from_secs(10);
/// Extra margin before the **post‑signal** watchdog kills the process.
const HARD_EXIT_MARGIN: Duration = Duration::from_secs(5);
/// Time allowed for the JSONL writer to drain after the scan loop finishes.
pub(crate) const JSONL_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Exit code for invalid CLI usage. Outside the 0..=3 verdict band (R25-36).
const EXIT_USAGE: i32 = 64; // sysexits.h EX_USAGE

/// Exit code for an incomplete scan: one or more scanners failed.
/// Distinct from non-root degradation (2) so CI can tell "no verdict"
/// from "verdict degraded by privileges" (R25-26 tail).
const EXIT_INCOMPLETE: i32 = 4;

/// Exit code for a scan interrupted by SIGINT/SIGTERM.
const EXIT_INTERRUPT: i32 = 130;

// R25-60: a panic is not an interrupt; use EX_SOFTWARE instead of 130.
/// Exit code for an internal error (panic), distinct from SIGINT (130).
const EXIT_INTERNAL_ERROR: i32 = 70; // sysexits.h EX_SOFTWARE

// R25-56: Fleet aggregation compares verdicts, not numeric exit codes.
/// Numeric exit codes are a PUBLIC CONTRACT and are NOT ordered by severity:
/// 4 (incomplete) is less severe than 3 (compromise). Fleet aggregation must
/// therefore compare verdicts and map to a code once, never `max()` the codes.
fn verdict_rank(v: Verdict) -> u8 {
    match v {
        Verdict::Clean => 0,
        Verdict::Critical => 1,
        Verdict::Incomplete => 2,
        Verdict::Compromised => 3,
    }
}

/// Return the more severe of two verdicts.
fn worse_of(a: Verdict, b: Verdict) -> Verdict {
    if verdict_rank(a) >= verdict_rank(b) {
        a
    } else {
        b
    }
}

/// Extract the verdict for a single report without mapping to an exit code.
/// This is the function fleet aggregation uses; it calls `evaluate` once.
fn compute_verdict(report: &AgentReport) -> Verdict {
    let findings = scoring::evaluate(report);
    scoring::verdict_from_findings(&findings, &report.failed_scanners)
}

fn is_running_as_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

fn exit_code_for_verdict(verdict: Verdict, is_root: bool, warnings_present: bool) -> i32 {
    match verdict {
        Verdict::Compromised => 3,
        Verdict::Incomplete => EXIT_INCOMPLETE,
        Verdict::Critical => {
            if !is_root {
                2
            } else {
                1
            }
        }
        Verdict::Clean => {
            if !is_root || warnings_present {
                2
            } else {
                0
            }
        }
    }
}

#[cfg_attr(not(feature = "local-scan"), allow(dead_code))]
fn compute_exit_code(report: &AgentReport) -> i32 {
    let verdict = compute_verdict(report);

    match verdict {
        Verdict::Compromised => {
            warn!(
                "ACTIVE COMPROMISE indicators detected — see SEC-015/016/017/019/020/021/022/023/024 or DOCK-010; exiting 3"
            );
            3
        }
        Verdict::Incomplete => {
            if report.failed_scanners.is_empty() {
                warn!("scan incomplete; exiting 4");
            } else {
                warn!(
                    failed = ?report.failed_scanners,
                    "one or more scanners failed — verdict incomplete, exiting 4"
                );
            }
            EXIT_INCOMPLETE
        }
        Verdict::Critical => {
            if !report.is_root_execution {
                warn!(
                    "not running as root AND critical issues detected – results may be incomplete, re-run with sudo."
                );
                2
            } else {
                1
            }
        }
        Verdict::Clean => {
            if !report.is_root_execution {
                warn!("not running as root – results may be incomplete.");
                2
            } else if !report.scan_warnings.is_empty() {
                // Superset of failed_scanners: a warning without a panic still
                // means the report is not a complete observation (R25-45).
                warn!(warnings = ?report.scan_warnings, "scan produced warnings — degraded");
                2
            } else {
                0
            }
        }
    }
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
            // R25-12: --keep-binary exists to avoid re-uploading. With mktemp
            // staging the next run picks a fresh random directory, so nothing
            // is ever reused: the flag only accumulates leftovers. Refuse the
            // combination up front.
            if args.keep_binary && args.copy_binary && args.remote_path.is_none() {
                eprintln!(
                    "--keep-binary requires an explicit --remote-path: with the default \
                     mktemp staging the kept binary can never be reused, only left behind"
                );
                return EXIT_USAGE;
            }

            let mut hosts: Vec<String> = Vec::new();
            for h in &args.host {
                hosts.push(h.clone());
            }
            // R24-13: an unreadable --hosts file must never degrade into a
            // local scan — the object of the audit would silently change.
            if let Some(ref path) = args.hosts {
                let contents = match std::fs::read_to_string(path) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!(
                            "Failed to read hosts file {:?}: {} — refusing to silently fall back to a LOCAL scan",
                            path, e
                        );
                        return EXIT_USAGE;
                    }
                };
                let before = hosts.len();
                for line in contents.lines() {
                    let h = line.trim();
                    if !h.is_empty() && !h.starts_with('#') {
                        hosts.push(h.to_string());
                    }
                }
                if hosts.len() == before && args.host.is_empty() {
                    eprintln!("hosts file {:?} contains no usable host entries", path);
                    return EXIT_USAGE;
                }
            }

            let mut seen = HashSet::new();
            hosts.retain(|h| seen.insert(h.clone()));

            // If local-scan is disabled (non-Linux), reject local-only audits early.
            if !hosts.is_empty() {
                let mut remote = Vec::new();
                #[cfg(feature = "local-scan")]
                let mut local = Vec::new();
                #[cfg(feature = "local-scan")]
                let mut local_seen = false;
                for h in hosts {
                    #[cfg(feature = "local-scan")]
                    if is_local_host(&h) {
                        if !local_seen {
                            local.push(h);
                            local_seen = true;
                        }
                        continue;
                    }
                    remote.push(h);
                }

                // Resolve sudo password once (before any progress bars)
                let sudo_pass: Option<Arc<Zeroizing<String>>> = if args.ask_sudo_pass {
                    match ssh_engine::resolve_sudo_password() {
                        Ok(p) => Some(Arc::new(p)),
                        Err(e) => {
                            eprintln!("Error: {e}");
                            return EXIT_USAGE;
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
                        let mut worst_verdict: Option<Verdict> = None;
                        let mut any_non_root = false;
                        let mut any_warnings = false;
                        while let Some(report) = rx.blocking_recv() {
                            let verdict = compute_verdict(&report);
                            worst_verdict = Some(match worst_verdict {
                                None => verdict,
                                Some(current) => worse_of(current, verdict),
                            });
                            any_non_root |= !report.is_root_execution;
                            any_warnings |= !report.scan_warnings.is_empty();

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
                        let exit_code = match worst_verdict {
                            Some(v) => exit_code_for_verdict(v, any_non_root, any_warnings),
                            None => 2, // no reports written
                        };
                        (written, exit_code, io_errors)
                    }))
                } else {
                    None
                };

                // R19V5-04: flag to return 130 after drain when local scan is
                // interrupted by the user in a mixed (local+remote) run.
                // Without `local-scan` the only assignment is compiled out, so the
                // `mut` is genuinely redundant there — but only there.
                #[cfg_attr(not(feature = "local-scan"), allow(unused_mut))]
                let mut interrupted = false;

                // Process local hosts synchronously (no SSH needed)
                #[cfg(feature = "local-scan")]
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
                        remote_path: None,
                        local_binary: None,
                        ..args.clone()
                    };

                    // Self‑integrity preflight
                    let integrity = scanners::self_integrity::run_self_integrity_check();

                    // R19V5-04: race‑free cancellation of the local scan.
                    let mut local_report = tokio::select! {
                        r = run_local_scan_async(&a) => r,
                        _ = shutdown_notify.notified() => {
                            local_spinner.finish_and_clear();
                            eprintln!(
                                "Local scan interrupted — no report emitted \
                                 (partial state would be indistinguishable from real findings)."
                            );
                            crate::utils::terminate_registered_children();
                            for w in crate::coverage::drain_scoped("local-interrupted") {
                                warn!("{w}");
                            }
                            interrupted = true;
                            break;
                        }
                    };

                    // (SEC-042/043/044 scanners run inside run_local_scan_async —
                    //  no duplication here.)

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
                        let multi = multi.clone();

                        join_set.spawn(async move {
                            // R13-03: explicit permit error handling.
                            let Ok(_permit) = sem.acquire_owned().await else {
                                return None;
                            };

                            // R16 hardening: validation must not depend on the presence
                            // of a sudo password.
                            if let Err(e) = runner::validate_host(&host) {
                                warn!("{e}");
                                return None;
                            }
                            if let Err(e) = runner::validate_ssh_user(&a.ssh_user) {
                                warn!("{e}");
                                return None;
                            }
                            if let Some(rp) = &a.remote_path
                                && let Err(e) = runner::validate_remote_path(rp)
                            {
                                warn!("{e}");
                                return None;
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
                                    a.remote_path.as_deref(),
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
                                    Ok((stdout, coverage)) => {
                                        match serde_json::from_slice::<AgentReport>(&stdout) {
                                            Ok(mut report) => {
                                                // R25-14: remote coverage belongs
                                                // in this host's report, not in
                                                // orchestrator's local sink.
                                                report.coverage_warnings.extend(coverage.notes);
                                                report.remote_privileged = coverage.privileged;
                                                Some(report)
                                            }
                                            Err(e) => {
                                                let raw_preview: String =
                                                    String::from_utf8_lossy(&stdout)
                                                        .chars()
                                                        .take(200)
                                                        .collect();
                                                let preview =
                                                    crate::utils::sanitize_for_log(&raw_preview);
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
                                        // Progress bars continuously redraw stderr.
                                        // Suspend them to ensure the error stays visible.
                                        // R25-18: never panic on EPIPE when stderr is closed early.
                                        multi.suspend(|| {
                                            let _ = writeln!(
                                                std::io::stderr(),
                                                "[error] russh scan failed for {host}: {e}"
                                            );
                                        });
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

                    // Process results with two-phase shutdown on Ctrl‑C
                    loop {
                        tokio::select! {
                            biased;
                            _ = shutdown_notify.notified() => {
                                // Phase 1: drain in-flight hosts; queued tasks abort
                                // footprint-free at the semaphore.
                                let deadline = tokio::time::Instant::now() + FLEET_TEARDOWN_GRACE;
                                loop {
                                    tokio::select! {
                                        biased;
                                        // Second Ctrl‑C – abort immediately
                                        _ = shutdown_notify.notified() => {
                                            warn!("second interrupt — aborting all tasks");
                                            join_set.abort_all();
                                            break;
                                        }
                                        // Grace period expired – abort remaining tasks
                                        _ = tokio::time::sleep_until(deadline) => {
                                            warn!("teardown grace expired — aborting remaining tasks; remote binaries may persist");
                                            join_set.abort_all();
                                            break;
                                        }
                                        res = join_set.join_next() => {
                                            match res {
                                                Some(Ok(Some(report))) => {
                                                    if let Some(s) = &tx {
                                                        let _ = s.send(report).await;
                                                    } else {
                                                        reports.push(report);
                                                    }
                                                }
                                                Some(Ok(None)) => {}
                                                Some(Err(e)) if e.is_panic() => warn!("scan task panicked during teardown: {e}"),
                                                Some(Err(e)) => warn!("scan task failed during teardown: {e}"),
                                                None => break, // All tasks finished cleanly
                                            }
                                        }
                                    }
                                }
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
                            }
                        }
                    }

                    // R15-01: single sequential drain point after all fleet tasks complete.
                    for warning in crate::coverage::drain_scoped("fleet-orchestrator") {
                        warn!("{warning}");
                    }
                }

                if let Some(tx) = tx {
                    drop(tx);
                }
                if let Some(writer) = writer_task {
                    let joined = if shutdown.load(Ordering::Relaxed) {
                        match tokio::time::timeout(JSONL_DRAIN_TIMEOUT, writer).await {
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
                        Ok((written, exit_code, io_errors)) => {
                            if io_errors > 0 {
                                warn!(
                                    written,
                                    io_errors,
                                    "JSONL output incomplete — returning degraded exit code"
                                );
                                return 2;
                            }
                            if interrupted {
                                return EXIT_INTERRUPT;
                            }
                            return if written == 0 { 2 } else { exit_code };
                        }
                        Err(_) => {
                            warn!("JSONL writer task failed");
                            return 2;
                        }
                    }
                }

                // R19V5-04: honour interruption when local scan was cancelled
                // in a streaming-less run.
                if interrupted {
                    return EXIT_INTERRUPT;
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

                let mut worst_verdict: Option<Verdict> = None;
                let mut any_non_root = false;
                let mut any_warnings = false;
                for report in &reports {
                    let verdict = compute_verdict(report);
                    worst_verdict = Some(match worst_verdict {
                        None => verdict,
                        Some(current) => worse_of(current, verdict),
                    });
                    any_non_root |= !report.is_root_execution;
                    any_warnings |= !report.scan_warnings.is_empty();
                }
                let exit_code = match worst_verdict {
                    Some(v) => exit_code_for_verdict(v, any_non_root, any_warnings),
                    None => 2,
                };

                if let Err(e) = output::output_multi(
                    &reports,
                    &args.format,
                    args.output.as_deref().map(std::path::Path::new),
                    verbose,
                ) {
                    warn!("output error: {e}");
                    return 2;
                }

                return exit_code;
            }

            // Single local scan (no hosts file or empty hosts)
            #[cfg(feature = "local-scan")]
            {
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
                let mut report = tokio::select! {
                    r = run_local_scan_async(&args) => r,
                    _ = shutdown_notify.notified() => {
                        local_spinner.finish_and_clear();
                        eprintln!(
                            "Local scan interrupted — no report emitted \
                             (partial state would be indistinguishable from real findings)."
                        );
                        // Cancelling the future does not stop spawn_blocking scanners;
                        // their helpers would outlive us without our timeout.
                        crate::utils::terminate_registered_children();
                        for w in crate::coverage::drain_scoped("local-interrupted") {
                            warn!("{w}");
                        }
                        return EXIT_INTERRUPT;
                    }
                };

                // (SEC-042/043/044 are handled by run_local_scan_async)

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
            #[cfg(not(feature = "local-scan"))]
            {
                eprintln!(
                    "Local audit is not supported on this platform. Use --host to scan a remote host."
                );
                EXIT_USAGE
            }
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

    let matches = match Cli::command().try_get_matches() {
        Ok(m) => m,
        Err(e) => {
            let _ = e.print();
            std::process::exit(EXIT_USAGE);
        }
    };

    let cli = match Cli::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            std::process::exit(EXIT_USAGE);
        }
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_notify = Arc::new(Notify::new());
    let shutdown_clone = shutdown.clone();
    let shutdown_notify_clone = shutdown_notify.clone();

    let cmd_handle = tokio::spawn(run_command(cli, shutdown_clone, shutdown_notify_clone));

    // ---- Signal handler (runs for the entire lifetime) ----
    let notify_sig = shutdown_notify.clone();
    let flag_sig = shutdown.clone();
    tokio::spawn(async move {
        let mut sig_int = signal::unix::signal(signal::unix::SignalKind::interrupt())
            .expect("failed to install SIGINT handler");
        let mut sig_term = signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        let mut hits = 0u8;
        loop {
            tokio::select! {
                _ = sig_int.recv()  => {}
                _ = sig_term.recv() => {}
            }
            hits += 1;
            flag_sig.store(true, Ordering::Relaxed);
            notify_sig.notify_one();
            match hits {
                1 => {
                    eprintln!(
                        "Interrupt received — finishing in-flight hosts (grace {:?})",
                        FLEET_TEARDOWN_GRACE
                    );
                    // Hard ceiling from the moment of first signal.
                    tokio::spawn(async move {
                        tokio::time::sleep(FLEET_TEARDOWN_GRACE + HARD_EXIT_MARGIN).await;
                        eprintln!("Graceful shutdown timed out, forcing exit.");
                        // Kill any remaining helpers so they don't become orphans.
                        crate::utils::terminate_registered_children();
                        std::process::exit(EXIT_INTERRUPT);
                    });
                }
                2 => {
                    eprintln!("Second interrupt — aborting remaining tasks");
                    // Now we are no longer promising a clean report — helpers can be killed.
                    crate::utils::terminate_registered_children();
                }
                _ => {
                    crate::utils::terminate_registered_children();
                    eprintln!("Third interrupt — forcing exit");
                    std::process::exit(EXIT_INTERRUPT);
                }
            }
        }
    });

    let exit_code = cmd_handle.await.unwrap_or_else(|join_err| {
        if join_err.is_panic() {
            eprintln!("Main task panicked");
            EXIT_INTERNAL_ERROR
        } else {
            1
        }
    });

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
            failed_scanners: Vec::new(),
            remote_privileged: None,
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

    #[test]
    fn exit_code_4_when_scanner_failed() {
        let mut r = minimal_report();
        r.network.firewall_active = true;
        r.security.ssh_root_login_enabled = false;
        r.host.backup_tools = vec!["restic".to_string()];
        r.host.ntp_synchronized = true;
        r.failed_scanners = vec!["security".to_string()];

        assert_eq!(compute_exit_code(&r), EXIT_INCOMPLETE);
    }

    #[test]
    fn hard_exit_ceiling_covers_grace_plus_drain() {
        assert!(
            FLEET_TEARDOWN_GRACE + HARD_EXIT_MARGIN > FLEET_TEARDOWN_GRACE + JSONL_DRAIN_TIMEOUT,
            "watchdog must not fire before the JSONL writer has drained"
        );
    }
}
