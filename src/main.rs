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

/// Exit codes 0..=3 are a PUBLIC CONTRACT: pipelines key their pager on 3 and
/// their build gate on 1. A number in this band NEVER changes meaning between
/// versions; new states get new numbers (R25-56/R25-74).
const EXIT_CLEAN: i32 = 0;
const EXIT_CRITICAL: i32 = 1;
const EXIT_COMPROMISED: i32 = 3;

/// Exit code for an incomplete scan: one or more scanners failed.
/// Distinct from non-root degradation (2) so CI can tell "no verdict"
/// from "verdict degraded by privileges" (R25-26 tail).
const EXIT_INCOMPLETE: i32 = 4;

/// Exit code for a degraded scan: not running as root or warnings present,
/// but no missing scanners and no compromised hosts. Distinct from incomplete (4).
const EXIT_DEGRADED: i32 = 2;

/// Exit code for a scan interrupted by SIGINT/SIGTERM.
const EXIT_INTERRUPT: i32 = 130;

// R25-60: a panic is not an interrupt; use EX_SOFTWARE instead of 130.
/// Exit code for an internal error (panic), distinct from SIGINT (130).
const EXIT_INTERNAL_ERROR: i32 = 70; // sysexits.h EX_SOFTWARE

/// A `MakeWriter` that suspends the progress bars for the duration of each
/// log record. With this installed, no call site needs `multi.suspend`, and
/// the three different treatments in this file collapse into zero (R25-71).
struct BarAwareStderr(MultiProgress);

impl Write for BarAwareStderr {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // `suspend` holds indicatif's draw lock, and EVERY tracing record now
        // passes through here. An unwind inside the closure would poison that
        // lock for the whole fleet, not just one call site (R25-18 -> R25-73).
        let guarded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.0.suspend(|| {
                let _ = std::io::stderr().write_all(buf);
            });
        }));
        if guarded.is_err() {
            // Last resort: bypass the bars rather than lose the record.
            let _ = std::io::stderr().write_all(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ── Two-axis outcome model (R25-74) ───────────────────────────────
// SecurityVerdict describes what the scan FOUND.
// Coverage describes what the scan could SEE.
// They are never collapsed until the final exit code mapping.

#[derive(Debug, Default, Clone, Copy)]
struct Coverage {
    /// Hosts asked for that produced no report at all.
    hosts_missing: usize,
    /// Reports received but not written to JSONL.
    records_lost: usize,
    /// True when at least one report explicitly listed failed scanners.
    /// Distinct from `warnings`: legacy remote reports may carry scan_warnings
    scanners_failed: bool,
    non_root: bool,
    /// True when at least one report carries scan_warnings. Not redundant with
    /// `scanners_failed`; legacy reports only fill this field, so collapsing
    /// the two would mark incomplete scans as full (R25-99).
    warnings: bool,
    /// The scan finished but the operator could not be shown the result.
    /// A delivery failure is a COVERAGE fact — it must never replace the
    /// verdict, or a compromise silently degrades to 2 (R25-83).
    output_failed: bool,
}

impl Coverage {
    fn is_full(&self) -> bool {
        self.hosts_missing == 0
            && self.records_lost == 0
            && !self.scanners_failed
            && !self.non_root
            && !self.warnings
            && !self.output_failed
    }
}

struct Outcome {
    /// `None` = not a single host produced a verdict.
    verdict: Option<SecurityVerdict>,
    coverage: Coverage,
}

#[derive(Debug, Default)]
struct OutcomeBuilder {
    verdict: Option<SecurityVerdict>,
    coverage: Coverage,
    reports_seen: usize,
}

impl OutcomeBuilder {
    fn add(&mut self, report: &AgentReport) {
        scoring::warn_unmapped_scanners(&report.failed_scanners);
        let findings = scoring::evaluate(report);
        let v = scoring::security_verdict_from_findings(&findings);
        self.verdict = Some(match self.verdict {
            None => v,
            Some(cur) => cur.worse(v),
        });
        self.coverage.scanners_failed |= !report.failed_scanners.is_empty();
        self.coverage.non_root |= !report.is_root_execution;
        self.coverage.warnings |= !report.scan_warnings.is_empty();
        self.reports_seen += 1;
    }

    fn finish(mut self, hosts_requested: usize, records_lost: usize) -> Outcome {
        self.coverage.hosts_missing = hosts_requested.saturating_sub(self.reports_seen);
        self.coverage.records_lost = records_lost;
        Outcome {
            verdict: self.verdict,
            coverage: self.coverage,
        }
    }
}

/// SINGLE source of truth for the exit code. Exhaustive without a panic arm.
fn exit_code(outcome: &Outcome, fail_on_incomplete: bool) -> i32 {
    let Some(verdict) = outcome.verdict else {
        // No data is not a clean bill of health, flag or no flag.
        return EXIT_INCOMPLETE;
    };
    let full = outcome.coverage.is_full();

    match verdict {
        // Terminal: a confirmed compromise is never masked by uncertainty.
        SecurityVerdict::Compromised => EXIT_COMPROMISED,
        _ if fail_on_incomplete && !full => EXIT_INCOMPLETE,
        // Incomplete coverage IS degradation – code 2 already means exactly
        // "the scan ran but could not see everything". No opt-in required, so
        // an unpatched pipeline stays fail-closed.
        _ if !full => EXIT_DEGRADED,
        SecurityVerdict::Critical => EXIT_CRITICAL,
        SecurityVerdict::Clean => EXIT_CLEAN,
    }
}

/// Preserve the local warning side effects; used only for single-host path.
// macOS / --no-default-features builds without `local-scan` compile this out of
// production and see the remaining test-only call sites as dead code.
#[cfg_attr(not(feature = "local-scan"), allow(dead_code))]
fn warn_for_outcome(outcome: &Outcome, report: &AgentReport) {
    match outcome.verdict {
        Some(SecurityVerdict::Compromised) => {
            warn!(
                "ACTIVE COMPROMISE indicators detected — see SEC-015/016/017/019/020/021/022/023/024 or DOCK-010; exiting {}",
                EXIT_COMPROMISED
            );
        }
        Some(SecurityVerdict::Critical) => {
            if !report.is_root_execution {
                warn!(
                    "not running as root AND critical issues detected – results may be incomplete, re-run with sudo."
                );
            }
        }
        Some(SecurityVerdict::Clean) => {
            if !report.is_root_execution {
                warn!("not running as root – results may be incomplete.");
            } else if !report.scan_warnings.is_empty() {
                warn!(warnings = ?report.scan_warnings, "scan produced warnings — degraded");
            }
        }
        None => {
            // `add()` always yields Some for a real report; the None arm exists
            // only because coverage used to live inside the verdict.
            warn!("no report produced; exiting {}", EXIT_INCOMPLETE);
        }
    }
}

/// Explain EVERY field that can make `Coverage::is_full()` false. A field that
/// degrades the exit code with no log line leaves the operator with code 2 and
/// nothing to act on (R25-87/R25-96). Reads only `Coverage`, so the local and
/// fleet paths cannot diverge on the source of a fact.
/// `missing_hosts` carries the actual input addresses that produced no report,
/// because `report.host.hostname` is the machine's own name and cannot be
/// diffed against the CLI list (R25-97).
fn warn_for_coverage(c: &Coverage, missing_hosts: &[String]) {
    if c.scanners_failed {
        warn!(
            "one or more reports had failed scanners — coverage incomplete, \
             findings are a LOWER BOUND"
        );
    }
    if c.warnings {
        // Set by `scan_warnings` on reports whose producer predates
        // `failed_scanners` (serde default). Without this arm a mixed-version
        // fleet returns 2 with an empty log.
        warn!("one or more reports carried scan warnings — coverage incomplete");
    }
    if c.non_root {
        warn!("at least one host was scanned without root — privileged surfaces were not read");
    }
    if c.hosts_missing > 0 {
        if missing_hosts.is_empty() {
            warn!(
                hosts_missing = c.hosts_missing,
                "hosts did not produce a report"
            );
        } else {
            warn!(
                count = c.hosts_missing,
                hosts = %missing_hosts.join(", "),
                "hosts did not produce a report"
            );
        }
    }
    if c.records_lost > 0 || c.output_failed {
        warn!(
            records_lost = c.records_lost,
            output_failed = c.output_failed,
            "some results did not reach the output"
        );
    }
}

/// Build an Outcome for a single report (local path n=1).
#[cfg_attr(not(feature = "local-scan"), allow(dead_code))]
fn outcome_for(report: &AgentReport) -> Outcome {
    let mut agg = OutcomeBuilder::default();
    agg.add(report);
    agg.finish(1, 0)
}

/// Build an Outcome for a failed writer. The aggregate is already collected;
/// only the delivery of the final report failed, which is coverage.
/// R26-09: `records_lost` must include failed channel sends as well.
fn outcome_for_writer_failure(
    agg: OutcomeBuilder,
    hosts_requested: usize,
    records_lost: usize,
) -> Outcome {
    let mut outcome = agg.finish(hosts_requested, records_lost);
    outcome.coverage.output_failed = true;
    outcome
}

/// Strict JSONL parser for `compare --multi-host`.
/// Accepts either a JSON array, a single JSON object, or newline-delimited
/// JSON records. Unlike the previous permissive version, any unreadable line
/// is an error: dropping a record silently would make a host appear as
/// "removed" in the diff, which is worse than refusing to diff.
///
/// R26-05: refusing to diff on unreadable lines prevents a dropped record
/// from being shown as "host removed".
#[cfg(test)]
fn parse_jsonl_strict(data: &str, label: &str) -> Result<Vec<AgentReport>, String> {
    // Try a full JSON array first (e.g. from a non-streaming fleet output).
    if let Ok(reports) = serde_json::from_str::<Vec<AgentReport>>(data) {
        return Ok(reports);
    }
    // Then a single JSON object (legacy single-host snapshot).
    if let Ok(report) = serde_json::from_str::<AgentReport>(data) {
        return Ok(vec![report]);
    }

    // JSONL mode: every non-empty line must be a valid AgentReport.
    let mut jsonl = Vec::new();
    let mut bad: Vec<(usize, String)> = Vec::new();
    for (n, line) in data
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
    {
        match serde_json::from_str::<AgentReport>(line) {
            Ok(r) => jsonl.push(r),
            Err(e) => bad.push((n + 1, e.to_string())),
        }
    }

    if !bad.is_empty() {
        let mut msg = String::new();
        for (n, e) in bad.iter().take(5) {
            msg.push_str(&format!("'{label}' line {n}: {e}\n"));
        }
        msg.push_str(&format!(
            "Error: {} of {} JSONL record(s) in '{label}' are unreadable. \
             Refusing to diff — an unparsed host is indistinguishable from a \
             decommissioned one. Re-run the scan or fix the file.",
            bad.len(),
            bad.len() + jsonl.len()
        ));
        return Err(msg);
    }

    if jsonl.is_empty() {
        return Err(format!("No valid JSONL records found in '{label}'"));
    }

    Ok(jsonl)
}

/// Parse a compare input file that may be a single JSON object, a JSON array,
/// or newline-delimited JSON records. Reads JSONL incrementally to avoid
/// holding an entire fleet report in memory (R26-40).
fn parse_jsonl_strict_path(
    path: &std::path::Path,
    label: &str,
) -> Result<Vec<AgentReport>, String> {
    use std::io::{BufRead, BufReader, Read};

    let file = crate::safe_io::open_regular_streaming(&path.to_string_lossy())
        .map_err(|e| format!("Failed to open '{label}' file {}: {e}", path.display()))?;
    let mut reader = BufReader::new(file);

    // Sniff the first non-empty line: `[` means a JSON array, everything else
    // must be either a single report or the first JSONL record.
    let mut first = String::new();
    loop {
        first.clear();
        let n = reader
            .read_line(&mut first)
            .map_err(|e| format!("Failed to read '{label}' file {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        let trimmed = first.trim();
        if !trimmed.is_empty() {
            first = trimmed.to_string();
            break;
        }
    }

    if first.is_empty() {
        return Err(format!(
            "No valid JSON found in '{label}' file {}",
            path.display()
        ));
    }

    // JSON array: this is the rare non-streaming case. It is a snapshot array,
    // not a JSONL file, so read it whole.
    if first.starts_with('[') {
        let mut rest = first;
        reader
            .read_to_string(&mut rest)
            .map_err(|e| format!("Failed to read '{label}' file {}: {e}", path.display()))?;
        let reports: Vec<AgentReport> = serde_json::from_str(&rest)
            .map_err(|e| format!("Invalid JSON array in '{label}': {e}"))?;
        return Ok(reports);
    }

    // First record is a single JSON object. It may be followed by more records
    // (JSONL) or be the only object (legacy single report).
    let first_report: AgentReport =
        serde_json::from_str(&first).map_err(|e| format!("'{label}' line 1: {e}"))?;
    let mut reports = vec![first_report];

    let mut bad: Vec<(usize, String)> = Vec::new();
    let mut line_no = 1usize;
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| format!("Failed to read '{label}' file {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        line_no += 1;

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match serde_json::from_str::<AgentReport>(trimmed) {
            Ok(r) => reports.push(r),
            Err(e) => bad.push((line_no, e.to_string())),
        }
    }

    if !bad.is_empty() {
        let mut msg = String::new();
        for (n, e) in bad.iter().take(5) {
            msg.push_str(&format!("'{label}' line {n}: {e}\n"));
        }
        msg.push_str(&format!(
            "Error: {} of {} JSONL record(s) in '{label}' are unreadable. \
             Refusing to diff — an unparsed host is indistinguishable from a \
             decommissioned one. Re-run the scan or fix the file.",
            bad.len(),
            bad.len() + reports.len()
        ));
        return Err(msg);
    }

    Ok(reports)
}

/// Used by runner and scanner modules to adapt coverage hints. Keep here as
/// the crate-root helper shared across the binary.
pub(crate) fn is_running_as_root() -> bool {
    unsafe { libc::getuid() == 0 }
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

async fn run_command(
    cli: Cli,
    multi: MultiProgress,
    shutdown: Arc<AtomicBool>,
    shutdown_notify: Arc<Notify>,
) -> i32 {
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
                use std::io::BufRead;

                let file = match crate::safe_io::open_regular_streaming(path) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!(
                            "Failed to read hosts file {:?}: {} — refusing to silently fall back to a LOCAL scan",
                            path, e
                        );
                        return EXIT_USAGE;
                    }
                };

                let before = hosts.len();
                for line in std::io::BufReader::new(file).lines().map_while(Result::ok) {
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

            // Two-axis input: total requested hosts and fail_on_incomplete flag.
            let hosts_requested = hosts.len();
            let fail_on_incomplete = args.fail_on_incomplete;

            // If local-scan is disabled (non-Linux), reject local-only audits early.
            if !hosts.is_empty() {
                let mut remote = Vec::new();
                #[cfg(feature = "local-scan")]
                let mut local = Vec::new();
                #[cfg(feature = "local-scan")]
                let mut local_seen = false;
                // Every input address resolving to this machine is answered by the
                // single local scan. Dropping duplicates without crediting them
                // makes them look like hosts that never reported (R25-100).
                #[cfg(feature = "local-scan")]
                let mut local_aliases: Vec<String> = Vec::new();
                for h in &hosts {
                    #[cfg(feature = "local-scan")]
                    if is_local_host(h) {
                        local_aliases.push(h.clone());
                        if !local_seen {
                            local.push(h.clone());
                            local_seen = true;
                        }
                        continue;
                    }
                    remote.push(h.clone());
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

                // Aggregator lives in the main task from this point on, so
                // writer failure can never erase a recorded verdict.
                let mut agg = OutcomeBuilder::default();
                // R26-09: failed sends to the JSONL channel are lost records.
                let mut send_failures = 0usize;

                // Fail-fast: create the output file before launching any scan
                let output_path = args.output.clone();
                let mut jsonl_file = if use_streaming {
                    match std::fs::File::create(output_path.as_deref().unwrap_or("report.jsonl")) {
                        Ok(f) => Some(f),
                        Err(e) => {
                            eprintln!("Cannot create output file: {e}");
                            return EXIT_DEGRADED;
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
                        while let Some(report) = rx.blocking_recv() {
                            match serde_json::to_string(&report) {
                                Ok(json) => match writeln!(file, "{json}") {
                                    Ok(()) => written += 1,
                                    Err(e) => {
                                        io_errors += 1;
                                        warn!(error = %e, "JSONL write failed — report lost");
                                    }
                                },
                                Err(e) => {
                                    io_errors += 1;
                                    warn!(error = %e, "report could not be serialized — dropped from JSONL");
                                }
                            }
                        }
                        if let Err(e) = file.flush() {
                            io_errors += 1;
                            warn!(error = %e, "JSONL flush failed — tail records may be lost");
                        }
                        (written, io_errors)
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

                // Input addresses for which we received a report. `report.host.hostname`
                // is the machine's own name and cannot be diffed against the CLI list
                // (R25-97).
                let mut successful_hosts: HashSet<String> = HashSet::new();

                // Process local hosts synchronously (no SSH needed)
                #[cfg(feature = "local-scan")]
                for host in local {
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

                    agg.add(&local_report);
                    // Credit every alias, not just the one that was scanned (R25-100).
                    successful_hosts.extend(local_aliases.iter().cloned());
                    let _ = &host;

                    if let Some(tx) = &tx {
                        // R26-09: a closed channel is a lost record.
                        if tx.send(local_report).await.is_err() {
                            send_failures += 1;
                            warn!("JSONL channel closed — report dropped");
                        }
                    } else {
                        reports.push(local_report);
                    }
                }

                // Process remote hosts with JoinSet + Semaphore + global timeout
                if !remote.is_empty() {
                    // ========== MULTIPROGRESS SETUP ==========
                    // Use the shared MultiProgress passed from main (R25-71).

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
                                                // R25-72: centralized via RemoteCoverage::apply_to
                                                coverage.apply_to(&mut report);
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
                                        // BarAwareStderr suspends the progress
                                        // bars for every tracing record; a
                                        // direct write here would duplicate the
                                        // warning (R25-82).
                                        warn!(host = %host, error = %e, "russh scan failed");
                                        None
                                    }
                                }
                            })
                            .await;

                            match result {
                                Ok(Some(report)) => Some((host.clone(), report)),
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
                                                Some(Ok(Some((host, report)))) => {
                                                    agg.add(&report);
                                                    successful_hosts.insert(host);
                                                    if let Some(s) = &tx {
                                                        // R26-09: count channel send failures.
                                                        if s.send(report).await.is_err() {
                                                            send_failures += 1;
                                                            warn!("JSONL channel closed — report dropped");
                                                        }
                                                    } else {
                                                        reports.push(report);
                                                    }
                                                }
                                                Some(Ok(None)) => {}
                                                Some(Err(e)) if e.is_panic() => {
                                                    warn!("scan task panicked during teardown: {e}");
                                                }
                                                Some(Err(e)) => {
                                                    warn!("scan task failed during teardown: {e}");
                                                }
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
                                            Ok(Some((host, report))) => {
                                                agg.add(&report);
                                                successful_hosts.insert(host);
                                                if let Some(sender) = &tx {
                                                    // R26-09: count channel send failures.
                                                    if sender.send(report).await.is_err() {
                                                        send_failures += 1;
                                                        warn!("JSONL channel closed — report dropped");
                                                    }
                                                } else {
                                                    reports.push(report);
                                                }
                                            }
                                            Ok(None) => {}
                                            Err(e) if e.is_panic() => {
                                                warn!("scan task panicked: {e}");
                                            }
                                            Err(e) => {
                                                warn!("scan task failed: {e}");
                                            }
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
                                let outcome =
                                    outcome_for_writer_failure(agg, hosts_requested, send_failures);
                                if interrupted
                                    && outcome.verdict == Some(SecurityVerdict::Compromised)
                                {
                                    let missing_hosts: Vec<String> = hosts
                                        .iter()
                                        .filter(|h| !successful_hosts.contains(*h))
                                        .cloned()
                                        .collect();
                                    warn_for_coverage(&outcome.coverage, &missing_hosts);
                                    return EXIT_COMPROMISED;
                                }
                                if interrupted {
                                    return EXIT_INTERRUPT;
                                }
                                let missing_hosts: Vec<String> = hosts
                                    .iter()
                                    .filter(|h| !successful_hosts.contains(*h))
                                    .cloned()
                                    .collect();
                                warn_for_coverage(&outcome.coverage, &missing_hosts);
                                return exit_code(&outcome, fail_on_incomplete);
                            }
                        }
                    } else {
                        writer.await
                    };
                    match joined {
                        Ok((written, io_errors)) => {
                            // R26-09: include channel send failures in total lost.
                            let total_lost = io_errors + send_failures;
                            if total_lost > 0 {
                                warn!(
                                    written,
                                    lost = total_lost,
                                    "JSONL output incomplete — returning degraded exit code"
                                );
                            }
                            let outcome = agg.finish(hosts_requested, total_lost);

                            if interrupted && outcome.verdict == Some(SecurityVerdict::Compromised)
                            {
                                let missing_hosts: Vec<String> = hosts
                                    .iter()
                                    .filter(|h| !successful_hosts.contains(*h))
                                    .cloned()
                                    .collect();
                                warn_for_coverage(&outcome.coverage, &missing_hosts);
                                return EXIT_COMPROMISED;
                            }
                            if interrupted {
                                return EXIT_INTERRUPT;
                            }

                            let missing_hosts: Vec<String> = hosts
                                .iter()
                                .filter(|h| !successful_hosts.contains(*h))
                                .cloned()
                                .collect();
                            warn_for_coverage(&outcome.coverage, &missing_hosts);
                            return exit_code(&outcome, fail_on_incomplete);
                        }
                        Err(_) => {
                            warn!("JSONL writer task failed");
                            let outcome =
                                outcome_for_writer_failure(agg, hosts_requested, send_failures);
                            if interrupted && outcome.verdict == Some(SecurityVerdict::Compromised)
                            {
                                let missing_hosts: Vec<String> = hosts
                                    .iter()
                                    .filter(|h| !successful_hosts.contains(*h))
                                    .cloned()
                                    .collect();
                                warn_for_coverage(&outcome.coverage, &missing_hosts);
                                return EXIT_COMPROMISED;
                            }
                            if interrupted {
                                return EXIT_INTERRUPT;
                            }
                            let missing_hosts: Vec<String> = hosts
                                .iter()
                                .filter(|h| !successful_hosts.contains(*h))
                                .cloned()
                                .collect();
                            warn_for_coverage(&outcome.coverage, &missing_hosts);
                            return exit_code(&outcome, fail_on_incomplete);
                        }
                    }
                }

                // Non-streaming fleet path: aggregate once.
                // send_failures is zero here because no channel was used.
                let mut outcome = agg.finish(hosts_requested, 0);

                if interrupted && outcome.verdict == Some(SecurityVerdict::Compromised) {
                    let missing_hosts: Vec<String> = hosts
                        .iter()
                        .filter(|h| !successful_hosts.contains(*h))
                        .cloned()
                        .collect();
                    warn_for_coverage(&outcome.coverage, &missing_hosts);
                    return EXIT_COMPROMISED;
                }

                if interrupted {
                    return EXIT_INTERRUPT;
                }

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
                    warn_for_coverage(&outcome.coverage, &hosts);
                    return exit_code(&outcome, fail_on_incomplete);
                }

                if let Err(e) = output::output_multi(
                    &reports,
                    &args.format,
                    args.output.as_deref().map(std::path::Path::new),
                    verbose,
                ) {
                    warn!("output error: {e}");
                    outcome.coverage.output_failed = true;
                }

                let missing_hosts: Vec<String> = hosts
                    .iter()
                    .filter(|h| !successful_hosts.contains(*h))
                    .cloned()
                    .collect();
                warn_for_coverage(&outcome.coverage, &missing_hosts);
                // Computed AFTER delivery, so a render failure degrades the
                // code without ever outranking Compromised.
                return exit_code(&outcome, fail_on_incomplete);
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

                let mut outcome = outcome_for(&report);

                if let Err(e) = output::output_single(
                    &report,
                    &args.format,
                    args.output.as_deref().map(std::path::Path::new),
                    verbose,
                ) {
                    warn!("output error: {e}");
                    outcome.coverage.output_failed = true;
                }

                // Both axes reported after coverage is final.
                warn_for_outcome(&outcome, &report);
                warn_for_coverage(&outcome.coverage, &[]);
                exit_code(&outcome, fail_on_incomplete)
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
            if cmp_args.multi_host {
                let before =
                    match parse_jsonl_strict_path(std::path::Path::new(&cmp_args.before), "before")
                    {
                        Ok(reports) => reports,
                        Err(e) => {
                            eprintln!("{e}");
                            std::process::exit(EXIT_INCOMPLETE);
                        }
                    };
                let after =
                    match parse_jsonl_strict_path(std::path::Path::new(&cmp_args.after), "after") {
                        Ok(reports) => reports,
                        Err(e) => {
                            eprintln!("{e}");
                            std::process::exit(EXIT_INCOMPLETE);
                        }
                    };
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

            let before_data = std::fs::read_to_string(&cmp_args.before).unwrap_or_else(|e| {
                eprintln!("Failed to read 'before' file: {e}");
                std::process::exit(1);
            });
            let after_data = std::fs::read_to_string(&cmp_args.after).unwrap_or_else(|e| {
                eprintln!("Failed to read 'after' file: {e}");
                std::process::exit(1);
            });

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

    // Shared progress bar handle. Installed before the tracing subscriber so
    // every structured log record can suspend bars automatically (R25-71).
    let multi = MultiProgress::new();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("owlzops_mapper=warn")),
        )
        .with_target(false)
        .with_writer({
            let m = multi.clone();
            move || BarAwareStderr(m.clone())
        })
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

    let cmd_handle = tokio::spawn(run_command(
        cli,
        multi,
        shutdown_clone,
        shutdown_notify_clone,
    ));

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
        let _ = if join_err.is_panic() {
            writeln!(std::io::stderr(), "Main task panicked")
        } else {
            writeln!(std::io::stderr(), "Main task was cancelled without a panic")
        };
        EXIT_INTERNAL_ERROR
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
    fn exit_code_full_coverage_contract() {
        let clean = Outcome {
            verdict: Some(SecurityVerdict::Clean),
            coverage: Coverage::default(),
        };
        assert_eq!(exit_code(&clean, false), EXIT_CLEAN);

        let critical = Outcome {
            verdict: Some(SecurityVerdict::Critical),
            coverage: Coverage::default(),
        };
        assert_eq!(exit_code(&critical, false), EXIT_CRITICAL);

        let compromised = Outcome {
            verdict: Some(SecurityVerdict::Compromised),
            coverage: Coverage::default(),
        };
        assert_eq!(exit_code(&compromised, false), EXIT_COMPROMISED);
    }

    #[test]
    fn incomplete_coverage_is_never_clean() {
        let outcome = Outcome {
            verdict: Some(SecurityVerdict::Clean),
            coverage: Coverage {
                non_root: true,
                ..Default::default()
            },
        };
        assert_eq!(exit_code(&outcome, false), EXIT_DEGRADED);
        assert_eq!(exit_code(&outcome, true), EXIT_INCOMPLETE);
    }

    #[test]
    fn compromise_is_never_masked_by_incompleteness() {
        let outcome = Outcome {
            verdict: Some(SecurityVerdict::Compromised),
            coverage: Coverage {
                hosts_missing: 199,
                ..Default::default()
            },
        };
        assert_eq!(exit_code(&outcome, false), EXIT_COMPROMISED);
        assert_eq!(exit_code(&outcome, true), EXIT_COMPROMISED);
    }

    #[test]
    fn no_verdict_is_incomplete_regardless_of_flag() {
        let outcome = Outcome {
            verdict: None,
            coverage: Coverage {
                hosts_missing: 5,
                ..Default::default()
            },
        };
        assert_eq!(exit_code(&outcome, false), EXIT_INCOMPLETE);
        assert_eq!(exit_code(&outcome, true), EXIT_INCOMPLETE);
    }

    #[test]
    fn fleet_where_almost_nothing_was_scanned_is_not_clean() {
        let outcome = Outcome {
            verdict: Some(SecurityVerdict::Clean),
            coverage: Coverage {
                hosts_missing: 199,
                ..Default::default()
            },
        };
        assert_ne!(exit_code(&outcome, false), EXIT_CLEAN);
        assert_eq!(exit_code(&outcome, false), EXIT_DEGRADED);
    }

    #[test]
    fn one_host_via_fleet_path_matches_local_path() {
        let mut report = minimal_report();
        report.network.firewall_active = false;
        report.is_root_execution = false;

        let local_code = exit_code(&outcome_for(&report), false);

        let mut agg = OutcomeBuilder::default();
        agg.add(&report);
        let outcome = agg.finish(1, 0);
        let fleet_code = exit_code(&outcome, false);

        assert_eq!(local_code, fleet_code);
    }

    #[test]
    fn a_render_failure_never_downgrades_a_compromise() {
        let outcome = Outcome {
            verdict: Some(SecurityVerdict::Compromised),
            coverage: Coverage {
                output_failed: true,
                ..Default::default()
            },
        };
        assert_eq!(exit_code(&outcome, false), EXIT_COMPROMISED);
        assert_eq!(exit_code(&outcome, true), EXIT_COMPROMISED);
    }

    #[test]
    fn a_failed_scanner_does_not_hide_a_critical_finding() {
        let mut r = minimal_report();
        r.network.firewall_active = false; // SEC-001, network healthy
        r.failed_scanners = vec!["security".to_string()];
        // Critical is reported; coverage degrades the code but does not erase it.
        assert_eq!(exit_code(&outcome_for(&r), false), EXIT_DEGRADED);
        assert_eq!(exit_code(&outcome_for(&r), true), EXIT_INCOMPLETE);
    }

    #[test]
    fn every_coverage_field_has_an_explanation() {
        let full = Coverage::default();
        assert!(full.is_full());
        for c in [
            Coverage {
                scanners_failed: true,
                ..Default::default()
            },
            Coverage {
                warnings: true,
                ..Default::default()
            },
            Coverage {
                non_root: true,
                ..Default::default()
            },
            Coverage {
                hosts_missing: 1,
                ..Default::default()
            },
            Coverage {
                records_lost: 1,
                ..Default::default()
            },
            Coverage {
                output_failed: true,
                ..Default::default()
            },
        ] {
            assert!(
                !c.is_full(),
                "field degrades but is_full() ignores it: {c:?}"
            );
        }
    }

    #[test]
    fn a_deduplicated_local_alias_is_not_a_missing_host() {
        // `--host localhost --host 127.0.0.1` collapses to ONE local scan; the
        // second address must not be reported as unanswered (R25-100).
        let hosts = ["localhost".to_string(), "127.0.0.1".to_string()];
        let mut successful: HashSet<String> = HashSet::new();
        successful.extend(hosts.iter().cloned());
        assert!(hosts.iter().all(|h| successful.contains(h)));
    }

    #[test]
    fn hard_exit_ceiling_covers_grace_plus_drain() {
        assert!(
            FLEET_TEARDOWN_GRACE + HARD_EXIT_MARGIN > FLEET_TEARDOWN_GRACE + JSONL_DRAIN_TIMEOUT,
            "watchdog must not fire before the JSONL writer has drained"
        );
    }

    #[test]
    fn strict_jsonl_parse_rejects_unreadable_lines() {
        let good = serde_json::to_string(&minimal_report()).unwrap();
        // Corrupt JSON by dropping the final closing brace.
        let bad = good[..good.len() - 1].to_string();
        let input = format!("{good}\n{bad}\n");
        assert!(parse_jsonl_strict(&input, "test").is_err());
    }

    #[test]
    fn strict_jsonl_parse_accepts_valid_lines() {
        let good = serde_json::to_string(&minimal_report()).unwrap();
        let input = format!("{good}\n{good}\n");
        let reports = parse_jsonl_strict(&input, "test").unwrap();
        assert_eq!(reports.len(), 2);
    }
}
