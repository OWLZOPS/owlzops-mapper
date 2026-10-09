use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// R35-10: `--max-concurrent` must be ≥ 1. `0` would scan nothing and mark
/// every host as missing. clap's `.range()` only exists for u64/i64, not
/// usize, so this is a tiny local validator.
fn parse_positive_usize(s: &str) -> Result<usize, String> {
    match s.parse::<usize>() {
        Ok(0) => Err("must be at least 1".to_string()),
        Ok(n) => Ok(n),
        Err(e) => Err(e.to_string()),
    }
}

// =====================================================================
// CLI structure with subcommands
// =====================================================================

#[derive(Parser, Debug)]
#[command(author = "Owlzops", version, about = "Infrastructure Discovery Agent")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Verbose output (show full VMA details in memory anomaly tables)
    #[arg(short = 'v', long = "verbose", global = true, default_value_t = false)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run an audit scan (local or remote)
    Audit(AuditArgs),
    /// Compare two audit snapshots
    Compare(CompareArgs),
    /// Save a snapshot to disk (always JSON)
    Snapshot(SnapshotArgs),
    /// Compare the two most recent snapshots in a directory
    DirCompare(DirCompareArgs),
    /// Sign a report with an Ed25519 private key (LT-1)
    Sign(SignArgs),
    /// Verify a signed report (LT-1)
    Verify(VerifyArgs),
}

#[derive(Args, Debug, Clone)]
pub struct AuditArgs {
    #[arg(short, long, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    #[arg(short, long)]
    pub output: Option<String>,

    #[arg(long, default_value_t = false)]
    pub external_ip: bool,

    #[arg(long, default_value_t = false)]
    pub offline: bool,

    #[arg(long, default_value_t = false)]
    pub refresh_packages: bool,

    // ---- remote scan options -------------------------------------------------
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub host: Vec<String>,

    #[arg(long)]
    pub hosts: Option<String>,

    // ---- M7: hosts from ssh config -------------------------------------------
    /// Select `Host` blocks from `~/.ssh/config` by alias glob (`*` and `?`,
    /// anchored). Each matching block contributes its `HostName` — or the
    /// alias itself, if the alias is not a glob and there is no `HostName` —
    /// to the fleet. May be repeated; merged with `--host` / `--hosts` and
    /// deduplicated.
    ///
    /// MVP limitations: `Include` is not followed, `Match` blocks are not
    /// evaluated, `Host *` catch-alls are skipped, and per-host
    /// `User` / `Port` / `IdentityFile` are ignored (`--ssh-user` /
    /// `--ssh-key` remain the only credential source).
    #[arg(
        long = "hosts-from-ssh-config",
        value_name = "PATTERN",
        value_delimiter = ',',
        num_args = 1..
    )]
    pub hosts_from_ssh_config: Vec<String>,

    #[arg(long, default_value = "root")]
    pub ssh_user: String,

    #[arg(long, default_value = "~/.ssh/id_rsa")]
    pub ssh_key: String,

    /// Authenticate through the running ssh-agent ($SSH_AUTH_SOCK) instead of
    /// --ssh-key. Hardware-backed keys (FIDO/PKCS#11) work only this way.
    #[arg(long, default_value_t = false)]
    pub ssh_agent: bool,

    #[arg(long, default_value_t = false)]
    pub copy_binary: bool,

    /// Where to place the binary on the remote host. When omitted, a private
    /// directory is created there with `mktemp -d` (mode 0700, unpredictable
    /// name) and removed afterwards — this is the recommended form.
    /// An explicit path is validated: a group/world-writable parent is refused,
    /// because the binary is executed under sudo (R24-41).
    #[arg(long)]
    pub remote_path: Option<String>,

    #[arg(long)]
    pub local_binary: Option<String>,

    /// Remote per-host deadline (s). Every host budget — the inner scan
    /// deadline and the orchestrator's per-host ceiling — derives from it
    /// (R35-10). The upper bound keeps `host_ceiling` from overflowing
    /// `Instant` on platforms where `tokio::time::timeout` saturates.
    #[arg(
        long,
        default_value = "120",
        value_parser = clap::value_parser!(u64).range(1..=86_400)
    )]
    pub remote_timeout_secs: u64,

    /// Ask for sudo password interactively and use russh engine (no NOPASSWD required).
    #[arg(long, default_value_t = false)]
    pub ask_sudo_pass: bool,

    /// Read sudo password from this already-open file descriptor instead of
    /// prompting or reading the environment. Mutually exclusive with
    /// `--ask-sudo-pass`; any value in `OWLZOPS_SUDO_PASS` is discarded.
    // R27-23: corrected help text (not precedence, mutual exclusion).
    #[arg(long, value_name = "FD", conflicts_with = "ask_sudo_pass")]
    pub sudo_pass_fd: Option<i32>,

    /// Maximum concurrent SSH sessions (default: 50). Rejected at the
    /// parser level: `0` would scan nothing and mark every host as missing
    /// (R35-10).
    #[arg(long, default_value_t = 50, value_parser = parse_positive_usize)]
    pub max_concurrent: usize,

    /// Exit 4 when coverage was incomplete (a scanner failed, a host did not
    /// report, or the scan ran without root). Without this flag incomplete
    /// coverage still yields the degraded code 2 — it is never invisible.
    #[arg(long, default_value_t = false)]
    pub fail_on_incomplete: bool,

    /// Keep the binary on the remote host after the scan (skip cleanup).
    #[arg(long, default_value_t = false)]
    pub keep_binary: bool,

    /// Enable heavy deep scans (Ghost PID, full capability walk, etc.)
    #[arg(long, default_value_t = false)]
    pub deep: bool,

    /// Path to the verdict cache file (default: /var/lib/owlzops/verdict-cache.json).
    #[arg(long)]
    pub verdict_cache: Option<PathBuf>,

    // ---- M3: retries ---------------------------------------------------------
    /// Re-attempt a host after a TRANSPORT failure (connect timeout, reset,
    /// SSH channel closed before an exit status). Policy answers — auth,
    /// host key, sudo, non-zero exit — are never retried. All attempts share
    /// the host's overall time budget.
    #[arg(long, default_value_t = 0)]
    pub retries: u32,

    /// Base delay between attempts; doubles per attempt (cap 16×) plus ≤1s jitter.
    #[arg(long, default_value_t = 2)]
    pub retry_backoff_secs: u64,

    // ---- M4: resume ----------------------------------------------------------
    /// Append to the JSONL in --output and skip every host that already has a
    /// record there. Requires --format json --output <file>. The existing
    /// records are re-scored so the exit code covers the whole fleet.
    #[arg(long, default_value_t = false)]
    pub resume: bool,

    // ---- M5: accept.json -----------------------------------------------------
    /// Path to an accept.json policy file. Findings matched by an entry are
    /// marked suppressed and excluded from the risk score and the exit
    /// verdict, but remain visible in the report (dashboard and JSON) so the
    /// operator can audit the policy. `COMPROMISE_IDS` (SEC-015…024, SEC-040,
    /// DOCK-010, …) and `SEC-041` / `COV-001` are NEVER acceptable and will
    /// cause the file to be rejected on load.
    #[arg(long, value_name = "FILE")]
    pub accept: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct SnapshotArgs {
    #[arg(long, default_value = "~/.owlzops/snapshots")]
    pub output_dir: String,

    #[command(flatten)]
    pub audit: AuditArgs,
}

#[derive(Args, Debug)]
pub struct DirCompareArgs {
    /// Directory containing snapshots (JSON files)
    pub dir: PathBuf,
    /// Output format: terminal (default), json, excel
    #[arg(short, long, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
    /// Output file for json/excel (optional)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct CompareArgs {
    /// Path to the earlier JSON report
    pub before: PathBuf,
    /// Path to the later JSON report
    pub after: PathBuf,
    /// Output format: terminal (default), json, excel
    #[arg(short, long, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
    /// Output file for json/excel (optional)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Treat the input files as arrays of host reports (multi-host)
    #[arg(long, default_value_t = false)]
    pub multi_host: bool,

    // ---- M6: baseline mode ------------------------------------------------
    /// Treat `before` as a known-good baseline and `after` as the current
    /// fleet; pair hosts by hostname, same as `--multi-host`. Output is
    /// worded as drift from a baseline ("not yet baselined" instead of
    /// "+ added", "decommissioned" instead of "− removed"). Implies
    /// `--multi-host`.
    #[arg(long, default_value_t = false)]
    pub baseline: bool,

    /// Exit 1 when any compared host has at least one Degraded change.
    /// Without this flag a diff always exits 0, matching historical
    /// behaviour. Applies to single-host compare and to `--multi-host` /
    /// `--baseline`.
    #[arg(long, default_value_t = false)]
    pub fail_on_drift: bool,
}

#[derive(Args, Debug)]
pub struct SignArgs {
    /// Path to private key file (PEM or OpenSSH)
    #[arg(long)]
    pub key: PathBuf,
    /// Input report JSON (AgentReport)
    #[arg(long)]
    pub input: PathBuf,
    /// Output signed report JSON
    #[arg(long, default_value = "signed.json")]
    pub output: PathBuf,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Path to public key file (OpenSSH format). If omitted, use built-in
    /// owlzops public keys.
    #[arg(long)]
    pub key: Option<PathBuf>,
    /// Input signed report JSON
    #[arg(long)]
    pub input: PathBuf,
}

#[derive(ValueEnum, Clone, Debug, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
    #[value(alias = "excel")]
    Xlsx,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Text => write!(f, "text"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Xlsx => write!(f, "xlsx"),
        }
    }
}
