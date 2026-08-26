use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

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

    #[arg(long, default_value = "root")]
    pub ssh_user: String,

    #[arg(long, default_value = "~/.ssh/id_rsa")]
    pub ssh_key: String,

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

    #[arg(long, default_value = "120")]
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

    /// Maximum concurrent SSH sessions (default: 50).
    #[arg(long, default_value_t = 50)]
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
