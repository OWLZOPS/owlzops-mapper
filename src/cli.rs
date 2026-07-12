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

    #[arg(long, default_value = "/tmp/owlzops-mapper")]
    pub remote_path: String,

    #[arg(long)]
    pub local_binary: Option<String>,

    #[arg(long, default_value = "120")]
    pub remote_timeout_secs: u64,

    /// Ask for sudo password interactively and use russh engine (no NOPASSWD required).
    #[arg(long, default_value_t = false)]
    pub ask_sudo_pass: bool,

    /// Maximum concurrent SSH sessions (default: 50).
    #[arg(long, default_value_t = 50)]
    pub max_concurrent: usize,

    /// Keep the binary on the remote host after the scan (skip cleanup).
    #[arg(long, default_value_t = false)]
    pub keep_binary: bool,

    /// Enable heavy deep scans (Ghost PID, full capability walk, etc.)
    #[arg(long, default_value_t = false)]
    pub deep: bool,
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
