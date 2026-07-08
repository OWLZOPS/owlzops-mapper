use serde::{Deserialize, Serialize};

fn default_scoring_version() -> u8 {
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

// Added #[serde(default)] to allow older snapshot formats
// to be deserialised even if new fields are missing.
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
    pub cron_jobs: Vec<String>,
    pub systemd_timers: Vec<String>,
    pub tech_stack: Vec<String>,
    pub top_memory_processes: Vec<ProcessInfo>,
    pub failed_services: Vec<String>,
    pub backup_tools: Vec<String>,
    pub last_restic_snapshot: Option<String>,
    pub ntp_synchronized: bool,
    pub time_offset_ms: Option<f64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProcessInfo {
    pub name: String,
    pub pid: u32,
    pub memory_mb: u64,
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
    pub total_gb: u64,
    pub used_gb: u64,
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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserInfo {
    pub username: String,
    pub last_login: String,
    pub last_ssh_login: String,
    pub authorized_keys_count: usize,
}

// PackageManager with forward-compatible deserialization:
// unknown variants map to `Unknown` so old binaries can read future snapshots.
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
    pub source: String,      // "environ" or "cmdline"
    pub matched_key: String, // compromised variable/flag name
}
