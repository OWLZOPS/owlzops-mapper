use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentReport {
    pub scan_id: String,
    pub timestamp: String,
    pub version: String,
    pub duration_secs: f64,
    pub risk_score: u8,
    pub is_root_execution: bool,
    pub host: HostInfo,
    pub databases: Vec<DatabaseInfo>,
    pub network: NetworkInfo,
    pub storage: StorageInfo,
    pub topology: TopologyInfo,
    pub security: SecurityInfo,
    pub packages: PackagesInfo,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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

#[derive(Serialize, Deserialize, Debug, Clone)]
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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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

#[derive(Serialize, Deserialize, Debug, Clone)]
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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecurityInfo {
    pub ssh_password_auth_enabled: bool,
    pub ssh_root_login_enabled: bool,
    pub shell_users: Vec<UserInfo>,
    pub fail2ban_active: bool,
    pub auditd_active: bool,
    pub ssh_config_source: String,
    pub sudo_nopasswd_entries: Vec<String>,
    pub sudoers_mode: Option<u32>,
    pub sysctl_issues: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserInfo {
    pub username: String,
    pub last_login: String,
    pub last_ssh_login: String,
    pub authorized_keys_count: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum PackageManager {
    Apt,
    Dnf,
    Yum,
    Pacman,
    Zypper,
    Unknown,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UpgradablePackage {
    pub name: String,
    pub current_version: String,
    pub new_version: String,
    pub is_security: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PackagesInfo {
    pub manager: PackageManager,
    pub installed_count: usize,
    pub upgradable: Vec<UpgradablePackage>,
    pub cache_refreshed: bool,
}
