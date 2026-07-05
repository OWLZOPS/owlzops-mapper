use crate::models::AgentReport;

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
pub const RISK_SUDO_NOPASSWD: u8 = 10;
pub const RISK_SUDOERS_MODE: u8 = 5;
pub const RISK_SYSCTL_PER_ISSUE: u8 = 5;
pub const RISK_SYSCTL_MAX: u8 = 15;

pub const SYSCTL_CRITICAL_THRESHOLD: usize = 3;

// ── New Finding model (v0.5) ───────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Category {
    Security,
    Reliability,
    Hygiene,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // will be removed once evaluate/score are wired in main
pub struct Finding {
    pub id: &'static str,
    pub title: String,
    pub category: Category,
    pub weight: u8,
    pub evidence: String,
    pub suppressed: Option<String>,
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
        });
    }

    if report.security.ssh_root_login_enabled {
        findings.push(Finding {
            id: "SEC-002",
            title: "SSH root login allowed".to_string(),
            category: Category::Security,
            weight: RISK_SSH_ROOT_LOGIN,
            evidence: "PermitRootLogin enabled".to_string(),
            suppressed: None,
        });
    }

    if report.packages.upgradable.iter().any(|p| p.is_security) {
        let count = report
            .packages
            .upgradable
            .iter()
            .filter(|p| p.is_security)
            .count();
        findings.push(Finding {
            id: "SEC-003",
            title: "Pending security updates".to_string(),
            category: Category::Security,
            weight: RISK_SECURITY_UPDATES,
            evidence: format!("{} security update(s) available", count),
            suppressed: None,
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
        });
    }

    if !report.security.sudo_nopasswd_entries.is_empty() {
        findings.push(Finding {
            id: "SEC-005",
            title: "Sudo NOPASSWD entries found".to_string(),
            category: Category::Security,
            weight: RISK_SUDO_NOPASSWD,
            evidence: format!(
                "{} NOPASSWD entries in sudoers",
                report.security.sudo_nopasswd_entries.len()
            ),
            suppressed: None,
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
            });
        } else {
            let title = issue
                .split('=')
                .next()
                .unwrap_or("sysctl issue")
                .to_string();
            findings.push(Finding {
                id: "SEC-007",
                title,
                category: Category::Security,
                weight: RISK_SYSCTL_PER_ISSUE,
                evidence: issue.clone(),
                suppressed: None,
            });
        }
    }

    if report.security.ssh_password_auth_enabled {
        findings.push(Finding {
            id: "SEC-008",
            title: "SSH password authentication enabled".to_string(),
            category: Category::Security,
            weight: RISK_SSH_PASSWORD_AUTH,
            evidence: "PasswordAuthentication yes".to_string(),
            suppressed: None,
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
    pub ssh_password_auth: bool,
    pub oom_kills: bool,
    pub sudoers_bad_mode: bool,
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
            ssh_password_auth: has("SEC-008"),
            oom_kills: has("REL-003"),
            sudoers_bad_mode: has("SEC-006"),
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

    pub fn breakdown(&self) -> Vec<(&'static str, u8)> {
        let mut items = Vec::new();
        if self.firewall_disabled {
            items.push(("Firewall inactive", RISK_NO_FIREWALL));
        }
        if self.ssh_root_login {
            items.push(("SSH root login allowed", RISK_SSH_ROOT_LOGIN));
        }
        if self.security_updates {
            items.push(("Pending security updates", RISK_SECURITY_UPDATES));
        }
        if self.critical_ssl {
            items.push(("SSL certificate expiring", RISK_CRITICAL_SSL_MAX));
        }
        if self.failed_services {
            items.push(("Failed systemd services", RISK_FAILED_SERVICES));
        }
        if self.ssh_password_auth {
            items.push(("SSH password auth enabled", RISK_SSH_PASSWORD_AUTH));
        }
        if self.oom_kills {
            items.push(("OOM kills present", RISK_OOM_KILLS));
        }
        if self.no_backups {
            items.push(("No backup tools detected", RISK_NO_BACKUP));
        }
        if self.ntp_not_synced {
            items.push(("NTP not synchronized", RISK_NTP_NOT_SYNCED));
        }
        if self.sudo_nopasswd {
            items.push(("Sudo NOPASSWD entries found", RISK_SUDO_NOPASSWD));
        }
        if self.sudoers_bad_mode {
            items.push(("Sudoers permissions not 0440", RISK_SUDOERS_MODE));
        }
        let sysctl_penalty = std::cmp::min(
            (self.sysctl_issues_count as u8).saturating_mul(RISK_SYSCTL_PER_ISSUE),
            RISK_SYSCTL_MAX,
        );
        if sysctl_penalty > 0 {
            items.push(("Sysctl security issues", sysctl_penalty));
        }
        items
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
            host: HostInfo::default(),
            databases: vec![],
            network: NetworkInfo::default(),
            storage: StorageInfo::default(),
            topology: TopologyInfo::default(),
            security: SecurityInfo::default(),
            packages: PackagesInfo::default(),
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
        // Ensure only the suppressed sysctl issue contributes
        r.network.firewall_active = true;
        r.security.ssh_password_auth_enabled = false;
        r.host.backup_tools = vec!["restic".to_string()];
        r.host.ntp_synchronized = true;
        r.security.sysctl_issues = vec!["net.ipv4.ip_forward=1 (expected 0)".to_string()];
        r.topology.docker_active = true; // triggers suppression

        let findings = evaluate(&r);
        assert!(findings.iter().any(|f| f.suppressed.is_some()));
        let scored = score(findings);
        assert_eq!(scored.total, 0);
    }
}
