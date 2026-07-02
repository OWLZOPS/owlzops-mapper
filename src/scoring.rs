// Risk score penalties
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

// Threshold for sysctl issues to be considered critical in exit code
pub const SYSCTL_CRITICAL_THRESHOLD: usize = 3;

// =====================================================================
// Unified critical conditions
// =====================================================================

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
    pub fn from_report(report: &crate::models::AgentReport) -> Self {
        Self {
            firewall_disabled: !report.network.firewall_active,
            ssh_root_login: report.security.ssh_root_login_enabled,
            security_updates: report.packages.upgradable.iter().any(|p| p.is_security),
            critical_ssl: report
                .network
                .ssl_certificates
                .iter()
                .any(|c| c.is_critical),
            failed_services: report
                .host
                .failed_services
                .iter()
                .any(|s| s.contains(".service")),
            no_backups: report.host.backup_tools.is_empty(),
            sudo_nopasswd: !report.security.sudo_nopasswd_entries.is_empty(),
            ntp_not_synced: !report.host.ntp_synchronized,
            sysctl_issues_count: report.security.sysctl_issues.len(),
            ssh_password_auth: report.security.ssh_password_auth_enabled,
            oom_kills: report.host.oom_kills > 0,
            sudoers_bad_mode: report.security.sudoers_mode.is_some_and(|m| m != 0o440),
        }
    }

    /// Critical conditions that trigger exit code 1.
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

    /// Full risk score penalty (0..100).
    pub fn risk_penalty(&self) -> u8 {
        let mut score = 0u8;
        if self.firewall_disabled {
            score = score.saturating_add(RISK_NO_FIREWALL);
        }
        if self.ssh_root_login {
            score = score.saturating_add(RISK_SSH_ROOT_LOGIN);
        }
        if self.security_updates {
            score = score.saturating_add(RISK_SECURITY_UPDATES);
        }
        if self.critical_ssl {
            score = score.saturating_add(RISK_CRITICAL_SSL_MAX);
        }
        if self.failed_services {
            score = score.saturating_add(RISK_FAILED_SERVICES);
        }
        if self.no_backups {
            score = score.saturating_add(RISK_NO_BACKUP);
        }
        if self.sudo_nopasswd {
            score = score.saturating_add(RISK_SUDO_NOPASSWD);
        }
        if self.ntp_not_synced {
            score = score.saturating_add(RISK_NTP_NOT_SYNCED);
        }
        if self.ssh_password_auth {
            score = score.saturating_add(RISK_SSH_PASSWORD_AUTH);
        }
        if self.oom_kills {
            score = score.saturating_add(RISK_OOM_KILLS);
        }
        if self.sudoers_bad_mode {
            score = score.saturating_add(RISK_SUDOERS_MODE);
        }
        let sysctl_penalty = std::cmp::min(
            self.sysctl_issues_count as u8 * RISK_SYSCTL_PER_ISSUE,
            RISK_SYSCTL_MAX,
        );
        score = score.saturating_add(sysctl_penalty);
        score.min(100)
    }
    /// Return a human-readable breakdown of the risk score contributions.
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
            self.sysctl_issues_count as u8 * RISK_SYSCTL_PER_ISSUE,
            RISK_SYSCTL_MAX,
        );
        if sysctl_penalty > 0 {
            items.push(("Sysctl security issues", sysctl_penalty));
        }
        items
    }
}
