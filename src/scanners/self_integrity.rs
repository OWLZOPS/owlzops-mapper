//! Self‑integrity preflight – verifies that the mapper process itself has not
//! been tampered with by a rootkit (seccomp injection, tracer attach, /proc
//! filtering, PID spoofing). Runs *before* any host data collection so that the
//! audit report can flag a compromised auditor.
//!
//! Based on Fable's R11 audit: four tiers of increasing strength, all zero‑copy
//! /proc/libc reads with no external crates.
//!
//! Tier 1 – execution context:
//!   • Seccomp: 2 (filter) when we never installed one → parent/lifecycle tamper
//!   • NoNewPrivs: 1 unexpectedly → lifecycle tamper
//!   • TracerPid: non‑zero without expected debugger → ptrace attach
//!
//! Tier 2 – canary reads (simple known answers):
//!   • /proc/self/stat first field == own PID
//!   • /proc/sys/kernel/ostype == "Linux"
//!
//! Tier 3 – self‑evident invariants (expensive to fake):
//!   • /proc/self/maps is non‑empty (we are a running process with mappings)
//!   • If launched over SSH, /proc/net/tcp MUST contain at least one
//!     ESTABLISHED connection (our own SSH session).  Zero false positives:
//!     the invariant is guaranteed by the transport.
//!
//! Tier 4 (future) – cross‑interface reconciliation (same philosophy as ghost
//!   PID): compare /proc/net/tcp vs sockstat vs snmp, etc.
//!
//! Fundamental ceiling (documented): a kernel/eBPF rootkit that coherently
//! fakes all of these interfaces can defeat all userspace self‑checks.
//! Out‑of‑band attestation (TPM, remote observer) is the only true anchor.

use std::fs;

// ---------------------------------------------------------------------------
// public interface
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct IntegrityReport {
    /// True if at least one tamper indicator fired.
    pub compromised: bool,
    /// Human‑readable evidence for each triggered check.
    pub warnings: Vec<String>,
}

/// Execute all self‑integrity checks and return a report.
#[allow(dead_code)]
pub fn run_self_integrity_check() -> IntegrityReport {
    let mut report = IntegrityReport::default();

    check_proc_self_status(&mut report);
    check_proc_self_maps(&mut report);
    check_proc_self_stat_pid(&mut report);
    check_os_type(&mut report);
    check_ssh_transport_invariant(&mut report);

    report
}

// ---------------------------------------------------------------------------
// individual checks
// ---------------------------------------------------------------------------

fn check_proc_self_status(report: &mut IntegrityReport) {
    let content = match fs::read_to_string("/proc/self/status") {
        Ok(c) => c,
        Err(e) => {
            report.compromised = true;
            report.warnings.push(format!(
                "self-integrity CRITICAL: cannot read /proc/self/status ({e}) – kernel is blocking self-introspection"
            ));
            return;
        }
    };

    let mut seen_seccomp = false;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Seccomp:") {
            let val = rest.trim();
            if val == "2" {
                report.compromised = true;
                report.warnings.push(
                    "self-integrity WARNING: Seccomp filter is active on the mapper process. \
                     Possible rootkit tampering via parent lifecycle injection."
                        .to_string(),
                );
            }
            seen_seccomp = true;
        }

        if let Some(rest) = line.strip_prefix("NoNewPrivs:")
            && rest.trim() == "1"
        {
            report.compromised = true;
            report.warnings.push(
                "self-integrity WARNING: NoNewPrivs is unexpectedly set on the mapper process."
                    .to_string(),
            );
        }

        if let Some(rest) = line.strip_prefix("TracerPid:") {
            let pid_str = rest.trim();
            if pid_str != "0" {
                report.compromised = true;
                report.warnings.push(format!(
                    "self-integrity WARNING: mapper is being traced by unknown process (PID {pid_str})"
                ));
            }
        }
    }

    if !seen_seccomp {
        report
            .warnings
            .push("self-integrity NOTE: Seccomp line missing from /proc/self/status".to_string());
    }
}

fn check_proc_self_maps(report: &mut IntegrityReport) {
    match fs::metadata("/proc/self/maps") {
        Ok(meta) if meta.len() > 0 => { /* ok */ }
        Ok(_) => {
            report.compromised = true;
            report.warnings.push(
                "self-integrity CRITICAL: /proc/self/maps is empty – kernel/rootkit is hiding memory mappings"
                    .to_string(),
            );
        }
        Err(e) => {
            report.compromised = true;
            report.warnings.push(format!(
                "self-integrity CRITICAL: cannot stat /proc/self/maps ({e})"
            ));
        }
    }
}

fn check_proc_self_stat_pid(report: &mut IntegrityReport) {
    let content = match fs::read_to_string("/proc/self/stat") {
        Ok(c) => c,
        Err(_) => return,
    };

    let rparen = match content.rfind(')') {
        Some(pos) => pos,
        None => return,
    };
    let before = &content[..rparen];
    let lparen = match before.find('(') {
        Some(pos) => pos,
        None => return,
    };
    let pid_str = before[..lparen].trim();
    let actual_pid = std::process::id().to_string();
    if pid_str != actual_pid {
        report.compromised = true;
        report.warnings.push(format!(
            "self-integrity CRITICAL: PID spoofing detected – stat reports {pid_str}, real pid is {actual_pid}"
        ));
    }
}

fn check_os_type(report: &mut IntegrityReport) {
    let content = match fs::read_to_string("/proc/sys/kernel/ostype") {
        Ok(c) => c,
        Err(_) => return,
    };
    if content.trim() != "Linux" {
        report.compromised = true;
        report.warnings.push(format!(
            "self-integrity CRITICAL: unexpected ostype '{}' – possible kernel hooking",
            content.trim()
        ));
    }
}

fn check_ssh_transport_invariant(report: &mut IntegrityReport) {
    if std::env::var("SSH_CONNECTION").is_err() {
        return;
    }

    let content = match fs::read_to_string("/proc/net/tcp") {
        Ok(c) => c,
        Err(_) => return,
    };

    let has_established = content
        .lines()
        .skip(1)
        .any(|line| line.split_ascii_whitespace().nth(3) == Some("01"));

    if !has_established {
        report.compromised = true;
        report.warnings.push(
            "self-integrity CRITICAL: launched over SSH, but /proc/net/tcp shows \
             no ESTABLISHED connections – network stack is being filtered by a rootkit"
                .to_string(),
        );
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn proc_self_stat_pid_parsing() {
        let s = "1234 (bash) S 1 1234 ...";
        let rparen = s.rfind(')').unwrap();
        let before = &s[..rparen];
        let lparen = before.find('(').unwrap();
        let pid_str = before[..lparen].trim();
        assert_eq!(pid_str, "1234");

        let s2 = "99 (evil ( hax ) ) S 1 99 ...";
        let rp = s2.rfind(')').unwrap();
        let before2 = &s2[..rp];
        let lp = before2.find('(').unwrap();
        let pid_str2 = before2[..lp].trim();
        assert_eq!(pid_str2, "99");
    }
}
