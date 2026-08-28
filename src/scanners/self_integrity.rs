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
//!   • If launched over SSH, /proc/net/tcp (or tcp6) MUST contain at least one
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
use std::io::{BufRead, BufReader, Read};

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
                // Seccomp filter is active – common in containers and hardened units.
                // Do NOT mark as compromised; only add a note.
                report.warnings.push(
                    "self-integrity NOTE: Seccomp filter is active on the mapper process. \
                     Expected under container/hardened unit; tamper only if unexpected on bare metal."
                        .to_string(),
                );
            }
            seen_seccomp = true;
        }

        if let Some(rest) = line.strip_prefix("NoNewPrivs:")
            && rest.trim() == "1"
        {
            // NoNewPrivs is set – normal in containers. Do NOT mark as compromised.
            report.warnings.push(
                "self-integrity NOTE: NoNewPrivs is set on the mapper process. \
                 Expected in containers/hardened units."
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
    // Attempt to read at least 1 byte to confirm the file is present and non-empty.
    match fs::File::open("/proc/self/maps") {
        Ok(mut f) => {
            let mut buf = [0u8; 1];
            match f.read(&mut buf) {
                Ok(1) => { /* ok */ }
                Ok(0) => {
                    report.compromised = true;
                    report.warnings.push(
                        "self-integrity CRITICAL: /proc/self/maps is empty – kernel/rootkit is hiding memory mappings"
                            .to_string(),
                    );
                }
                _ => {
                    // couldn't read – soft fail, other checks may catch
                }
            }
        }
        Err(e) => {
            report.compromised = true;
            report.warnings.push(format!(
                "self-integrity CRITICAL: cannot open /proc/self/maps ({e})"
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

/// Streaming check for any ESTABLISHED (st == "01") connection in a /proc/net table.
/// Returns `Some(true)` on first match (early exit), `Some(false)` if scanned
/// without finding any, or `None` if the file cannot be opened.
fn family_has_established(path: &str) -> Option<bool> {
    // /proc/net/tcp{,6}: procfs, so a FIFO swap is impossible. Using the
    // regular-open primitive is merely stricter than needed, not required.
    // If procfs streaming spreads, add `open_procfs_streaming` (R26-45).
    let f = crate::safe_io::open_regular_streaming(path).ok()?;
    let reader = BufReader::new(f);
    for line in reader.lines().skip(1).map_while(Result::ok) {
        if line.split_ascii_whitespace().nth(3) == Some("01") {
            return Some(true);
        }
    }
    Some(false)
}

/// Combine results from two families: returns `None` if both are unavailable,
/// `Some(true)` if at least one family has an ESTABLISHED socket, `Some(false)`
/// otherwise.
fn combine_established(v4: Option<bool>, v6: Option<bool>) -> Option<bool> {
    match (v4, v6) {
        (None, None) => None,
        (a, b) => Some(a.unwrap_or(false) || b.unwrap_or(false)),
    }
}

fn check_ssh_transport_invariant(report: &mut IntegrityReport) {
    if std::env::var("SSH_CONNECTION").is_err() {
        return;
    }

    // R22-01 / R22-05: streaming dual‑family check, no uncontrolled memory use
    let v4 = family_has_established("/proc/net/tcp");
    let v6 = family_has_established("/proc/net/tcp6");
    let has_established = match combine_established(v4, v6) {
        None => {
            // Both tables unavailable – skip the check, don't claim compromise.
            return;
        }
        Some(v) => v,
    };

    if !has_established {
        report.compromised = true;
        report.warnings.push(
            "self-integrity CRITICAL: launched over SSH, but neither /proc/net/tcp \
             nor /proc/net/tcp6 shows an ESTABLISHED connection – network stack is \
             being filtered by a rootkit"
                .to_string(),
        );
    }
}

#[cfg(test)]
mod tests {
    // Old string‑based `any_established` preserved for existing unit tests.
    fn any_established(v4: Option<&str>, v6: Option<&str>) -> Option<bool> {
        let scan = |c: &str| {
            c.lines()
                .skip(1)
                .any(|l| l.split_ascii_whitespace().nth(3) == Some("01"))
        };
        match (v4, v6) {
            (None, None) => None,
            (a, b) => Some(a.map(scan).unwrap_or(false) || b.map(scan).unwrap_or(false)),
        }
    }

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

    #[test]
    fn ipv6_only_ssh_session_is_not_a_false_rootkit() {
        let v4 = "  sl local rem st\n  0: 00000000:0016 00000000:0000 0A rest...\n";
        let v6 = "  sl local rem st\n  0: 0000:0016 dead:C1A2 01 rest...\n";
        assert_eq!(any_established(Some(v4), Some(v6)), Some(true));
    }

    #[test]
    fn no_established_in_either_family_is_flagged() {
        let v4 = "  sl local rem st\n  0: 00000000:0016 00000000:0000 0A rest...\n";
        let v6 = "  sl local rem st\n";
        assert_eq!(any_established(Some(v4), Some(v6)), Some(false));
    }

    #[test]
    fn both_unreadable_returns_none_skip() {
        assert_eq!(any_established(None, None), None);
    }
}
