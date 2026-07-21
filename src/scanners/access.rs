use crate::models::{AccessAuditResult, SshKeyAudit, SudoersEntry};
use russh::keys::ssh_key::{Algorithm, EcdsaCurve, PublicKey};

// ── Unified sudoers parser (R16 hardening) ────────────────────────────────
use crate::scanners::sudoers;

const KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

fn strip_options(line: &str) -> Option<String> {
    let toks: Vec<&str> = line.split_whitespace().collect();
    let pos = toks.iter().position(|t| KEY_TYPES.contains(t))?;
    Some(toks[pos..].join(" "))
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeyPolicy {
    pub allow_ed25519: bool,
    pub allow_rsa_min_bits: Option<u32>,
    pub allow_ecdsa: bool,
    pub allow_sk_hardware: bool,
}

impl Default for KeyPolicy {
    fn default() -> Self {
        Self {
            allow_ed25519: true,
            allow_rsa_min_bits: Some(3072),
            allow_ecdsa: false,
            allow_sk_hardware: true,
        }
    }
}

impl KeyPolicy {
    fn evaluate(&self, algo: &str, bits: u32) -> (bool, Option<String>) {
        match algo {
            "ed25519" if self.allow_ed25519 => (true, None),
            "rsa" => match self.allow_rsa_min_bits {
                Some(min) if bits >= min => (true, None),
                Some(min) => (
                    false,
                    Some(format!("RSA {bits}-bit below policy minimum {min}")),
                ),
                None => (false, Some("RSA not permitted".into())),
            },
            a if a.starts_with("sk-") && self.allow_sk_hardware => (true, None),
            a if a.starts_with("ecdsa") => {
                if self.allow_ecdsa {
                    (true, None)
                } else {
                    (false, Some("ECDSA not permitted by policy".into()))
                }
            }
            "dsa" => (
                false,
                Some("DSA (1024-bit, deprecated) not permitted".into()),
            ),
            other => (false, Some(format!("{other} not in allowed algorithm set"))),
        }
    }
}

fn classify_key(user: &str, line: &str, policy: &KeyPolicy) -> Option<SshKeyAudit> {
    let stripped = strip_options(line)?;
    let key = PublicKey::from_openssh(&stripped).ok()?;
    let comment = key.comment().to_string();
    let (algorithm, bits) = match key.algorithm() {
        Algorithm::Ed25519 => ("ed25519".to_string(), 256),
        Algorithm::Rsa { .. } => {
            let bits = key.key_data().rsa().map(|r| r.key_size()).unwrap_or(0);
            ("rsa".to_string(), bits)
        }
        Algorithm::Ecdsa { curve } => match curve {
            EcdsaCurve::NistP256 => ("ecdsa-nistp256".to_string(), 256),
            EcdsaCurve::NistP384 => ("ecdsa-nistp384".to_string(), 384),
            EcdsaCurve::NistP521 => ("ecdsa-nistp521".to_string(), 521),
        },
        Algorithm::Dsa => ("dsa".to_string(), 1024),
        Algorithm::SkEd25519 => ("sk-ed25519".to_string(), 256),
        other => (other.to_string(), 0),
    };
    let (compliant, reason) = policy.evaluate(&algorithm, bits);
    Some(SshKeyAudit {
        user: user.to_string(),
        algorithm,
        bits,
        comment,
        compliant,
        reason,
    })
}

/// Check whether an entry is a NOPASSWD: ALL rule.
/// Uses the unified parser for consistency with security.rs.
fn is_nopasswd_all(entry: &str) -> bool {
    if !sudoers::entry_has_nopasswd(entry) {
        return false;
    }
    // Look for an "ALL" token after a colon (the command list)
    if let Some(tail) = entry.rsplit(':').next() {
        tail.split([',', ' ', '\t'])
            .map(str::trim)
            .any(|t| t == "ALL")
    } else {
        false
    }
}

pub fn gather_access_alignment(policy: &KeyPolicy) -> AccessAuditResult {
    use std::io::ErrorKind;
    let mut result = AccessAuditResult::default();

    if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 7 {
                continue;
            }
            let (user, home, shell) = (f[0], f[5], f[6]);
            if shell.ends_with("nologin") || shell.ends_with("false") {
                continue;
            }
            let ak = format!("{home}/.ssh/authorized_keys");

            match std::fs::read_to_string(&ak) {
                Ok(content) => {
                    for l in content.lines() {
                        let l = l.trim();
                        if l.is_empty() || l.starts_with('#') {
                            continue;
                        }
                        if let Some(audit) = classify_key(user, l, policy) {
                            result.keys.push(audit);
                        }
                    }
                }
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                    result.coverage_warnings.push(format!(
                        "user '{user}': {ak} unreadable (permission denied)"
                    ));
                }
                Err(e) => result
                    .coverage_warnings
                    .push(format!("user '{user}': {ak} unreadable ({})", e.kind())),
            }
        }
    } else {
        result
            .coverage_warnings
            .push("/etc/passwd unreadable — account enumeration incomplete".into());
    }

    // Use the unified sudoers parser for NOPASSWD: ALL detection.
    sudoers::each_sudoers_entry(|file, entry| {
        if is_nopasswd_all(entry) {
            // Extract the principal (first word) from the logical entry.
            let principal = entry.split_whitespace().next().unwrap_or("?").to_string();
            result.sudoers_nopasswd_all.push(SudoersEntry {
                principal,
                source_file: file.to_string(),
                scope: "ALL".into(),
            });
        }
    });

    result
}
