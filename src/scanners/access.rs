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

/// ~4000 keys at 256 B — anything larger is either abuse or a typo.
pub(crate) const CAP_AUTHORIZED_KEYS: usize = 1024 * 1024;

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

pub fn gather_access_alignment(
    scan: &sudoers::SudoersScan,
    policy: &KeyPolicy,
) -> AccessAuditResult {
    use std::io::ErrorKind;
    let mut result = AccessAuditResult::default();

    // R26-17: complete R26-02 — the third /etc/passwd reader must be capped and
    // regular-file-only. Uncapped read_to_string also violated Capped I/O.
    match crate::safe_io::read_file_capped_regular("/etc/passwd", 4 * 1024 * 1024) {
        Ok((passwd, truncated)) => {
            if truncated {
                result
                    .coverage_warnings
                    .push("/etc/passwd exceeded cap — account enumeration PARTIAL".into());
            }
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

                // R24-02: use safe_io capped regular read to prevent DoS via FIFO,
                // /dev/zero symlinks, or other non-regular files.
                match crate::safe_io::read_file_capped_regular(&ak, CAP_AUTHORIZED_KEYS) {
                    Ok((content, truncated)) => {
                        if truncated {
                            result.coverage_warnings.push(format!(
                                "user '{user}': {ak} exceeded {CAP_AUTHORIZED_KEYS} B — key audit PARTIAL"
                            ));
                        }
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
                    // read_file_capped_regular rejects FIFOs/devices by design.
                    // It signals this with ErrorKind::InvalidData (R24-12).
                    Err(e) if e.kind() == ErrorKind::InvalidData => {
                        result.coverage_warnings.push(format!(
                            "user '{user}': {ak} is NOT a regular file (fifo/device/symlink to one) — \
                             key audit refused; treat as tampering"
                        ));
                    }
                    Err(e) => result
                        .coverage_warnings
                        .push(format!("user '{user}': {ak} unreadable ({})", e.kind())),
                }
            }
        }
        Err(e) if e.kind() == ErrorKind::InvalidData => {
            result.coverage_warnings.push(
                "/etc/passwd is NOT a regular file (fifo/device) — account \
                 enumeration refused; treat as tampering"
                    .into(),
            );
        }
        Err(e) => {
            result.coverage_warnings.push(format!(
                "/etc/passwd unreadable ({}) — account enumeration incomplete",
                e.kind()
            ));
        }
    }

    // R26-18: single walk — aliases and entries from one pass.
    for (file, entry) in &scan.entries {
        if sudoers::is_nopasswd_all(entry, &scan.aliases) {
            let principal = entry.split_whitespace().next().unwrap_or("?").to_string();
            result.sudoers_nopasswd_all.push(SudoersEntry {
                principal,
                source_file: file.clone(),
                scope: "ALL".into(),
            });
        }
        // R33-04: passwordless sudo declared as a Defaults parameter. The
        // rule itself may carry no NOPASSWD tag at all, so is_nopasswd_all
        // never sees it. `Defaults:deploy !authenticate` + `deploy ALL=(ALL)
        // ALL` is equivalent to `deploy ALL=(ALL) NOPASSWD: ALL`.
        if let Some(scope) = sudoers::defaults_no_authenticate(entry) {
            let principal = match scope {
                "ALL" => "ALL".to_string(),
                s => s.trim_start_matches([':', '@', '!', '>']).to_string(),
            };
            result.sudoers_nopasswd_all.push(SudoersEntry {
                principal,
                source_file: file.clone(),
                scope: format!("ALL (Defaults{scope} !authenticate)"),
            });
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmnd_alias_indirection_is_detected_as_nopasswd_all() {
        let mut aliases = sudoers::CmndAliases::default();
        aliases.absorb("Cmnd_Alias MAINTENANCE = ALL");
        let entry = "deploy ALL=(ALL) NOPASSWD: MAINTENANCE";
        assert!(sudoers::is_nopasswd_all(entry, &aliases));
    }

    #[test]
    fn non_alias_path_does_not_match() {
        let aliases = sudoers::CmndAliases::default();
        let entry = "deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl";
        assert!(!sudoers::is_nopasswd_all(entry, &aliases));
    }

    #[test]
    fn defaults_no_authenticate_emits_sudoers_entry() {
        let scan = sudoers::SudoersScan {
            aliases: sudoers::CmndAliases::default(),
            entries: vec![(
                "/etc/sudoers.d/20-auth".into(),
                "Defaults:deploy !authenticate".into(),
            )],
        };
        // gather_access_alignment also walks /etc/passwd; we only check our entry.
        let result = gather_access_alignment(&scan, &KeyPolicy::default());
        let hit = result
            .sudoers_nopasswd_all
            .iter()
            .find(|e| e.scope.contains("Defaults"));
        assert!(
            hit.is_some(),
            "Defaults !authenticate must emit a SudoersEntry"
        );
        let hit = hit.unwrap();
        assert_eq!(hit.principal, "deploy");
        assert_eq!(hit.source_file, "/etc/sudoers.d/20-auth");
    }

    #[test]
    fn defaults_no_authenticate_global_scope_is_all() {
        let scan = sudoers::SudoersScan {
            aliases: sudoers::CmndAliases::default(),
            entries: vec![("/etc/sudoers".into(), "Defaults !authenticate".into())],
        };
        let result = gather_access_alignment(&scan, &KeyPolicy::default());
        let hit = result
            .sudoers_nopasswd_all
            .iter()
            .find(|e| e.scope.contains("Defaults"));
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().principal, "ALL");
    }
}
