use crate::models::{AccessAuditResult, SshKeyAudit, SudoersEntry};
use russh::keys::ssh_key::{Algorithm, EcdsaCurve, PublicKey};

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

fn spec_nopasswd_all(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let first = line.split_whitespace().next()?;
    if first == "Defaults" || first.ends_with("_Alias") {
        return None;
    }

    let eq = line.find('=')?;
    let principal = first.to_string();
    let mut rhs = line[eq + 1..].trim_start();
    if let Some(open) = rhs.strip_prefix('(') {
        rhs = open.find(')').map(|c| &open[c + 1..]).unwrap_or(open);
    }

    let mut nopasswd = false;
    for raw in rhs
        .split([',', ' ', '\t'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        let mut tok = raw;
        if let Some(rest) = tok.strip_prefix("NOPASSWD:") {
            nopasswd = true;
            tok = rest.trim();
        } else if let Some(rest) = tok.strip_prefix("PASSWD:") {
            nopasswd = false;
            tok = rest.trim();
        } else if tok == "NOPASSWD" {
            nopasswd = true;
            continue;
        } else if tok == "PASSWD" {
            nopasswd = false;
            continue;
        } else if tok.ends_with(':') {
            continue;
        }
        if tok == "ALL" && nopasswd {
            return Some(principal);
        }
    }
    None
}

fn parse_sudoers_file(path: &std::path::Path, out: &mut Vec<SudoersEntry>) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    let src = path.display().to_string();
    let mut logical = String::new();

    let flush = |full: &str, out: &mut Vec<SudoersEntry>| {
        if let Some(principal) = spec_nopasswd_all(full) {
            out.push(SudoersEntry {
                principal,
                source_file: src.clone(),
                scope: "ALL".into(),
            });
        }
    };

    for raw in content.lines() {
        let line = raw.trim_end();
        if let Some(cont) = line.strip_suffix('\\') {
            logical.push_str(cont);
            logical.push(' ');
            continue;
        }
        logical.push_str(line);
        let full = std::mem::take(&mut logical);
        flush(&full, out);
    }
    if !logical.is_empty() {
        flush(&logical, out);
    }
}

fn parse_sudoers_dir(dir: &str, out: &mut Vec<SudoersEntry>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<_> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            if name.contains('.') || name.ends_with('~') {
                return None;
            }
            Some(e.path())
        })
        .collect();
    files.sort();
    for path in files {
        parse_sudoers_file(&path, out);
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

    parse_sudoers_file(
        std::path::Path::new("/etc/sudoers"),
        &mut result.sudoers_nopasswd_all,
    );
    parse_sudoers_dir("/etc/sudoers.d", &mut result.sudoers_nopasswd_all);
    result
}
