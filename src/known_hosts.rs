use data_encoding::BASE64;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use std::path::PathBuf;
use subtle::ConstantTimeEq;

type HmacSha1 = Hmac<Sha1>;

pub struct KnownHostsChecker {
    host: String,
    port: u16,
    system_file: PathBuf, // ~/.ssh/known_hosts (read-only)
    pin_file: PathBuf,    // ~/.owlzops/known_hosts (our TOFU store)
}

impl KnownHostsChecker {
    /// Create a new checker.
    ///
    /// # Errors
    /// Returns `HostKeyCheck` if `HOME` is not set, because we refuse to
    /// place the trust store in a world‑writable directory like `/tmp`.
    pub fn new(host: String, port: u16) -> Result<Self, crate::ssh_engine::RemoteError> {
        let home =
            dirs_next::home_dir().ok_or_else(|| crate::ssh_engine::RemoteError::HostKeyCheck {
                host: host.clone(),
                detail: "HOME unset — cannot locate known_hosts trust store".into(),
            })?;
        Ok(Self {
            host,
            port,
            system_file: home.join(".ssh/known_hosts"),
            pin_file: home.join(".owlzops/known_hosts"),
        })
    }

    fn host_candidates(&self) -> Vec<String> {
        if self.port == 22 {
            vec![self.host.clone()]
        } else {
            vec![format!("[{}]:{}", self.host, self.port)]
        }
    }

    fn hashed_matches(salt_b64: &str, mac_b64: &str, host: &str) -> bool {
        let (Ok(salt), Ok(mac_expected)) = (
            BASE64.decode(salt_b64.as_bytes()),
            BASE64.decode(mac_b64.as_bytes()),
        ) else {
            return false;
        };
        let Ok(mut mac) = HmacSha1::new_from_slice(&salt) else {
            return false;
        };
        mac.update(host.as_bytes());
        mac.finalize()
            .into_bytes()
            .as_slice()
            .ct_eq(mac_expected.as_slice())
            .into()
    }

    fn line_host_matches(&self, host_field: &str) -> bool {
        let candidates = self.host_candidates();
        if let Some(rest) = host_field.strip_prefix("|1|") {
            // Hashed entry: |1|salt|mac
            let mut parts = rest.splitn(2, '|');
            let (Some(salt), Some(mac)) = (parts.next(), parts.next()) else {
                return false;
            };
            candidates
                .iter()
                .any(|h| Self::hashed_matches(salt, mac, h))
        } else {
            // Plain entry: host1,host2,...
            host_field
                .split(',')
                .any(|h| candidates.iter().any(|c| c == h))
        }
    }

    /// Host key algorithms already pinned for this host in either trust store.
    /// Constraining the SSH offer to these prevents russh preference changes
    /// from turning into fleet-wide HostKeyChanged (R25-30). Empty = unknown
    /// host; caller should fall back to the default set.
    pub fn pinned_algorithms(&self) -> Vec<russh::keys::ssh_key::Algorithm> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();

        for path in [&self.system_file, &self.pin_file] {
            let Ok(content) = std::fs::read_to_string(path) else {
                continue;
            };

            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                let mut f = line.split_whitespace();
                let (Some(hf), Some(kt), Some(_kd)) = (f.next(), f.next(), f.next()) else {
                    continue;
                };

                if !self.line_host_matches(hf) {
                    continue;
                }

                let Some(alg) = Self::algorithm_from_openssh_name(kt) else {
                    continue;
                };

                // Algorithm does not implement Ord/Hash in every russh version;
                // use a stable debug key for deduplication.
                if seen.insert(format!("{alg:?}")) {
                    out.push(alg);
                }
            }
        }

        out
    }

    fn algorithm_from_openssh_name(name: &str) -> Option<russh::keys::ssh_key::Algorithm> {
        use russh::keys::ssh_key::{Algorithm, EcdsaCurve, HashAlg};

        match name {
            "ssh-ed25519" => Some(Algorithm::Ed25519),
            "ssh-rsa" => Some(Algorithm::Rsa { hash: None }),
            "rsa-sha2-256" => Some(Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            }),
            "rsa-sha2-512" => Some(Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            }),
            "ecdsa-sha2-nistp256" => Some(Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            }),
            "ecdsa-sha2-nistp384" => Some(Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            }),
            "ecdsa-sha2-nistp521" => Some(Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            }),
            _ => None,
        }
    }

    /// Verify the presented server key.
    ///
    /// Logic:
    /// 1. Collect all matching host entries from both trust stores.
    /// 2. If any entry matches the presented key exactly (type AND data) →
    ///    `Ok(true)`.
    /// 3. If there is at least one entry for the host but none matched →
    ///    `HostKeyChanged`. This is independent of the key algorithm: a
    ///    change from Ed25519 to RSA is a change, not a new TOFU pin.
    /// 4. Only if the host is completely unknown → TOFU and pin the key.
    pub fn verify(
        &self,
        key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, crate::ssh_engine::RemoteError> {
        let presented =
            key.to_openssh()
                .map_err(|e| crate::ssh_engine::RemoteError::HostKeyCheck {
                    host: self.host.clone(),
                    detail: e.to_string(),
                })?;
        let mut pit = presented.split_whitespace();
        let (Some(ptype), Some(pdata)) = (pit.next(), pit.next()) else {
            return Err(crate::ssh_engine::RemoteError::HostKeyCheck {
                host: self.host.clone(),
                detail: "invalid key format".into(),
            });
        };

        // `Some` means the host already has a known key that does NOT match
        // the presented one. The algorithm type is deliberately ignored here:
        // any mismatch is a security event.
        let mut conflict: Option<(String, PathBuf)> = None;

        for path in [&self.system_file, &self.pin_file] {
            let Ok(content) = std::fs::read_to_string(path) else {
                continue;
            };
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let mut f = line.split_whitespace();
                let (Some(hf), Some(kt), Some(kd)) = (f.next(), f.next(), f.next()) else {
                    continue;
                };
                if !self.line_host_matches(hf) {
                    continue;
                }

                // Exact match: host, key type, and key data all agree.
                if kt == ptype && kd == pdata {
                    return Ok(true);
                }

                // Record the first mismatching entry for this host. We do not
                // filter by `kt != ptype`, so an algorithm change cannot be
                // mistaken for an unknown host.
                conflict.get_or_insert_with(|| (line.to_string(), path.clone()));
            }
        }

        if let Some((conflict_line, conflict_file)) = conflict {
            return Err(crate::ssh_engine::RemoteError::HostKeyChanged {
                host: self.host.clone(),
                file: conflict_file.display().to_string(),
                line: conflict_line,
            });
        }

        // No entry for this host at all → TOFU.
        let entry = format!("{} {} {}\n", self.host_candidates()[0], ptype, pdata);
        if let Some(dir) = self.pin_file.parent()
            && let Err(e) = std::fs::create_dir_all(dir)
        {
            tracing::error!(dir = %dir.display(), error = %e, "failed to create directory for known_hosts");
        }
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.pin_file)
        {
            Ok(mut f) => {
                use std::io::Write;
                if let Err(e) = f.write_all(entry.as_bytes()) {
                    tracing::error!(path = %self.pin_file.display(), error = %e, "failed to write to known_hosts");
                }
            }
            Err(e) => {
                tracing::error!(path = %self.pin_file.display(), error = %e, "cannot open known_hosts for writing");
            }
        }
        tracing::warn!(host = %self.host, "new host key — pinned to ~/.owlzops/known_hosts");
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_host_matches() {
        let checker = KnownHostsChecker::new("example.com".into(), 22).expect("HOME must be set");
        assert!(checker.line_host_matches("example.com,other.example.com"));
        assert!(!checker.line_host_matches("evil.com"));
    }

    #[test]
    fn verify_matches_exact_key() {
        let key = russh::keys::ssh_key::PrivateKey::random(
            &mut rand::rng(),
            russh::keys::ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let pub_key = key.public_key();
        let pub_line = pub_key.to_openssh().unwrap();
        let parts: Vec<_> = pub_line.split_whitespace().collect();
        let key_type = parts[0];
        let key_data = parts[1];

        let tmp_dir = tempfile::TempDir::new().unwrap();
        let kh_path = tmp_dir.path().join("known_hosts");
        std::fs::write(&kh_path, format!("localhost {} {}\n", key_type, key_data)).unwrap();

        let checker = KnownHostsChecker {
            host: "localhost".into(),
            port: 22,
            system_file: kh_path.clone(),
            pin_file: tmp_dir.path().join("pin"),
        };
        assert!(checker.verify(pub_key).is_ok());

        // Change key and expect HostKeyChanged
        let bad_line = format!("localhost {} AAAA...fake\n", key_type);
        std::fs::write(&kh_path, bad_line).unwrap();
        let checker_bad = KnownHostsChecker {
            host: "localhost".into(),
            port: 22,
            system_file: kh_path,
            pin_file: tmp_dir.path().join("pin2"),
        };
        assert!(matches!(
            checker_bad.verify(pub_key),
            Err(crate::ssh_engine::RemoteError::HostKeyChanged { .. })
        ));
    }

    /// Regression test for R24-20: changing the key algorithm must be treated
    /// as a key change, not as a new unknown host.
    #[test]
    fn algorithm_change_is_host_key_changed_not_tofu() {
        let rsa_key = russh::keys::ssh_key::PrivateKey::random(
            &mut rand::rng(),
            russh::keys::ssh_key::Algorithm::Rsa {
                hash: Some(russh::keys::ssh_key::HashAlg::Sha512),
            },
        )
        .unwrap();
        let ed_key = russh::keys::ssh_key::PrivateKey::random(
            &mut rand::rng(),
            russh::keys::ssh_key::Algorithm::Ed25519,
        )
        .unwrap();

        let tmp_dir = tempfile::TempDir::new().unwrap();
        let kh_path = tmp_dir.path().join("known_hosts");
        std::fs::write(
            &kh_path,
            format!("localhost {}\n", rsa_key.public_key().to_openssh().unwrap()),
        )
        .unwrap();

        let checker = KnownHostsChecker {
            host: "localhost".into(),
            port: 22,
            system_file: kh_path,
            pin_file: tmp_dir.path().join("pin"),
        };

        // Present Ed25519 while trust store has RSA: must be HostKeyChanged.
        assert!(matches!(
            checker.verify(ed_key.public_key()),
            Err(crate::ssh_engine::RemoteError::HostKeyChanged { .. })
        ));
    }
}
