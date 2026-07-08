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

    /// Verify the presented server key.
    ///
    /// Logic:
    /// 1. Collect all lines from both known_hosts files that match the host.
    /// 2. Filter those lines to only the ones with the same key type (`ptype`).
    /// 3. If any of those match exactly → `Ok(true)`.
    /// 4. If there are lines of the same type but none matched → `HostKeyChanged`.
    /// 5. If no lines of this type exist at all → TOFU (pin the new key type).
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

        // Collect all matching host entries, keeping track of same-type matches
        // alongside the file they came from so the error message can be precise.
        let mut same_type_conflict: Option<(String, PathBuf)> = None;

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
                // Only consider lines with the same key type.
                if kt != ptype {
                    continue;
                }
                if kd == pdata {
                    return Ok(true); // exact match found
                }
                // Same type but different data – record conflict, but keep scanning
                // because there might be another line of the same type that matches.
                same_type_conflict.get_or_insert_with(|| (line.to_string(), path.clone()));
            }
        }

        // If we found any same-type entry but none matched exactly → key has changed.
        if let Some((conflict_line, conflict_file)) = same_type_conflict {
            return Err(crate::ssh_engine::RemoteError::HostKeyChanged {
                host: self.host.clone(),
                file: conflict_file.display().to_string(),
                line: conflict_line,
            });
        }

        // No entry for this host+type combination → TOFU: pin new key.
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
}
