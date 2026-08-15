use data_encoding::BASE64;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use std::path::{Path, PathBuf};
use subtle::ConstantTimeEq;

type HmacSha1 = Hmac<Sha1>;

/// A trust store larger than this is not a trust store.
const CAP_KNOWN_HOSTS: usize = 4 * 1024 * 1024;
// R25-54: unreadable trust store is an error, not silent TOFU.
// R25-57: entries are filtered by host during load to bound memory.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustStore {
    System,
    Pin,
}

#[derive(Debug, Clone)]
struct KnownHostEntry {
    host_field: String,
    key_type: String,
    key_data: String,
    store: TrustStore,
}

impl KnownHostEntry {
    /// Reconstructed for the HostKeyChanged message; storing the raw line as
    /// well would duplicate every field a second time.
    fn as_line(&self) -> String {
        format!("{} {} {}", self.host_field, self.key_type, self.key_data)
    }
}

pub struct KnownHostsChecker {
    host: String,
    port: u16,
    system_file: PathBuf,
    pin_file: PathBuf, // ~/.owlzops/known_hosts (our TOFU store)
    entries: Vec<KnownHostEntry>,
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

        let system_file = home.join(".ssh/known_hosts");
        let pin_file = home.join(".owlzops/known_hosts");
        let candidates = Self::host_candidates(&host, port);
        let entries =
            Self::load_entries(&system_file, &pin_file, &candidates).map_err(|(path, e)| {
                crate::ssh_engine::RemoteError::HostKeyCheck {
                    host: host.clone(),
                    detail: format!(
                        "trust store {} is unreadable ({e}) — refusing to fall back to \
                     trust-on-first-use, which would pin whatever the server presents",
                        path.display()
                    ),
                }
            })?;

        Ok(Self {
            host,
            port,
            system_file,
            pin_file,
            entries,
        })
    }

    fn load_entries(
        system_file: &Path,
        pin_file: &Path,
        candidates: &[String],
    ) -> Result<Vec<KnownHostEntry>, (PathBuf, std::io::Error)> {
        let mut out = Vec::new();

        for (path, store) in [
            (system_file, TrustStore::System),
            (pin_file, TrustStore::Pin),
        ] {
            let (content, _is_regular) = match crate::safe_io::read_file_capped_regular(
                &path.to_string_lossy(),
                CAP_KNOWN_HOSTS,
            ) {
                Ok(tuple) => tuple,
                // A missing store is the first-run case and is legitimate.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err((path.to_path_buf(), e)),
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

                // Keep only entries for THIS host. The checker lives for the
                // whole session; a fleet operator's known_hosts holds
                // thousands of lines we will never look at (R25-57).
                if !Self::host_field_matches(hf, candidates) {
                    continue;
                }

                out.push(KnownHostEntry {
                    host_field: hf.to_string(),
                    key_type: kt.to_string(),
                    key_data: kd.to_string(),
                    store,
                });
            }
        }

        Ok(out)
    }

    #[cfg(test)]
    fn from_files(host: String, port: u16, system_file: PathBuf, pin_file: PathBuf) -> Self {
        let candidates = Self::host_candidates(&host, port);
        let entries = Self::load_entries(&system_file, &pin_file, &candidates)
            .unwrap_or_else(|_| panic!("test trust store must be readable"));

        Self {
            host,
            port,
            system_file,
            pin_file,
            entries,
        }
    }

    fn host_candidates(host: &str, port: u16) -> Vec<String> {
        if port == 22 {
            vec![host.to_string()]
        } else {
            vec![format!("[{}]:{}", host, port)]
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

    fn host_field_matches(host_field: &str, candidates: &[String]) -> bool {
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
        let mut out = Vec::new();

        for entry in &self.entries {
            // Entries are already filtered by host during load_entries,
            // so no further filtering is needed here.
            for alg in Self::algorithms_from_openssh_name(&entry.key_type) {
                if !out.contains(&alg) {
                    out.push(alg);
                }
            }
        }

        out
    }

    /// One known_hosts key type maps to SEVERAL negotiable host-key algorithms.
    /// known_hosts stores the KEY type (`ssh-rsa`), never the signature
    /// algorithm (`rsa-sha2-*`); pinning `Rsa { hash: None }` alone offers
    /// SHA-1 only, which OpenSSH >= 8.8 refuses by default — the connection
    /// then fails outright instead of being pinned (R25-40).
    fn algorithms_from_openssh_name(name: &str) -> Vec<russh::keys::ssh_key::Algorithm> {
        use russh::keys::ssh_key::{Algorithm, EcdsaCurve, HashAlg};

        match name {
            "ssh-ed25519" => vec![Algorithm::Ed25519],
            "ssh-rsa" => vec![
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha512),
                },
                Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256),
                },
                Algorithm::Rsa { hash: None },
            ],
            "ecdsa-sha2-nistp256" => vec![Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            }],
            "ecdsa-sha2-nistp384" => vec![Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            }],
            "ecdsa-sha2-nistp521" => vec![Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            }],
            other => {
                crate::coverage::record(format!(
                    "known_hosts: unmapped host key type `{}` for this host — offer not pinned",
                    crate::utils::sanitize_for_log(other)
                ));
                Vec::new()
            }
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

        let mut conflict: Option<(String, PathBuf)> = None;

        for entry in &self.entries {
            if entry.key_type == ptype && entry.key_data == pdata {
                return Ok(true);
            }

            // Store the first conflicting entry for error reporting.
            conflict.get_or_insert_with(|| {
                let file = match entry.store {
                    TrustStore::System => self.system_file.clone(),
                    TrustStore::Pin => self.pin_file.clone(),
                };
                (entry.as_line(), file)
            });
        }

        if let Some((conflict_line, conflict_file)) = conflict {
            return Err(crate::ssh_engine::RemoteError::HostKeyChanged {
                host: self.host.clone(),
                file: conflict_file.display().to_string(),
                line: conflict_line,
            });
        }

        // No entry for this host at all → TOFU.
        let candidate = &Self::host_candidates(&self.host, self.port)[0];
        let entry = format!("{} {} {}\n", candidate, ptype, pdata);
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
        let candidates = KnownHostsChecker::host_candidates("example.com", 22);
        assert!(KnownHostsChecker::host_field_matches(
            "example.com,other.example.com",
            &candidates
        ));
        assert!(!KnownHostsChecker::host_field_matches(
            "evil.com",
            &candidates
        ));
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

        let checker = KnownHostsChecker::from_files(
            "localhost".into(),
            22,
            kh_path.clone(),
            tmp_dir.path().join("pin"),
        );
        assert!(checker.verify(pub_key).is_ok());

        // Change key and expect HostKeyChanged
        let bad_line = format!("localhost {} AAAA...fake\n", key_type);
        std::fs::write(&kh_path, bad_line).unwrap();
        let checker_bad = KnownHostsChecker::from_files(
            "localhost".into(),
            22,
            kh_path,
            tmp_dir.path().join("pin2"),
        );
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

        let checker = KnownHostsChecker::from_files(
            "localhost".into(),
            22,
            kh_path,
            tmp_dir.path().join("pin"),
        );

        assert!(matches!(
            checker.verify(ed_key.public_key()),
            Err(crate::ssh_engine::RemoteError::HostKeyChanged { .. })
        ));
    }

    #[test]
    fn pinned_algorithms_reads_host_key_types() {
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let kh_path = tmp_dir.path().join("known_hosts");
        std::fs::write(
            &kh_path,
            "localhost ssh-ed25519 AAAAB3NzaC1lZDI1NTE5AAAAI\nlocalhost ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB\n",
        )
            .unwrap();

        let checker = KnownHostsChecker::from_files(
            "localhost".into(),
            22,
            kh_path,
            tmp_dir.path().join("pin"),
        );

        let algs = checker.pinned_algorithms();
        assert!(algs.len() >= 2);
    }
}
