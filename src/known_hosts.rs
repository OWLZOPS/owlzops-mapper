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
    /// `true` if this entry came from an OpenSSH `@revoked` marker line.
    revoked: bool,
    /// 1-based line number in the source file, for `HostKeyChanged` diagnostics.
    line_number: usize,
}

impl KnownHostEntry {
    /// Reconstructed for the HostKeyChanged message; storing the raw line as
    /// well would duplicate every field a second time.
    fn as_line(&self) -> String {
        let prefix = if self.revoked { "@revoked " } else { "" };
        format!(
            "{}{} {} {}",
            prefix, self.host_field, self.key_type, self.key_data
        )
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
            // R25-72: trust store must be strict UTF-8. A lossy conversion
            // would silently replace a corrupted byte with U+FFFD and could
            // turn a valid key into a different one, causing false TOFU or
            // HostKeyChanged.
            let (content, truncated) = match crate::safe_io::read_file_capped_regular_strict(
                &path.to_string_lossy(),
                CAP_KNOWN_HOSTS,
            ) {
                Ok(tuple) => tuple,
                // A missing store is the first-run case and is legitimate.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err((path.to_path_buf(), e)),
            };

            // Entries past the cap are invisible, so a host whose key lives in
            // the tail looks UNKNOWN and gets TOFU-pinned to whatever the
            // server presents — the exact failure R25-54 closed (R25-63).
            if truncated {
                return Err((
                    path.to_path_buf(),
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "trust store exceeds {CAP_KNOWN_HOSTS} bytes and was truncated; \
                             refusing to treat a partial store as complete"
                        ),
                    ),
                ));
            }

            for (idx, raw_line) in content.lines().enumerate() {
                let line_number = idx + 1;
                let line = raw_line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                // OpenSSH marker lines start with `@revoked` / `@cert-authority`.
                // Positional parsing silently drops them, so an explicitly
                // REVOKED key looks like an unknown host and gets TOFU-pinned
                // (R25-66).
                let (marker, rest) = match line.strip_prefix('@') {
                    Some(r) => match r.split_once(char::is_whitespace) {
                        Some((m, rest)) => (Some(m), rest.trim_start()),
                        None => continue,
                    },
                    None => (None, line),
                };

                match marker {
                    // A CA-signed host key is a trust model we do not implement.
                    // Refusing is correct; silently ignoring is not.
                    Some("cert-authority") => {
                        crate::coverage::record(format!(
                            "known_hosts: @cert-authority entry for {} ignored — \
                             certificate host keys are not supported",
                            candidates.first().map(String::as_str).unwrap_or("?")
                        ));
                        continue;
                    }
                    Some("revoked") => {}
                    Some(other) => {
                        crate::coverage::record(format!(
                            "known_hosts: unknown marker `@{}` — entry ignored",
                            crate::utils::sanitize_for_log(other)
                        ));
                        continue;
                    }
                    None => {}
                }

                let mut f = rest.split_whitespace();
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
                    revoked: marker == Some("revoked"),
                    line_number,
                });
            }
        }

        Ok(out)
    }

    #[cfg(test)]
    fn from_files(host: String, port: u16, system_file: PathBuf, pin_file: PathBuf) -> Self {
        let candidates = Self::host_candidates(&host, port);
        let entries = Self::load_entries(&system_file, &pin_file, &candidates)
            .expect("test trust store must be readable");

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
            let (algs, unknown) = Self::algorithms_from_openssh_name(&entry.key_type);
            if let Some(unknown) = unknown {
                crate::coverage::record(format!(
                    "known_hosts: unmapped host key type `{}` for host {} — offer not pinned",
                    crate::utils::sanitize_for_log(unknown),
                    self.host
                ));
            }
            for alg in algs {
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
    fn algorithms_from_openssh_name(
        name: &str,
    ) -> (Vec<russh::keys::ssh_key::Algorithm>, Option<&str>) {
        use russh::keys::ssh_key::{Algorithm, EcdsaCurve, HashAlg};

        match name {
            "ssh-ed25519" => (vec![Algorithm::Ed25519], None),
            "ssh-rsa" => (
                vec![
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha512),
                    },
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha256),
                    },
                    Algorithm::Rsa { hash: None },
                ],
                None,
            ),
            "ecdsa-sha2-nistp256" => (
                vec![Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP256,
                }],
                None,
            ),
            "ecdsa-sha2-nistp384" => (
                vec![Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP384,
                }],
                None,
            ),
            "ecdsa-sha2-nistp521" => (
                vec![Algorithm::Ecdsa {
                    curve: EcdsaCurve::NistP521,
                }],
                None,
            ),
            other => (Vec::new(), Some(other)),
        }
    }

    /// Normalises a key type string for comparison.
    ///
    /// R25-55: known_hosts records the KEY type; a session may negotiate a SHA-2
    /// signature over the same key. Compare on the key type, never on the
    /// signature algorithm.
    ///
    /// The SSH wire format repeats the algorithm name inside the key blob as
    /// `ssh-rsa` regardless of the signature hash, so this normalises only the
    /// TYPE FIELD. The blob itself is already hash-independent.
    /// R25-64: test `the_openssh_blob_encodes_the_base_algorithm_name` proves
    /// this; R25-78: resolved by the same test and this doc.
    fn canonical_key_type(t: &str) -> &str {
        match t {
            "rsa-sha2-256" | "rsa-sha2-512" => "ssh-rsa",
            other => other,
        }
    }

    /// Verify the presented server key.
    ///
    /// The `entries` slice is captured once in `new()`/`from_files()` and is
    /// deliberately NOT refreshed after a successful TOFU write to `pin_file`.
    /// A repeated `verify()` on the same `KnownHostsChecker` after the first
    /// TOFU must therefore not be used to re-check the same connection: create
    /// a new checker for a new session/rekey.
    ///
    /// Logic:
    /// 0. If the presented key matches an entry flagged `@revoked`, return
    ///    `HostKeyRevoked` immediately — explicit operator decision outranks
    ///    both exact match and TOFU (R25-66).
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
        let ptype_canon = Self::canonical_key_type(ptype);

        // A revoked key is an explicit operator decision and outranks both an
        // exact match and TOFU.
        for entry in self.entries.iter().filter(|e| e.revoked) {
            if Self::canonical_key_type(&entry.key_type) == ptype_canon && entry.key_data == pdata {
                return Err(crate::ssh_engine::RemoteError::HostKeyRevoked {
                    host: self.host.clone(),
                });
            }
        }

        let mut conflict: Option<(String, PathBuf, usize)> = None;

        for entry in &self.entries {
            if Self::canonical_key_type(&entry.key_type) == ptype_canon && entry.key_data == pdata {
                return Ok(true);
            }

            // Store the first conflicting entry for error reporting.
            conflict.get_or_insert_with(|| {
                let file = match entry.store {
                    TrustStore::System => self.system_file.clone(),
                    TrustStore::Pin => self.pin_file.clone(),
                };
                (entry.as_line(), file, entry.line_number)
            });
        }

        if let Some((conflict_line, conflict_file, conflict_line_number)) = conflict {
            return Err(crate::ssh_engine::RemoteError::HostKeyChanged {
                host: self.host.clone(),
                file: conflict_file.display().to_string(),
                line: conflict_line,
                line_number: conflict_line_number,
            });
        }

        // No entry for this host at all → TOFU.
        let candidate = &Self::host_candidates(&self.host, self.port)[0];
        let entry = format!("{} {} {}\n", candidate, ptype_canon, pdata);
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
        // Synthetic key blobs: pinned_algorithms reads only the key type field,
        // so the truncated base64 payloads are intentionally not real keys.
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

    #[test]
    fn an_ssh_rsa_entry_offers_sha2_signature_algorithms() {
        use russh::keys::ssh_key::{Algorithm, HashAlg};

        let tmp_dir = tempfile::TempDir::new().unwrap();
        let kh_path = tmp_dir.path().join("known_hosts");
        std::fs::write(&kh_path, "localhost ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB\n").unwrap();

        let checker = KnownHostsChecker::from_files(
            "localhost".into(),
            22,
            kh_path,
            tmp_dir.path().join("pin"),
        );

        let algs = checker.pinned_algorithms();
        assert!(algs.contains(&Algorithm::Rsa {
            hash: Some(HashAlg::Sha512)
        }));
        assert!(algs.contains(&Algorithm::Rsa {
            hash: Some(HashAlg::Sha256)
        }));
    }

    #[test]
    fn an_rsa_key_verifies_against_an_rsa_sha2_known_hosts_line() {
        use russh::keys::ssh_key::{Algorithm, HashAlg, PrivateKey};

        let rsa = PrivateKey::random(
            &mut rand::rng(),
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
        )
        .unwrap();
        let pub_key = rsa.public_key();
        let openssh = pub_key.to_openssh().unwrap();
        let mut parts = openssh.split_whitespace();
        let _ptype = parts.next().unwrap();
        let pdata = parts.next().unwrap();

        // The file records the SIGNATURE algorithm, while our key material is
        // the same. canonical_key_type must treat rsa-sha2-512 as ssh-rsa for
        // the comparison (R25-64).
        let tmp_dir = tempfile::TempDir::new().unwrap();
        let kh_path = tmp_dir.path().join("known_hosts");
        std::fs::write(&kh_path, format!("localhost rsa-sha2-512 {pdata}\n")).unwrap();

        let checker = KnownHostsChecker::from_files(
            "localhost".into(),
            22,
            kh_path,
            tmp_dir.path().join("pin"),
        );

        assert!(matches!(checker.verify(pub_key), Ok(true)));
    }

    #[test]
    fn the_openssh_blob_encodes_the_base_algorithm_name() {
        // `canonical_key_type` normalises only the TYPE FIELD. The SSH wire
        // format repeats the algorithm name as the first length-prefixed
        // string INSIDE the blob. If that varies with the signature hash,
        // `entry.key_data == pdata` still fails and every RSA host becomes
        // HostKeyChanged — R25-55 would not be closed (R25-78).
        use russh::keys::ssh_key::{Algorithm, HashAlg, PrivateKey};

        let k = PrivateKey::random(
            &mut rand::rng(),
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
        )
        .unwrap();

        let line = k.public_key().to_openssh().unwrap();
        let mut parts = line.split_whitespace();
        let ptype = parts.next().unwrap();
        let blob = data_encoding::BASE64
            .decode(parts.next().unwrap().as_bytes())
            .unwrap();

        let n = u32::from_be_bytes(blob[..4].try_into().unwrap()) as usize;
        let name = std::str::from_utf8(&blob[4..4 + n]).unwrap();

        assert_eq!(
            name, "ssh-rsa",
            "blob carries the signature algorithm ({ptype}); normalise KeyData, \
             not just the type field"
        );
    }
}
