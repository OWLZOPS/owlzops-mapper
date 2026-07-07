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
    pub fn new(host: String, port: u16) -> Self {
        let home = dirs_next::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        Self {
            host,
            port,
            system_file: home.join(".ssh/known_hosts"),
            pin_file: home.join(".owlzops/known_hosts"),
        }
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
