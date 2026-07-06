use russh::keys::{PrivateKeyWithHashAlg, load_secret_key};
use russh::*;
use std::io::{IsTerminal, Read};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum RemoteError {
    #[error("host key for {host} has changed! possible MITM attack. Run: ssh-keygen -R {host}")]
    HostKeyChanged { host: String, line: String },
    #[error("host key for {host} is unknown and not in known_hosts")]
    HostKeyUnknown { host: String },
    #[error("failed to check host key for {host}: {detail}")]
    HostKeyCheck { host: String, detail: String },
    #[error("I/O error on {host}: {source}")]
    Io {
        host: String,
        source: std::io::Error,
    },
    #[error("SSH protocol error on {host}: {source}")]
    Ssh { host: String, source: russh::Error },
    #[error("authentication failed for {user}@{host}")]
    Auth { host: String, user: String },
    #[error("sudo rejected password on {host}")]
    SudoAuth { host: String },
    #[error("timeout on {host}")]
    Timeout { host: String },
    #[error("remote command exited with {code} on {host}: {stderr}")]
    NonZeroExit {
        host: String,
        code: u32,
        stderr: String,
    },
}

impl From<russh::Error> for RemoteError {
    fn from(source: russh::Error) -> Self {
        RemoteError::Ssh {
            host: String::new(),
            source,
        }
    }
}

struct ClientHandler {
    host: String,
    known_hosts: PathBuf,
}

impl client::Handler for ClientHandler {
    type Error = RemoteError;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        let path = self.known_hosts.clone();
        let host = self.host.clone();

        if !path.exists() {
            tracing::warn!(
                "{}: ~/.ssh/known_hosts not found, accepting server key (TOFU)",
                host
            );
            return Ok(true);
        }

        let contents = std::fs::read_to_string(&path).map_err(|e| RemoteError::HostKeyCheck {
            host: host.clone(),
            detail: e.to_string(),
        })?;
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.contains(&host) || line.contains(&format!("[{}]", host)) {
                return Ok(true);
            }
        }
        tracing::warn!(
            "{}: host not found in known_hosts, accepting server key (TOFU)",
            host
        );
        Ok(true)
    }
}

pub fn resolve_sudo_password() -> Result<Zeroizing<String>, RemoteError> {
    if let Ok(p) = std::env::var("OWLZOPS_SUDO_PASS")
        && !p.is_empty()
    {
        return Ok(Zeroizing::new(p));
    }

    if std::io::stdin().is_terminal() {
        let p = dialoguer::Password::new()
            .with_prompt("sudo password (remote)")
            .interact()
            .map_err(|e| RemoteError::HostKeyCheck {
                host: "localhost".to_string(),
                detail: e.to_string(),
            })?;
        if p.is_empty() {
            return Err(RemoteError::SudoAuth {
                host: "localhost".to_string(),
            });
        }
        return Ok(Zeroizing::new(p));
    }

    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| RemoteError::HostKeyCheck {
            host: "localhost".to_string(),
            detail: e.to_string(),
        })?;
    let pass = buf.trim_end_matches(['\n', '\r']).to_string();
    if pass.is_empty() {
        return Err(RemoteError::SudoAuth {
            host: "localhost".to_string(),
        });
    }
    Ok(Zeroizing::new(pass))
}

fn split_host_port(host: &str) -> (String, u16) {
    if let Some((h, p)) = host.rsplit_once(':')
        && p.chars().all(|c| c.is_ascii_digit())
        && !p.is_empty()
    {
        return (h.to_string(), p.parse().unwrap_or(22));
    }
    (host.to_string(), 22)
}

/// Upload the mapper binary to the remote host asynchronously using system scp.
/// Uses an atomic replace pattern: upload to .tmp, then mv to final path and chmod.
pub async fn upload_binary_async(
    host: &str,
    ssh_user: &str,
    ssh_key: &str,
    local_bin: &str,
    remote_path: &str,
    timeout_secs: u64,
) -> Result<(), RemoteError> {
    let tmp_remote = format!("{}.tmp", remote_path);

    // 1. Remove old temporary file (ignore errors)
    let _ = Command::new("ssh")
        .arg("-i")
        .arg(ssh_key)
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new")
        .arg("-o")
        .arg("ConnectTimeout=10")
        .arg(format!("{}@{}", ssh_user, host))
        .arg("rm")
        .arg("-f")
        .arg(&tmp_remote)
        .status()
        .await;

    // 2. Upload binary to temporary file
    let scp_status = tokio::time::timeout(
        Duration::from_secs(timeout_secs / 2),
        Command::new("scp")
            .arg("-i")
            .arg(ssh_key)
            .arg("-o")
            .arg("StrictHostKeyChecking=accept-new")
            .arg(local_bin)
            .arg(format!("{}@{}:{}", ssh_user, host, tmp_remote))
            .status(),
    )
    .await
    .map_err(|_| RemoteError::Timeout {
        host: host.to_string(),
    })?
    .map_err(|e| RemoteError::Io {
        host: host.to_string(),
        source: e,
    })?;

    if !scp_status.success() {
        return Err(RemoteError::HostKeyCheck {
            host: host.to_string(),
            detail: "SCP returned non-zero exit code".to_string(),
        });
    }

    // 3. Atomic replace: mv .tmp → final && chmod +x
    let mv_status = tokio::time::timeout(
        Duration::from_secs(10),
        Command::new("ssh")
            .arg("-i")
            .arg(ssh_key)
            .arg("-o")
            .arg("StrictHostKeyChecking=accept-new")
            .arg("-o")
            .arg("ConnectTimeout=10")
            .arg(format!("{}@{}", ssh_user, host))
            .arg("mv")
            .arg("-f")
            .arg(&tmp_remote)
            .arg(remote_path)
            .arg("&&")
            .arg("chmod")
            .arg("+x")
            .arg(remote_path)
            .status(),
    )
    .await
    .map_err(|_| RemoteError::Timeout {
        host: host.to_string(),
    })?
    .map_err(|e| RemoteError::Io {
        host: host.to_string(),
        source: e,
    })?;

    if !mv_status.success() {
        return Err(RemoteError::HostKeyCheck {
            host: host.to_string(),
            detail: "Atomic replace returned non-zero exit code".to_string(),
        });
    }

    Ok(())
}

/// Connect to a remote host via russh, execute the audit with `sudo -S`,
/// and return the raw JSON output.
/// Binary upload is handled by `upload_binary_async` before calling this function.
pub async fn run_remote_scan_russh(
    host: &str,
    ssh_user: &str,
    ssh_key_path: &str,
    remote_path: &str,
    sudo_pass: &Zeroizing<String>,
) -> Result<Vec<u8>, RemoteError> {
    let (hostname, port) = split_host_port(host);
    let known_hosts = dirs_next::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".ssh")
        .join("known_hosts");

    let stream = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::net::TcpStream::connect((hostname.as_str(), port)),
    )
    .await
    .map_err(|_| RemoteError::Timeout {
        host: hostname.clone(),
    })?
    .map_err(|e| RemoteError::Io {
        host: hostname.clone(),
        source: e,
    })?;

    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    });
    let handler = ClientHandler {
        host: hostname.clone(),
        known_hosts,
    };
    let mut session = client::connect_stream(config, stream, handler).await?;

    let key = load_secret_key(ssh_key_path, None).map_err(|_| RemoteError::Auth {
        host: hostname.clone(),
        user: ssh_user.to_string(),
    })?;

    let auth = session
        .authenticate_publickey(
            ssh_user.to_string(),
            PrivateKeyWithHashAlg::new(
                Arc::new(key),
                session.best_supported_rsa_hash().await?.flatten(),
            ),
        )
        .await?;

    if !auth.success() {
        return Err(RemoteError::Auth {
            host: hostname.clone(),
            user: ssh_user.to_string(),
        });
    }

    // Execute audit with sudo -S (no binary upload here — caller handles that)
    let mut exec_channel = session.channel_open_session().await?;
    exec_channel
        .exec(
            true,
            format!(
                "sudo -k -S -p '' -- {} audit --format json --offline",
                remote_path
            ),
        )
        .await?;

    let mut line = Zeroizing::new(sudo_pass.to_string());
    line.push('\n');
    exec_channel.data(line.as_bytes()).await?;
    exec_channel.eof().await?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_code: Option<u32> = None;

    while let Some(msg) = exec_channel.wait().await {
        match msg {
            ChannelMsg::Data { ref data } => stdout.extend_from_slice(data),
            ChannelMsg::ExtendedData { ref data, ext: 1 } => stderr.extend_from_slice(data),
            ChannelMsg::ExitStatus { exit_status } => exit_code = Some(exit_status),
            ChannelMsg::Close => break,
            ChannelMsg::Eof => {
                // Do not break — ExitStatus arrives after EOF
            }
            _ => {}
        }
    }

    match exit_code {
        Some(code) => {
            let se = String::from_utf8_lossy(&stderr);

            // 1. Check if sudo rejected the password
            if se.contains("incorrect password")
                || se.contains("Sorry, try again")
                || se.contains("a password is required")
            {
                return Err(RemoteError::SudoAuth { host: hostname });
            }

            // 2. If stdout looks like JSON, the audit succeeded regardless of exit code
            if !stdout.is_empty() && stdout.starts_with(b"{") {
                return Ok(stdout);
            }

            // 3. Real failure (no binary, segfault, etc.)
            if code != 0 {
                let trimmed: String = se.trim().chars().take(300).collect();
                Err(RemoteError::NonZeroExit {
                    host: hostname,
                    code,
                    stderr: trimmed,
                })
            } else {
                Ok(stdout)
            }
        }
        None => Err(RemoteError::Timeout { host: hostname }),
    }
}
