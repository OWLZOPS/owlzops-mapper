use indicatif::{ProgressBar, ProgressStyle};
use russh::keys::{PrivateKeyWithHashAlg, load_secret_key};
use russh::*;
use std::io::{IsTerminal, Read};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

use crate::known_hosts::KnownHostsChecker;
use crate::safe_io;

const CAP_REMOTE_STDERR: usize = 256 * 1024; // 256 KiB

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum RemoteError {
    #[error(
        "host key for {host} in {file} has changed! possible MITM attack. Run: ssh-keygen -R {host} -f {file}"
    )]
    HostKeyChanged {
        host: String,
        file: String,
        line: String,
    },
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

// Required by russh::client::Handler::Error bound
impl From<russh::Error> for RemoteError {
    fn from(source: russh::Error) -> Self {
        RemoteError::Ssh {
            host: String::new(),
            source,
        }
    }
}

impl RemoteError {
    fn from_russh(err: russh::Error, host: &str) -> Self {
        RemoteError::Ssh {
            host: host.to_string(),
            source: err,
        }
    }
}

struct ClientHandler {
    known_hosts_checker: KnownHostsChecker,
}

impl client::Handler for ClientHandler {
    type Error = RemoteError;

    async fn check_server_key(
        &mut self,
        key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        self.known_hosts_checker.verify(key)
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
    // [addr]:port
    if let Some(rest) = host.strip_prefix('[')
        && let Some((addr, tail)) = rest.split_once(']')
    {
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(22);
        return (addr.to_string(), port);
    }
    // bare IPv6 (>=2 colons, no brackets)
    if host.matches(':').count() >= 2 {
        return (host.to_string(), 22);
    }
    // host:port
    if let Some((h, p)) = host.rsplit_once(':')
        && !p.is_empty()
        && p.bytes().all(|b| b.is_ascii_digit())
    {
        return (h.to_string(), p.parse().unwrap_or(22));
    }
    (host.to_string(), 22)
}

/// Upload a binary file over an existing russh channel by piping `cat > path`
/// and feeding the file in chunks. Progress bar is updated incrementally.
async fn upload_via_channel(
    channel: &mut Channel<client::Msg>,
    local_bin: &str,
    remote_path: &str,
    host: &str,
) -> Result<(), RemoteError> {
    let metadata = std::fs::metadata(local_bin).map_err(|e| RemoteError::Io {
        host: host.to_string(),
        source: e,
    })?;
    let file_size = metadata.len();

    // Setup progress bar
    let pb = ProgressBar::new(file_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message(format!("Uploading to {host}"));

    // Start remote cat command
    channel
        .exec(
            true,
            format!(
                "cat > {}.tmp && mv {}.tmp {} && chmod +x {}",
                remote_path, remote_path, remote_path, remote_path
            ),
        )
        .await
        .map_err(|e| RemoteError::from_russh(e, host))?;

    // Stream file content in chunks
    let mut file = std::fs::File::open(local_bin).map_err(|e| RemoteError::Io {
        host: host.to_string(),
        source: e,
    })?;
    let mut buf = [0u8; 64 * 1024]; // 64 KiB chunks
    loop {
        let n = file.read(&mut buf).map_err(|e| RemoteError::Io {
            host: host.to_string(),
            source: e,
        })?;
        if n == 0 {
            break;
        }
        channel
            .data(&buf[..n])
            .await
            .map_err(|e| RemoteError::from_russh(e, host))?;
        pb.inc(n as u64);
    }
    channel
        .eof()
        .await
        .map_err(|e| RemoteError::from_russh(e, host))?;
    pb.finish_with_message("Uploaded");
    Ok(())
}

/// Connect to a remote host via russh, upload the binary if needed,
/// execute the audit with `sudo -S`, and return the raw JSON output.
#[allow(clippy::too_many_arguments)]
pub async fn run_remote_scan_russh(
    host: &str,
    ssh_user: &str,
    ssh_key_path: &str,
    remote_path: &str,
    sudo_pass: &Zeroizing<String>,
    copy_binary: bool,
    local_bin: Option<&str>,
    remote_timeout_secs: u64,
) -> Result<Vec<u8>, RemoteError> {
    let (hostname, port) = split_host_port(host);

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
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 3,
        ..Default::default()
    });
    let handler = ClientHandler {
        known_hosts_checker: KnownHostsChecker::new(hostname.clone(), port),
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
        .await
        .map_err(|e| RemoteError::from_russh(e, &hostname))?;

    if !auth.success() {
        return Err(RemoteError::Auth {
            host: hostname.clone(),
            user: ssh_user.to_string(),
        });
    }

    // Apply overall timeout for the rest of the operation.
    // Clone hostname so the outer scope can still use it for the timeout error.
    let hostname_for_timeout = hostname.clone();
    let overall = Duration::from_secs(remote_timeout_secs.saturating_mul(2).saturating_add(60) + 5);

    let result = tokio::time::timeout(overall, async {
        // If binary copy is requested, upload via the same channel
        if copy_binary {
            let default_exe = std::path::PathBuf::from("./owlzops-mapper");
            let current_exe = std::env::current_exe().unwrap_or(default_exe);
            let current_exe_lossy = current_exe.to_string_lossy();
            let local = local_bin.unwrap_or(&current_exe_lossy);
            let mut upload_channel = session
                .channel_open_session()
                .await
                .map_err(|e| RemoteError::from_russh(e, &hostname_for_timeout))?;
            upload_via_channel(
                &mut upload_channel,
                local,
                remote_path,
                &hostname_for_timeout,
            )
            .await?;
        }

        // Execute audit with sudo -S
        let mut exec_channel = session
            .channel_open_session()
            .await
            .map_err(|e| RemoteError::from_russh(e, &hostname_for_timeout))?;
        exec_channel
            .exec(
                true,
                format!(
                    "sudo -k -S -p '' -- {} audit --format json --offline",
                    remote_path
                ),
            )
            .await
            .map_err(|e| RemoteError::from_russh(e, &hostname_for_timeout))?;

        let mut line = Zeroizing::new(sudo_pass.to_string());
        line.push('\n');
        exec_channel
            .data(line.as_bytes())
            .await
            .map_err(|e| RemoteError::from_russh(e, &hostname_for_timeout))?;
        exec_channel
            .eof()
            .await
            .map_err(|e| RemoteError::from_russh(e, &hostname_for_timeout))?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code: Option<u32> = None;
        let mut stdout_truncated = false;
        let mut stderr_truncated = false;

        while let Some(msg) = exec_channel.wait().await {
            match msg {
                ChannelMsg::Data { ref data } => {
                    let room = safe_io::CAP_CHILD_STDOUT.saturating_sub(stdout.len());
                    if room > 0 {
                        stdout.extend_from_slice(&data[..data.len().min(room)]);
                    } else if !stdout_truncated {
                        stdout_truncated = true;
                        tracing::warn!(
                            host = %hostname_for_timeout,
                            "remote stdout exceeded cap ({} bytes), truncating",
                            safe_io::CAP_CHILD_STDOUT
                        );
                    }
                }
                ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                    let room = CAP_REMOTE_STDERR.saturating_sub(stderr.len());
                    if room > 0 {
                        stderr.extend_from_slice(&data[..data.len().min(room)]);
                    } else if !stderr_truncated {
                        stderr_truncated = true;
                        tracing::warn!(
                            host = %hostname_for_timeout,
                            "remote stderr exceeded cap ({} bytes), truncating",
                            CAP_REMOTE_STDERR
                        );
                    }
                }
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
                    return Err(RemoteError::SudoAuth {
                        host: hostname_for_timeout,
                    });
                }

                // 2. If stdout looks like JSON, the audit succeeded regardless of exit code
                if !stdout.is_empty() && stdout.starts_with(b"{") {
                    return Ok(stdout);
                }

                // 3. Real failure (no binary, segfault, etc.)
                if code != 0 {
                    let trimmed: String = se.trim().chars().take(300).collect();
                    Err(RemoteError::NonZeroExit {
                        host: hostname_for_timeout,
                        code,
                        stderr: trimmed,
                    })
                } else {
                    Ok(stdout)
                }
            }
            None => Err(RemoteError::Timeout {
                host: hostname_for_timeout,
            }),
        }
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_elapsed) => Err(RemoteError::Timeout { host: hostname }),
    }
}
