use indicatif::{ProgressBar, ProgressStyle};
use russh::keys::{PrivateKeyWithHashAlg, load_secret_key};
use russh::*;
use std::io::{IsTerminal, Read};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::AsyncReadExt; // for .read() on tokio::fs::File
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
    #[error("binary upload to {host} failed: {detail}")]
    UploadFailed { host: String, detail: String },
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

pub(crate) fn split_host_port(host: &str) -> (String, u16) {
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

/// Kernel-level dead-transport detection. Idle-death of a peer is detected
/// within ~KEEPIDLE + KEEPINTVL*KEEPCNT seconds (≈60 s). TCP_USER_TIMEOUT
/// ensures that unsent data does not hang in retransmissions beyond that window
/// when the budget expires.
#[cfg(target_os = "linux")]
fn harden_tcp(stream: &tokio::net::TcpStream) -> std::io::Result<()> {
    const KEEPIDLE_S: libc::c_int = 30;
    const KEEPINTVL_S: libc::c_int = 10;
    const KEEPCNT: libc::c_int = 3;

    fn set<T>(
        fd: std::os::fd::RawFd,
        level: libc::c_int,
        name: libc::c_int,
        v: &T,
    ) -> std::io::Result<()> {
        // SAFETY: pointer and size match T; kernel copies value synchronously.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                (v as *const T).cast(),
                std::mem::size_of::<T>() as libc::socklen_t,
            )
        };
        if rc == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    let fd = stream.as_raw_fd();
    set(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, &1i32)?;
    set(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, &KEEPIDLE_S)?;
    set(fd, libc::IPPROTO_TCP, libc::TCP_KEEPINTVL, &KEEPINTVL_S)?;
    set(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, &KEEPCNT)?;
    let user_timeout_ms: libc::c_uint =
        ((KEEPIDLE_S + KEEPINTVL_S * KEEPCNT) * 1000) as libc::c_uint;
    set(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_USER_TIMEOUT,
        &user_timeout_ms,
    )
}

#[cfg(not(target_os = "linux"))]
fn harden_tcp(_stream: &tokio::net::TcpStream) -> std::io::Result<()> {
    // macOS: SO_KEEPALIVE exists, but TCP_KEEPIDLE/USER_TIMEOUT don't.
    // Dead-transport detection is handled by application-level tokio deadlines.
    Ok(())
}

/// Upload a binary file over an existing russh channel by piping `cat > path`
/// and feeding the file in chunks. If `upload_pb` is provided it is used to
/// show progress; otherwise a hidden bar is substituted so call sites do not
/// need special-case handling. The caller is responsible for cleaning up the
/// bar afterwards (e.g. via `finish_and_clear` on the MultiProgress).
async fn upload_via_channel(
    channel: &mut Channel<client::Msg>,
    local_bin: &str,
    remote_path: &str,
    host: &str,
    upload_pb: Option<ProgressBar>,
) -> Result<(), RemoteError> {
    let metadata = tokio::fs::metadata(local_bin)
        .await
        .map_err(|e| RemoteError::Io {
            host: host.to_string(),
            source: e,
        })?;
    let file_size = metadata.len();

    let pb = if let Some(pb) = upload_pb {
        pb.set_length(file_size);
        pb.set_message(format!("Uploading to {host}"));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {bytes}/{total_bytes} ({eta})")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("#>-"),
        );
        pb
    } else {
        ProgressBar::hidden()
    };

    let res = async {
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

        let mut file = tokio::fs::File::open(local_bin)
            .await
            .map_err(|e| RemoteError::Io {
                host: host.to_string(),
                source: e,
            })?;
        let mut buf = [0u8; 32 * 1024];
        loop {
            let n = file.read(&mut buf).await.map_err(|e| RemoteError::Io {
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

        let mut exit: Option<u32> = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        match exit {
            Some(0) => Ok(()),
            Some(code) => Err(RemoteError::UploadFailed {
                host: host.to_string(),
                detail: format!("remote command exited {code} (disk full / permissions?)"),
            }),
            None => Err(RemoteError::UploadFailed {
                host: host.to_string(),
                detail: "channel closed without exit status".into(),
            }),
        }
    }
    .await;

    pb.finish_and_clear();

    if let Err(ref e) = res {
        tracing::warn!(host = %host, error = %e, "Binary upload failed");
    }

    res
}

/// Best-effort removal of the uploaded binary (including any leftover `.tmp`
/// staging file) over a fresh channel. Failures are logged but never fatal —
/// the audit outcome is already final by the time this runs.
async fn cleanup_remote_binary(
    session: &client::Handle<ClientHandler>,
    remote_path: &str,
    host: &str,
) {
    let fut = async {
        let mut ch = session.channel_open_session().await?;
        ch.exec(true, format!("rm -f -- {remote_path} {remote_path}.tmp"))
            .await?;
        ch.eof().await?;
        let mut exit: Option<u32> = None;
        while let Some(msg) = ch.wait().await {
            match msg {
                ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        Ok::<Option<u32>, russh::Error>(exit)
    };
    match tokio::time::timeout(Duration::from_secs(10), fut).await {
        Ok(Ok(Some(0))) => tracing::debug!(host = %host, "remote binary removed"),
        Ok(Ok(code)) => tracing::warn!(
            host = %host,
            exit = ?code,
            "cleanup did not confirm success — binary may be left on host"
        ),
        Ok(Err(e)) => {
            tracing::warn!(host = %host, error = %e, "cleanup failed — binary left on host")
        }
        Err(_) => tracing::warn!(host = %host, "cleanup timed out — binary left on host"),
    }
}

/// Connect to a remote host via russh, upload the binary if needed,
/// execute the audit (with or without sudo depending on whether `sudo_pass`
/// is provided), and return the raw JSON output.
/// Unless `keep_binary` is set, the binary at `remote_path` is removed
/// afterwards (parity with the legacy SSH path) and the session is
/// disconnected cleanly via SSH_MSG_DISCONNECT.
#[allow(clippy::too_many_arguments)]
pub async fn run_remote_scan_russh(
    host: &str,
    ssh_user: &str,
    ssh_key_path: &str,
    remote_path: &str,
    sudo_pass: Option<&Zeroizing<String>>,
    copy_binary: bool,
    keep_binary: bool,
    local_bin: Option<&str>,
    deep: bool,
    remote_timeout_secs: u64,
    upload_pb: Option<ProgressBar>,
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

    if let Err(e) = stream.set_nodelay(true) {
        tracing::warn!(
            host = %hostname,
            error = %e,
            "failed to set TCP_NODELAY — continuing with default socket options"
        );
    }

    // Kernel-level dead-transport detection; best-effort
    if let Err(e) = harden_tcp(&stream) {
        tracing::warn!(
            host = %hostname,
            error = %e,
            "failed to tune TCP keepalive/user-timeout — dead-transport detection degraded"
        );
    }

    // Internal SSH timers removed – duration is entirely controlled
    // by external tokio deadlines (connect / handshake+auth / overall).
    let config = Arc::new(client::Config {
        inactivity_timeout: None,
        keepalive_interval: None,
        ..Default::default()
    });

    let handler = ClientHandler {
        known_hosts_checker: KnownHostsChecker::new(hostname.clone(), port).map_err(|e| {
            RemoteError::HostKeyCheck {
                host: hostname.clone(),
                detail: e.to_string(),
            }
        })?,
    };

    // Wrap handshake + auth in a 30-second deadline; load key
    // before the deadline so local disk I/O does not count against it.
    // The key loading itself is a blocking operation (disk I/O + parsing),
    // so run it on a blocking thread to avoid stalling the async runtime.
    let ssh_key_path = ssh_key_path.to_string();
    let key = tokio::task::spawn_blocking(move || load_secret_key(&ssh_key_path, None))
        .await
        .map_err(|_| RemoteError::Auth {
            host: hostname.clone(),
            user: ssh_user.to_string(),
        })?
        .map_err(|_| RemoteError::Auth {
            host: hostname.clone(),
            user: ssh_user.to_string(),
        })?;

    const HANDSHAKE_AUTH_BUDGET: Duration = Duration::from_secs(30);
    let (session, auth) = tokio::time::timeout(HANDSHAKE_AUTH_BUDGET, async {
        let mut session = client::connect_stream(config, stream, handler).await?;
        let hash = session.best_supported_rsa_hash().await?.flatten();
        let auth = session
            .authenticate_publickey(
                ssh_user.to_string(),
                PrivateKeyWithHashAlg::new(Arc::new(key), hash),
            )
            .await
            .map_err(|e| RemoteError::from_russh(e, &hostname))?;
        Ok::<_, RemoteError>((session, auth))
    })
    .await
    .map_err(|_| RemoteError::Timeout {
        host: hostname.clone(),
    })??;

    if !auth.success() {
        return Err(RemoteError::Auth {
            host: hostname.clone(),
            user: ssh_user.to_string(),
        });
    }

    let overall = Duration::from_secs(crate::utils::host_budget_secs(remote_timeout_secs) + 5);

    // The flag must outlive the timeout future to be readable after Elapsed.
    let uploaded = AtomicBool::new(false);

    let result = tokio::time::timeout(overall, async {
        if copy_binary {
            let default_exe = std::path::PathBuf::from("./owlzops-mapper");
            let current_exe = std::env::current_exe().unwrap_or(default_exe);
            let current_exe_lossy = current_exe.to_string_lossy();
            let local = local_bin.unwrap_or(&current_exe_lossy);
            let mut upload_channel = session
                .channel_open_session()
                .await
                .map_err(|e| RemoteError::from_russh(e, &hostname))?;
            uploaded.store(true, Ordering::Relaxed);
            upload_via_channel(
                &mut upload_channel,
                local,
                remote_path,
                &hostname,
                upload_pb,
            )
            .await?;
        }

        let mut exec_channel = session
            .channel_open_session()
            .await
            .map_err(|e| RemoteError::from_russh(e, &hostname))?;

        let deep_arg = if deep { " --deep" } else { "" };
        let cmd = if sudo_pass.is_some() {
            format!(
                "LC_ALL=C sudo -k -S -p '' -- {} audit --format json --offline{}",
                remote_path, deep_arg
            )
        } else {
            format!(
                "LC_ALL=C {} audit --format json --offline{}",
                remote_path, deep_arg
            )
        };
        exec_channel
            .exec(true, cmd)
            .await
            .map_err(|e| RemoteError::from_russh(e, &hostname))?;

        if let Some(pass) = sudo_pass {
            let mut line = Zeroizing::new(pass.to_string());
            line.push('\n');
            exec_channel
                .data(line.as_bytes())
                .await
                .map_err(|e| RemoteError::from_russh(e, &hostname))?;
        }
        exec_channel
            .eof()
            .await
            .map_err(|e| RemoteError::from_russh(e, &hostname))?;

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
                            host = %hostname,
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
                            host = %hostname,
                            "remote stderr exceeded cap ({} bytes), truncating",
                            CAP_REMOTE_STDERR
                        );
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => exit_code = Some(exit_status),
                ChannelMsg::Close => break,
                ChannelMsg::Eof => {}
                _ => {}
            }
        }

        match exit_code {
            Some(code) => {
                let se = String::from_utf8_lossy(&stderr);
                if sudo_pass.is_some()
                    && (se.contains("incorrect password")
                        || se.contains("Sorry, try again")
                        || se.contains("a password is required"))
                {
                    Err(RemoteError::SudoAuth {
                        host: hostname.clone(),
                    })
                } else if !stdout.is_empty() && stdout.starts_with(b"{") {
                    Ok(stdout)
                } else if code != 0 {
                    let raw_trimmed: String = se.trim().chars().take(300).collect();
                    let trimmed = crate::utils::sanitize_for_log(&raw_trimmed);
                    Err(RemoteError::NonZeroExit {
                        host: hostname.clone(),
                        code,
                        stderr: trimmed,
                    })
                } else {
                    Ok(stdout)
                }
            }
            None => Err(RemoteError::Timeout {
                host: hostname.clone(),
            }),
        }
    })
    .await;

    // Teardown always executes, even after Elapsed.
    if uploaded.load(Ordering::Relaxed) && !keep_binary {
        cleanup_remote_binary(&session, remote_path, &hostname).await;
    }
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        session.disconnect(russh::Disconnect::ByApplication, "audit complete", "en"),
    )
    .await;

    match result {
        Ok(inner) => inner,
        Err(_elapsed) => Err(RemoteError::Timeout { host: hostname }),
    }
}
