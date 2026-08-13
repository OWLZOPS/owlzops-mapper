use indicatif::{ProgressBar, ProgressStyle};
use russh::keys::{PrivateKeyWithHashAlg, load_secret_key};
use russh::*;
use std::io::{IsTerminal, Read};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;

use crate::known_hosts::KnownHostsChecker;
use crate::safe_io;

// ---------------------------------------------------------------------------
// Remote channel constants
// ---------------------------------------------------------------------------

/// Hard cap for stderr of the **main** remote audit command.
const CAP_REMOTE_STDERR: usize = 256 * 1024; // 256 KiB

/// Every short probe (`mktemp`, `sudo -n` check) carries its own deadline.
/// The sum of probes still has to fit inside the host budget; a single wedged
/// channel can no longer outlive it.
const PROBE_BUDGET: Duration = Duration::from_secs(20);

/// Cap for stdout/stderr of a short probe. A hostile host replacing `mktemp`
/// with `/dev/zero` must not OOM the scanner. Truncation is recorded in
/// coverage (Raw Truth), not silently dropped.
const PROBE_OUTPUT_CAP: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Sudo outcome classification
// ---------------------------------------------------------------------------

/// Result of a `sudo` probe. Never a bare bool: "not permitted" and "the
/// binary would not start" are different facts and must not collapse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SudoOutcome {
    Ok,
    /// `sudo -n` could not proceed; credentials are needed but were not supplied.
    PasswordRequired,
    /// A password was supplied and rejected.
    BadPassword,
    /// `Defaults requiretty`.
    NeedsTty,
    /// sudoers does not authorise this command for this user.
    NotPermitted,
    /// Recognised nothing. Never treated as success.
    Unknown,
}

/// Single source of truth for sudo's stderr.
///
/// Refines an ALREADY-FAILING exit code — sudo prints warnings on success too,
/// so this must never be used to declare success on its own.
///
/// Order matters: the authorization wordings also contain "Sorry", so
/// `NeedsTty` and `NotPermitted` are checked first.
pub(crate) fn classify_sudo_stderr(se: &str) -> SudoOutcome {
    if se.contains("no tty present") || se.contains("you must have a tty") {
        SudoOutcome::NeedsTty
    } else if se.contains("is not allowed to execute") || se.contains("is not in the sudoers file")
    {
        SudoOutcome::NotPermitted
    } else if se.contains("incorrect password") || se.contains("Sorry, try again") {
        SudoOutcome::BadPassword
    } else if se.contains("a password is required")
        || se.contains("a terminal is required to read the password")
    {
        SudoOutcome::PasswordRequired
    } else if se.trim().is_empty() {
        SudoOutcome::Ok
    } else {
        SudoOutcome::Unknown
    }
}

// ---------------------------------------------------------------------------
// Remote errors
// ---------------------------------------------------------------------------

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
    #[error("sudo authentication failed on {host}: {detail}")]
    SudoAuth { host: String, detail: String },
    /// `Defaults requiretty` is a deliberate host policy. We refuse to defeat
    /// it by allocating a PTY; instead we tell the operator how to install the
    /// binary at a fixed path and grant NOPASSWD for that path. Recommending a
    /// staging path under /tmp would be `NOPASSWD: ALL` in disguise.
    #[error(
        "host {host} has `Defaults requiretty` in sudoers — sudo refuses to run without a \
         terminal. This is a deliberate host policy; owlzops-mapper will not defeat it. \
         Install the binary at a fixed, non-world-writable path (e.g. \
         /usr/local/bin/owlzops-mapper), grant NOPASSWD for THAT path, and pass it via \
         --remote-path. A rule naming a staging path under /tmp is `NOPASSWD: ALL` in \
         disguise and this scanner reports it as a finding (see docs/DEPLOY.md)."
    )]
    SudoRequiresTty { host: String, path: String },
    #[error("timeout on {host}")]
    Timeout { host: String },
    /// Not a timeout: the channel closed without ever reporting an exit
    /// status. Saying "timeout" would send the operator after --remote-timeout.
    #[error("channel on {host} closed without an exit status while running `{cmd}`")]
    ChannelClosedEarly { host: String, cmd: String },
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

// ---------------------------------------------------------------------------
// Client handler
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Sudo password resolution
// ---------------------------------------------------------------------------

/// Resolve sudo password from environment or interactive prompt. The returned
/// string is zeroizing; never log it.
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
                detail: "empty sudo password entered".to_string(),
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
            detail: "empty sudo password provided via stdin".to_string(),
        });
    }
    Ok(Zeroizing::new(pass))
}

// ---------------------------------------------------------------------------
// Host/port parsing and TCP hardening
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Short probe helpers (mktemp, sudo -n)
// ---------------------------------------------------------------------------

/// Append `data` to `buf` up to `PROBE_OUTPUT_CAP`. Returns whether all data
/// fit; if false, the rest is discarded and the caller records the truncation.
fn push_capped(buf: &mut Vec<u8>, data: &[u8]) -> bool {
    let room = PROBE_OUTPUT_CAP.saturating_sub(buf.len());
    buf.extend_from_slice(&data[..room.min(data.len())]);
    room >= data.len()
}

/// Execute a short command on the remote host, returning trimmed stdout.
/// The caller is responsible for any timeout — this inner function has none.
async fn exec_capture_inner(
    session: &client::Handle<ClientHandler>,
    host: &str,
    cmd: &str,
) -> Result<String, RemoteError> {
    let mut ch = session.channel_open_session().await?;
    ch.exec(true, cmd).await?;
    ch.eof().await?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_code = None;
    let mut truncated = false;
    while let Some(msg) = ch.wait().await {
        match msg {
            ChannelMsg::Data { data } => truncated |= !push_capped(&mut stdout, &data),
            ChannelMsg::ExtendedData { data, ext: 1 } => {
                truncated |= !push_capped(&mut stderr, &data)
            }
            ChannelMsg::ExitStatus { exit_status } => exit_code = Some(exit_status),
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    if truncated {
        crate::coverage::record(format!(
            "remote {host}: probe output exceeded {PROBE_OUTPUT_CAP} bytes and was capped"
        ));
    }
    match exit_code {
        Some(0) => Ok(String::from_utf8_lossy(&stdout).into_owned()),
        Some(code) => Err(RemoteError::NonZeroExit {
            host: host.to_string(),
            code,
            stderr: crate::utils::sanitize_for_log(&String::from_utf8_lossy(&stderr)),
        }),
        // Channel closed without exit status: not a timeout.
        None => Err(RemoteError::ChannelClosedEarly {
            host: host.to_string(),
            cmd: cmd.to_string(),
        }),
    }
}

/// Execute a short command with its own deadline.
async fn exec_capture(
    session: &client::Handle<ClientHandler>,
    host: &str,
    cmd: &str,
) -> Result<String, RemoteError> {
    tokio::time::timeout(PROBE_BUDGET, exec_capture_inner(session, host, cmd))
        .await
        .map_err(|_| RemoteError::Timeout {
            host: host.to_string(),
        })?
}

// ---------------------------------------------------------------------------
// Remote staging (temporary until R25-04/R25-07)
// ---------------------------------------------------------------------------

/// Create a private staging directory on the remote host.
///
/// `mktemp -d` gives mode 0700 and an unpredictable name in one atomic step —
/// no pre-created inode to inherit, no sticky-directory race (R24-41/R24-96).
///
/// TODO R25-04: choose root (`/var/tmp` first, fallback `/tmp`) based on
/// `/proc/mounts` to avoid `noexec`.
/// TODO R25-07: replace the ad-hoc validation with `staging_dir_is_sane`.
async fn make_remote_staging(
    session: &client::Handle<ClientHandler>,
    host: &str,
) -> Result<String, RemoteError> {
    let out = exec_capture(session, host, "LC_ALL=C mktemp -d /tmp/owlzops-XXXXXXXX").await?;
    let dir = out.trim();

    // Temporary validation; will be replaced by staging_dir_is_sane.
    let ok = dir.starts_with("/tmp/owlzops-")
        && dir.len() < 128
        && dir
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b));
    if !ok {
        return Err(RemoteError::UploadFailed {
            host: host.to_string(),
            detail: format!(
                "mktemp returned an unusable path: {}",
                crate::utils::sanitize_for_log(&dir.chars().take(64).collect::<String>())
            ),
        });
    }
    Ok(format!("{dir}/owlzops-mapper"))
}

// ---------------------------------------------------------------------------
// Pre-flight sudo password check
// ---------------------------------------------------------------------------

/// Validate sudo credentials **before** uploading anything.
///
/// Runs `sudo -k -S -p '' -- true` and feeds the password via stdin. If the
/// password is wrong, we return early and do not create a staging directory or
/// transfer a 10 MB binary.
///
/// R25-02: remote stderr is sanitized ONCE, here, and the sanitized `detail`
/// flows to the caller. We deliberately do NOT emit a raw `tracing::error!`
/// here; the caller logs the final `RemoteError` once.
async fn validate_sudo_password(
    session: &client::Handle<ClientHandler>,
    sudo_pass: &Zeroizing<String>,
    host: &str,
) -> Result<(), RemoteError> {
    let mut ch = session.channel_open_session().await?;
    ch.exec(true, "LC_ALL=C sudo -k -S -p '' -- true").await?;

    let mut line = Zeroizing::new(sudo_pass.to_string());
    line.push('\n');
    ch.data(line.as_bytes()).await?;
    ch.eof().await?;

    let mut stderr = Vec::new();
    let mut exit_code = None;
    while let Some(msg) = ch.wait().await {
        match msg {
            ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => exit_code = Some(exit_status),
            ChannelMsg::Close => break,
            _ => {}
        }
    }

    let se = String::from_utf8_lossy(&stderr);
    let detail = crate::utils::sanitize_for_log(se.trim());
    let outcome = if exit_code == Some(0) {
        SudoOutcome::Ok
    } else {
        classify_sudo_stderr(&se)
    };
    if outcome != SudoOutcome::Ok {
        return Err(match outcome {
            SudoOutcome::NeedsTty => RemoteError::SudoRequiresTty {
                host: host.to_string(),
                path: String::new(), // Path not known yet; filled by caller if needed
            },
            _ => RemoteError::SudoAuth {
                host: host.to_string(),
                detail,
            },
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Binary upload
// ---------------------------------------------------------------------------

/// Upload a binary file over an existing russh channel.
///
/// The directory may be `mktemp`-owned (0700, unpredictable) or operator
/// supplied; in both cases the file is written to a temporary `.part` and
/// atomically moved to the final name. The rename ensures no partially written
/// file is ever executable.
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
                    "umask 077 && cat > {p}.part && chmod 700 -- {p}.part && mv -f -- {p}.part {p}",
                    p = remote_path
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

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

/// Best-effort removal of the uploaded binary.
///
/// TODO R25-06: This currently decides `rm -rf` based on a string prefix
/// (`/tmp/owlzops-`). That is unsafe: an operator-provided path like
/// `/tmp/owlzops-mine/mapper` would also match and be recursively deleted.
/// Replace with `Staging` enum that records ownership at creation time.
async fn cleanup_remote_binary(
    session: &client::Handle<ClientHandler>,
    remote_path: &str,
    host: &str,
) {
    let fut = async {
        let mut ch = session.channel_open_session().await?;
        let dir = remote_path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
        let cmd = if dir.starts_with("/tmp/owlzops-") {
            format!("rm -rf -- {dir}")
        } else {
            format!("rm -f -- {remote_path} {remote_path}.part")
        };
        ch.exec(true, cmd).await?;
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

// ---------------------------------------------------------------------------
// Main remote scan
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn run_remote_scan_russh(
    host: &str,
    ssh_user: &str,
    ssh_key_path: &str,
    remote_path: Option<&str>,
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
    let uploaded = AtomicBool::new(false);

    // Store the actual staging path so teardown can know it even after the
    // overall timeout. Mutex is used because the async block may be dropped by
    // `timeout` while teardown still needs the value.
    let staging_path: Mutex<Option<String>> = Mutex::new(None);

    let result = tokio::time::timeout(overall, async {
        // Pre-flight sudo password check (R25-03: inside overall budget)
        if let Some(pass) = sudo_pass {
            validate_sudo_password(&session, pass, &hostname).await?;
        }

        // Determine actual remote path
        let actual_remote_path: String;
        if copy_binary {
            if let Some(p) = remote_path {
                actual_remote_path = p.to_string();
            } else {
                actual_remote_path = make_remote_staging(&session, &hostname).await?;
            }
        } else {
            match remote_path {
                Some(p) => actual_remote_path = p.to_string(),
                None => {
                    return Err(RemoteError::UploadFailed {
                        host: hostname.clone(),
                        detail: "remote path is required when --copy-binary is not used".into(),
                    });
                }
            }
        }
        *staging_path
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(actual_remote_path.clone());

        // Upload binary if requested
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
                &actual_remote_path,
                &hostname,
                upload_pb,
            )
            .await?;
        }

        let mut exec_channel = session
            .channel_open_session()
            .await
            .map_err(|e| RemoteError::from_russh(e, &hostname))?;

        // Decide whether to use sudo.
        //
        // If sudo_pass is provided, we use -S. If not, but NOPASSWD is
        // available, we use sudo -n automatically. If sudo is unavailable,
        // we record a coverage warning (degraded scan) but DO NOT silently
        // fall back to an unprivileged scan without telling the report.
        //
        // R25-05: classify the probe result, never collapse to bool.
        let use_sudo = if sudo_pass.is_some() {
            true
        } else {
            match exec_capture(
                &session,
                &hostname,
                &format!("LC_ALL=C sudo -n -- {actual_remote_path} --version"),
            )
            .await
            {
                Ok(_) => true,
                Err(RemoteError::NonZeroExit { stderr, .. }) => {
                    let outcome = classify_sudo_stderr(&stderr);
                    match outcome {
                        SudoOutcome::Ok => true,
                        SudoOutcome::PasswordRequired | SudoOutcome::NotPermitted => {
                            crate::coverage::record(format!(
                                "remote {hostname}: scanned WITHOUT root — sudo unavailable; \
                                 privileged surfaces were not read"
                            ));
                            false
                        }
                        SudoOutcome::NeedsTty => {
                            return Err(RemoteError::SudoRequiresTty {
                                host: hostname.clone(),
                                path: actual_remote_path.clone(),
                            });
                        }
                        SudoOutcome::BadPassword => {
                            return Err(RemoteError::SudoAuth {
                                host: hostname.clone(),
                                detail: crate::utils::sanitize_for_log(&stderr),
                            });
                        }
                        // The binary itself did not start (noexec, wrong arch,
                        // truncated upload). Silently dropping to unprivileged
                        // scan would hand back a clean-looking report.
                        SudoOutcome::Unknown => {
                            return Err(RemoteError::UploadFailed {
                                host: hostname.clone(),
                                detail: format!(
                                    "uploaded binary at {} did not execute; check staging \
                                     mount and architecture",
                                    actual_remote_path
                                ),
                            });
                        }
                    }
                }
                Err(e) => {
                    return Err(RemoteError::UploadFailed {
                        host: hostname.clone(),
                        detail: format!("sudo probe failed: {e}"),
                    });
                }
            }
        };

        let deep_arg = if deep { " --deep" } else { "" };
        let cmd = if use_sudo {
            if sudo_pass.is_some() {
                format!(
                    "LC_ALL=C sudo -k -S -p '' -- {} audit --format json --offline{}",
                    actual_remote_path, deep_arg
                )
            } else {
                format!(
                    "LC_ALL=C sudo -n -- {} audit --format json --offline{}",
                    actual_remote_path, deep_arg
                )
            }
        } else {
            format!(
                "LC_ALL=C {} audit --format json --offline{}",
                actual_remote_path, deep_arg
            )
        };
        // Keep a copy for ChannelClosedEarly error (cmd is moved into exec).
        let cmd_for_error = cmd.clone();
        exec_channel
            .exec(true, cmd)
            .await
            .map_err(|e| RemoteError::from_russh(e, &hostname))?;

        if let Some(pass) = sudo_pass
            && use_sudo
        {
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
                        let take = data.len().min(room);
                        stdout.extend_from_slice(&data[..take]);
                        if data.len() > room && !stdout_truncated {
                            stdout_truncated = true;
                            tracing::warn!(
                                host = %hostname,
                                "remote stdout exceeded cap ({} bytes), truncating",
                                safe_io::CAP_CHILD_STDOUT
                            );
                        }
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
                        let take = data.len().min(room);
                        stderr.extend_from_slice(&data[..take]);
                        if data.len() > room && !stderr_truncated {
                            stderr_truncated = true;
                            tracing::warn!(
                                host = %hostname,
                                "remote stderr exceeded cap ({} bytes), truncating",
                                CAP_REMOTE_STDERR
                            );
                        }
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
                let outcome = classify_sudo_stderr(&se);
                if use_sudo && outcome == SudoOutcome::BadPassword {
                    Err(RemoteError::SudoAuth {
                        host: hostname.clone(),
                        detail: crate::utils::sanitize_for_log(se.trim()),
                    })
                } else if use_sudo && outcome == SudoOutcome::NeedsTty {
                    Err(RemoteError::SudoRequiresTty {
                        host: hostname.clone(),
                        path: actual_remote_path.clone(),
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
            None => Err(RemoteError::ChannelClosedEarly {
                host: hostname.clone(),
                cmd: cmd_for_error,
            }),
        }
    })
    .await;

    // Teardown always executes, even after Elapsed.
    //
    // We must not hold a MutexGuard across .await; clone the Option<String>
    // and drop the guard immediately. This preserves Send for the outer task.
    if uploaded.load(Ordering::Relaxed) {
        let maybe_path = staging_path
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(path) = maybe_path {
            if !keep_binary {
                cleanup_remote_binary(&session, &path, &hostname).await;
            } else {
                tracing::warn!(
                    host = %hostname,
                    path = %path,
                    "binary kept on remote host (--keep-binary); remove it manually if needed"
                );
            }
        }
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
