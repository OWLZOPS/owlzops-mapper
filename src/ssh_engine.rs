use indicatif::{ProgressBar, ProgressStyle};
use russh::keys::{PrivateKeyWithHashAlg, load_secret_key};
use russh::*;
use std::io::{IsTerminal, Read};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::sync::Arc;
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

/// A much shorter deadline dedicated to the sudo NOPASSWD probe. A wedged
/// sudo on a host with broken PAM/LDAP must not stall the scan for the full
/// `PROBE_BUDGET`: we need to find out quickly, then either degrade to an
/// unprivileged scan (with a recorded fact) or abort the host with a clear
/// error.
const SUDO_PROBE_BUDGET: Duration = Duration::from_secs(5);

/// Pre-flight sudo validation is a REAL authentication round trip: pam_unix
/// applies ~2 s FAIL_DELAY on a wrong password and pam_sss/pam_ldap reach a
/// directory server. `SUDO_PROBE_BUDGET` is for `sudo -n`, which never
/// authenticates, and is far too short here (R25-43).
const SUDO_AUTH_BUDGET: Duration = Duration::from_secs(30);

/// Cap for stdout/stderr of a short probe. A hostile host replacing `mktemp`
/// with `/dev/zero` must not OOM the scanner. Truncation is recorded in
/// coverage (Raw Truth), not silently dropped.
const PROBE_OUTPUT_CAP: usize = 64 * 1024;

/// No progress for this long during a single write means the transfer is dead.
/// A slow link is not a dead link; bounding stall punishes only actual hangs.
const UPLOAD_STALL_BUDGET: Duration = Duration::from_secs(30);

/// Floor on acceptable throughput. A slow link must never be the reason we
/// give up; only a dead one.
const MIN_UPLOAD_BYTES_PER_SEC: u64 = 16 * 1024;

/// Tail allowance: after EOF the remote is only running chmod/mv, and that
/// wait is covered by no other bound (R25-58).
const UPLOAD_TAIL_BUDGET: Duration = Duration::from_secs(60);

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

/// Maps a sudo failure to the kind of error that should be raised by the main
/// exec path. Pure and exhaustive: adding a variant to `SudoOutcome` breaks the
/// build here instead of silently falling through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SudoErrorKind {
    Auth,
    Tty,
    NotPermitted,
}

pub(crate) fn sudo_error_kind(use_sudo: bool, se: &str) -> Option<SudoErrorKind> {
    if !use_sudo {
        return None;
    }
    match classify_sudo_stderr(se) {
        SudoOutcome::BadPassword | SudoOutcome::PasswordRequired => Some(SudoErrorKind::Auth),
        SudoOutcome::NeedsTty => Some(SudoErrorKind::Tty),
        SudoOutcome::NotPermitted => Some(SudoErrorKind::NotPermitted),
        SudoOutcome::Ok | SudoOutcome::Unknown => None,
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
    #[error("sudo not permitted for {host}: {detail}")]
    SudoNotPermitted {
        host: String,
        path: Option<String>,
        detail: String,
    },
    /// The PAM stack did not answer. Distinct from a transport timeout: the
    /// fix is a directory/PAM problem on the host, not --remote-timeout.
    #[error(
        "sudo authentication on {host} did not complete within {}s — the PAM stack \
         (pam_sss/pam_ldap/pam_krb5) may be waiting on an unreachable directory server",
        SUDO_AUTH_BUDGET.as_secs()
    )]
    SudoAuthTimeout { host: String },
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
         disguise and this scanner reports it as a finding (see docs/DEPLOY.md). \
         Attempted target: {}",
        path.as_deref().unwrap_or("<not determined — failed at pre-flight>")
    )]
    SudoRequiresTty { host: String, path: Option<String> },
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
// Short probe helpers
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
    exec_capture_with_budget(session, host, cmd, PROBE_BUDGET).await
}

/// Execute a short command with an explicit deadline. Used when the default
/// `PROBE_BUDGET` is not appropriate, e.g. sudo NOPASSWD probe where a wedged
/// PAM stack must not stall the whole scan.
async fn exec_capture_with_budget(
    session: &client::Handle<ClientHandler>,
    host: &str,
    cmd: &str,
    budget: Duration,
) -> Result<String, RemoteError> {
    tokio::time::timeout(budget, exec_capture_inner(session, host, cmd))
        .await
        .map_err(|_| RemoteError::Timeout {
            host: host.to_string(),
        })?
}

// ---------------------------------------------------------------------------
// Remote artifact (staging ownership)
// ---------------------------------------------------------------------------

/// What WE put on the remote host and are therefore obliged to remove.
/// Recorded at the moment of creation, never re-derived from a path prefix
/// (RC-1) and never inferred from "did the upload finish" (R25-17): a
/// directory made by `mktemp -d` outlives a failed transfer.
#[derive(Debug, Clone)]
pub(crate) enum RemoteArtifact {
    /// `mktemp -d` created this directory for us: the whole subtree is ours.
    OwnedDir { dir: String, bin: String },
    /// We wrote a file into an operator-supplied directory. Only that file.
    UploadedFile { bin: String, part: String },
}

impl RemoteArtifact {
    pub(crate) fn bin(&self) -> &str {
        match self {
            Self::OwnedDir { bin, .. } | Self::UploadedFile { bin, .. } => bin,
        }
    }

    /// `replaced` — did the atomic `mv` complete? Before it lands, the file at
    /// `bin` is still the operator's; only our `.part` may be removed (R25-24).
    pub(crate) fn teardown_cmd(&self, replaced: bool) -> String {
        match self {
            Self::OwnedDir { dir, .. } => format!("rm -rf -- {dir}"),
            Self::UploadedFile { part, .. } if !replaced => format!("rm -f -- {part}"),
            Self::UploadedFile { bin, .. } => format!("rm -f -- {bin}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Remote staging
// ---------------------------------------------------------------------------

/// Candidate staging roots, best first. The binary is *executed* here under
/// sudo, so a `noexec` mount disqualifies the root outright (CIS 1.1.2.x).
const STAGING_ROOTS: [&str; 2] = ["/var/tmp", "/tmp"];

/// Longest-prefix match of `dir` against the mount table.
pub(crate) fn mount_is_noexec(mounts: &str, dir: &str) -> bool {
    let mut best = 0usize;
    let mut noexec = false;
    for line in mounts.lines() {
        let mut f = line.split_whitespace();
        let (Some(_dev), Some(mp), Some(_fs), Some(opts)) =
            (f.next(), f.next(), f.next(), f.next())
        else {
            continue;
        };
        let covers = mp == "/"
            || dir == mp
            || (dir.starts_with(mp) && dir.as_bytes().get(mp.len()) == Some(&b'/'));
        if covers && mp.len() >= best {
            best = mp.len();
            noexec = opts.split(',').any(|o| o == "noexec");
        }
    }
    noexec
}

/// `dir` is interpolated into shell commands and becomes the argument of an
/// `rm -rf`. It must be exactly `{root}/owlzops-XXXXXXXX`: one component, no
/// traversal, no metacharacters.
pub(crate) fn staging_dir_is_sane(dir: &str, root: &str) -> bool {
    let Some(leaf) = dir.strip_prefix(root).and_then(|r| r.strip_prefix('/')) else {
        return false;
    };
    let Some(rand) = leaf.strip_prefix("owlzops-") else {
        return false;
    };
    !rand.is_empty() && rand.len() <= 32 && rand.bytes().all(|b| b.is_ascii_alphanumeric())
}

async fn make_remote_staging(
    session: &client::Handle<ClientHandler>,
    host: &str,
) -> Result<RemoteArtifact, RemoteError> {
    let mounts = exec_capture(session, host, "LC_ALL=C cat /proc/mounts").await?;
    let root = STAGING_ROOTS
        .iter()
        .copied()
        .find(|r| !mount_is_noexec(&mounts, r))
        .ok_or_else(|| RemoteError::UploadFailed {
            host: host.to_string(),
            detail: "every candidate staging root is mounted noexec (CIS 1.1.2.x): \
                     pass --remote-path pointing at an exec-capable directory whose \
                     parent is not group/world-writable"
                .into(),
        })?;

    let out = exec_capture(
        session,
        host,
        &format!("LC_ALL=C mktemp -d {root}/owlzops-XXXXXXXX"),
    )
    .await?;
    let dir = out.trim();

    if !staging_dir_is_sane(dir, root) {
        return Err(RemoteError::UploadFailed {
            host: host.to_string(),
            detail: format!(
                "mktemp returned an unusable path: {}",
                crate::utils::sanitize_for_log(&dir.chars().take(64).collect::<String>())
            ),
        });
    }

    Ok(RemoteArtifact::OwnedDir {
        dir: dir.to_string(),
        bin: format!("{dir}/owlzops-mapper"),
    })
}

// ---------------------------------------------------------------------------
// Pre-flight sudo password check
// ---------------------------------------------------------------------------

/// Validate sudo credentials **before** uploading anything.
///
/// Runs `sudo -k -S -p '' -v` and feeds the password via stdin. `-v` validates
/// the user's credentials without coupling to sudoers' command list (R25-09b).
/// If the password is wrong, we return early and create no staging directory.
///
/// R25-16: stderr from the remote sudo is capped; a malicious host cannot OOM
/// the orchestrator before upload.
async fn validate_sudo_password(
    session: &client::Handle<ClientHandler>,
    sudo_pass: &Zeroizing<String>,
    host: &str,
) -> Result<(), RemoteError> {
    let mut ch = session.channel_open_session().await?;
    ch.exec(true, "LC_ALL=C sudo -k -S -p '' -v").await?;

    let mut line = Zeroizing::new(sudo_pass.to_string());
    line.push('\n');
    ch.data(line.as_bytes()).await?;
    ch.eof().await?;

    let mut stderr = Vec::new();
    let mut exit_code = None;
    let mut truncated = false;
    while let Some(msg) = ch.wait().await {
        match msg {
            ChannelMsg::ExtendedData { data, ext: 1 } => {
                truncated |= !push_capped(&mut stderr, &data);
            }
            ChannelMsg::ExitStatus { exit_status } => exit_code = Some(exit_status),
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    if truncated {
        crate::coverage::record(format!(
            "remote {host}: sudo pre-flight stderr exceeded {PROBE_OUTPUT_CAP} bytes"
        ));
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
                path: None,
            },
            SudoOutcome::NotPermitted => RemoteError::SudoNotPermitted {
                host: host.to_string(),
                path: None,
                detail,
            },
            SudoOutcome::BadPassword | SudoOutcome::PasswordRequired | SudoOutcome::Unknown => {
                RemoteError::SudoAuth {
                    host: host.to_string(),
                    detail,
                }
            }
            SudoOutcome::Ok => unreachable!("guarded by the enclosing if"),
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
    part_path: &str,
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

    let upload_fut = async {
        // `rm -f` reclaims a stale .part from an earlier crash; `set -C`
        // (O_CREAT|O_EXCL) then refuses anything that reappears in the gap,
        // so the worst case is a failed upload, never a write through an
        // attacker's symlink (R24-96/R25-32/R25-47).
        // Chained with `&&`: a shell that does not support `set -C` must
        // abort, not continue unprotected (R25-48).
        channel
            .exec(
                true,
                format!(
                    "rm -f -- {part} && set -C && umask 077 && cat > {part} \
                     && chmod 700 -- {part} && mv -f -- {part} {bin}",
                    part = part_path,
                    bin = remote_path,
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
        let mut stderr = Vec::new();
        let mut exit: Option<u32> = None;
        let mut stderr_truncated = false;
        let mut eof_sent = false;
        let mut closed = false;

        loop {
            if closed {
                break;
            }

            tokio::select! {
                msg = channel.wait() => {
                    match msg {
                        Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                            let room = PROBE_OUTPUT_CAP.saturating_sub(stderr.len());
                            if room > 0 {
                                let take = data.len().min(room);
                                stderr.extend_from_slice(&data[..take]);
                                if data.len() > room {
                                    stderr_truncated = true;
                                }
                            }
                        }
                        Some(ChannelMsg::ExitStatus { exit_status }) => {
                            // Do NOT stop here: extended data may still be in
                            // flight and it is the diagnostic this code exists
                            // to surface. Close (or channel end) is the
                            // terminator; the outer host budget bounds the
                            // overall wait.
                            exit = Some(exit_status);
                        }
                        Some(ChannelMsg::Close) | None => closed = true,
                        _ => {}
                    }
                }
                read = file.read(&mut buf), if !eof_sent => {
                    let n = read.map_err(|e| RemoteError::Io {
                        host: host.to_string(),
                        source: e,
                    })?;

                    if n == 0 {
                        // EOF: close our stdin exactly once. From now on only
                        // the channel branch remains active, which prevents a
                        // busy-spin on an immediately-ready Ok(0) read
                        // (R25-39).
                        channel
                            .eof()
                            .await
                            .map_err(|e| RemoteError::from_russh(e, host))?;
                        eof_sent = true;
                        continue;
                    }

                    let send_fut = channel.data(&buf[..n]);
                    match tokio::time::timeout(UPLOAD_STALL_BUDGET, send_fut).await {
                        Ok(res) => {
                            res.map_err(|e| RemoteError::from_russh(e, host))?;
                            pb.inc(n as u64);
                        }
                        Err(_) => {
                            return Err(RemoteError::UploadFailed {
                                host: host.to_string(),
                                detail: format!(
                                    "upload stalled: no progress for {} seconds",
                                    UPLOAD_STALL_BUDGET.as_secs()
                                ),
                            });
                        }
                    }
                }
            }
        }

        // Drain any remaining stderr after Close as well.
        while let Some(msg) = channel.wait().await {
            if let ChannelMsg::ExtendedData { data, ext: 1 } = msg {
                let room = PROBE_OUTPUT_CAP.saturating_sub(stderr.len());
                if room > 0 {
                    let take = data.len().min(room);
                    stderr.extend_from_slice(&data[..take]);
                    if data.len() > room {
                        stderr_truncated = true;
                    }
                }
            } else if let ChannelMsg::ExitStatus { exit_status } = msg {
                exit = Some(exit_status);
            }
        }

        if stderr_truncated {
            crate::coverage::record(format!(
                "remote {host}: upload stderr exceeded {PROBE_OUTPUT_CAP} bytes and was capped"
            ));
        }

        match exit {
            Some(0) => Ok(()),
            Some(code) => {
                let se = String::from_utf8_lossy(&stderr);
                let detail = if se.trim().is_empty() {
                    format!("remote command exited {code}")
                } else {
                    format!(
                        "remote command exited {code}: {}",
                        crate::utils::sanitize_for_log(se.trim())
                    )
                };
                Err(RemoteError::UploadFailed {
                    host: host.to_string(),
                    detail,
                })
            }
            None => Err(RemoteError::UploadFailed {
                host: host.to_string(),
                detail: "channel closed without exit status".into(),
            }),
        }
    };

    // Not a fixed 120 s cap on throughput (R25-35): the transfer itself is
    // bounded per write by UPLOAD_STALL_BUDGET; this bounds the tail and
    // scales the rest with the payload.
    let budget =
        UPLOAD_TAIL_BUDGET + Duration::from_secs(file_size / MIN_UPLOAD_BYTES_PER_SEC.max(1));
    let res = match tokio::time::timeout(budget, upload_fut).await {
        Ok(inner) => inner,
        Err(_) => Err(RemoteError::UploadFailed {
            host: host.to_string(),
            detail: format!(
                "upload of {file_size} bytes did not complete within {}s",
                budget.as_secs()
            ),
        }),
    };

    pb.finish_and_clear();

    if let Err(ref e) = res {
        tracing::warn!(host = %host, error = %e, "Binary upload failed");
    }

    res
}

async fn cleanup_remote_artifact(
    session: &client::Handle<ClientHandler>,
    artifact: &RemoteArtifact,
    replaced: bool,
    host: &str,
) {
    let cmd = artifact.teardown_cmd(replaced);
    let fut = async {
        let mut ch = session.channel_open_session().await?;
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
        Ok(Ok(Some(0))) => tracing::debug!(host = %host, "remote artifact removed"),
        Ok(Ok(code)) => tracing::warn!(
            host = %host,
            exit = ?code,
            "cleanup did not confirm success — artifact may be left on host"
        ),
        Ok(Err(e)) => {
            tracing::warn!(host = %host, error = %e, "cleanup failed — artifact left on host")
        }
        Err(_) => tracing::warn!(host = %host, "cleanup timed out — artifact left on host"),
    }
}

// ---------------------------------------------------------------------------
// Facts learned by orchestrator about remote host
// ---------------------------------------------------------------------------

/// Facts the orchestrator learned about a host that the remote binary could not
/// know about itself. They belong in THAT host's report.
#[derive(Debug, Default, Clone)]
pub struct RemoteCoverage {
    pub notes: Vec<String>,
    pub privileged: Option<bool>,
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
) -> Result<(Vec<u8>, RemoteCoverage), RemoteError> {
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

    if let Err(e) = harden_tcp(&stream) {
        tracing::warn!(
            host = %hostname,
            error = %e,
            "failed to tune TCP keepalive/user-timeout — dead-transport detection degraded"
        );
    }

    let known_hosts_checker =
        KnownHostsChecker::new(hostname.clone(), port).map_err(|e| RemoteError::HostKeyCheck {
            host: hostname.clone(),
            detail: e.to_string(),
        })?;

    let pinned = known_hosts_checker.pinned_algorithms();

    // Constrain the server's host key choice to algorithms already present in
    // known_hosts. Without this, a russh preference change can make the entire
    // fleet see HostKeyChanged on a legitimate server (R25-30).
    let preferred = if pinned.is_empty() {
        // Unknown host: keep the default offer; verify() will TOFU the key.
        russh::Preferred::default()
    } else {
        russh::Preferred {
            key: pinned.into(),
            ..russh::Preferred::default()
        }
    };

    let config = Arc::new(client::Config {
        inactivity_timeout: None,
        keepalive_interval: None,
        preferred,
        ..Default::default()
    });

    let handler = ClientHandler {
        known_hosts_checker,
    };

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
    let artifact: std::sync::OnceLock<RemoteArtifact> = std::sync::OnceLock::new();
    let mut remote_coverage = RemoteCoverage::default();

    let result = tokio::time::timeout(overall, async {
        if let Some(pass) = sudo_pass {
            let sudo_check = tokio::time::timeout(
                SUDO_AUTH_BUDGET,
                validate_sudo_password(&session, pass, &hostname),
            )
            .await
            .map_err(|_| RemoteError::SudoAuthTimeout {
                host: hostname.clone(),
            })?;
            sudo_check?;
        }

        let actual_remote_path: String;
        if copy_binary {
            if let Some(p) = remote_path {
                actual_remote_path = p.to_string();

                // Deterministic: a crash-orphaned `.part` must be reclaimable
                // by the NEXT run. `set -C` already closes the symlink race,
                // so an unpredictable name buys nothing and costs cleanup
                // (R25-47).
                let part = format!("{p}.part");
                let a = RemoteArtifact::UploadedFile {
                    bin: actual_remote_path.clone(),
                    part: part.clone(),
                };
                let _ = artifact.set(a);
            } else {
                let a = make_remote_staging(&session, &hostname).await?;
                actual_remote_path = a.bin().to_string();
                let _ = artifact.set(a);
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

        if copy_binary {
            let default_exe = std::path::PathBuf::from("./owlzops-mapper");
            let current_exe = std::env::current_exe().unwrap_or(default_exe);
            let current_exe_lossy = current_exe.to_string_lossy();
            let local = local_bin.unwrap_or(&current_exe_lossy);
            let mut upload_channel = session
                .channel_open_session()
                .await
                .map_err(|e| RemoteError::from_russh(e, &hostname))?;

            let part_for_upload = match artifact.get() {
                Some(RemoteArtifact::UploadedFile { part, .. }) => part.clone(),
                Some(RemoteArtifact::OwnedDir { dir, .. }) => {
                    format!("{dir}/.owlzops-upload.part")
                }
                _ => String::new(),
            };

            upload_via_channel(
                &mut upload_channel,
                local,
                &actual_remote_path,
                &part_for_upload,
                &hostname,
                upload_pb,
            )
            .await?;
            uploaded.store(true, Ordering::Relaxed);
        }

        let mut exec_channel = session
            .channel_open_session()
            .await
            .map_err(|e| RemoteError::from_russh(e, &hostname))?;

        let use_sudo = if sudo_pass.is_some() {
            true
        } else {
            match exec_capture_with_budget(
                &session,
                &hostname,
                &format!("LC_ALL=C sudo -n -- {actual_remote_path} --version"),
                SUDO_PROBE_BUDGET,
            )
            .await
            {
                Ok(_) => true,
                Err(RemoteError::NonZeroExit { stderr, .. }) => {
                    match classify_sudo_stderr(&stderr) {
                        SudoOutcome::Ok => {
                            return Err(RemoteError::UploadFailed {
                                host: hostname.clone(),
                                detail: format!(
                                    "`sudo -n -- {actual_remote_path} --version` exited \
                                     non-zero with no diagnostic output; refusing to guess \
                                     whether the scan would run privileged"
                                ),
                            });
                        }
                        SudoOutcome::PasswordRequired | SudoOutcome::NotPermitted => {
                            remote_coverage.notes.push(format!(
                                "remote {hostname}: scanned WITHOUT root — sudo unavailable; \
                                 privileged surfaces were not read"
                            ));
                            remote_coverage.privileged = Some(false);
                            false
                        }
                        SudoOutcome::NeedsTty => {
                            return Err(RemoteError::SudoRequiresTty {
                                host: hostname.clone(),
                                path: Some(actual_remote_path.clone()),
                            });
                        }
                        SudoOutcome::BadPassword => {
                            return Err(RemoteError::SudoAuth {
                                host: hostname.clone(),
                                detail: crate::utils::sanitize_for_log(&stderr),
                            });
                        }
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
                Err(e) => return Err(e),
            }
        };

        // Persist how the scan was actually executed. `Some(false)` is already
        // set by the sudo-unavailable branch; otherwise reflect the resolved
        // privilege level (R25-31).
        if remote_coverage.privileged.is_none() {
            remote_coverage.privileged = Some(use_sudo);
        }

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
                match sudo_error_kind(use_sudo, &se) {
                    Some(SudoErrorKind::Auth) => Err(RemoteError::SudoAuth {
                        host: hostname.clone(),
                        detail: crate::utils::sanitize_for_log(se.trim()),
                    }),
                    Some(SudoErrorKind::Tty) => Err(RemoteError::SudoRequiresTty {
                        host: hostname.clone(),
                        path: Some(actual_remote_path.clone()),
                    }),
                    Some(SudoErrorKind::NotPermitted) => Err(RemoteError::SudoNotPermitted {
                        host: hostname.clone(),
                        path: Some(actual_remote_path.clone()),
                        detail: crate::utils::sanitize_for_log(se.trim()),
                    }),
                    None if !stdout.is_empty() && stdout.starts_with(b"{") => Ok(stdout),
                    None => {
                        let raw_trimmed: String = se.trim().chars().take(300).collect();
                        let trimmed = crate::utils::sanitize_for_log(&raw_trimmed);
                        Err(RemoteError::NonZeroExit {
                            host: hostname.clone(),
                            code,
                            stderr: trimmed,
                        })
                    }
                }
            }
            None => Err(RemoteError::ChannelClosedEarly {
                host: hostname.clone(),
                cmd: cmd_for_error,
            }),
        }
    })
    .await;

    if let Some(a) = artifact.get() {
        let replaced = uploaded.load(Ordering::Relaxed);
        if keep_binary && replaced {
            tracing::warn!(
                host = %hostname,
                path = %a.bin(),
                teardown = %a.teardown_cmd(replaced),
                "binary kept on remote host (--keep-binary)"
            );
        } else {
            cleanup_remote_artifact(&session, a, replaced, &hostname).await;
        }
    }

    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        session.disconnect(russh::Disconnect::ByApplication, "audit complete", "en"),
    )
    .await;

    match result {
        Ok(Ok(stdout)) => Ok((stdout, remote_coverage)),
        Ok(Err(e)) => Err(e),
        Err(_elapsed) => Err(RemoteError::Timeout { host: hostname }),
    }
}
