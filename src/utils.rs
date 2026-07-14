#![allow(dead_code)]

use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use crate::coverage;
use crate::safe_io;

// ---------------------------------------------------------------------------
// Hardened tool resolution
// ---------------------------------------------------------------------------

fn tool_cache() -> &'static Mutex<HashMap<String, String>> {
    static CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

// R10-04: poison-tolerant lock helper
fn lock_cache() -> std::sync::MutexGuard<'static, HashMap<String, String>> {
    tool_cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Resolve a system tool by searching fixed standard directories.
/// This avoids a fork of `which` and is resilient against PATH manipulation.
pub fn resolve_tool(tool: &str) -> Option<String> {
    // Fast path: hit the (poison-tolerant) cache
    if let Some(path) = lock_cache().get(tool) {
        return Some(path.clone());
    }

    use std::os::unix::fs::PermissionsExt;
    for dir in ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] {
        let candidate = format!("{dir}/{tool}");
        if let Ok(md) = std::fs::metadata(&candidate)
            && md.is_file()
            && md.permissions().mode() & 0o111 != 0
        {
            lock_cache().insert(tool.to_string(), candidate.clone());
            return Some(candidate);
        }
    }
    None
}

pub fn hardened_command(program: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C");
    cmd
}

pub(crate) const fn host_budget_secs(t: u64) -> u64 {
    t.saturating_mul(2).saturating_add(60)
}

// ---------------------------------------------------------------------------
// Network predicates
// ---------------------------------------------------------------------------

pub fn is_wildcard_bind(addr: &str) -> bool {
    matches!(addr, "0.0.0.0" | "::" | "::ffff:0.0.0.0")
}

pub fn is_loopback_bind(addr: &str) -> bool {
    fn v4_loopback(s: &str) -> bool {
        s.strip_prefix("127.").is_some_and(|rest| {
            !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        })
    }
    matches!(addr, "::1")
        || v4_loopback(addr)
        || addr.strip_prefix("::ffff:").is_some_and(v4_loopback)
}

/// Executables served from writable/ephemeral locations — a shared signal
/// for shadow-IT (SEC-013), IoC (SEC-015) and ambiguous-malware corroboration.
///
/// `/memfd:` covers `memfd_create`-backed execution (fully in-memory implants);
/// the kernel renders such exe links as `/memfd:<name> (deleted)`. Prefix match
/// is deletion-suffix agnostic, so this holds whether called on the raw link
/// or on the base path after the ` (deleted)` suffix is stripped.
pub fn is_ephemeral_exec_path(path: &str) -> bool {
    path.starts_with("/tmp/")
        || path.starts_with("/var/tmp/")
        || path.starts_with("/dev/shm/")
        || path.starts_with("/home/")
        || path.starts_with("/memfd:")
}

// ---------------------------------------------------------------------------
// Known malware / miner process names
// ---------------------------------------------------------------------------

pub const KNOWN_MALWARE: &[&str] = &["kdevtmpfsi", "kinsing", "xmrig", "sysupdate"];
pub const AMBIGUOUS_MALWARE: &[&str] = &["networkservice"];

pub fn is_known_malware(comm: &str) -> bool {
    let c = comm.trim();
    KNOWN_MALWARE.iter().any(|m| c.eq_ignore_ascii_case(m))
}

pub fn is_ambiguous_malware(comm: &str) -> bool {
    let c = comm.trim();
    AMBIGUOUS_MALWARE.iter().any(|m| c.eq_ignore_ascii_case(m))
}

// ---------------------------------------------------------------------------
// Child process registry (R10-07) — graceful shutdown of legacy SSH children
// ---------------------------------------------------------------------------

static CHILD_REGISTRY: OnceLock<Mutex<Vec<u32>>> = OnceLock::new();

fn with_registry<F, R>(f: F) -> R
where
    F: FnOnce(&Mutex<Vec<u32>>) -> R,
{
    let registry = CHILD_REGISTRY.get_or_init(|| Mutex::new(Vec::new()));
    f(registry)
}

pub fn register_child(pid: u32) {
    with_registry(|reg| {
        reg.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(pid);
    });
}

pub fn unregister_child(pid: u32) {
    with_registry(|reg| {
        reg.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|&p| p != pid);
    });
}

/// Send SIGTERM to all currently tracked child processes and clear the list.
/// Used during graceful shutdown to terminate any remaining `ssh`/`scp`
/// processes started by the legacy engine.
pub fn terminate_registered_children() {
    with_registry(|reg| {
        let pids: Vec<u32> = {
            let mut guard = reg
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let pids = guard.clone();
            guard.clear();
            pids
        };
        for pid in pids {
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Child helpers
// ---------------------------------------------------------------------------

pub fn run_child_with_timeout(
    program: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Option<std::process::Output> {
    let resolved = resolve_tool(program).unwrap_or_else(|| program.to_string());
    let mut child = hardened_command(&resolved, args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
        .ok()?;

    let child_pid = child.id();
    register_child(child_pid);

    // stdout safety block
    let Some(out_pipe) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        unregister_child(child_pid);
        return None;
    };

    // stderr safety block
    let Some(err_pipe) = child.stderr.take() else {
        let _ = child.kill();
        let _ = child.wait();
        unregister_child(child_pid);
        return None;
    };

    let prog = program.to_string();

    let out_handle = thread::spawn(move || {
        let (data, truncated) = safe_io::read_reader_capped(out_pipe, safe_io::CAP_CHILD_STDOUT);
        if truncated {
            coverage::record(format!(
                "Output of '{}' exceeded {} bytes and was truncated",
                prog,
                safe_io::CAP_CHILD_STDOUT
            ));
            tracing::warn!(tool = %prog, "child stdout truncated at cap");
        }
        data
    });
    let err_handle = thread::spawn(move || {
        let (data, _trunc) = safe_io::read_reader_capped(err_pipe, 1024 * 1024);
        data
    });

    let deadline = Duration::from_secs(timeout_secs);
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if start.elapsed() < deadline => {
                thread::sleep(Duration::from_millis(50));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                drop(out_handle);
                drop(err_handle);
                unregister_child(child_pid);
                return None;
            }
        }
    };

    unregister_child(child_pid);
    Some(std::process::Output {
        status,
        stdout: out_handle.join().unwrap_or_default(),
        stderr: err_handle.join().unwrap_or_default(),
    })
}

/// Wait for a child process to finish, polling with `try_wait()` until `deadline`.
/// R10-05: defensive reap in the `Err(_)` branch so no zombie escapes.
fn poll_wait(child: &mut Child, deadline: Duration) -> Option<std::process::ExitStatus> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if start.elapsed() < deadline => {
                thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                return child.wait().ok();
            }
            Err(_) => {
                // try_wait failed (realistically ECHILD) – reap defensively
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

pub fn run_with_timeout(program: &str, args: &[&str], timeout_secs: u64) -> Option<String> {
    run_with_timeout_inner(program, args, timeout_secs, true)
}

pub fn run_with_timeout_any_exit(
    program: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Option<String> {
    run_with_timeout_inner(program, args, timeout_secs, false)
}

// R10-05: capped stdout reader + defensive take() guard instead of `?`
fn run_with_timeout_inner(
    program: &str,
    args: &[&str],
    timeout_secs: u64,
    require_success: bool,
) -> Option<String> {
    let resolved = resolve_tool(program).unwrap_or_else(|| program.to_string());
    let mut child = hardened_command(&resolved, args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .ok()?;

    let child_pid = child.id();
    register_child(child_pid);

    let (tx, rx) = mpsc::channel();
    // Defensive: if stdout was somehow not captured, reap the child immediately
    let Some(child_stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        unregister_child(child_pid);
        return None;
    };
    let prog = program.to_string();
    thread::spawn(move || {
        let (data, truncated) =
            safe_io::read_reader_capped(child_stdout, safe_io::CAP_CHILD_STDOUT);
        if truncated {
            coverage::record(format!(
                "Output of '{}' exceeded {} bytes and was truncated",
                prog,
                safe_io::CAP_CHILD_STDOUT
            ));
            tracing::warn!(tool = %prog, "child stdout truncated at cap");
        }
        // Lossy conversion preserves everything after the cap
        let _ = tx.send(String::from_utf8_lossy(&data).into_owned());
    });

    match rx.recv_timeout(Duration::from_secs(timeout_secs)) {
        Ok(stdout) => {
            let status = poll_wait(&mut child, Duration::from_secs(2));
            let result = if require_success {
                match status {
                    Some(s) if s.success() => Some(stdout),
                    _ => None,
                }
            } else {
                Some(stdout)
            };
            unregister_child(child_pid);
            result
        }
        Err(_timeout) => {
            let _ = child.kill();
            let _ = child.wait();
            unregister_child(child_pid);
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Structural provenance (exe install shape vs lone dropper)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExeProvenance {
    Deleted,           // "(deleted)" / memfd — image removed after launch
    LoneDropped,       // ephemeral path, sparse directory — trojan shape
    NestedUserInstall, // populated tree, but USER-writable -> weak trust
    InstalledApp,      // populated tree + ROOT-owned -> strong trust
}

/// Locations where applications are LEGITIMATELY installed (paths, NOT app names).
const INSTALL_ROOTS: &[&str] = &[
    "/.local/share/",
    "/.local/lib/",
    "/.vscode/",
    "/.vscode-server/",
    "/.config/",
    "/.var/app/",
    "/.cache/",
    "/opt/",
    "/snap/",
    "/usr/lib/",
    "/usr/share/",
    "/var/lib/flatpak/",
];

/// System binary paths — territory of the package manager (root-owned).
const SYSTEM_BIN: &[&str] = &[
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/usr/libexec/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
];

/// Version-managed runtime roots (nvm/pyenv/rbenv/...). The binary here IS the runtime
/// by convention. Membership-alone -> NestedUserInstall: the manager's layout keeps files
/// in child branches, not up the ancestor chain, so the populated-tree heuristic misfits.
/// User-writable -> WEAK tier (provisional-visible), residual risk is bound by parentage.
const RUNTIME_MANAGER_ROOTS: &[&str] = &[
    "/.nvm/",
    "/.fnm/",
    "/.volta/",
    "/.asdf/",
    "/.pyenv/",
    "/.rbenv/",
    "/.bun/",
    "/.deno/",
    "/linuxbrew/",
    "/usr/lib/node_modules/",
    "/node_modules/",
];

const INSTALL_TREE_MIN_FILES: usize = 8;
const MAX_UPWARD_DEPTH: usize = 6;

/// Factored out string check (SYSTEM_BIN ∪ RUNTIME_MANAGER ∪ INSTALL_ROOTS).
fn is_standard_install_path(p: &str) -> bool {
    SYSTEM_BIN.iter().any(|s| p.starts_with(s))
        || RUNTIME_MANAGER_ROOTS.iter().any(|r| p.contains(r))
        || INSTALL_ROOTS.iter().any(|r| p.contains(r))
}

/// Check if the given PID is running in a foreign mount namespace (i.e., a container).
/// This relies on comparing its mount namespace to the host's init process (PID 1).
pub fn in_foreign_mnt_ns(pid: u32) -> bool {
    let p = std::fs::read_link(format!("/proc/{}/ns/mnt", pid)).ok();
    let host = std::fs::read_link("/proc/1/ns/mnt").ok(); // host-init as reference
    matches!((p, host), (Some(a), Some(b)) if a != b)
}

/// Walk ancestors (up to MAX_UPWARD_DEPTH) and return true if any directory
/// contains at least INSTALL_TREE_MIN_FILES entries — indicating a populated
/// install tree rather than a sparse dropper location.
fn populated_tree_within(exe: &str) -> bool {
    std::path::Path::new(exe)
        .ancestors()
        .skip(1) // skip the binary itself → start with its parent directory
        .take(MAX_UPWARD_DEPTH)
        .take_while(|dir| {
            let d = dir.to_string_lossy();
            INSTALL_ROOTS.iter().any(|r| d.contains(*r)) // stop once we leave the install root
        })
        .any(|dir| {
            std::fs::read_dir(dir)
                .map(|rd| rd.take(INSTALL_TREE_MIN_FILES + 1).count() >= INSTALL_TREE_MIN_FILES)
                .unwrap_or(false)
        })
}

pub fn exe_provenance(exe: &str, pid: u32) -> ExeProvenance {
    use std::os::unix::fs::MetadataExt;

    if exe.ends_with(" (deleted)") || exe.starts_with("/memfd:") {
        return ExeProvenance::Deleted;
    }

    // Foreign mount ns (container): CEILING at weak tier, classification by PATH STRING
    // (the file doesn't exist on the host — it's a phantom path here).
    // Ownership is irrelevant (container-root != trusted host-root), the file is never stat'd.
    // Residual risk is closed by parentage.
    if in_foreign_mnt_ns(pid) {
        return if is_standard_install_path(exe) {
            ExeProvenance::NestedUserInstall // provisional-visible
        } else {
            ExeProvenance::LoneDropped
        };
    }

    // Host ns: ownership via PINNED inode (magic symlink) — immune to binary swap
    // post-exec even on the host.
    let root_owned = std::fs::metadata(format!("/proc/{pid}/exe"))
        .map(|m| m.uid() == 0)
        .unwrap_or(false);

    if SYSTEM_BIN.iter().any(|p| exe.starts_with(p)) {
        return if root_owned {
            ExeProvenance::InstalledApp
        } else {
            ExeProvenance::LoneDropped
        };
    }

    if RUNTIME_MANAGER_ROOTS.iter().any(|r| exe.contains(r)) {
        return ExeProvenance::NestedUserInstall;
    }

    if !INSTALL_ROOTS.iter().any(|r| exe.contains(*r)) || !populated_tree_within(exe) {
        return ExeProvenance::LoneDropped;
    }

    if root_owned {
        ExeProvenance::InstalledApp
    } else {
        ExeProvenance::NestedUserInstall
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_child_with_timeout_large_stdout_does_not_deadlock() {
        let result = run_child_with_timeout("sh", &["-c", "head -c 200000 /dev/zero | base64"], 10);
        assert!(result.is_some());
        let output = result.unwrap();
        assert!(output.status.success());
        assert!(output.stdout.len() > 100_000);
    }

    #[test]
    fn run_child_with_timeout_timeout_kills_child() {
        let result = run_child_with_timeout("sleep", &["60"], 1);
        assert!(result.is_none());
    }

    #[test]
    fn wildcard_bind_matches_canonical_forms() {
        assert!(is_wildcard_bind("0.0.0.0"));
        assert!(is_wildcard_bind("::"));
        assert!(is_wildcard_bind("::ffff:0.0.0.0"));
    }

    #[test]
    fn wildcard_bind_rejects_everything_else() {
        assert!(!is_wildcard_bind("127.0.0.1"));
        assert!(!is_wildcard_bind("::1"));
        assert!(!is_wildcard_bind("10.0.0.1"));
        assert!(!is_wildcard_bind("::ffff:127.0.0.1"));
        assert!(!is_wildcard_bind(""));
        assert!(!is_wildcard_bind("0.0.0.0 "));
        assert!(!is_wildcard_bind("[::]"));
        assert!(!is_wildcard_bind("*"));
        assert!(!is_wildcard_bind("::ffff:0:0"));
    }

    #[test]
    fn loopback_bind_matches_canonical_forms() {
        assert!(is_loopback_bind("127.0.0.1"));
        assert!(is_loopback_bind("127.0.0.53"));
        assert!(is_loopback_bind("127.0.1.1"));
        assert!(is_loopback_bind("::1"));
        assert!(is_loopback_bind("::ffff:127.0.0.1"));
        assert!(is_loopback_bind("::ffff:127.0.0.53"));
    }

    #[test]
    fn loopback_bind_rejects_everything_else() {
        assert!(!is_loopback_bind("0.0.0.0"));
        assert!(!is_loopback_bind("::"));
        assert!(!is_loopback_bind("::ffff:0.0.0.0"));
        assert!(!is_loopback_bind("10.0.0.1"));
        assert!(!is_loopback_bind("128.0.0.1"));
        assert!(!is_loopback_bind("1127.0.0.1"));
        assert!(!is_loopback_bind("127."));
        assert!(!is_loopback_bind("127.0.0.1 "));
        assert!(!is_loopback_bind("::ffff:10.0.0.1"));
        assert!(!is_loopback_bind("::2"));
        assert!(!is_loopback_bind("localhost"));
        assert!(!is_loopback_bind(""));
    }

    #[test]
    fn ephemeral_exec_path_matches_expected_directories() {
        assert!(is_ephemeral_exec_path("/tmp/malware"));
        assert!(is_ephemeral_exec_path("/var/tmp/.hidden"));
        assert!(is_ephemeral_exec_path("/dev/shm/session"));
        assert!(is_ephemeral_exec_path("/home/user/script"));
    }

    #[test]
    fn ephemeral_exec_path_rejects_system_paths() {
        assert!(!is_ephemeral_exec_path("/usr/bin/ls"));
        assert!(!is_ephemeral_exec_path("/bin/bash"));
        assert!(!is_ephemeral_exec_path("/opt/tmp/bin"));
        assert!(!is_ephemeral_exec_path("/etc/cron.d/backup"));
        assert!(!is_ephemeral_exec_path(""));
        assert!(!is_ephemeral_exec_path("/tmp"));
        assert!(!is_ephemeral_exec_path("/tmp "));
    }

    #[test]
    fn ephemeral_exec_path_boundary_cases() {
        assert!(is_ephemeral_exec_path("/tmp/"));
        assert!(!is_ephemeral_exec_path("/tmp"));
        assert!(!is_ephemeral_exec_path("/var/log/syslog"));
        assert!(!is_ephemeral_exec_path("/dev/null"));
        assert!(is_ephemeral_exec_path("/home/user/.local/share/something"));
    }

    #[test]
    fn ephemeral_path_matches_memfd() {
        assert!(is_ephemeral_exec_path("/memfd:kdevtmpfsi"));
        assert!(is_ephemeral_exec_path("/memfd:kdevtmpfsi (deleted)"));
        assert!(is_ephemeral_exec_path("/memfd:x"));
        assert!(!is_ephemeral_exec_path("/usr/bin/memfd:tool"));
        assert!(!is_ephemeral_exec_path("memfd:foo"));
        assert!(!is_ephemeral_exec_path("/opt/memfd:app"));
    }

    #[test]
    fn known_malware_exact_case_insensitive() {
        assert!(is_known_malware("xmrig"));
        assert!(is_known_malware("KDevTmpFSi"));
        assert!(is_known_malware("  kinsing  "));
        assert!(!is_known_malware("xmrigd"));
        assert!(!is_known_malware("networkservice"));
        assert!(!is_known_malware("nginx"));
        assert!(!is_known_malware(""));
    }

    #[test]
    fn ambiguous_malware_is_separate_tier() {
        assert!(is_ambiguous_malware("networkservice"));
        assert!(!is_ambiguous_malware("NetworkManager"));
        assert!(!is_known_malware("networkservice"));
    }
}
