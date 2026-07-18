//! Lightweight coverage/truncation signaler for parsers.
//! Uses a global lock to avoid threading through every scanner.
//!
//! Attribution to a specific scan is done at drain time via `drain_scoped`,
//! which correctly handles the fact that scanners run inside `spawn_blocking`
//! and thread‑local state is not visible there.

use std::sync::{Mutex, OnceLock};

const MAX_ENTRIES: usize = 1024;

fn sink() -> &'static Mutex<Vec<String>> {
    static S: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Vec::new()))
}

/// Record a coverage warning (e.g., file truncated, resource unavailable).
/// The sink is capped: when the limit is reached a single suppression marker
/// is appended and further records are silently dropped.
///
/// INVARIANT: callers that run concurrently with other scans (russh fleet
/// tasks, ssh_engine, known_hosts) MUST NOT call this — drain-time scoping
/// cannot attribute concurrent writers. Scanner (spawn_blocking) paths only.
pub fn record(msg: impl Into<String>) {
    if let Ok(mut v) = sink().lock() {
        use std::cmp::Ordering::*;
        match v.len().cmp(&MAX_ENTRIES) {
            Less => v.push(msg.into()),
            Equal => v.push("coverage cap reached — further warnings suppressed".into()),
            Greater => {}
        }
    }
}

/// Drain and tag every entry with the given `scope` in one shot.
/// This is the primary function for scan runners: they know the scope
/// (scan_id for local scans, remote‑<host> for fleet tasks) and call this
/// once after the scanners have finished.
pub fn drain_scoped(scope: &str) -> Vec<String> {
    sink()
        .lock()
        .map(|mut v| {
            std::mem::take(&mut *v)
                .into_iter()
                .map(|msg| format!("[{scope}] {msg}"))
                .collect()
        })
        .unwrap_or_default()
}
