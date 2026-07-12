//! Lightweight coverage/truncation signaler for parsers.
//! Uses a global lock to avoid threading through every scanner.

use std::sync::{Mutex, OnceLock};

const MAX_ENTRIES: usize = 1024;

fn sink() -> &'static Mutex<Vec<String>> {
    static S: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Vec::new()))
}

/// Record a coverage warning (e.g., file truncated, resource unavailable).
/// The sink is capped: when the limit is reached a single suppression marker
/// is appended and further records are silently dropped.
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

/// Drain all recorded warnings (call once per scan in the runner).
pub fn drain() -> Vec<String> {
    sink()
        .lock()
        .map(|mut v| std::mem::take(&mut *v))
        .unwrap_or_default()
}

/// Drain warnings and log each one under the given `scope` via `tracing::warn!`.
/// Useful for fleet orchestrator to surface per‑host coverage events.
pub fn drain_and_log(scope: &str) {
    for warning in drain() {
        tracing::warn!(scope = %scope, "{warning}");
    }
}
