//! Lightweight coverage/truncation signaler for parsers.
//! Uses a global lock to avoid threading through every scanner.
//!
//! Each scanner is expected to call `set_scope(scan_id)` before starting and
//! `clear_scope()` afterwards, so that coverage entries are attributed to the
//! correct scan even when multiple scans run concurrently (local + remote, or
//! fleet tasks on the same runtime).

use std::cell::Cell;
use std::sync::{Mutex, OnceLock};

const MAX_ENTRIES: usize = 1024;

type Entry = (Option<String>, String);

thread_local! {
    static SCOPE: Cell<Option<String>> = const { Cell::new(None) };
}

fn sink() -> &'static Mutex<Vec<Entry>> {
    static S: OnceLock<Mutex<Vec<Entry>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Vec::new()))
}

/// Set the scope for the current thread. Subsequent `record` calls will
/// attach this scope to the entry.
pub fn set_scope(scope: String) {
    SCOPE.with(|s| s.set(Some(scope)));
}

/// Remove the scope for the current thread.
pub fn clear_scope() {
    SCOPE.with(|s| s.set(None));
}

/// Record a coverage warning (e.g., file truncated, resource unavailable).
/// The current thread's scope is captured at call time.
/// The sink is capped: when the limit is reached a single suppression marker
/// is appended and further records are silently dropped.
pub fn record(msg: impl Into<String>) {
    let scope = SCOPE.with(|s| s.take());
    let msg = msg.into();
    if let Ok(mut v) = sink().lock() {
        use std::cmp::Ordering::*;
        match v.len().cmp(&MAX_ENTRIES) {
            Less => v.push((scope, msg)),
            Equal => v.push((
                None,
                "coverage cap reached — further warnings suppressed".into(),
            )),
            Greater => {}
        }
    }
}

/// Drain all recorded warnings (call once per scan in the runner).
/// Entries are formatted as `"[scope] message"` when a scope is present,
/// and plain `message` otherwise.
pub fn drain() -> Vec<String> {
    sink()
        .lock()
        .map(|mut v| {
            std::mem::take(&mut *v)
                .into_iter()
                .map(|(scope, msg)| {
                    if let Some(s) = scope {
                        format!("[{s}] {msg}")
                    } else {
                        msg
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Drain warnings and log each one under the given `scope` via `tracing::warn!`.
/// Useful for fleet orchestrator to surface per‑host coverage events.
/// (The scope is already embedded in the message; the `scope` argument here
/// is used for the tracing span / log field.)
pub fn drain_and_log(scope: &str) {
    for warning in drain() {
        tracing::warn!(scope = %scope, "{warning}");
    }
}
