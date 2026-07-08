//! Lightweight coverage/truncation signaler for parsers.
//! Uses a global lock to avoid threading through every scanner.

use std::sync::{Mutex, OnceLock};

fn sink() -> &'static Mutex<Vec<String>> {
    static S: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Vec::new()))
}

/// Record a coverage warning (e.g., file truncated, resource unavailable).
pub fn record(msg: impl Into<String>) {
    if let Ok(mut v) = sink().lock() {
        v.push(msg.into());
    }
}

/// Drain all recorded warnings (call once per scan in the runner).
pub fn drain() -> Vec<String> {
    sink()
        .lock()
        .map(|mut v| std::mem::take(&mut *v))
        .unwrap_or_default()
}
