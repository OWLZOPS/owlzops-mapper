//! Lightweight coverage/truncation signaler for parsers.
//! Uses a global lock to avoid threading through every scanner.
//!
//! Attribution to a specific scan in production is done at drain time via
//! `drain_scoped`, which correctly handles the fact that scanners run inside
//! `spawn_blocking` and thread-local state is not visible there.
//!
//! In tests (M8) scanners run inline, so `capture` can redirect `record` to a
//! per-thread buffer and let unit tests assert on coverage lines directly.

#[cfg(test)]
use std::cell::RefCell;
use std::sync::{Mutex, OnceLock};

const MAX_ENTRIES: usize = 1024;

#[cfg(test)]
thread_local! {
    /// M8: when set on the current thread, `record` appends here instead of
    /// the global sink. Tests run scanners inline, so the thread-local sees
    /// exactly the records of the scanner under test.
    static CAPTURE: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
}

fn sink() -> &'static Mutex<Vec<String>> {
    static S: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Vec::new()))
}

/// Record a coverage warning (e.g., file truncated, resource unavailable).
/// The sink is capped: when the limit is reached a single suppression marker
/// is appended and further records are silently dropped.
///
/// INVARIANT: only scanner (spawn_blocking) paths call this in production.
/// Callers running concurrently with other scans (russh fleet tasks,
/// ssh_engine, known_hosts) MUST NOT — drain-time scoping cannot attribute
/// concurrent writers.
///
/// Under `capture` (tests only) records go to the per-thread buffer first.
pub fn record(msg: impl Into<String>) {
    let msg = msg.into();

    #[cfg(test)]
    {
        let captured = CAPTURE.with(|c| {
            let mut b = c.borrow_mut();
            match b.as_mut() {
                Some(buf) => {
                    buf.push(msg.clone());
                    true
                }
                None => false,
            }
        });
        if captured {
            return;
        }
    }

    if let Ok(mut v) = sink().lock() {
        use std::cmp::Ordering::*;
        match v.len().cmp(&MAX_ENTRIES) {
            Less => v.push(msg),
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

/// M8: run `f` with every `record` on this thread redirected to the returned
/// Vec. The previous capture (if any) is restored afterwards, so nesting works.
///
/// Caveat: records emitted from OTHER threads (rayon, tokio::spawn,
/// std::thread::spawn) are NOT captured — they still hit the global sink.
/// Scanners must be single-threaded in tests. If a scanner gains internal
/// threading, capture silently degrades to "empty"; wrap the inner work in
/// `tokio::task::block_in_place` or refactor to return records explicitly.
#[cfg(test)]
pub fn capture<R>(f: impl FnOnce() -> R) -> (R, Vec<String>) {
    let prev = CAPTURE.with(|c| c.borrow_mut().replace(Vec::new()));
    let out = f();
    let lines = CAPTURE
        .with(|c| std::mem::replace(&mut *c.borrow_mut(), prev))
        .unwrap_or_default();
    (out, lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_sees_only_this_threads_records() {
        let ((), lines) = capture(|| record("inside"));
        assert_eq!(lines, vec!["inside".to_string()]);
    }

    #[test]
    fn capture_restores_previous_on_exit() {
        let (_, outer) = capture(|| {
            record("outer-1");
            let (_, inner) = capture(|| record("inner"));
            assert_eq!(inner, vec!["inner".to_string()]);
            record("outer-2");
        });
        assert_eq!(outer, vec!["outer-1".to_string(), "outer-2".to_string()]);
    }
}
