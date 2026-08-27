//! Single source of truth for process-age arithmetic.
//!
//! Two independent copies produced R27-39: the hardened one in `dlp.rs` and
//! the original in `ghost_pid.rs`, which still saturated an impossible age to 0.
//! Both scanners now use these functions instead of local implementations.

/// Seconds since boot from `/proc/uptime`. `None` when unreadable — callers
/// must NOT substitute 0: that makes every process look newborn.
pub fn uptime_secs() -> Option<u64> {
    // R27-43: keep the capped read from the original dlp.rs. This is a procfs
    // read, and the project convention is to use safe_io for all /proc paths.
    let (raw, _truncated) = crate::safe_io::read_procfs_capped("/proc/uptime", 128).ok()?;
    let value = raw
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v >= 0.0)?;
    Some(value.floor() as u64)
}

/// USER_HZ. `None` when `sysconf` fails — never guessed. A wrong HZ scales
/// `start_secs` and pushes the age into the impossible range, which the
/// caller then reads as "newborn".
pub fn clock_ticks_per_sec() -> Option<u64> {
    u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) })
        .ok()
        .filter(|&hz| hz > 0)
}

/// Age in seconds from raw `starttime` ticks and the system's actual boot time.
/// Returns `None` if the result would be impossible (start after boot,
/// negative duration) — never a saturated 0.
pub fn age_from_parts(start_ticks: u64, clk_tck: u64, uptime_secs: u64) -> Option<u64> {
    if clk_tck == 0 {
        return None;
    }
    let start_secs = start_ticks / clk_tck;
    uptime_secs.checked_sub(start_secs)
}

/// Extract the `starttime` field from a `/proc/[pid]/stat` line.
/// The field follows the `)` that terminates the comm field and is 20 fields
/// after it (index 19 in a zero-based split of the rest).
pub fn starttime_ticks(stat: &str) -> Option<u64> {
    stat.rfind(')')?
        .checked_add(1)
        .and_then(|idx| stat.get(idx..))
        .and_then(|after| after.split_ascii_whitespace().nth(19))
        .and_then(|field| field.parse().ok())
}
