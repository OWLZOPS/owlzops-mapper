//! Single source of truth for process-age arithmetic.
//!
//! Two independent copies produced R27-39: the hardened one in `dlp.rs` and
//! the original in `ghost_pid.rs`, which still saturated an impossible age to 0.
//! Both scanners now use these functions instead of local implementations.

use std::sync::OnceLock;

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

/// `/proc/stat` places `btime` **after** the per-IRQ `intr` line, so the whole
/// preamble (one `cpuN` line per online CPU plus one counter per IRQ) has to be
/// read first. R27-44: a 256-byte cap never reached it and `boot_epoch`
/// silently returned `None` on every host.
const CAP_PROC_STAT: usize = 1024 * 1024;

/// Pure parser: btime may sit far beyond the first screen of /proc/stat.
fn parse_btime(stat: &str) -> Option<u64> {
    stat.lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// Boot epoch from `/proc/stat`, cached for the lifetime of the process.
/// Valid only for the real `/proc`; tempdir-based tests must not rely on this
/// if they need a different proc root.
pub fn boot_epoch() -> Option<u64> {
    static BOOT: OnceLock<Option<u64>> = OnceLock::new();
    *BOOT.get_or_init(|| {
        let (stat, truncated) =
            match crate::safe_io::read_procfs_capped("/proc/stat", CAP_PROC_STAT) {
                Ok(v) => v,
                Err(e) => {
                    crate::coverage::record(format!(
                        "proc_time: /proc/stat unreadable ({}) — boot epoch unknown; \
                         deep ghost analysis loses its metadata sharpening",
                        e.kind()
                    ));
                    return None;
                }
            };
        let btime = parse_btime(&stat);
        if btime.is_none() {
            crate::coverage::record(format!(
                "proc_time: btime absent from /proc/stat (truncated={truncated}) — \
                 boot epoch unknown; deep ghost analysis loses its metadata sharpening"
            ));
        }
        btime
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn btime_is_found_after_the_intr_line() {
        // Real layout: btime follows `intr`, which carries one counter per IRQ.
        // A cap that stops inside `intr` never reaches it (R27-44).
        let mut s = String::from("cpu  1 2 3 4 5 6 7 8 9 10\ncpu0 1 2 3 4 5 6 7 8 9 10\nintr 999");
        for _ in 0..512 {
            s.push_str(" 0");
        }
        s.push_str("\nctxt 12345\nbtime 1700000000\nprocesses 999\n");
        assert!(
            s.len() > 256,
            "fixture must exceed the cap that used to be here"
        );
        assert_eq!(parse_btime(&s), Some(1_700_000_000));
    }

    #[test]
    fn btime_absent_or_malformed_is_none() {
        assert_eq!(
            parse_btime("cpu  1 2 3\nintr 0 0 0\n"),
            None,
            "truncated before btime"
        );
        assert_eq!(parse_btime("btime notanumber\n"), None);
        assert_eq!(parse_btime("btimenospace 123\n"), None);
        assert_eq!(parse_btime(""), None);
    }
}
