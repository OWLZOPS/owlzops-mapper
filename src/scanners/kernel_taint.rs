//! Agentless kernel taint audit (SEC-038).
//! One capped read of /proc/sys/kernel/tainted (an integer OR of all taint
//! bits). Unsigned/force-loaded/test module loads are surfaced as a low-cost
//! LKM-rootkit lead — visible even when the module hides itself from
//! /proc/modules. std-only, no new crates.

use crate::coverage;
use crate::models::{KernelTaint, TaintFlag};
use crate::safe_io;

/// (bit, letter, description, security_relevant). Source: kernel/panic.c
/// `taint_flags[]` (Documentation/admin-guide/tainted-kernels.rst).
/// `O` (out-of-tree) is deliberately NOT security_relevant: nvidia/dkms/vbox
/// set it legitimately, so escalating it would flood.
const TAINT_TABLE: &[(u8, char, &str, bool)] = &[
    (0, 'P', "proprietary module loaded", false),
    (1, 'F', "module force-loaded (insmod -f)", true),
    (2, 'S', "SMP kernel on non-SMP-safe CPU", false),
    (3, 'R', "module force-unloaded (rmmod -f)", true),
    (4, 'M', "machine check exception", false),
    (5, 'B', "bad page referenced", false),
    (6, 'U', "user-requested taint", false),
    (7, 'D', "kernel died (oops/BUG)", false),
    (8, 'A', "ACPI table overridden", false),
    (9, 'W', "warning issued (WARN_ON)", false),
    (10, 'C', "staging driver loaded", false),
    (11, 'I', "firmware workaround applied", false),
    (12, 'O', "out-of-tree module loaded", false),
    (13, 'E', "unsigned module loaded", true),
    (14, 'L', "soft lockup occurred", false),
    (15, 'K', "kernel live-patched", false),
    (16, 'X', "auxiliary taint (distro-defined)", false),
    (17, 'T', "struct-layout randomization override", false),
    (18, 'N', "in-tree test module loaded", true),
];

/// Defensive parse of the single decimal integer (untrusted /proc contract).
pub(crate) fn parse_tainted(content: &str) -> Option<u64> {
    let t = content.trim();
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    t.parse().ok()
}

/// Decode a raw mask into per-bit flags. Unknown high bits (future kernels)
/// become `?`/`unknown taint bit N` — raw truth over silence.
pub(crate) fn decode_taint(raw: u64) -> Vec<TaintFlag> {
    (0..u64::BITS as u8)
        .filter(|&b| raw & (1u64 << b) != 0)
        .map(|b| match TAINT_TABLE.iter().find(|(bit, ..)| *bit == b) {
            Some(&(bit, code, name, sec)) => TaintFlag {
                bit,
                code,
                name: name.to_string(),
                security_relevant: sec,
            },
            None => TaintFlag {
                bit: b,
                code: '?',
                name: format!("unknown taint bit {b}"),
                security_relevant: false,
            },
        })
        .collect()
}

#[cfg(target_os = "linux")]
pub fn gather_kernel_taint() -> KernelTaint {
    let (content, _) = match safe_io::read_file_capped("/proc/sys/kernel/tainted", 64) {
        Ok(v) => v,
        Err(e) => {
            coverage::record(format!(
                "kernel_taint: /proc/sys/kernel/tainted unreadable ({}) — taint state UNKNOWN",
                e.kind()
            ));
            return KernelTaint {
                unavailable: true,
                ..Default::default()
            };
        }
    };
    let Some(raw) = parse_tainted(&content) else {
        coverage::record(format!(
            "kernel_taint: unparseable value {:?} — taint state UNKNOWN",
            content.trim().chars().take(32).collect::<String>()
        ));
        return KernelTaint {
            unavailable: true,
            ..Default::default()
        };
    };
    KernelTaint {
        raw,
        flags: decode_taint(raw),
        unavailable: false,
    }
}

#[cfg(not(target_os = "linux"))]
pub fn gather_kernel_taint() -> KernelTaint {
    KernelTaint::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rejects_garbage() {
        assert_eq!(parse_tainted("12288\n"), Some(12288));
        assert_eq!(parse_tainted("0"), Some(0));
        assert_eq!(parse_tainted(""), None);
        assert_eq!(parse_tainted("0x10"), None);
        assert_eq!(parse_tainted("-1"), None);
    }

    #[test]
    fn unsigned_escalates_out_of_tree_does_not() {
        let flags = decode_taint((1 << 13) | (1 << 12)); // E + O
        assert!(
            flags
                .iter()
                .find(|f| f.code == 'E')
                .unwrap()
                .security_relevant
        );
        assert!(
            !flags
                .iter()
                .find(|f| f.code == 'O')
                .unwrap()
                .security_relevant
        );
    }

    #[test]
    fn clean_kernel_has_no_flags() {
        assert!(decode_taint(0).is_empty());
    }

    #[test]
    fn unknown_future_bit_not_dropped() {
        let f = decode_taint(1 << 40);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].code, '?');
    }
}
