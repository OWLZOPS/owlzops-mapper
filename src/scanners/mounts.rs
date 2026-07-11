//! Bind-mount / overlay masking detection (SEC-021).
//!
//! Reads `/proc/self/mountinfo` and flags mounts that are characteristic of
//! user-space rootkit evasion — no kernel module required:
//!   * a mount point matching `/proc/<pid>` — hides a process from `ps`
//!     (`mount --bind /empty /proc/<pid>`);
//!   * a tmpfs or bind overlay rooted on `/var/log` or
//!     `/var/lib/docker/containers` — hides logs/evidence.
//!
//! mountinfo line (kernel Documentation/filesystems/proc.rst):
//!   36 35 98:0 /root-in-fs /mount/point opts... [optional tags] - fstype source super-opts
//!            ^0 ^1  ^2      ^3           ^4                        ^sep ^0    ^1
//! The number of optional tags before the single `-` separator is VARIABLE
//! (shared:/master:/propagate_from:/unbindable), so fstype and source CANNOT
//! be located by a fixed column index — we split on the `-` separator first.

use crate::coverage;
use crate::models::MountMaskingFinding;

/// Log paths whose overlaying is treated as evidence hiding.
const MASKABLE_LOG_ROOTS: [&str; 2] = ["/var/log", "/var/lib/docker/containers"];

/// Cap: mountinfo is tiny (KiBs), but never trust an untrusted /proc blindly.
const CAP_MOUNTINFO: usize = 1024 * 1024;

/// Hard cap on stored findings — avoids unbounded growth from a hostile /proc.
const MAX_FINDINGS: usize = 64;

pub fn scan_mount_masking() -> Vec<MountMaskingFinding> {
    detect_from_path("/proc/self/mountinfo")
}

/// Split out for testing against a tempfile fixture.
fn detect_from_path(path: &str) -> Vec<MountMaskingFinding> {
    let (content, truncated) = match crate::safe_io::read_file_capped(path, CAP_MOUNTINFO) {
        Ok(v) => v,
        Err(_) => {
            // mountinfo is world-readable on normal hosts; failure is notable.
            coverage::record(format!("mount masking scan skipped: {path} unreadable"));
            return Vec::new();
        }
    };
    if truncated {
        coverage::record(format!(
            "{path} truncated — mount masking scan may be incomplete"
        ));
    }

    let mut findings = Vec::new();
    for line in content.lines() {
        if findings.len() >= MAX_FINDINGS {
            break;
        }
        if let Some(f) = classify_line(line) {
            findings.push(f);
        }
    }
    findings
}

/// Parse one mountinfo line and classify it. Returns `Some` only for a
/// masking pattern. Pure over `&str` — the returned struct owns its strings.
fn classify_line(line: &str) -> Option<MountMaskingFinding> {
    // Left of separator: positional fields. Right: fstype, source, super-opts.
    // rsplit is wrong (super-opts can't contain " - " but be defensive): we
    // want the FIRST " - " that delimits the optional-tag section.
    let (left, right) = line.split_once(" - ")?;

    let mut lf = left.split_whitespace();
    // 0:mount_id 1:parent_id 2:major:minor 3:root_in_fs 4:mount_point
    let _mount_id = lf.next()?;
    let _parent_id = lf.next()?;
    let _dev = lf.next()?;
    let root_in_fs = lf.next()?; // fs-internal path being mounted ("/" = whole fs)
    let mount_point = lf.next()?;

    let mut rf = right.split_whitespace();
    let fstype = rf.next()?; // 0:fstype
    let mount_source = rf.next().unwrap_or("-"); // 1:source (may be "none" for tmpfs)

    // Mount points are octal-escaped in mountinfo (space -> \040 etc.). For our
    // prefix/PID checks the escapes don't collide with the ASCII we match on;
    // we compare on the raw field, which is correct for /proc/<digits> and the
    // /var/log prefixes (none of which contain esc- able chars in practice).

    // ── Pattern 1: /proc/<pid> overlay → process hiding ──────────────
    if let Some(rest) = mount_point.strip_prefix("/proc/") {
        // Exactly `/proc/<digits>` (no deeper path): a whole-PID-dir overlay.
        // A legit mount like /proc/sys/fs/binfmt_misc has non-digit segments.
        if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
            return Some(MountMaskingFinding {
                target_path: mount_point.to_string(),
                mount_source: mount_source.to_string(),
                fstype: fstype.to_string(),
                reason: "overlay hides a PID from /proc (process masking)".to_string(),
            });
        }
    }

    // ── Pattern 2: tmpfs / bind overlay on a log root → evidence hiding ──
    if let Some(root) = MASKABLE_LOG_ROOTS
        .iter()
        .find(|&&r| is_at_or_under(mount_point, r))
    {
        // A tmpfs mounted over logs is almost always evidence hiding.
        let is_tmpfs = fstype == "tmpfs";
        // A bind mount re-roots a subtree of some fs onto this path: its
        // fs-internal root is NOT "/". (A normal fs mount has root_in_fs "/".)
        let is_bind_overlay = root_in_fs != "/";

        if is_tmpfs || is_bind_overlay {
            let kind = if is_tmpfs { "tmpfs" } else { "bind" };
            return Some(MountMaskingFinding {
                target_path: mount_point.to_string(),
                mount_source: mount_source.to_string(),
                fstype: fstype.to_string(),
                reason: format!("{kind} overlay on {root} (evidence hiding)"),
            });
        }
    }

    None
}

/// True if `path` equals `root` or is a path-segment descendant of it.
/// Avoids the `/var/logfoo` false match that a bare `starts_with` would make.
fn is_at_or_under(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn detect(fixture: &str) -> Vec<MountMaskingFinding> {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(fixture.as_bytes()).unwrap();
        detect_from_path(tmp.path().to_str().unwrap())
    }

    // A realistic clean line (systemd host, shared subtree tags present).
    const CLEAN: &str = "\
23 28 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:14 - proc proc rw
25 28 0:23 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
28 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
30 28 0:24 / /var/log rw,relatime shared:9 - ext4 /dev/sda1 rw
31 23 0:25 / /proc/sys/fs/binfmt_misc rw,relatime shared:2 - autofs systemd-1 rw
";

    #[test]
    fn clean_host_yields_nothing() {
        assert!(detect(CLEAN).is_empty());
    }

    #[test]
    fn hidden_pid_is_flagged() {
        // /proc/1337 fully overlaid by an empty tmpfs — classic process hide.
        let f = "\
99 23 0:99 / /proc/1337 rw,relatime - tmpfs tmpfs rw
";
        let out = detect(f);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].target_path, "/proc/1337");
        assert_eq!(out[0].fstype, "tmpfs");
        assert!(out[0].reason.contains("process masking"));
    }

    #[test]
    fn binfmt_misc_under_proc_is_not_flagged() {
        // Non-digit path segment under /proc — legitimate, must NOT flag.
        let f = "\
31 23 0:25 / /proc/sys/fs/binfmt_misc rw,relatime shared:2 - autofs systemd-1 rw
";
        assert!(detect(f).is_empty());
    }

    #[test]
    fn tmpfs_over_var_log_is_flagged() {
        let f = "\
99 28 0:99 / /var/log rw,relatime - tmpfs none rw
";
        let out = detect(f);
        assert_eq!(out.len(), 1);
        assert!(out[0].reason.contains("tmpfs overlay on /var/log"));
    }

    #[test]
    fn bind_overlay_on_container_logs_is_flagged() {
        // root_in_fs is a subtree ("/decoy"), not "/" → bind overlay.
        let f = "\
99 28 8:1 /decoy /var/lib/docker/containers rw,relatime - ext4 /dev/sda1 rw
";
        let out = detect(f);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].target_path, "/var/lib/docker/containers");
        assert!(out[0].reason.contains("bind overlay"));
    }

    #[test]
    fn normal_var_log_mount_is_not_flagged() {
        // Dedicated /var/log partition, whole-fs root "/", ext4 → legitimate.
        let f = "\
30 28 8:2 / /var/log rw,relatime shared:9 - ext4 /dev/sdb1 rw
";
        assert!(detect(f).is_empty());
    }

    #[test]
    fn var_logfoo_is_not_a_descendant() {
        // Prefix-collision guard: /var/logfoo must not match /var/log.
        let f = "\
99 28 8:1 /x /var/logfoo rw,relatime - tmpfs none rw
";
        assert!(detect(f).is_empty());
    }

    #[test]
    fn variable_optional_tags_do_not_break_fstype_parse() {
        // Multiple optional tags before '-'; fstype must still be read correctly.
        let f = "\
99 23 0:99 / /proc/4242 rw,relatime shared:3 master:2 propagate_from:1 - tmpfs tmpfs rw
";
        let out = detect(f);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].fstype, "tmpfs");
        assert_eq!(out[0].target_path, "/proc/4242");
    }

    #[test]
    fn malformed_lines_are_skipped_not_panicked() {
        let f = "garbage\n12 34 - onlyright\n\n42 41 0:1 / /proc/9 rw - tmpfs t rw\n";
        // Only the last well-formed line is a finding; no panic on the rest.
        let out = detect(f);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].target_path, "/proc/9");
    }
}
