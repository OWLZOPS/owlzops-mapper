//! systemd unit hardening posture (SEC-081).
//!
//! Enumerates running services and reads the *effective* hardening
//! directives from `systemctl show`. Effective means drop-in overrides,
//! instance templates and vendor defaults are all resolved — we do not
//! parse `.service` files on disk, and we do not reimplement systemd's
//! lookup order.
//!
//! Not compromise-class. A service without `ProtectSystem=strict` is a
//! privilege-escalation *surface*, not an exploited one. Findings drive
//! exit 1 by score, never 3.
//!
//! Non-systemd hosts (containers without systemd, minimal images) yield
//! a coverage warning, not a false "clean" reading. The tool not being
//! present, or `systemctl` failing to talk to the bus, is a fact about
//! the host, not a hygiene finding.

use crate::models::HardeningFinding;
use crate::{coverage, utils};
use std::collections::HashMap;
use std::process::Command;

/// Directives we check and the weight each contributes when missing.
///
/// Weight is the *severity of the absence*. A missing `NoNewPrivileges`
/// is more dangerous than a missing `PrivateTmp`: the first directly
/// enables setuid-based escalation inside the service's execution
/// context, the second merely widens the blast radius of a symlink
/// attack. The aggregate is capped at 25 in `scoring.rs`.
const DIRECTIVES: &[(&str, u8)] = &[
    ("NoNewPrivileges", 10),
    ("ProtectSystem", 8),
    ("ProtectKernelTunables", 8),
    ("ProtectKernelModules", 8),
    ("ProtectHome", 5),
    ("PrivateTmp", 5),
    ("PrivateDevices", 5),
    ("ProtectControlGroups", 5),
    ("RestrictAddressFamilies", 5),
];

/// Directives that are meaningless on a `User=root` unit: root has every
/// privilege and no home directory to protect, so flagging their absence
/// is noise on a unit where the check is a no-op by construction.
///
/// `ProtectSystem`, `ProtectKernelTunables`, `ProtectKernelModules`,
/// `PrivateTmp`, `PrivateDevices`, `ProtectControlGroups` and
/// `RestrictAddressFamilies` stay in scope for root units — they restrict
/// even root inside the unit's namespace, which is exactly the point.
const ROOT_IRRELEVANT: &[&str] = &["NoNewPrivileges", "ProtectHome"];

/// `true` when the unit is systemd's own. Its hardening posture is the
/// init system's decision, not the operator's, and the ones that matter
/// on a real host (journald, logind, udevd, resolved) ship hardened on
/// every distro we target. If an operator wants systemd-of-systemd
/// hardening audited, that is a separate meta-task — the noise of
/// flagging every `systemd-*.service` would drown the findings that
/// actually belong to the host.
fn is_systemd_internal(unit: &str) -> bool {
    unit.starts_with("systemd-")
}

/// `true` for units an operator does not configure and cannot usefully
/// harden: transient units, per-user systemd managers, and D-Bus
/// activation units. These are runtime artifacts, not service posture.
///
/// Transient units live in `/run/systemd/transient/` and are spawned and
/// destroyed by D-Bus activation; `user@*.service` runs the per-user
/// systemd instance, whose hardening boundary is the user's own session,
/// not the host's; `dbus-:*` are the D-Bus activations themselves. All
/// three produce findings an operator cannot act on, and 39-row walls in
/// the dashboard are exactly what the project's "one noisy category must
/// not hide a real problem" rule exists to prevent.
fn is_runtime_artifact(unit: &str, fragment_path: &str) -> bool {
    unit.starts_with("user@")
        || unit.starts_with("dbus-:")
        || fragment_path.starts_with("/run/systemd/transient/")
}

/// `true` when the effective value of `directive` shows the unit is *not*
/// hardened on that axis. Directive-specific because systemd uses
/// different value vocabularies per directive: a boolean for
/// `PrivateTmp`, an enum for `ProtectSystem`, a list for
/// `RestrictAddressFamilies`.
///
/// Unknown directives fall through to `false` so an unhandled name can
/// never produce a false positive.
fn is_unhardened(directive: &str, value: &str) -> bool {
    match directive {
        "NoNewPrivileges"
        | "PrivateTmp"
        | "PrivateDevices"
        | "ProtectKernelTunables"
        | "ProtectKernelModules"
        | "ProtectControlGroups" => value != "yes",
        // `yes` is an alias for `full`; `strict` is stricter than both.
        // `auto` is the default and means "only /usr is read-only",
        // which is not what an auditor means by hardened.
        "ProtectSystem" => !matches!(value, "yes" | "full" | "strict"),
        "ProtectHome" => !matches!(value, "yes" | "read-only" | "tmpfs"),
        "RestrictAddressFamilies" => value.trim().is_empty(),
        _ => false,
    }
}

/// Parse `systemctl show` output — one `key=value` per line — into a
/// map. Lines without `=` are ignored; systemd does not emit any, but
/// refusing to panic on malformed output is cheaper than validating it.
fn parse_show(stdout: &str) -> HashMap<String, String> {
    stdout
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.to_string()))
        .collect()
}

/// Main entry. Returns one finding per running unit whose effective
/// hardening is weaker than the baseline. Coverage warnings, not
/// findings, when `systemctl` is unavailable or fails.
pub fn scan_systemd_hardening() -> Vec<HardeningFinding> {
    let mut out = Vec::new();

    let Some(systemctl) = utils::resolve_tool("systemctl") else {
        coverage::record(
            "systemd hardening scan skipped: `systemctl` not resolvable \
             (missing, or on a path writable by a non-root principal)",
        );
        return out;
    };

    // `--plain` strips the ● markers, `--no-legend` drops the header.
    // `--state=running` is what an auditor cares about: a stopped unit
    // has no live attack surface, and counting it would make the finding
    // swing on every reboot.
    let list = match Command::new(&systemctl)
        .args([
            "list-units",
            "--type=service",
            "--state=running",
            "--no-legend",
            "--plain",
        ])
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        Ok(o) => {
            coverage::record(format!(
                "systemd hardening scan: list-units failed (status {}): {}",
                o.status,
                String::from_utf8_lossy(&o.stderr).trim()
            ));
            return out;
        }
        Err(e) => {
            coverage::record(format!(
                "systemd hardening scan: list-units could not be spawned: {e}"
            ));
            return out;
        }
    };

    let list_stdout = String::from_utf8_lossy(&list);
    let units: Vec<&str> = list_stdout
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|u| u.ends_with(".service"))
        .filter(|u| !is_systemd_internal(u))
        .collect();

    if units.is_empty() {
        // A host with zero running services is legal (very minimal
        // container). No warning.
        return out;
    }

    // Query one unit at a time. Batching is possible — `systemctl show`
    // accepts multiple names — but the output format places FragmentPath
    // in alphabetical order somewhere in the middle of each record,
    // forcing us to anchor on it as a delimiter. One call per unit is
    // ~3 ms of overhead on the average host; correctness wins.
    for unit in units {
        let mut cmd = Command::new(&systemctl);
        cmd.arg("show").arg(unit).arg("--no-pager");
        cmd.arg("-p").arg("FragmentPath");
        cmd.arg("-p").arg("User");
        for (name, _) in DIRECTIVES {
            cmd.arg("-p").arg(name);
        }

        let output = match cmd.output() {
            Ok(o) if o.status.success() => o.stdout,
            Ok(_) => {
                // A single unit disappearing between list-units and show
                // is normal on a busy host — do not warn, do not skip the
                // rest of the units.
                continue;
            }
            Err(_) => {
                // Spawn failure is a systemic problem (EACCES, ENOENT on
                // the resolved path). Report once and stop: every
                // remaining unit would produce the same error.
                coverage::record(format!(
                    "systemd hardening scan: `systemctl show {unit}` could not be spawned; \
                     the rest of the unit list is skipped"
                ));
                return out;
            }
        };

        let stdout = String::from_utf8_lossy(&output);
        let props = parse_show(&stdout);

        let fragment_path = props.get("FragmentPath").cloned().unwrap_or_default();

        // Runtime artifacts are skipped AFTER the show call, not before:
        // `FragmentPath` is the canonical signal that a unit is transient,
        // and it is not visible in `list-units --plain` output.
        if is_runtime_artifact(unit, &fragment_path) {
            continue;
        }

        // `systemctl show -p User` emits either a name ("root", "sssd")
        // or the numeric uid ("0", "1000"). Both forms of root must land
        // in the ROOT_IRRELEVANT filter — otherwise `user@0.service`
        // and similar carry `NoNewPrivileges`/`ProtectHome` noise.
        let user = props.get("User").map(String::as_str).unwrap_or("");
        let is_root = user.is_empty() || user == "root" || user == "0";

        let mut missing = Vec::new();
        let mut raw_weight: u16 = 0;
        for (name, weight) in DIRECTIVES {
            if is_root && ROOT_IRRELEVANT.contains(name) {
                continue;
            }
            // Missing key = systemd did not return the property. In
            // practice `-p NAME` always yields a line; treating absence
            // as unhardened is the defensive reading.
            let unhardened = props.get(*name).is_none_or(|v| is_unhardened(name, v));
            if unhardened {
                missing.push((*name).to_string());
                raw_weight += u16::from(*weight);
            }
        }

        if missing.is_empty() {
            continue;
        }

        out.push(HardeningFinding {
            unit: unit.to_string(),
            missing,
            // 255-cap is a formality: the sum of DIRECTIVES weights is
            // 59. Saturating cast keeps the type honest if the list grows.
            raw_weight: raw_weight.min(u16::from(u8::MAX)) as u8,
            user: if is_root {
                "root".to_string()
            } else {
                user.to_string()
            },
            fragment_path,
        });
    }

    // Sort by weight descending, then by unit name for determinism.
    // `compare.rs` keys on the unit name and the whole-vec ordering does
    // not affect diffing, but the dashboard reads top-to-bottom and the
    // worst offender should be first.
    out.sort_by(|a, b| {
        b.raw_weight
            .cmp(&a.raw_weight)
            .then_with(|| a.unit.cmp(&b.unit))
    });

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_internal_units_are_skipped() {
        assert!(is_systemd_internal("systemd-journald.service"));
        assert!(is_systemd_internal("systemd-resolved.service"));
        assert!(is_systemd_internal("systemd-udevd.service"));
        assert!(is_systemd_internal("systemd-analyze.service"));
        assert!(!is_systemd_internal("nginx.service"));
        assert!(!is_systemd_internal("ssh.service"));
        // Prefix is anchored on `systemd-`: a name that merely contains
        // the substring, or starts with `systemd` but not the dash, is
        // not an internal unit.
        assert!(!is_systemd_internal("systemd.service"));
        assert!(!is_systemd_internal("mysystemd-agent.service"));
    }

    #[test]
    fn runtime_artifacts_are_skipped() {
        // Per-user systemd manager.
        assert!(is_runtime_artifact(
            "user@1000.service",
            "/usr/lib/systemd/system/user@.service"
        ));
        assert!(is_runtime_artifact(
            "user@0.service",
            "/usr/lib/systemd/system/user@.service"
        ));
        // D-Bus activation, name form.
        assert!(is_runtime_artifact(
            "dbus-:1.12-org.freedesktop.problems@0.service",
            "/run/systemd/transient/dbus-:1.12-org.freedesktop.problems@0.service"
        ));
        // Transient unit with an unexpected name — the FragmentPath check
        // is the backstop when the name-based filter does not fire.
        assert!(is_runtime_artifact(
            "weird.service",
            "/run/systemd/transient/weird.service"
        ));
        // Real services are not filtered.
        assert!(!is_runtime_artifact(
            "nginx.service",
            "/usr/lib/systemd/system/nginx.service"
        ));
        assert!(!is_runtime_artifact(
            "sssd-kcm.service",
            "/usr/lib/systemd/system/sssd-kcm.service"
        ));
    }

    #[test]
    fn boolean_directives_require_yes() {
        assert!(is_unhardened("NoNewPrivileges", "no"));
        assert!(!is_unhardened("NoNewPrivileges", "yes"));
        assert!(is_unhardened("PrivateTmp", "no"));
        assert!(!is_unhardened("PrivateTmp", "yes"));
        assert!(is_unhardened("ProtectKernelTunables", ""));
        assert!(!is_unhardened("ProtectKernelTunables", "yes"));
    }

    #[test]
    fn protect_system_accepts_only_hardened_enums() {
        assert!(is_unhardened("ProtectSystem", "no"));
        assert!(is_unhardened("ProtectSystem", "auto"));
        assert!(!is_unhardened("ProtectSystem", "yes"));
        assert!(!is_unhardened("ProtectSystem", "full"));
        assert!(!is_unhardened("ProtectSystem", "strict"));
    }

    #[test]
    fn protect_home_accepts_read_only_variants() {
        assert!(is_unhardened("ProtectHome", "no"));
        assert!(!is_unhardened("ProtectHome", "yes"));
        assert!(!is_unhardened("ProtectHome", "read-only"));
        assert!(!is_unhardened("ProtectHome", "tmpfs"));
    }

    #[test]
    fn restrict_address_families_empty_is_unhardened() {
        assert!(is_unhardened("RestrictAddressFamilies", ""));
        assert!(is_unhardened("RestrictAddressFamilies", "   "));
        assert!(!is_unhardened("RestrictAddressFamilies", "AF_UNIX AF_INET"));
    }

    #[test]
    fn unknown_directive_never_fires() {
        // Defensive: a directive not listed in DIRECTIVES must not be
        // reported as unhardened even if `is_unhardened` is called with
        // an unexpected name. The public scan loop only calls with known
        // names, but the guard prevents future refactors from turning a
        // typo into false positives.
        assert!(!is_unhardened("SomeFutureDirective", ""));
        assert!(!is_unhardened("SomeFutureDirective", "whatever"));
    }

    #[test]
    fn parse_show_handles_empty_values() {
        let out = parse_show(
            "User=nginx\nFragmentPath=/usr/lib/systemd/system/nginx.service\nRestrictAddressFamilies=\n",
        );
        assert_eq!(out.get("User").map(String::as_str), Some("nginx"));
        assert_eq!(
            out.get("RestrictAddressFamilies").map(String::as_str),
            Some("")
        );
    }

    #[test]
    fn parse_show_ignores_lines_without_equals() {
        let out = parse_show(
            "User=nginx\nsome garbage line\nFragmentPath=/etc/systemd/system/x.service\n",
        );
        assert_eq!(out.len(), 2);
    }
}
