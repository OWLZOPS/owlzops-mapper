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
//!
//! R37-01: every exec goes through `utils::run_child_with_timeout` —
//! trusted path, env_clear + LC_ALL=C, setsid, capped stdout, registry,
//! kill-before-reap. `show` is batched at `SHOW_BATCH` units per call;
//! records are blank-line-separated and keyed by `Id`, so the original
//! "FragmentPath mid-record" objection to batching no longer applies.
//!
//! R37-06: `systemd-*` and `user@*` are excluded only when `FragmentPath`
//! is under a vendor directory. A persistence unit named
//! `systemd-update.service` in `/etc/systemd/system` is an operator file
//! and enters drift like any other.

use crate::models::HardeningFinding;
use crate::{coverage, utils};
use std::collections::{HashMap, HashSet};

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

/// One budget per `systemctl` call. sd-bus's own method-call timeout is
/// 25 s; a wedged PID 1 must cost one budget per batch, not 25 s per unit.
const SYSTEMCTL_TIMEOUT_SECS: u64 = 30;

/// Units per `systemctl show` call — argv stays far below ARG_MAX.
const SHOW_BATCH: usize = 256;

/// Written only by the package manager. Provenance is WHERE the unit file
/// lives; the name is whatever its author chose (R37-06).
const VENDOR_UNIT_DIRS: &[&str] = &["/usr/lib/systemd/system/", "/lib/systemd/system/"];

fn is_vendor_unit(fragment_path: &str) -> bool {
    VENDOR_UNIT_DIRS
        .iter()
        .any(|d| fragment_path.starts_with(d))
}

/// R37-06: systemd's own unit = `systemd-*` name AND vendor location. A
/// persistence unit named `systemd-update.service` in `/etc/systemd/system`
/// is an operator file, not init-system internals, and enters drift.
fn is_systemd_internal(unit: &str, fragment_path: &str) -> bool {
    unit.starts_with("systemd-") && is_vendor_unit(fragment_path)
}

/// Transient units (D-Bus activations live in `/run/systemd/transient/` too)
/// and instances of the vendor `user@.service` template only. An operator
/// `user@backdoor.service` in `/etc/systemd/system` is a normal unit.
fn is_runtime_artifact(unit: &str, fragment_path: &str) -> bool {
    fragment_path.starts_with("/run/systemd/transient/")
        || (unit.starts_with("user@")
            && is_vendor_unit(fragment_path)
            && fragment_path.ends_with("/user@.service"))
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

/// Parse one `systemctl show` record — one `key=value` per line — into a
/// map. Lines without `=` are ignored; systemd does not emit any, but
/// refusing to panic on malformed output is cheaper than validating it.
fn parse_show(stdout: &str) -> HashMap<String, String> {
    stdout
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.to_string()))
        .collect()
}

/// `systemctl show A B …`: one key=value block per unit, blank-line
/// separated. Keyed by `Id`, so block order is irrelevant.
fn parse_show_records(stdout: &str) -> Vec<HashMap<String, String>> {
    stdout
        .split("\n\n")
        .map(parse_show)
        .filter(|r| r.contains_key("Id"))
        .collect()
}

/// Turn one unit's properties into a finding, or `None` when the unit is
/// out of scope (vanished, inactive, systemd-internal, or runtime
/// artifact) or already hardened.
fn evaluate_unit(props: &HashMap<String, String>) -> Option<HardeningFinding> {
    let get = |k: &str| props.get(k).map(String::as_str);
    let unit = get("Id")?;

    // Gone between list-units and show: systemctl still exits 0 and reports
    // every directive at its unhardened default. Not posture.
    if get("LoadState") == Some("not-found")
        || matches!(get("ActiveState"), Some("inactive" | "failed"))
    {
        return None;
    }

    let fragment_path = get("FragmentPath").unwrap_or("");
    if is_systemd_internal(unit, fragment_path) || is_runtime_artifact(unit, fragment_path) {
        return None;
    }

    // DynamicUser= runs under a transient non-root uid even with User= empty.
    let dynamic = get("DynamicUser") == Some("yes");
    let user = get("User").unwrap_or("");
    let is_root = !dynamic && (user.is_empty() || user == "root" || user == "0");

    let mut missing = Vec::new();
    let mut raw_weight: u16 = 0;
    for (name, weight) in DIRECTIVES {
        if is_root && ROOT_IRRELEVANT.contains(name) {
            continue;
        }
        if get(name).is_none_or(|v| is_unhardened(name, v)) {
            missing.push((*name).to_string());
            raw_weight += u16::from(*weight);
        }
    }
    if missing.is_empty() {
        return None;
    }

    Some(HardeningFinding {
        unit: unit.to_string(),
        missing,
        raw_weight: raw_weight.min(u16::from(u8::MAX)) as u8,
        user: match (is_root, dynamic && user.is_empty()) {
            (true, _) => "root".to_string(),
            (false, true) => "dynamic".to_string(),
            (false, false) => user.to_string(),
        },
        fragment_path: fragment_path.to_string(),
    })
}

/// Main entry. Returns one finding per running unit whose effective
/// hardening is weaker than the baseline. Coverage warnings, not
/// findings, when `systemctl` is unavailable or fails.
pub fn scan_systemd_hardening() -> Vec<HardeningFinding> {
    let mut out = Vec::new();

    if utils::resolve_tool("systemctl").is_none() {
        coverage::record(
            "systemd hardening scan skipped: `systemctl` not resolvable \
             (missing, or on a path writable by a non-root principal)",
        );
        return out;
    }

    // R37-01: every exec goes through run_child_with_timeout — trusted path,
    // env_clear + LC_ALL=C, setsid, capped stdout, registry, kill-before-reap.
    // `--plain` strips the ● markers, `--no-legend` drops the header,
    // `--state=running` is what an auditor cares about: a stopped unit has
    // no live attack surface.
    let list = match utils::run_child_with_timeout(
        "systemctl",
        &[
            "list-units",
            "--type=service",
            "--state=running",
            "--no-legend",
            "--plain",
            "--no-pager",
        ],
        SYSTEMCTL_TIMEOUT_SECS,
    ) {
        Some(o) if o.status.success() => o.stdout,
        Some(o) => {
            coverage::record(format!(
                "systemd hardening scan: list-units failed (status {}): {}",
                o.status,
                String::from_utf8_lossy(&o.stderr).trim()
            ));
            return out;
        }
        None => {
            coverage::record(format!(
                "systemd hardening scan: `systemctl list-units` did not finish within \
                 {SYSTEMCTL_TIMEOUT_SECS}s or could not be spawned — SEC-081 NOT evaluated"
            ));
            return out;
        }
    };

    let list_stdout = String::from_utf8_lossy(&list);
    // R37-06: the systemd-internal / runtime-artifact filters moved after
    // `show` — `FragmentPath` is the provenance signal, and it only exists
    // in the show output. Filtering by name here would hide a persistence
    // unit that happens to start with `systemd-`.
    let units: Vec<&str> = list_stdout
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|u| u.ends_with(".service"))
        .collect();

    if units.is_empty() {
        // A host with zero running services is legal (very minimal
        // container). No warning.
        return out;
    }

    // Every property `evaluate_unit` reads, in one string. `Id` is required
    // for the record split; `LoadState`/`ActiveState` distinguish a unit
    // that vanished between list-units and show; `DynamicUser` picks up
    // transient non-root uids; `FragmentPath` is the provenance signal.
    let prop_list = std::iter::once("Id,LoadState,ActiveState,FragmentPath,User,DynamicUser")
        .chain(DIRECTIVES.iter().map(|(n, _)| *n))
        .collect::<Vec<_>>()
        .join(",");

    let mut unanswered = 0usize;
    for batch in units.chunks(SHOW_BATCH) {
        let mut args = vec!["show", "--no-pager", "-p", prop_list.as_str()];
        args.extend_from_slice(batch);
        let Some(o) = utils::run_child_with_timeout("systemctl", &args, SYSTEMCTL_TIMEOUT_SECS)
            .filter(|o| o.status.success())
        else {
            unanswered += batch.len();
            continue;
        };
        let stdout = String::from_utf8_lossy(&o.stdout);
        let records = parse_show_records(&stdout);
        let ids: HashSet<&str> = records
            .iter()
            .filter_map(|r| r.get("Id").map(String::as_str))
            .collect();
        unanswered += batch.iter().filter(|u| !ids.contains(*u)).count();
        out.extend(records.iter().filter_map(evaluate_unit));
    }

    // R37-01: a failed or timed-out show is a coverage fact, not a vanished
    // unit. Without this, the SEC-081 list silently undercounts and the
    // operator reads a clean finding for a host whose PID 1 was wedged.
    if unanswered > 0 {
        coverage::record(format!(
            "systemd hardening scan: {unanswered} running service(s) returned no properties \
             (systemctl failed or exceeded {SYSTEMCTL_TIMEOUT_SECS}s) — SEC-081 list is a LOWER BOUND"
        ));
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

    // R37-06: a unit is systemd-internal only when its name says so AND
    // its file lives under a vendor directory. Masquerading units in
    // /etc/systemd/system or /run/systemd/system are operator files.
    #[test]
    fn systemd_internal_needs_vendor_provenance() {
        assert!(is_systemd_internal(
            "systemd-journald.service",
            "/usr/lib/systemd/system/systemd-journald.service"
        ));
        assert!(is_systemd_internal(
            "systemd-resolved.service",
            "/lib/systemd/system/systemd-resolved.service"
        ));
        assert!(!is_systemd_internal(
            "systemd-update.service",
            "/etc/systemd/system/systemd-update.service"
        ));
        assert!(!is_systemd_internal(
            "systemd-update.service",
            "/run/systemd/system/systemd-update.service"
        ));
        assert!(!is_systemd_internal(
            "mysystemd-agent.service",
            "/usr/lib/systemd/system/mysystemd-agent.service"
        ));
    }

    #[test]
    fn runtime_artifacts_are_skipped() {
        // Per-user systemd manager — vendor template only.
        assert!(is_runtime_artifact(
            "user@1000.service",
            "/usr/lib/systemd/system/user@.service"
        ));
        assert!(is_runtime_artifact(
            "user@0.service",
            "/usr/lib/systemd/system/user@.service"
        ));
        // D-Bus activation, transient path.
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

    // R37-06: an operator unit whose name matches the user@* pattern but
    // whose file is not the vendor template is a normal unit.
    #[test]
    fn an_operator_unit_named_user_at_is_not_a_runtime_artifact() {
        assert!(!is_runtime_artifact(
            "user@backdoor.service",
            "/etc/systemd/system/user@backdoor.service"
        ));
        assert!(!is_runtime_artifact(
            "user@1000.service",
            "/etc/systemd/system/user@1000.service"
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

    // R37-01: batched `show` is split per unit; a unit gone between
    // list-units and show (LoadState=not-found) is skipped, not reported
    // as fully unhardened.
    #[test]
    fn batched_show_is_split_per_unit_and_vanished_units_are_skipped() {
        let out = "Id=a.service\nLoadState=loaded\nActiveState=active\n\
                   FragmentPath=/etc/systemd/system/a.service\nUser=\nNoNewPrivileges=no\n\n\
                   Id=gone.service\nLoadState=not-found\nActiveState=inactive\nFragmentPath=\n";
        let found: Vec<_> = parse_show_records(out)
            .iter()
            .filter_map(evaluate_unit)
            .collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].unit, "a.service");
    }
}
