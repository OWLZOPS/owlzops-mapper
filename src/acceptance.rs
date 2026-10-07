//! Accepted risks. A rule turns a finding into `suppressed` (kept in every
//! render, excluded from score and verdict). Compromise-class findings can
//! never be accepted: an accepted rootkit is not a risk decision, it is a
//! cover-up.
//!
//! File format — a JSON list of rules:
//!
//! ```json
//! [
//!   { "finding_id": "SEC-001", "host": "*",
//!     "justification": "cloud SG is the firewall",
//!     "expires": "2099-01-01", "ticket": "OPS-1234" }
//! ]
//! ```

use crate::scoring::Finding;
use serde::Deserialize;
use std::path::Path;

/// IDs whose acceptance is refused at load time. This is
/// `scoring::COMPROMISE_IDS` (the exit-3 set) plus two IDs that are also
/// never acceptable:
///
///   * `SEC-041` — an ftrace hook correlated with a module hidden from
///     /proc/modules. It does not currently feed `compromised_host` (see
///     `scoring::COMPROMISE_IDS` — the ID is deliberately absent), but it is
///     still a confirmed LKM-rootkit signal and must not be accept-able.
///   * `COV-001` — the scan was incomplete. Accepting it would silently hide
///     the incompleteness of the host's own verdict.
///
/// The `compromise_ids_are_never_acceptable` test enforces
/// `scoring::COMPROMISE_IDS ⊆ (never-accept set)` so a future IoC cannot
/// drift out of the refusal path.
const EXTRA_NEVER_ACCEPTABLE: &[&str] = &["SEC-041", "COV-001"];

fn is_never_acceptable(id: &str) -> bool {
    crate::scoring::COMPROMISE_IDS.contains(&id) || EXTRA_NEVER_ACCEPTABLE.contains(&id)
}

const CAP_ACCEPT_FILE: usize = 1024 * 1024;
const MIN_JUSTIFICATION: usize = 10;

#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
pub struct AcceptRule {
    pub finding_id: String,
    /// Glob over `host.hostname` ("*" = every host).
    pub host: String,
    pub justification: String,
    /// "YYYY-MM-DD" or RFC 3339. Expired rules are ignored and reported.
    pub expires: String,
    pub ticket: Option<String>,
}

impl Default for AcceptRule {
    fn default() -> Self {
        Self {
            finding_id: String::new(),
            host: "*".into(),
            justification: String::new(),
            expires: String::new(),
            ticket: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct Acceptances {
    rules: Vec<AcceptRule>,
}

fn parse_expiry(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&chrono::Utc));
    }
    let d = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()?;
    Some(d.and_hms_opt(23, 59, 59)?.and_utc())
}

/// `*` and `?` only; anchored. No regex crate.
///
/// M5: this is also M7's glob for `~/.ssh/config` Host aliases
/// (`crate::acceptance::glob_match`), by design: one glob implementation, one
/// place to change the semantics.
pub(crate) fn glob_match(pattern: &str, s: &str) -> bool {
    fn go(p: &[u8], s: &[u8]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) => go(&p[1..], s) || (!s.is_empty() && go(p, &s[1..])),
            (Some(b'?'), Some(_)) => go(&p[1..], &s[1..]),
            (Some(a), Some(b)) if a == b => go(&p[1..], &s[1..]),
            _ => false,
        }
    }
    go(pattern.as_bytes(), s.as_bytes())
}

impl Acceptances {
    pub fn load(path: &Path) -> Result<Self, String> {
        let (text, truncated) =
            crate::safe_io::read_file_capped_regular(&path.to_string_lossy(), CAP_ACCEPT_FILE)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if truncated {
            return Err(format!(
                "{} exceeds {CAP_ACCEPT_FILE} bytes — refused",
                path.display()
            ));
        }
        let rules: Vec<AcceptRule> = serde_json::from_str(&text)
            .map_err(|e| format!("{}: invalid JSON: {e}", path.display()))?;
        for (i, r) in rules.iter().enumerate() {
            let at = |msg: String| format!("{} rule #{}: {msg}", path.display(), i + 1);
            if r.finding_id.is_empty() {
                return Err(at("finding_id is required".into()));
            }
            if is_never_acceptable(&r.finding_id) {
                return Err(at(format!(
                    "{} is a compromise indicator and cannot be accepted",
                    r.finding_id
                )));
            }
            if r.justification.trim().len() < MIN_JUSTIFICATION {
                return Err(at(format!(
                    "justification must be at least {MIN_JUSTIFICATION} characters"
                )));
            }
            if parse_expiry(&r.expires).is_none() {
                return Err(at(format!(
                    "expires {:?} is not YYYY-MM-DD or RFC 3339",
                    r.expires
                )));
            }
        }
        Ok(Self { rules })
    }

    /// Mark matching findings as suppressed. Returns notes about rules that
    /// matched a finding but had expired — silence there would look like the
    /// risk came back for no reason.
    pub fn apply(&self, hostname: &str, findings: &mut [Finding]) -> Vec<String> {
        let now = chrono::Utc::now();
        let mut notes = Vec::new();
        for f in findings.iter_mut() {
            if f.suppressed.is_some() {
                continue; // scanner-level suppression stays as is
            }
            let Some(rule) = self
                .rules
                .iter()
                .find(|r| r.finding_id == f.id && glob_match(&r.host, hostname))
            else {
                continue;
            };
            let expiry = parse_expiry(&rule.expires).unwrap_or(now);
            if expiry < now {
                notes.push(format!(
                    "acceptance for {} on {hostname} expired on {} — finding is live again",
                    f.id, rule.expires
                ));
                continue;
            }
            let ticket = rule
                .ticket
                .as_deref()
                .map(|t| format!(", {t}"))
                .unwrap_or_default();
            f.suppressed = Some(format!(
                "ACCEPTED: {} (until {}{ticket})",
                rule.justification.trim(),
                rule.expires
            ));
        }
        notes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_is_anchored_with_star_and_question() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("web-??.corp", "web-01.corp"));
        assert!(!glob_match("web-*", "db-1"));
        assert!(!glob_match("web", "web-1"));
    }

    #[test]
    fn compromise_ids_are_never_acceptable() {
        // The never-accept set must be a superset of the exit-3 set in
        // scoring. A new IoC that lands in `scoring::COMPROMISE_IDS` and not
        // here would be silently acceptable, and the exit-3 verdict would go
        // away for that finding.
        for &id in crate::scoring::COMPROMISE_IDS {
            assert!(
                is_never_acceptable(id),
                "{id} is a compromise ID in scoring but --accept would refuse to refuse it"
            );
        }
        for &id in EXTRA_NEVER_ACCEPTABLE {
            assert!(is_never_acceptable(id));
        }
        // And a couple of ordinary IDs must remain acceptable.
        for id in ["SEC-001", "SEC-002", "HYG-001", "REL-002"] {
            assert!(!is_never_acceptable(id), "{id} must stay acceptable");
        }
    }

    #[test]
    fn compromise_ids_are_refused_at_load() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("accept.json");
        std::fs::write(
            &p,
            r#"[{"finding_id":"SEC-016","justification":"we like miners","expires":"2099-01-01"}]"#,
        )
        .unwrap();
        assert!(
            Acceptances::load(&p)
                .unwrap_err()
                .contains("cannot be accepted")
        );
        std::fs::write(
            &p,
            r#"[{"finding_id":"SEC-001","justification":"cloud SG is the firewall","expires":"2099-01-01"}]"#,
        )
            .unwrap();
        assert!(Acceptances::load(&p).is_ok());
    }

    #[test]
    fn short_justification_is_refused_at_load() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("accept.json");
        std::fs::write(
            &p,
            r#"[{"finding_id":"SEC-001","justification":"ok","expires":"2099-01-01"}]"#,
        )
        .unwrap();
        assert!(Acceptances::load(&p).unwrap_err().contains("at least"));
    }

    #[test]
    fn expired_rule_emits_a_note_and_leaves_finding_live() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("accept.json");
        std::fs::write(
            &p,
            r#"[{"finding_id":"SEC-001","host":"*","justification":"old decision","expires":"2000-01-01"}]"#,
        )
            .unwrap();
        let acc = Acceptances::load(&p).expect("loads");
        let mut findings = vec![Finding {
            id: "SEC-001",
            source: crate::scoring::Scanner::Network,
            title: "Firewall inactive".into(),
            category: crate::scoring::Category::Security,
            weight: 30,
            evidence: String::new(),
            suppressed: None,
            cis_ref: None,
        }];
        let notes = acc.apply("web-1", &mut findings);
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("expired"));
        assert!(findings[0].suppressed.is_none(), "expired != accepted");
    }

    #[test]
    fn live_rule_marks_finding_as_accepted() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("accept.json");
        std::fs::write(
            &p,
            r#"[{"finding_id":"SEC-001","host":"web-*","justification":"cloud SG is the firewall","expires":"2099-01-01","ticket":"OPS-1"}]"#,
        )
            .unwrap();
        let acc = Acceptances::load(&p).expect("loads");
        let mut findings = vec![Finding {
            id: "SEC-001",
            source: crate::scoring::Scanner::Network,
            title: "Firewall inactive".into(),
            category: crate::scoring::Category::Security,
            weight: 30,
            evidence: String::new(),
            suppressed: None,
            cis_ref: None,
        }];
        let notes = acc.apply("web-1", &mut findings);
        assert!(notes.is_empty());
        let s = findings[0].suppressed.as_deref().expect("accepted");
        assert!(s.starts_with("ACCEPTED: cloud SG is the firewall"));
        assert!(s.contains("OPS-1"));
    }

    #[test]
    fn host_glob_does_not_match_a_different_host() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("accept.json");
        std::fs::write(
            &p,
            r#"[{"finding_id":"SEC-001","host":"web-*","justification":"cloud SG is the firewall","expires":"2099-01-01"}]"#,
        )
            .unwrap();
        let acc = Acceptances::load(&p).expect("loads");
        let mut findings = vec![Finding {
            id: "SEC-001",
            source: crate::scoring::Scanner::Network,
            title: "Firewall inactive".into(),
            category: crate::scoring::Category::Security,
            weight: 30,
            evidence: String::new(),
            suppressed: None,
            cis_ref: None,
        }];
        acc.apply("db-1", &mut findings);
        assert!(findings[0].suppressed.is_none());
    }

    #[test]
    fn scanner_level_suppression_is_not_overwritten() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("accept.json");
        std::fs::write(
            &p,
            r#"[{"finding_id":"SEC-001","host":"*","justification":"cloud SG is the firewall","expires":"2099-01-01"}]"#,
        )
            .unwrap();
        let acc = Acceptances::load(&p).expect("loads");
        let mut findings = vec![Finding {
            id: "SEC-001",
            source: crate::scoring::Scanner::Network,
            title: "Firewall inactive".into(),
            category: crate::scoring::Category::Security,
            weight: 30,
            evidence: String::new(),
            suppressed: Some("scanner-level".into()),
            cis_ref: None,
        }];
        acc.apply("web-1", &mut findings);
        assert_eq!(findings[0].suppressed.as_deref(), Some("scanner-level"));
    }
}
