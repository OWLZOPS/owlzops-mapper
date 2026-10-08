//! Minimal parser for `~/.ssh/config`, in service of M7's
//! `--hosts-from-ssh-config`.
//!
//! Scope (MVP, deliberately narrow):
//!
//! - Reads a flat file. `Include` is **not** followed; a file with any
//!   `Include` directive produces a warning, not hosts. Following it would
//!   mean tracking search paths and cycle detection — a milestone of its own.
//! - Handles `Host` and `HostName`. Every other directive is recorded but
//!   ignored: M7 chooses *which hosts to scan*, not *how to authenticate to
//!   them*. Per-host `User` / `Port` / `IdentityFile` would change
//!   `scan_remote_host`'s signature and are a separate feature.
//! - `Match` blocks are skipped entirely; their contents are conditional on
//!   the connection context, which we do not have at parse time.
//! - Keyword names are case-insensitive (`host`, `Host`, `HOST` all work),
//!   matching OpenSSH.
//! - `Host` accepts one or more space-separated patterns. A pattern that
//!   starts with `!` is a negative pattern in OpenSSH; we record it but do
//!   not apply it (`Host *.example.com !db.example.com` would still match
//!   `db.example.com` here). This is documented as a known limitation.
//!
//! The parser is `pub(crate)` — it is a private implementation detail of
//! M7, not a public API.

use crate::acceptance::glob_match;
use std::path::Path;

/// Cap on the config file we are willing to read. A `~/.ssh/config` above
/// 1 MiB is a sign of a mistake, not a policy; refusing is cheaper than
/// allocating for it and then producing nonsense.
const CAP_SSH_CONFIG: usize = 1024 * 1024;

/// A `Host` block: its alias patterns and, if present, its `HostName`.
#[derive(Debug, Default)]
struct Block {
    /// Raw patterns from the `Host` line, in order. Includes any `!` prefix.
    aliases: Vec<String>,
    /// The `HostName` value, if the block declared one.
    host_name: Option<String>,
}

/// Read `path`, return every host name that matches one of `patterns`.
///
/// A block contributes its `HostName` when:
///   * at least one of its aliases matches at least one of `patterns`
///     (using [`glob_match`]); and
///   * the block declares a `HostName`.
///
/// A block with no `HostName` contributes its **alias** instead, but only
/// if that alias contains no glob metacharacters (`*`, `?`) — otherwise the
/// "host name" would be a pattern, and passing a pattern to SSH would try
/// to resolve a literal `web-*` host, which is never what the operator
/// wants.
///
/// The second return value is a list of warnings — one per `Include` or
/// `Match` directive encountered, one for blocks that matched but had no
/// usable host name. Callers are expected to surface these; silent skipping
/// is a bug.
pub(crate) fn load_hosts(
    path: &Path,
    patterns: &[String],
) -> Result<(Vec<String>, Vec<String>), String> {
    let (text, truncated) =
        crate::safe_io::read_file_capped_regular(&path.to_string_lossy(), CAP_SSH_CONFIG)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if truncated {
        return Err(format!(
            "{} exceeds {CAP_SSH_CONFIG} bytes — refusing (an ssh config this \
             size is a bug, not a policy)",
            path.display()
        ));
    }
    Ok(extract_hosts(&text, patterns))
}

/// Pure function — separated so tests can exercise it without touching
/// a filesystem.
fn extract_hosts(text: &str, patterns: &[String]) -> (Vec<String>, Vec<String>) {
    let mut warnings: Vec<String> = Vec::new();
    let mut blocks: Vec<Block> = Vec::new();
    let mut current: Option<Block> = None;
    let mut includes_seen = 0usize;
    let mut matches_seen = 0usize;

    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (key, value) = split_kv(line);
        let key_lower = key.to_ascii_lowercase();
        let value = value.trim();

        match key_lower.as_str() {
            "host" => {
                // Flush the previous block before starting a new one.
                if let Some(b) = current.take() {
                    blocks.push(b);
                }
                current = Some(Block {
                    aliases: value.split_whitespace().map(str::to_owned).collect(),
                    host_name: None,
                });
            }
            "hostname" => {
                if let Some(b) = current.as_mut() {
                    // First wins, matching OpenSSH's "first obtained value".
                    if b.host_name.is_none() {
                        let first = value.split_whitespace().next().unwrap_or("");
                        if !first.is_empty() {
                            b.host_name = Some(first.to_string());
                        }
                    }
                } else {
                    warnings.push(format!(
                        "line {n}: HostName outside any Host block — ignored"
                    ));
                }
            }
            "include" => {
                includes_seen += 1;
            }
            "match" => {
                matches_seen += 1;
                // A Match block is a new context; commit anything open
                // and stop collecting directives until the next Host.
                if let Some(b) = current.take() {
                    blocks.push(b);
                }
            }
            _ => {
                // Any other directive — User, Port, IdentityFile, etc.
                // Ignored by design (see module doc).
            }
        }
    }
    if let Some(b) = current.take() {
        blocks.push(b);
    }

    if includes_seen > 0 {
        warnings.push(format!(
            "ssh config contains {includes_seen} Include directive(s); \
             not followed in this version — hosts from included files are \
             NOT scanned"
        ));
    }
    if matches_seen > 0 {
        warnings.push(format!(
            "ssh config contains {matches_seen} Match block(s); not evaluated \
             — hosts conditional on connection context are NOT scanned"
        ));
    }

    let mut hosts: Vec<String> = Vec::new();
    let mut skipped_pattern_blocks = 0usize;
    for b in blocks {
        let matched_alias = b
            .aliases
            .iter()
            .find(|a| !a.starts_with('!') && patterns.iter().any(|p| glob_match(p, a)));

        let Some(alias) = matched_alias else {
            // Not our block — no warning, no output.
            continue;
        };

        if let Some(h) = b.host_name {
            hosts.push(h);
            continue;
        }

        // No HostName. Use the alias if it is a literal.
        if !alias.contains('*') && !alias.contains('?') {
            hosts.push(alias.clone());
            continue;
        }

        // Alias is a pattern (`*`, `web-*`) and there is no HostName. Nothing
        // useful to scan; the operator selected this block and would
        // otherwise see a silent no-op.
        skipped_pattern_blocks += 1;
    }
    if skipped_pattern_blocks > 0 {
        warnings.push(format!(
            "{skipped_pattern_blocks} Host block(s) matched the pattern but \
             had no HostName and a glob alias (`Host *`, `Host web-*`) — \
             nothing to scan"
        ));
    }

    // Deduplicate while preserving order: the same HostName can legitimately
    // appear in two blocks with different aliases.
    let mut seen = std::collections::HashSet::new();
    hosts.retain(|h| seen.insert(h.clone()));

    (hosts, warnings)
}

/// Split `Host foo` and `Host=foo` into `("Host", "foo")`.
fn split_kv(line: &str) -> (&str, &str) {
    let line = line.trim_start();
    if let Some(eq) = line.find('=') {
        let (k, v) = line.split_at(eq);
        // `=` is not part of either side.
        (k.trim_end(), &v[1..])
    } else {
        match line.find(char::is_whitespace) {
            Some(i) => (&line[..i], &line[i..]),
            None => (line, ""),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pats(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn extracts_hostname_from_simple_alias() {
        let cfg = "\
Host web-01
    HostName 192.0.2.11
Host web-02
    HostName 192.0.2.12
Host db-01
    HostName 192.0.2.21
";
        let (hosts, warnings) = extract_hosts(cfg, &pats(&["web-*"]));
        assert_eq!(hosts, vec!["192.0.2.11", "192.0.2.12"]);
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn falls_back_to_alias_when_no_hostname() {
        let cfg = "\
Host web-01
    User deploy
";
        let (hosts, _) = extract_hosts(cfg, &pats(&["web-*"]));
        assert_eq!(hosts, vec!["web-01"]);
    }

    #[test]
    fn skips_glob_aliases_without_hostname() {
        // `Host web-*` without HostName — the "host name" would be `web-*`,
        // which SSH would try to resolve literally. Nothing to contribute.
        let cfg = "\
Host web-*
    User deploy
Host db-*
    User dba
";
        let (hosts, warnings) = extract_hosts(cfg, &pats(&["*"]));
        assert!(hosts.is_empty(), "{hosts:?}");
        assert!(
            warnings.iter().any(|w| w.contains("no HostName")),
            "expected a no-HostName warning, got {warnings:?}"
        );
    }

    #[test]
    fn skips_host_star_block() {
        let cfg = "\
Host *
    ServerAliveInterval 60
Host web-01
    HostName 192.0.2.11
";
        let (hosts, warnings) = extract_hosts(cfg, &pats(&["*"]));
        assert_eq!(hosts, vec!["192.0.2.11"]);
        assert!(warnings.iter().any(|w| w.contains("no HostName")));
    }

    #[test]
    fn host_is_case_insensitive() {
        let cfg = "\
HOST web-01
    hostname 192.0.2.11
";
        let (hosts, _) = extract_hosts(cfg, &pats(&["web-*"]));
        assert_eq!(hosts, vec!["192.0.2.11"]);
    }

    #[test]
    fn host_equals_form_is_accepted() {
        let cfg = "\
Host=web-01
    HostName=192.0.2.11
";
        let (hosts, _) = extract_hosts(cfg, &pats(&["web-*"]));
        assert_eq!(hosts, vec!["192.0.2.11"]);
    }

    #[test]
    fn include_emits_warning_and_yields_nothing() {
        let cfg = "\
Include config.d/*
Host web-01
    HostName 192.0.2.11
";
        let (hosts, warnings) = extract_hosts(cfg, &pats(&["web-*"]));
        assert_eq!(hosts, vec!["192.0.2.11"]);
        assert!(warnings.iter().any(|w| w.contains("Include")));
    }

    #[test]
    fn match_emits_warning_and_flushes_block() {
        let cfg = "\
Host web-01
    HostName 192.0.2.11
Match host web-02
    User deploy
Host web-02
    HostName 192.0.2.12
";
        let (hosts, warnings) = extract_hosts(cfg, &pats(&["web-*"]));
        assert_eq!(hosts, vec!["192.0.2.11", "192.0.2.12"]);
        assert!(warnings.iter().any(|w| w.contains("Match")));
    }

    #[test]
    fn first_wins_when_hostname_is_repeated() {
        let cfg = "\
Host web-01
    HostName 192.0.2.11
    HostName 192.0.2.99
";
        let (hosts, _) = extract_hosts(cfg, &pats(&["web-*"]));
        assert_eq!(hosts, vec!["192.0.2.11"]);
    }

    #[test]
    fn deduplicates_same_hostname() {
        let cfg = "\
Host web-01 web-a
    HostName 192.0.2.11
Host web-02 web-b
    HostName 192.0.2.11
";
        let (hosts, _) = extract_hosts(cfg, &pats(&["web-*"]));
        assert_eq!(hosts, vec!["192.0.2.11"]);
    }

    #[test]
    fn multiple_patterns_are_unioned() {
        let cfg = "\
Host web-01
    HostName 192.0.2.11
Host db-01
    HostName 192.0.2.21
Host cache-01
    HostName 192.0.2.31
";
        let (hosts, _) = extract_hosts(cfg, &pats(&["web-*", "db-*"]));
        assert_eq!(hosts, vec!["192.0.2.11", "192.0.2.21"]);
    }

    #[test]
    fn comments_and_blanks_are_ignored() {
        let cfg = "\
# leading comment

Host web-01
    # inline comment
    HostName 192.0.2.11

# trailing comment
";
        let (hosts, _) = extract_hosts(cfg, &pats(&["web-*"]));
        assert_eq!(hosts, vec!["192.0.2.11"]);
    }
}
