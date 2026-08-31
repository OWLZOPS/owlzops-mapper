//! Unified sudoers parser – single source of truth for reading sudoers files,
//! handling line continuations, and providing logical entries.
//! Used by both `security.rs` (NOPASSWD detection) and `access.rs` (NOPASSWD: ALL).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::{coverage, safe_io};

/// Maximum alias expansion depth. Our own bound; sudo detects cycles instead
/// of imposing a fixed depth, so a deep acyclic chain can diverge from our
/// resolver. R27-67: reaching this limit must surface as UNKNOWN, not as a
/// negative answer that hides a passwordless grant.
const MAX_ALIAS_DEPTH: u8 = 16;

/// Yield logical (continuation-joined) lines from sudoers content.
/// Lines ending with a backslash are joined with the next line, preserving
/// a single space between them (after stripping trailing whitespace).
pub fn logical_lines(content: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut continuation = String::new();
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            if !continuation.is_empty() {
                result.push(std::mem::take(&mut continuation));
            }
            continue;
        }
        if !continuation.is_empty() {
            continuation.push(' ');
        }
        continuation.push_str(line);
        if line.ends_with('\\') {
            continuation.truncate(continuation.len() - 1);
            // R26-08: honour the documented "single space" contract. The
            // physical line usually ends with " \", and the join above adds
            // another space before the next line.
            while continuation.ends_with(' ') {
                continuation.pop();
            }
        } else {
            result.push(std::mem::take(&mut continuation));
        }
    }
    if !continuation.is_empty() {
        result.push(continuation);
    }
    result
}

/// Case‑insensitive substring check WITHOUT allocation.
fn contains_icase(hay: &str, needle_lower: &str) -> bool {
    let (h, n) = (hay.as_bytes(), needle_lower.as_bytes());
    if n.is_empty() || h.len() < n.len() {
        return false;
    }
    h.windows(n.len())
        .any(|w| w.iter().zip(n).all(|(a, b)| a.to_ascii_lowercase() == *b))
}

/// Attempt to parse an include directive from a sudoers line.
/// Returns Some((path, is_dir)) on success, None otherwise.
/// The directive must be followed by whitespace to avoid matching comments
/// like "#includes are handled below" (R19V5‑03).
fn include_target(line: &str) -> Option<(&str, bool)> {
    for (prefix, is_dir) in &[
        ("#includedir", true),
        ("@includedir", true),
        ("#include", false),
        ("@include", false),
    ] {
        if let Some(rest) = line.strip_prefix(prefix) {
            if !rest.starts_with(char::is_whitespace) {
                continue;
            }
            let path = rest.trim();
            if !path.is_empty() {
                return Some((path, *is_dir));
            }
        }
    }
    None
}

const MAX_SUDOERS_BYTES: usize = 4 * 1024 * 1024;
const MAX_INCLUDE_DEPTH: u8 = 16;
const MAX_SUDOERS_FILES: usize = 512;

/// Collected `Cmnd_Alias NAME = a, b, c` definitions.
/// Transitive by design: `Cmnd_Alias A = ALL` + `Cmnd_Alias B = A` must both
/// resolve to ALL.
#[derive(Default)]
pub struct CmndAliases(HashMap<String, Vec<String>>);

impl CmndAliases {
    /// Absorb one or more `Cmnd_Alias` definitions. sudoers(5) allows several
    /// specs in a single directive, separated by ':' (R26-23):
    ///   Cmnd_Alias SAFE = /usr/bin/id : MAINTENANCE = ALL
    pub fn absorb(&mut self, entry: &str) {
        let Some(rest) = entry.strip_prefix("Cmnd_Alias") else {
            return;
        };
        if !rest.starts_with(char::is_whitespace) {
            return;
        }

        for spec in rest.trim().split(':') {
            let Some((name, list)) = spec.split_once('=') else {
                continue;
            };
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            let members: Vec<String> = list
                .split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect();
            if !members.is_empty() {
                self.0.insert(name.to_string(), members);
            }
        }
    }

    /// Does `token` resolve — directly or through aliases — to `ALL`?
    ///
    /// `None` = the chain was cut at `MAX_ALIAS_DEPTH` and the answer is
    /// UNKNOWN. R27-67: returning `false` there made a 17-deep chain read as
    /// "not a passwordless grant", clearing SEC-005 on a host where sudo does
    /// grant it. Unknown must never masquerade as negative — the same rule the
    /// three other budgets in this module already follow.
    pub fn resolves_to_all(&self, token: &str, depth: u8) -> Option<bool> {
        if token == "ALL" {
            return Some(true);
        }
        if depth >= MAX_ALIAS_DEPTH {
            return None;
        }
        let Some(members) = self.0.get(token) else {
            return Some(false); // not an alias at all: a plain command path
        };
        let mut cut = false;
        for m in members {
            match self.resolves_to_all(m, depth + 1) {
                Some(true) => return Some(true), // one resolving branch is enough
                Some(false) => {}
                None => cut = true,
            }
        }
        if cut { None } else { Some(false) }
    }
}

/// Result of a single sudoers tree walk.
/// `each_sudoers_entry` has coverage side effects; calling it more than once
/// duplicates every warning and multiplies I/O. Callers needing both aliases
/// and entries take this instead (R26-18).
pub struct SudoersScan {
    pub aliases: CmndAliases,
    /// (source file, logical entry), in walk order.
    pub entries: Vec<(String, String)>,
}

/// Walk the sudoers tree exactly once and return both aliases and entries.
pub fn scan_sudoers() -> SudoersScan {
    let mut aliases = CmndAliases::default();
    let mut entries = Vec::new();
    each_sudoers_entry(|file, entry| {
        aliases.absorb(entry);
        entries.push((file.to_string(), entry.to_string()));
    });
    SudoersScan { aliases, entries }
}

/// Walk the given sudoers roots exactly once and return both aliases and entries.
///
/// Used by tests and intended for future non-/etc roots; production currently
/// goes through `scan_sudoers`.
#[allow(dead_code)]
pub fn scan_sudoers_from(roots: &[String]) -> SudoersScan {
    let mut aliases = CmndAliases::default();
    let mut entries = Vec::new();
    each_sudoers_entry_from(roots, |file, entry| {
        aliases.absorb(entry);
        entries.push((file.to_string(), entry.to_string()));
    });
    SudoersScan { aliases, entries }
}

/// Apply a Tag_Spec. Returns true if `tok` WAS a tag (so the caller must not
/// treat it as a command). Only NOPASSWD/PASSWD change the password state;
/// the rest are consumed so they cannot be mistaken for a command name.
fn apply_tag(tok: &str, nopasswd: &mut bool) -> bool {
    if tok.eq_ignore_ascii_case("NOPASSWD") {
        *nopasswd = true;
        return true;
    }
    if tok.eq_ignore_ascii_case("PASSWD") {
        *nopasswd = false;
        return true;
    }
    const OTHER: [&str; 14] = [
        "NOEXEC",
        "EXEC",
        "SETENV",
        "NOSETENV",
        "LOG_INPUT",
        "NOLOG_INPUT",
        "LOG_OUTPUT",
        "NOLOG_OUTPUT",
        "FOLLOW",
        "NOFOLLOW",
        "MAIL",
        "NOMAIL",
        "INTERCEPT",
        "NOINTERCEPT",
    ];
    OTHER.iter().any(|t| tok.eq_ignore_ascii_case(t))
}

/// True if the entry grants a passwordless ALL, directly or via `Cmnd_Alias`.
///
/// R26-27: tags are transitive across the Cmnd_Spec_List, so the grant may sit
/// anywhere in it — `NOPASSWD: ALL, PASSWD: /bin/false` is full passwordless
/// root. Looking only after the LAST colon missed exactly that shape.
pub fn is_nopasswd_all(entry: &str, aliases: &CmndAliases) -> bool {
    if !entry_has_nopasswd(entry) {
        return false;
    }

    // User_List Host_List '=' Cmnd_Spec_List — commands live after the first '='.
    let Some((_, rhs)) = entry.split_once('=') else {
        return false;
    };

    let mut nopasswd = false;
    let mut paren = 0i32;

    for raw in rhs.split([',', ' ', '\t']) {
        let tok = raw.trim();
        if tok.is_empty() {
            continue;
        }

        // A parenthesised Runas_Spec may hold commas and colons: `(ALL:ALL)`.
        let opens = tok.matches('(').count() as i32;
        let closes = tok.matches(')').count() as i32;
        let was_inside = paren > 0;
        paren = (paren + opens - closes).max(0);
        if was_inside || opens > 0 {
            continue;
        }

        // A tag may be glued to the command: "NOPASSWD:ALL".
        let mut rest = tok;
        while let Some(i) = rest.find(':') {
            apply_tag(rest[..i].trim(), &mut nopasswd);
            rest = rest[i + 1..].trim_start();
        }
        if rest.is_empty() {
            continue;
        }
        // "NOPASSWD : ALL" — the tag arrives as a standalone token.
        if apply_tag(rest, &mut nopasswd) {
            continue;
        }
        // A negation removes a command; it never grants one.
        if rest.starts_with('!') {
            continue;
        }
        if nopasswd {
            match aliases.resolves_to_all(rest, 0) {
                Some(true) => return true,
                Some(false) => {}
                None => coverage::record(format!(
                    "sudoers: alias chain from '{rest}' exceeds {MAX_ALIAS_DEPTH} levels — \
                     cannot determine whether it grants NOPASSWD: ALL; SEC-005 audit \
                     INCOMPLETE for this entry"
                )),
            }
        }
    }
    false
}

/// Canonical key for the visited set – always an absolute, cleaned path.
fn canon_path_key(path: &str) -> String {
    Path::new(path)
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(path))
        .to_string_lossy()
        .to_string()
}

/// Walk the given sudoers roots.
/// Production uses `each_sudoers_entry`; this parameterised form exists so the
/// walk and cross-file alias resolution are testable against a tempdir instead
/// of the real /etc (R26-24).
pub fn each_sudoers_entry_from<F>(roots: &[String], mut callback: F)
where
    F: FnMut(&str, &str),
{
    let mut queue: Vec<(String, u8)> = roots.iter().map(|r| (r.clone(), 0)).collect();
    let mut visited: HashSet<String> = HashSet::new();
    let mut files_seen = 0usize;

    while let Some((file, depth)) = queue.pop() {
        if files_seen >= MAX_SUDOERS_FILES {
            coverage::record(format!(
                "sudoers: file budget {MAX_SUDOERS_FILES} exhausted — NOPASSWD audit INCOMPLETE"
            ));
            break;
        }
        if depth > MAX_INCLUDE_DEPTH {
            coverage::record(format!(
                "sudoers: include depth limit at {file} — subtree skipped"
            ));
            continue;
        }

        let key = canon_path_key(&file);
        if !visited.insert(key) {
            continue;
        }
        files_seen += 1;

        let path = Path::new(&file);
        if path.is_dir() {
            if let Ok(entries) = fs::read_dir(&file) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    // R19‑13: sudo ignores files containing a dot or ending with ~.
                    // This includes `.conf` files – they must be excluded.
                    let ignored = name.contains('.') || name.ends_with('~');
                    if ignored {
                        continue;
                    }
                    if entry.path().is_file() && !name.starts_with('.') && name != "README" {
                        queue.push((entry.path().to_string_lossy().to_string(), depth + 1));
                    }
                }
            }
            continue;
        }

        // R26-02: sudoers files are host-controlled — a FIFO here would block
        // open(2) forever and hang the whole scan.
        match safe_io::read_file_capped_regular(&file, MAX_SUDOERS_BYTES) {
            Ok((content, truncated)) => {
                if truncated {
                    coverage::record(format!(
                        "sudoers: {file} truncated — NOPASSWD audit partial"
                    ));
                }

                // Process include directives, resolving relative paths against the
                // parent directory of the including file (R19V‑09).
                let parent = Path::new(&file).parent().map(Path::to_path_buf);
                for raw in content.lines() {
                    let line = raw.trim();
                    if let Some((target, is_dir)) = include_target(line) {
                        let resolved = if target.starts_with('/') {
                            target.to_string()
                        } else if let Some(ref p) = parent {
                            p.join(target).to_string_lossy().to_string()
                        } else {
                            target.to_string()
                        };
                        if is_dir {
                            if let Ok(entries) = fs::read_dir(&resolved) {
                                for entry in entries.flatten() {
                                    let name = entry.file_name();
                                    let name = name.to_string_lossy();
                                    // R19‑13: same filter for included directories.
                                    let ignored = name.contains('.') || name.ends_with('~');
                                    if ignored {
                                        continue;
                                    }
                                    if entry.path().is_file()
                                        && !name.starts_with('.')
                                        && name != "README"
                                    {
                                        queue.push((
                                            entry.path().to_string_lossy().to_string(),
                                            depth + 1,
                                        ));
                                    }
                                }
                            }
                        } else {
                            queue.push((resolved, depth + 1));
                        }
                    }
                }

                for entry in logical_lines(&content) {
                    callback(&file, &entry);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if depth == 0 {
                    coverage::record(format!(
                        "sudoers: {file} does not exist — sudo is likely not installed"
                    ));
                } else {
                    coverage::record(format!(
                        "sudoers: {file} referenced by an include directive but does not exist \
                         (config defect, not a coverage gap)"
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                coverage::record(format!(
                    "sudoers: {file} is NOT a regular file (fifo/device) — \
                     parse refused; treat as tampering. NOPASSWD audit INCOMPLETE"
                ));
            }
            Err(e) => {
                coverage::record(format!(
                    "sudoers: {file} unreadable ({}) — NOPASSWD audit INCOMPLETE for this file",
                    e.kind()
                ));
            }
        }
    }
}

/// Walk all sudoers files (including those referenced via #include/@include)
/// and call the callback for each logical line.
pub fn each_sudoers_entry<F>(callback: F)
where
    F: FnMut(&str, &str),
{
    each_sudoers_entry_from(
        &["/etc/sudoers".to_string(), "/etc/sudoers.d".to_string()],
        callback,
    );
}

/// Check if the given entry contains a NOPASSWD tag.
/// Case‑insensitive, matches any occurrence of the substring "nopasswd"
/// (with or without a following colon/space), mirroring the original behaviour.
pub fn entry_has_nopasswd(entry: &str) -> bool {
    contains_icase(entry, "nopasswd")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_lines_joins_continuations() {
        let input = "user ALL=(ALL) NOPASSWD: \\\n  /bin/foo, /bin/bar";
        let lines = logical_lines(input);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("/bin/foo") && lines[0].contains("/bin/bar"));
        assert!(!lines[0].contains('\\'));
    }

    #[test]
    fn logical_lines_handles_comments_and_blanks() {
        let input = "# comment\n\nroot ALL=(ALL) ALL\n";
        let lines = logical_lines(input);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "root ALL=(ALL) ALL");
    }

    #[test]
    fn continuation_join_never_doubles_whitespace() {
        let lines = logical_lines("deploy ALL=(ALL) NOPASSWD: \\\nALL\n");
        assert_eq!(lines, vec!["deploy ALL=(ALL) NOPASSWD: ALL".to_string()]);
        assert!(lines[0].to_lowercase().contains("nopasswd: all"));
    }

    #[test]
    fn contains_icase_case_insensitive() {
        assert!(contains_icase("NOPASSWD: ALL", "nopasswd:"));
        assert!(contains_icase("Nopasswd: all", "nopasswd:"));
        assert!(!contains_icase("PASSWD: ALL", "nopasswd:"));
        assert!(!contains_icase("nopassw", "nopasswd:"));
    }

    #[test]
    fn entry_has_nopasswd_detects_variants() {
        assert!(entry_has_nopasswd("user ALL=(ALL) NOPASSWD: /bin/foo"));
        assert!(entry_has_nopasswd("user ALL=(ALL) NOPASSWD : /bin/foo"));
        assert!(entry_has_nopasswd("user ALL=(ALL) NOPASSWD  : /bin/foo"));
        assert!(!entry_has_nopasswd("user ALL=(ALL) PASSWD: ALL"));
    }

    #[test]
    fn cmnd_alias_indirection_is_still_nopasswd_all() {
        let mut a = CmndAliases::default();
        a.absorb("Cmnd_Alias MAINTENANCE = ALL");
        a.absorb("Cmnd_Alias WRAPPER = MAINTENANCE");
        assert_eq!(
            a.resolves_to_all("WRAPPER", 0),
            Some(true),
            "transitive alias must resolve"
        );
        assert_eq!(a.resolves_to_all("/usr/bin/systemctl", 0), Some(false));
    }

    #[test]
    fn absorb_handles_multiple_specs_on_one_line() {
        let mut a = CmndAliases::default();
        a.absorb("Cmnd_Alias SAFE = /usr/bin/id, /usr/bin/uptime : MAINTENANCE = ALL");

        assert_eq!(
            a.resolves_to_all("MAINTENANCE", 0),
            Some(true),
            "second spec must register"
        );
        assert_eq!(a.resolves_to_all("SAFE", 0), Some(false));
    }

    #[test]
    fn alias_in_one_file_resolves_a_rule_in_another() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("sudoers.d");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("10-aliases"), "Cmnd_Alias MAINTENANCE = ALL\n").unwrap();
        std::fs::write(
            d.join("20-deploy"),
            "deploy ALL=(ALL) NOPASSWD: MAINTENANCE\n",
        )
        .unwrap();

        let roots = vec![d.to_string_lossy().to_string()];
        let scan = scan_sudoers_from(&roots);
        let hit = scan
            .entries
            .iter()
            .any(|(_, e)| is_nopasswd_all(e, &scan.aliases));
        assert!(hit, "an alias defined in another file must still resolve");
    }

    #[test]
    fn each_file_is_read_exactly_once_per_scan() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("sudoers.d");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("10-one"), "a ALL=(ALL) NOPASSWD: ALL\n").unwrap();
        std::fs::write(d.join("20-two"), "b ALL=(ALL) NOPASSWD: ALL\n").unwrap();

        let roots = vec![d.to_string_lossy().to_string()];
        let mut per_file: std::collections::HashMap<String, usize> = Default::default();
        each_sudoers_entry_from(&roots, |file, _| {
            *per_file.entry(file.to_string()).or_default() += 1;
        });

        assert_eq!(per_file.len(), 2);
        assert!(
            per_file.values().all(|&n| n == 1),
            "duplicate walk: {per_file:?}"
        );
    }

    #[test]
    fn nopasswd_all_is_found_when_a_later_spec_re_tags() {
        let a = CmndAliases::default();
        assert!(is_nopasswd_all(
            "deploy ALL=(ALL) NOPASSWD: ALL, PASSWD: /bin/false",
            &a
        ));
        assert!(is_nopasswd_all(
            "deploy ALL=(ALL) NOPASSWD: ALL, NOEXEC: /bin/foo",
            &a
        ));
    }

    #[test]
    fn passwd_tagged_all_is_not_a_passwordless_grant() {
        let a = CmndAliases::default();
        assert!(!is_nopasswd_all("deploy ALL=(ALL) PASSWD: ALL", &a));
        assert!(!is_nopasswd_all(
            "deploy ALL=(ALL) NOPASSWD: /usr/bin/id, PASSWD: ALL",
            &a
        ));
    }

    #[test]
    fn runas_spec_with_a_colon_is_not_parsed_as_a_tag() {
        let a = CmndAliases::default();
        assert!(is_nopasswd_all("deploy ALL=(ALL:ALL) NOPASSWD: ALL", &a));
    }

    #[test]
    fn spaced_and_glued_tag_forms_both_resolve() {
        let a = CmndAliases::default();
        assert!(is_nopasswd_all("deploy ALL=(ALL) NOPASSWD:ALL", &a));
        assert!(is_nopasswd_all("deploy ALL=(ALL) NOPASSWD : ALL", &a));
        assert!(!is_nopasswd_all("deploy ALL=(ALL) NOPASSWD : /bin/foo", &a));
    }

    #[test]
    fn an_over_deep_alias_chain_is_unknown_not_negative() {
        // A0→A1→…→A16 = ALL, 17 links. sudo resolves it; we must not answer "false".
        let mut a = CmndAliases::default();
        let names: Vec<String> = (0..17).map(|i| format!("A{i}")).collect();
        for w in names.windows(2) {
            a.absorb(&format!("Cmnd_Alias {} = {}", w[0], w[1]));
        }
        a.absorb(&format!("Cmnd_Alias {} = ALL", names[16]));

        assert_eq!(
            a.resolves_to_all(&names[0], 0),
            None,
            "cut chain must be UNKNOWN, never a negative answer"
        );
        // Within the limit it still resolves.
        assert_eq!(a.resolves_to_all(&names[2], 0), Some(true));
    }

    #[test]
    fn a_plain_command_is_a_real_negative_not_unknown() {
        let a = CmndAliases::default();
        assert_eq!(a.resolves_to_all("/usr/bin/systemctl", 0), Some(false));
    }

    #[test]
    fn a_cycle_terminates_as_unknown() {
        let mut a = CmndAliases::default();
        a.absorb("Cmnd_Alias A = B");
        a.absorb("Cmnd_Alias B = A");
        assert_eq!(
            a.resolves_to_all("A", 0),
            None,
            "must terminate, not recurse"
        );
    }

    #[test]
    fn one_resolving_branch_wins_over_a_cut_sibling() {
        let mut a = CmndAliases::default();
        a.absorb("Cmnd_Alias X = DEEP, ALL");
        assert_eq!(a.resolves_to_all("X", 0), Some(true));
    }
}
