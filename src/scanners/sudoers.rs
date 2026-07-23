//! Unified sudoers parser – single source of truth for reading sudoers files,
//! handling line continuations, and providing logical entries.
//! Used by both `security.rs` (NOPASSWD detection) and `access.rs` (NOPASSWD: ALL).

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::{coverage, safe_io};

/// Yield logical (continuation-joined) lines from sudoers content.
/// Lines ending with a backslash are joined with the next line, preserving
/// a single space between them (after stripping trailing whitespace).
pub fn logical_lines(content: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut continuation = String::new();
    for raw in content.lines() {
        let line = raw.trim();
        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            if !continuation.is_empty() {
                result.push(std::mem::take(&mut continuation));
            }
            continue;
        }
        // Join with previous continuation
        if !continuation.is_empty() {
            continuation.push(' ');
        }
        continuation.push_str(line);
        if line.ends_with('\\') {
            // Remove trailing backslash, continue accumulating
            continuation.truncate(continuation.len() - 1);
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
fn include_target(line: &str) -> Option<(&str, bool)> {
    for (prefix, is_dir) in &[
        ("#includedir", true),
        ("@includedir", true),
        ("#include", false),
        ("@include", false),
    ] {
        if let Some(rest) = line.strip_prefix(prefix) {
            let path = rest.trim();
            if !path.is_empty() {
                return Some((path, *is_dir));
            }
        }
    }
    None
}

const MAX_SUDOERS_BYTES: usize = 4 * 1024 * 1024;

/// Walk all sudoers files (including those referenced via #include/@include)
/// and call the callback for each logical line.
pub fn each_sudoers_entry<F>(mut callback: F)
where
    F: FnMut(&str, &str),
{
    let mut queue: Vec<String> = vec!["/etc/sudoers".to_string(), "/etc/sudoers.d".to_string()];
    let mut visited: HashSet<String> = HashSet::new();
    let mut depth_budget = 32usize;

    while let Some(file) = queue.pop() {
        if depth_budget == 0 {
            crate::coverage::record(
                "sudoers: include depth limit reached — NOPASSWD audit INCOMPLETE",
            );
            break;
        }
        if !visited.insert(file.clone()) {
            continue;
        }
        depth_budget -= 1;

        let path = Path::new(&file);
        if path.is_dir() {
            if let Ok(entries) = fs::read_dir(&file) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    // Ignore files containing '.' or ending with '~' (backups, editors),
                    // unless the extension is explicitly ".conf" (some distros use this).
                    let has_disallowed_char = name.contains('.') || name.ends_with('~');
                    let is_conf = entry
                        .path()
                        .extension()
                        .map(|x| x == "conf")
                        .unwrap_or(false);
                    if has_disallowed_char && !is_conf {
                        continue;
                    }
                    if entry.path().is_file() && !name.starts_with('.') && name != "README" {
                        queue.push(entry.path().to_string_lossy().to_string());
                    }
                }
            }
            continue;
        }

        match safe_io::read_file_capped(&file, MAX_SUDOERS_BYTES) {
            Ok((content, truncated)) => {
                if truncated {
                    coverage::record(format!(
                        "sudoers: {file} truncated — NOPASSWD audit partial"
                    ));
                }

                // Process include directives before parsing entries, so that
                // included files are added to the queue for scanning.
                for raw in content.lines() {
                    let line = raw.trim();
                    if let Some((target, is_dir)) = include_target(line) {
                        if is_dir {
                            if let Ok(entries) = fs::read_dir(target) {
                                for entry in entries.flatten() {
                                    let name = entry.file_name();
                                    let name = name.to_string_lossy();
                                    let has_disallowed_char =
                                        name.contains('.') || name.ends_with('~');
                                    let is_conf = entry
                                        .path()
                                        .extension()
                                        .map(|x| x == "conf")
                                        .unwrap_or(false);
                                    if has_disallowed_char && !is_conf {
                                        continue;
                                    }
                                    if entry.path().is_file()
                                        && !name.starts_with('.')
                                        && name != "README"
                                    {
                                        queue.push(format!("{}/{}", target, name));
                                    }
                                }
                            }
                        } else {
                            queue.push(target.to_string());
                        }
                    }
                }

                for entry in logical_lines(&content) {
                    callback(&file, &entry);
                }
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
}
