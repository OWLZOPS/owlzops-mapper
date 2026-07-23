//! Unified sudoers parser – single source of truth for reading sudoers files,
//! handling line continuations, and providing logical entries.
//! Used by both `security.rs` (NOPASSWD detection) and `access.rs` (NOPASSWD: ALL).

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::{coverage, safe_io};

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

/// Canonical key for the visited set – always an absolute, cleaned path.
fn canon_path_key(path: &str) -> String {
    Path::new(path)
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(path))
        .to_string_lossy()
        .to_string()
}

/// Walk all sudoers files (including those referenced via #include/@include)
/// and call the callback for each logical line.
pub fn each_sudoers_entry<F>(mut callback: F)
where
    F: FnMut(&str, &str),
{
    let mut queue: Vec<(String, u8)> = vec![
        ("/etc/sudoers".to_string(), 0),
        ("/etc/sudoers.d".to_string(), 0),
    ];
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
                        queue.push((entry.path().to_string_lossy().to_string(), depth + 1));
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
                coverage::record(format!(
                    "sudoers: {file} referenced by an include directive but does not exist \
                     (config defect, not a coverage gap)"
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
