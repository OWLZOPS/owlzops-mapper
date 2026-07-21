//! Unified sudoers parser – single source of truth for reading sudoers files,
//! handling line continuations, and providing logical entries.
//! Used by both `security.rs` (NOPASSWD detection) and `access.rs` (NOPASSWD: ALL).

use std::fs;
use std::path::Path;

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

/// Callback for each logical entry found in sudoers files.
/// `path` is the source file, `entry` is the logical (joined) line.
pub fn each_sudoers_entry<F>(mut callback: F)
where
    F: FnMut(&str, &str),
{
    let sudoers_dir = Path::new("/etc/sudoers.d");
    let mut files = vec!["/etc/sudoers".to_string()];
    if sudoers_dir.is_dir()
        && let Ok(entries) = fs::read_dir(sudoers_dir)
    {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_file()
                && p.extension()
                    .map(|x| x == "sudoers" || x == "conf")
                    .unwrap_or(false)
                && !p
                    .file_name()
                    .map(|n| n == ".gitkeep" || n == "README")
                    .unwrap_or(false)
            {
                files.push(p.to_string_lossy().to_string());
            }
        }
    }

    for file in &files {
        if let Ok(content) = fs::read_to_string(file) {
            for entry in logical_lines(&content) {
                callback(file, &entry);
            }
        }
    }
}

/// Check if the given entry contains a NOPASSWD tag.
/// Designed to be fast and allocation‑free.
pub fn entry_has_nopasswd(entry: &str) -> bool {
    contains_icase(entry, "nopasswd:")
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
}
