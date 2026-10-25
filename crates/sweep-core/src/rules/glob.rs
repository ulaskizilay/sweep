//! Glob patterns for `exclude` and `file-pattern`.
//!
//! Deliberately small: `*`, `?` and `**`, and nothing else. No character
//! classes, no braces, no dependency. A rule file is data a human reviews, and
//! a pattern language whose corner cases nobody can predict is worse than a
//! limited one that behaves the same way twice.
//!
//! Semantics, matching what a shell user already expects:
//!
//! * `*` matches any run of bytes except `/`.
//! * `?` matches one byte except `/`.
//! * `**` matches any run of bytes including `/`.
//! * `**/` also matches zero segments, so `a/**/b` matches `a/b`.
//! * A trailing `/**` also matches the directory itself, so `logs/**` excludes
//!   `logs` as well as everything under it.
//!
//! Matching is on bytes, so a non-UTF-8 file name can still be excluded.

use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternError {
    Empty,
    Absolute(String),
    ControlByte,
    TrailingSlash(String),
}

impl std::fmt::Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatternError::Empty => f.write_str("pattern is empty"),
            PatternError::Absolute(pattern) => {
                write!(f, "pattern {pattern:?} must be relative to the rule root")
            }
            PatternError::ControlByte => f.write_str("pattern contains a control byte"),
            PatternError::TrailingSlash(pattern) => {
                write!(f, "pattern {pattern:?} ends with a separator")
            }
        }
    }
}

impl std::error::Error for PatternError {}

/// A compiled pattern, anchored either to a base name or to a relative path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    source: String,
    /// True when the pattern contains `/` and therefore addresses a path
    /// relative to the rule root rather than a single file name.
    anchored: bool,
    /// For a `dir/**` pattern, the directory part, which the pattern also
    /// matches on its own.
    directory: Option<String>,
}

impl Pattern {
    pub fn new(source: &str) -> Result<Self, PatternError> {
        if source.is_empty() {
            return Err(PatternError::Empty);
        }
        if source.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
            return Err(PatternError::ControlByte);
        }
        if source.starts_with('/') {
            return Err(PatternError::Absolute(source.to_string()));
        }
        if source.ends_with('/') {
            return Err(PatternError::TrailingSlash(source.to_string()));
        }
        let directory = source
            .strip_suffix("/**")
            .filter(|prefix| !prefix.is_empty())
            .map(|prefix| prefix.to_string());
        Ok(Self {
            source: source.to_string(),
            anchored: source.contains('/'),
            directory,
        })
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    /// True when the pattern names at least one byte that is not a wildcard or a
    /// separator.
    ///
    /// Used to refuse `pattern = "*"` behind a home-directory root: a pattern
    /// with no literal text is not a target, it is "everything".
    pub fn has_literal(&self) -> bool {
        self.source
            .bytes()
            .any(|byte| byte != b'*' && byte != b'?' && byte != b'/')
    }

    /// True when `relative`, a path below the rule root, is covered.
    ///
    /// A pattern without `/` is compared with the base name, so `*.log` covers
    /// a matching file at any depth. A pattern with `/` is compared with the
    /// whole relative path, so `logs/*.log` covers only one level.
    pub fn matches_relative(&self, relative: &Path) -> bool {
        if let Some(directory) = &self.directory {
            if relative == Path::new(directory) {
                return true;
            }
        }
        let relative_bytes = relative.as_os_str().as_encoded_bytes();
        if self.anchored {
            return matches(&self.source, relative_bytes);
        }
        let name = relative
            .file_name()
            .map(|name| name.as_encoded_bytes())
            .unwrap_or(relative_bytes);
        matches(&self.source, name)
    }
}

/// Byte-level glob match. See the module documentation for the syntax.
pub fn matches(pattern: &str, text: &[u8]) -> bool {
    let mut dead = HashSet::new();
    go(pattern.as_bytes(), 0, text, 0, &mut dead)
}

/// Recursive matcher with failure memoisation.
///
/// Every branch either advances the pattern index or the text index, so there
/// are no cycles; remembering the states that failed turns the pathological
/// `a*a*a*a*` case from exponential into `O(pattern * text)`.
fn go(
    pattern: &[u8],
    pi: usize,
    text: &[u8],
    ti: usize,
    dead: &mut HashSet<(usize, usize)>,
) -> bool {
    if dead.contains(&(pi, ti)) {
        return false;
    }

    let found = if pi == pattern.len() {
        ti == text.len()
    } else {
        match pattern[pi] {
            b'*' if pattern.get(pi + 1) == Some(&b'*') => {
                let mut rest = pi + 2;
                // `**/` matches zero segments too, so `a/**/b` covers `a/b`.
                if pattern.get(rest) == Some(&b'/') {
                    if go(pattern, rest + 1, text, ti, dead) {
                        return true;
                    }
                    rest += 1;
                }
                (ti..=text.len()).any(|skip| go(pattern, rest, text, skip, dead))
            }
            b'*' => {
                let mut cursor = ti;
                loop {
                    if go(pattern, pi + 1, text, cursor, dead) {
                        return true;
                    }
                    if cursor >= text.len() || text[cursor] == b'/' {
                        break;
                    }
                    cursor += 1;
                }
                false
            }
            b'?' => ti < text.len() && text[ti] != b'/' && go(pattern, pi + 1, text, ti + 1, dead),
            byte => ti < text.len() && text[ti] == byte && go(pattern, pi + 1, text, ti + 1, dead),
        }
    };

    if !found {
        dead.insert((pi, ti));
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn check(pattern: &str, text: &str) -> bool {
        matches(pattern, text.as_bytes())
    }

    #[test]
    fn literals_must_match_exactly() {
        assert!(check("cache", "cache"));
        assert!(!check("cache", "cache2"));
        assert!(!check("cache", "Cache"));
    }

    #[test]
    fn star_does_not_cross_a_separator() {
        assert!(check("*.log", "app.log"));
        assert!(!check("*.log", "logs/app.log"));
        assert!(check("a/*/c", "a/b/c"));
        assert!(!check("a/*/c", "a/b/d/c"));
    }

    #[test]
    fn double_star_crosses_separators() {
        assert!(check("a/**/c", "a/c"));
        assert!(check("a/**/c", "a/b/c"));
        assert!(check("a/**/c", "a/b/d/c"));
        assert!(check("**/*.log", "app.log"));
        assert!(check("**/*.log", "deep/nested/app.log"));
        assert!(!check("**/*.log", "deep/app.txt"));
    }

    #[test]
    fn question_mark_is_one_non_separator_byte() {
        assert!(check("a?c", "abc"));
        assert!(!check("a?c", "ac"));
        assert!(!check("a?c", "a/c"));
    }

    #[test]
    fn pathological_patterns_stay_fast() {
        // Failure memoisation is the only thing keeping this from taking
        // exponential time; without it the test suite hangs rather than fails.
        let pattern = "a*a*a*a*a*a*a*a*a*a*a*a*b";
        let text = "a".repeat(400);
        assert!(!check(pattern, &text));
    }

    #[test]
    fn directory_pattern_covers_the_directory_itself() {
        let pattern = Pattern::new("logs/**").unwrap();
        assert!(pattern.matches_relative(Path::new("logs")));
        assert!(pattern.matches_relative(Path::new("logs/app.log")));
        assert!(!pattern.matches_relative(Path::new("logs2/app.log")));
    }

    #[test]
    fn unanchored_patterns_match_a_base_name_at_any_depth() {
        let pattern = Pattern::new("*.crate.part").unwrap();
        assert!(pattern.matches_relative(Path::new("x.crate.part")));
        assert!(pattern.matches_relative(Path::new("a/b/x.crate.part")));
        assert!(!pattern.matches_relative(Path::new("a/x.crate")));
    }

    #[test]
    fn anchored_patterns_match_the_relative_path() {
        let pattern = Pattern::new("Cache/*.bin").unwrap();
        assert!(pattern.matches_relative(Path::new("Cache/x.bin")));
        assert!(!pattern.matches_relative(Path::new("Other/Cache/x.bin")));
    }

    #[test]
    fn absolute_and_empty_patterns_are_refused() {
        assert_eq!(Pattern::new(""), Err(PatternError::Empty));
        assert!(matches!(
            Pattern::new("/etc/**"),
            Err(PatternError::Absolute(_))
        ));
        assert!(matches!(
            Pattern::new("logs/"),
            Err(PatternError::TrailingSlash(_))
        ));
        let with_control = format!("a{}b", char::from(0x7f));
        assert_eq!(Pattern::new(&with_control), Err(PatternError::ControlByte));
    }

    #[test]
    fn non_utf8_names_can_still_be_matched() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let name = OsString::from_vec(vec![b'x', 0xff, b'.', b'l', b'o', b'g']);
        let pattern = Pattern::new("*.log").unwrap();
        assert!(pattern.matches_relative(&PathBuf::from(name)));
    }
}
