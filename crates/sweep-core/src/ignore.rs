//! `~/.config/sweep/ignore`: the paths the user asked sweep to leave alone.
//!
//! A rule's `exclude` is the catalog author saying "not this one, it is not what
//! the rule is for". This file is the *user* saying "not this one, I am using
//! it". They are different decisions with different owners, so they live in
//! different places: the catalog ships with sweep and is replaced on upgrade,
//! and anything a user edits there is lost on the next release.
//!
//! ## The file
//!
//! One pattern per line. Blank lines and lines whose first non-space byte is
//! `#` are ignored. Leading and trailing whitespace is trimmed, because a
//! trailing space is invisible in every editor and would silently change what
//! the line means.
//!
//! | Line | Protects |
//! |---|---|
//! | `~/work` | `~/work` and everything below it |
//! | `/srv/data` | the same, written absolutely |
//! | `*.iso` | every file or directory named `*.iso`, at any depth below `$HOME` |
//! | `.cache/big-project/**` | the directory itself and everything below |
//!
//! The glob language is the one the rule files already use ([`crate::rules::glob`]):
//! `*`, `?`, `**`, and nothing else. A second dialect in the same product would
//! be a second set of corner cases to remember.
//!
//! A pattern with no `/` matches a single name at any depth, which is why
//! `*.iso` is useful. A pattern with `/` is anchored to its base: `$HOME` for a
//! bare line or one that starts with `~/`, `/` for one that starts with `/`.
//! The `~/` form is anchored even when only one component follows it, so
//! `~/work` is that directory and not every `work` at any depth.
//!
//! ## Protection covers the subtree
//!
//! A path is protected when it, **or any of its ancestors**, matches a pattern.
//! Without that, `~/work` would protect the directory and nothing inside it,
//! which is never what the line means.
//!
//! ## What it does not do
//!
//! There is no negation. A file that only protects paths cannot un-protect one,
//! and a rule language with `!` needs an ordering rule to answer "which line
//! wins". Deleting the line is the way to stop protecting a path, and that is
//! also the only version a reader can verify by looking at the file.
//!
//! The file applies to the commands that sweep a catalog on their own: `clean`,
//! `purge`, `installer` and `aur`. `analyze` and `uninstall` act on a path or a
//! package the user named in the same breath, and refusing those would be
//! refusing an instruction the user just gave.

use std::io;
use std::path::{Path, PathBuf};

use crate::rules::glob;
use crate::Xdg;

/// Where a pattern is anchored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Base {
    /// A bare line or one starting with `~/`: relative to `$HOME`.
    Home,
    /// A line starting with `/`: relative to `/`.
    Root,
}

/// One compiled line.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    /// Exactly as written, so a report can quote the line the user will edit.
    source: String,
    /// The pattern with its base prefix removed.
    pattern: String,
    base: Base,
    /// A pattern holding `/` addresses a whole relative path; one without it
    /// addresses a single name at any depth.
    anchored: bool,
    /// For `dir/**`, the directory part, which the pattern also covers on its
    /// own — the same rule the rule-file globs follow.
    directory: Option<String>,
    /// No `*` or `?`. The common line is a literal path, and comparing it
    /// component by component is what keeps the check off the walk's hot path:
    /// a glob call per entry per ancestor doubled a 200k-entry scan when this
    /// was measured.
    literal: bool,
    /// The literal bytes after the last wildcard, which a match must end with.
    ///
    /// A necessary condition only, used to reject an entry before the glob runs.
    /// It can never accept one, so a wrong `tail` would cost time, not safety.
    tail: String,
}

impl Entry {
    /// True when this line covers `path`, which must be absolute.
    fn covers(&self, path: &Path, home: &Path) -> bool {
        let relative = match self.base {
            Base::Home => match path.strip_prefix(home) {
                Ok(relative) => relative,
                Err(_) => return false,
            },
            Base::Root => match path.strip_prefix("/") {
                Ok(relative) => relative,
                Err(_) => return false,
            },
        };
        if relative.as_os_str().is_empty() {
            // The base itself. `/` or `$HOME` is not a target; refusing to treat
            // it as one keeps a stray line from protecting the whole home.
            return false;
        }
        if self.literal {
            return if self.anchored {
                // A literal anchored pattern is a path prefix, so the subtree is
                // covered without asking about each ancestor.
                relative.starts_with(&self.pattern)
            } else {
                relative
                    .file_name()
                    .map(|name| name.as_encoded_bytes() == self.pattern.as_bytes())
                    .unwrap_or(false)
            };
        }
        if let Some(directory) = &self.directory {
            if relative == Path::new(directory) {
                return true;
            }
        }
        let bytes = relative.as_os_str().as_encoded_bytes();
        // Cheap rejection first: most entries fail on the last four bytes.
        if self.anchored && !bytes.ends_with(self.tail.as_bytes()) {
            return false;
        }
        if self.anchored {
            return glob::matches(&self.pattern, bytes);
        }
        let name = relative
            .file_name()
            .map(|name| name.as_encoded_bytes())
            .unwrap_or(bytes);
        if !name.ends_with(self.tail.as_bytes()) {
            return false;
        }
        glob::matches(&self.pattern, name)
    }
}

/// Why the file could not be used.
///
/// A malformed line refuses the whole command rather than being skipped. The
/// user wrote it to protect something; ignoring the line and sweeping anyway is
/// the one outcome they would not expect, and it is unrecoverable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoreError {
    /// The file, written as `~/.config/sweep/ignore` when it lives in `$HOME`.
    pub source: String,
    /// 1-based line number, or 0 for a whole-file problem.
    pub line: usize,
    pub message: String,
}

impl std::fmt::Display for IgnoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.line == 0 {
            write!(f, "{}: {}", self.source, self.message)
        } else {
            write!(f, "{}:{}: {}", self.source, self.line, self.message)
        }
    }
}

impl std::error::Error for IgnoreError {}

/// The compiled file. Empty when the user has no ignore file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ignore {
    home: PathBuf,
    entries: Vec<Entry>,
}

impl Ignore {
    /// Reads `$XDG_CONFIG_HOME/sweep/ignore`.
    pub fn load(xdg: &Xdg) -> Result<Self, IgnoreError> {
        let path = xdg.config_dir().join("ignore");
        let source = display_path(&path, &xdg.home);
        match std::fs::read(&path) {
            Ok(bytes) => {
                let body = String::from_utf8(bytes).map_err(|_| IgnoreError {
                    source: source.clone(),
                    line: 0,
                    message: "the file is not valid UTF-8; a path with a non-UTF-8 name cannot be \
                              written here"
                        .to_string(),
                })?;
                Self::parse(&xdg.home, &body, &source)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self::empty(&xdg.home)),
            Err(error) => Err(IgnoreError {
                source,
                line: 0,
                message: format!("cannot be read: {error}"),
            }),
        }
    }

    /// An `Ignore` that protects nothing, for a machine with no file.
    pub fn empty(home: &Path) -> Self {
        Self {
            home: home.to_path_buf(),
            entries: Vec::new(),
        }
    }

    /// Compiles `body`. `source` is only used to build error messages.
    pub fn parse(home: &Path, body: &str, source: &str) -> Result<Self, IgnoreError> {
        let mut entries = Vec::new();
        for (index, raw) in body.lines().enumerate() {
            let line = index + 1;
            let text = raw.trim();
            if text.is_empty() || text.starts_with('#') {
                continue;
            }
            let fail = |message: String| IgnoreError {
                source: source.to_string(),
                line,
                message,
            };
            if text.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
                return Err(fail("the line contains a control byte".to_string()));
            }
            if let Some(rest) = text.strip_prefix('!') {
                return Err(fail(format!(
                    "negation is not supported: this file only protects paths, so there is nothing \
                     to un-protect; delete the line that protects {rest:?} instead"
                )));
            }

            let (base, pattern, tilde) = if text == "~" {
                return Err(fail(
                    "`~` is your home directory, which is not a target; name something inside it, \
                     like `~/work`"
                        .to_string(),
                ));
            } else if let Some(rest) = text.strip_prefix("~/") {
                (Base::Home, rest, true)
            } else if text.starts_with('~') {
                return Err(fail(format!(
                    "`{text}` names another user's home, which this file cannot expand; use an \
                     absolute path or `~/...`"
                )));
            } else if let Some(rest) = text.strip_prefix('/') {
                (Base::Root, rest, false)
            } else {
                (Base::Home, text, false)
            };

            if pattern.is_empty() {
                return Err(fail(
                    "the pattern names no path; write the directory or file to protect".to_string(),
                ));
            }
            if pattern.ends_with('/') {
                let stem = text.trim_end_matches('/');
                return Err(fail(format!(
                    "`{text}` ends with `/`; write `{stem}/**` to protect a directory and \
                     everything below it, or `{stem}` for the directory alone"
                )));
            }
            if pattern.split('/').any(|part| part == "..") {
                return Err(fail(format!(
                    "`{text}` contains `..`; write the path you mean instead"
                )));
            }
            let directory = pattern
                .strip_suffix("/**")
                .filter(|prefix| !prefix.is_empty())
                .map(|prefix| prefix.to_string());
            let entry = Entry {
                source: text.to_string(),
                pattern: pattern.to_string(),
                base,
                // `~/x` is a path the user wrote out, so it is anchored even when
                // what follows is a single component: `~/work` must not also
                // protect every `work` at any depth.
                anchored: pattern.contains('/') || base == Base::Root || tilde,
                directory,
                literal: !pattern.bytes().any(|byte| byte == b'*' || byte == b'?'),
                tail: pattern
                    .rsplit(['*', '?'])
                    .next()
                    .unwrap_or_default()
                    .to_string(),
            };
            if !entry
                .pattern
                .bytes()
                .any(|byte| byte != b'*' && byte != b'?' && byte != b'/')
            {
                return Err(fail(format!(
                    "`{text}` is wildcards only and would protect everything; delete the line \
                     instead"
                )));
            }
            entries.push(entry);
        }
        Ok(Self {
            home: home.to_path_buf(),
            entries,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// The pattern that protects `path`, as it was written, when one does.
    ///
    /// Every ancestor is checked as well: a line protecting a directory protects
    /// what is inside it.
    pub fn matched(&self, path: &Path) -> Option<&str> {
        if self.entries.is_empty() {
            return None;
        }
        let mut current = Some(path);
        while let Some(candidate) = current {
            if let Some(source) = self.matched_exact(candidate) {
                return Some(source);
            }
            current = candidate.parent();
        }
        None
    }

    /// The pattern that protects `path` itself, ignoring its ancestors.
    ///
    /// A directory walk uses this. An ignored directory is blocked before it is
    /// entered, so its descendants are never reached and asking about every
    /// ancestor again would only cost time.
    pub fn matched_exact(&self, path: &Path) -> Option<&str> {
        self.entries
            .iter()
            .find(|entry| entry.covers(path, &self.home))
            .map(|entry| entry.source.as_str())
    }
}

/// `~/.config/sweep/ignore` when the file lives in `$HOME`, the full path
/// otherwise.
fn display_path(path: &Path, home: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(relative) => format!("~/{}", relative.display()),
        Err(_) => path.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ignore(body: &str) -> Ignore {
        Ignore::parse(Path::new("/home/alice"), body, "ignore").expect("parses")
    }

    fn matched(body: &str, path: &str) -> Option<String> {
        ignore(body).matched(Path::new(path)).map(str::to_string)
    }

    #[test]
    fn a_tilde_line_protects_the_directory_and_everything_below_it() {
        assert_eq!(
            matched("~/work\n", "/home/alice/work"),
            Some("~/work".to_string())
        );
        assert_eq!(
            matched("~/work\n", "/home/alice/work/deep/file.rs"),
            Some("~/work".to_string())
        );
        // `~/work` is a path, not a name match: the same name somewhere else
        // under `$HOME` is not what the line names.
        assert_eq!(
            matched("~/work\n", "/home/alice/.cache/build/work"),
            None,
            "a `~/` line is anchored to $HOME"
        );
    }

    #[test]
    fn a_bare_line_is_relative_to_home() {
        assert_eq!(
            matched(".cache/keep\n", "/home/alice/.cache/keep"),
            Some(".cache/keep".to_string())
        );
        // Anchored: it is not a name match, so a same-named path elsewhere is
        // not protected.
        assert_eq!(
            matched(".cache/keep\n", "/home/alice/other/.cache/keep"),
            None
        );
    }

    #[test]
    fn an_absolute_line_is_relative_to_the_root() {
        assert_eq!(
            matched("/srv/data\n", "/srv/data/x"),
            Some("/srv/data".to_string())
        );
        assert_eq!(matched("/srv/data\n", "/home/alice/srv/data"), None);
    }

    #[test]
    fn a_name_pattern_matches_at_any_depth() {
        assert_eq!(
            matched("*.iso\n", "/home/alice/a/b.iso"),
            Some("*.iso".to_string())
        );
        assert_eq!(
            matched("*.iso\n", "/home/alice/a/b.iso/inner"),
            Some("*.iso".to_string()),
            "a directory that matches protects its subtree too"
        );
    }

    #[test]
    fn a_double_star_directory_line_covers_the_directory_itself() {
        assert_eq!(
            matched(".cache/big/**\n", "/home/alice/.cache/big"),
            Some(".cache/big/**".to_string())
        );
        assert_eq!(
            matched(".cache/big/**\n", "/home/alice/.cache/big/x/y"),
            Some(".cache/big/**".to_string())
        );
        assert_eq!(
            matched(".cache/big/**\n", "/home/alice/.cache/bigger"),
            None
        );
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let parsed = ignore("# a note\n\n   \n  ~/work  \n");
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed.matched(Path::new("/home/alice/work")),
            Some("~/work")
        );
    }

    #[test]
    fn a_pattern_with_no_literal_tail_still_matches() {
        // The cheap rejection compares the bytes after the last wildcard; an
        // empty tail must reject nothing.
        assert_eq!(
            matched("*.tar.*\n", "/home/alice/a/arch.tar.zst"),
            Some("*.tar.*".to_string())
        );
        assert_eq!(
            matched("data?.bin\n", "/home/alice/x/data1.bin"),
            Some("data?.bin".to_string())
        );
        assert_eq!(matched("data?.bin\n", "/home/alice/x/data12.bin"), None);
    }

    #[test]
    fn a_double_star_name_pattern_matches_at_any_depth() {
        assert_eq!(
            matched("**/node_modules\n", "/home/alice/code/app/node_modules"),
            Some("**/node_modules".to_string())
        );
        assert_eq!(
            matched("**/node_modules\n", "/home/alice/code/app/node_modules/x/y"),
            Some("**/node_modules".to_string())
        );
    }

    #[test]
    fn a_path_outside_home_is_never_protected_by_a_relative_line() {
        assert_eq!(matched("work\n", "/srv/work"), None);
    }

    #[test]
    fn the_home_directory_itself_is_not_a_target() {
        assert_eq!(matched("~/work\n", "/home/alice"), None);
    }

    #[test]
    fn negation_is_refused_with_the_fix() {
        let error = Ignore::parse(Path::new("/home"), "!~/work\n", "ignore").unwrap_err();
        assert_eq!(error.line, 1);
        assert!(
            error.message.contains("negation is not supported"),
            "{error}"
        );
        assert!(error.message.contains("delete the line"), "{error}");
    }

    #[test]
    fn a_trailing_slash_names_the_directory_form() {
        let error = Ignore::parse(Path::new("/home"), "~/work/\n", "ignore").unwrap_err();
        assert!(error.message.contains("~/work/**"), "{error}");
    }

    #[test]
    fn a_wildcard_only_line_is_refused() {
        for body in ["*\n", "**\n", "**/*\n"] {
            let error = Ignore::parse(Path::new("/home"), body, "ignore").unwrap_err();
            assert!(
                error.message.contains("would protect everything"),
                "{body}: {error}"
            );
        }
    }

    #[test]
    fn a_traversal_component_is_refused() {
        let error = Ignore::parse(Path::new("/home"), "~/../etc\n", "ignore").unwrap_err();
        assert!(error.message.contains("contains `..`"), "{error}");
    }

    #[test]
    fn a_whole_file_error_prints_without_a_line_number() {
        let error = IgnoreError {
            source: "~/.config/sweep/ignore".to_string(),
            line: 0,
            message: "cannot be read: permission denied".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "~/.config/sweep/ignore: cannot be read: permission denied"
        );
    }

    #[test]
    fn a_missing_file_protects_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let xdg = Xdg::resolve(|key| match key {
            "HOME" => Some(temp.path().as_os_str().to_os_string()),
            _ => None,
        })
        .unwrap();
        let parsed = Ignore::load(&xdg).unwrap();
        assert!(parsed.is_empty());
    }
}
