//! Root templates: `{home}/.cargo/registry/cache`.
//!
//! A rule may not contain a literal home directory, because that path is not
//! known until the process starts and a rule that hard-codes `/home/alice` is
//! wrong on every other machine. It may not contain `..` either, because a root
//! that climbs out of its own base can reach a directory the rule never named.
//!
//! A variable is a whole path segment. `{home}/.cargo` is fine;
//! `{home}.cargo` is refused, because an expansion that concatenates two words
//! into `/home/alice.cargo` is almost always a typo and is hard to spot when
//! reading the rule file.
//!
//! A segment may also be a glob, because some tools name their cache directory
//! after a version: `{cache}/Google/AndroidStudio*`. The language is the same
//! small one `exclude` uses (`*`, `?`), but the safety rules are stricter: the
//! last segment must contain literal text, the literal prefix must be at least
//! three components deep, and a match must be a real directory. Those three
//! together are what stop `{home}/*` from being a rule.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::Xdg;

/// A base directory a template may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Base {
    Home,
    Cache,
    Config,
    Data,
    State,
    Runtime,
}

impl Base {
    pub const ALL: [Base; 6] = [
        Base::Home,
        Base::Cache,
        Base::Config,
        Base::Data,
        Base::State,
        Base::Runtime,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Base::Home => "home",
            Base::Cache => "cache",
            Base::Config => "config",
            Base::Data => "data",
            Base::State => "state",
            Base::Runtime => "runtime",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|base| base.as_str() == name)
    }

    pub fn path(self, xdg: &Xdg) -> &Path {
        match self {
            Base::Home => &xdg.home,
            Base::Cache => &xdg.cache,
            Base::Config => &xdg.config,
            Base::Data => &xdg.data,
            Base::State => &xdg.state,
            Base::Runtime => &xdg.runtime,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateError {
    Empty,
    NotAbsolute(String),
    Traversal(String),
    ControlByte,
    UnknownBase(String),
    UnclosedBrace(String),
    BracesInsideSegment(String),
    EmptySegment(String),
    UnsupportedGlob(String),
}

impl std::fmt::Display for TemplateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemplateError::Empty => f.write_str("root is empty"),
            TemplateError::NotAbsolute(template) => {
                write!(f, "root {template:?} is not absolute")
            }
            TemplateError::Traversal(template) => write!(
                f,
                "root {template:?} contains a parent component; name the directory directly"
            ),
            TemplateError::ControlByte => f.write_str("root contains a control byte"),
            TemplateError::UnknownBase(name) => write!(
                f,
                "unknown variable {{{name}}}; expected one of {}",
                Base::ALL
                    .iter()
                    .map(|base| format!("{{{}}}", base.as_str()))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            TemplateError::UnclosedBrace(template) => {
                write!(f, "root {template:?} has an unclosed '{{'")
            }
            TemplateError::BracesInsideSegment(segment) => write!(
                f,
                "root segment {segment:?} mixes a variable with text; write {{base}}/name"
            ),
            TemplateError::EmptySegment(template) => {
                write!(f, "root {template:?} has an empty path segment")
            }
            TemplateError::UnsupportedGlob(segment) => write!(
                f,
                "root segment {segment:?} uses a wildcard this rule language does not support; \
                 only * and ? are allowed, and ** is refused because it would walk an unbounded tree"
            ),
        }
    }
}

impl std::error::Error for TemplateError {}

/// Why a glob root could not be turned into concrete directories.
///
/// Both answers mean "unknown", and the caller must plan nothing from the rule.
/// An empty `Ok` is different: it means the pattern was expanded completely and
/// nothing matched, so the target is genuinely absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpandError {
    TooMany { root: String, limit: usize },
    Unreadable { path: PathBuf, message: String },
}

impl std::fmt::Display for ExpandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExpandError::TooMany { root, limit } => write!(
                f,
                "root {root:?} matched more than {limit} directories; narrow the pattern"
            ),
            ExpandError::Unreadable { path, message } => {
                write!(
                    f,
                    "root pattern could not read {}: {message}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for ExpandError {}

/// Upper bound on the directories one glob root may expand to.
///
/// A cache layout is one or two version directories, so a pattern that matches
/// hundreds is either a mistake or a wildcard that reached too high. Refusing
/// the rule is the same answer the engine gives any incomplete scan: unknown
/// never deletes.
pub const MAX_GLOB_MATCHES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    Literal(String),
    Base(Base),
    Glob(String),
}

/// A parsed, not yet expanded rule root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    raw: String,
    parts: Vec<Part>,
}

impl Template {
    pub fn parse(raw: &str) -> Result<Self, TemplateError> {
        if raw.is_empty() {
            return Err(TemplateError::Empty);
        }
        if raw.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
            return Err(TemplateError::ControlByte);
        }

        let mut parts = Vec::new();
        // Split rather than scan, so "a variable is a whole segment" is enforced
        // by construction and not by a second check.
        for (index, segment) in raw.split('/').enumerate() {
            // A leading empty segment is the absolute-root marker.
            if index == 0 && segment.is_empty() {
                continue;
            }
            if segment.is_empty() {
                return Err(TemplateError::EmptySegment(raw.to_string()));
            }
            if segment == "." || segment == ".." {
                return Err(TemplateError::Traversal(raw.to_string()));
            }
            if segment.starts_with('{') {
                let Some(close) = segment.find('}') else {
                    return Err(TemplateError::UnclosedBrace(raw.to_string()));
                };
                let name = &segment[1..close];
                // `{home}.cargo` is a brace that does not span its segment; it
                // would expand to `/home/alice.cargo`, which is almost always a
                // typo and is invisible when reading the rule file.
                if close + 1 != segment.len() || name.contains('{') || name.contains('}') {
                    return Err(TemplateError::BracesInsideSegment(segment.to_string()));
                }
                let Some(base) = Base::parse(name) else {
                    return Err(TemplateError::UnknownBase(name.to_string()));
                };
                parts.push(Part::Base(base));
                continue;
            }
            if segment.contains('{') || segment.contains('}') {
                return Err(TemplateError::BracesInsideSegment(segment.to_string()));
            }
            if segment.contains('*') || segment.contains('?') {
                // The same small language `exclude` uses, minus recursion: a
                // root is expanded by listing directories, so `**` would mean a
                // walk whose depth nobody bounded.
                if segment.contains("**") || segment.contains('[') || segment.contains(']') {
                    return Err(TemplateError::UnsupportedGlob(segment.to_string()));
                }
                parts.push(Part::Glob(segment.to_string()));
                continue;
            }
            parts.push(Part::Literal(segment.to_string()));
        }

        // The path must be absolute, which after the split means it either began
        // with `/` or with a base variable.
        let starts_absolute = raw.starts_with('/') || matches!(parts.first(), Some(Part::Base(_)));
        if !starts_absolute {
            return Err(TemplateError::NotAbsolute(raw.to_string()));
        }

        Ok(Self {
            raw: raw.to_string(),
            parts,
        })
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// The base directories the template depends on, for diagnostics.
    pub fn bases(&self) -> Vec<Base> {
        self.parts
            .iter()
            .filter_map(|part| match part {
                Part::Base(base) => Some(*base),
                Part::Literal(_) | Part::Glob(_) => None,
            })
            .collect()
    }

    /// True when at least one segment has to be discovered by listing a
    /// directory.
    pub fn has_glob(&self) -> bool {
        self.parts.iter().any(|part| matches!(part, Part::Glob(_)))
    }

    /// True when the final segment names something more specific than "every
    /// child".
    ///
    /// `{cache}/Google/AndroidStudio*` passes; `{home}/.var/app/*` does not.
    /// Without this, a glob root at the last segment would be a rule that says
    /// "delete everything in this directory" while looking like a target.
    pub fn last_segment_has_literal(&self) -> bool {
        match self.parts.last() {
            Some(Part::Literal(text)) => !text.is_empty(),
            Some(Part::Glob(segment)) => segment.bytes().any(|byte| byte != b'*' && byte != b'?'),
            Some(Part::Base(_)) | None => false,
        }
    }

    /// The absolute path up to the first wildcard.
    ///
    /// Validation runs on this rather than on the raw template: a protected
    /// directory is protected however many levels below it a pattern reaches.
    pub fn literal_prefix(&self, xdg: &Xdg) -> PathBuf {
        let mut out = PathBuf::new();
        if matches!(self.parts.first(), Some(Part::Literal(_))) && self.raw.starts_with('/') {
            out.push("/");
        }
        for part in &self.parts {
            match part {
                Part::Base(base) => out.push(base.path(xdg)),
                Part::Literal(text) => out.push(text),
                Part::Glob(_) => break,
            }
        }
        out
    }

    /// The template as a readable path, with bases expanded and wildcards kept.
    ///
    /// This is what `rules list` prints: a glob rule has many concrete roots on
    /// one machine and different ones on the next, so the pattern is the stable
    /// thing to show.
    pub fn display(&self, xdg: &Xdg) -> String {
        let mut out = PathBuf::new();
        if self.raw.starts_with('/') {
            out.push("/");
        }
        for part in &self.parts {
            match part {
                Part::Base(base) => out.push(base.path(xdg)),
                Part::Literal(text) => out.push(text),
                Part::Glob(segment) => out.push(segment),
            }
        }
        out.display().to_string()
    }

    /// Expands a literal template. A glob template must use [`Self::expand_all`].
    pub fn expand(&self, xdg: &Xdg) -> PathBuf {
        debug_assert!(
            !self.has_glob(),
            "expand() is for literal templates; {} needs expand_all()",
            self.raw
        );
        let mut out = PathBuf::new();
        // A literal absolute root such as `/var/cache/fontconfig` lost its
        // leading separator when split. Bases are already absolute, so only a
        // literal-first template needs it back.
        if matches!(self.parts.first(), Some(Part::Literal(_))) && self.raw.starts_with('/') {
            out.push("/");
        }
        for part in &self.parts {
            match part {
                Part::Base(base) => out.push(base.path(xdg)),
                Part::Literal(text) => out.push(text),
                Part::Glob(segment) => out.push(segment),
            }
        }
        out
    }

    /// Every concrete directory a root names, in sorted order.
    ///
    /// A literal template has exactly one answer, even when the directory is
    /// missing: the caller decides what "absent" means. A glob template lists
    /// the parent, keeps entries whose name matches and that are real
    /// directories, and repeats for the next segment. Symlinks are skipped, not
    /// followed: `~/snap/<app>/current` is a link into a revision directory, and
    /// resolving it would let a link outside the tree choose the target.
    pub fn expand_all(&self, xdg: &Xdg) -> Result<Vec<PathBuf>, ExpandError> {
        if !self.has_glob() {
            return Ok(vec![self.expand(xdg)]);
        }

        let mut current = vec![if self.raw.starts_with('/') {
            PathBuf::from("/")
        } else {
            PathBuf::new()
        }];

        for part in &self.parts {
            match part {
                Part::Base(base) => {
                    for path in &mut current {
                        path.push(base.path(xdg));
                    }
                }
                Part::Literal(text) => {
                    for path in &mut current {
                        path.push(text);
                    }
                }
                Part::Glob(pattern) => {
                    let mut matched = Vec::new();
                    for directory in &current {
                        let entries = match std::fs::read_dir(directory) {
                            Ok(entries) => entries,
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    ErrorKind::NotFound | ErrorKind::NotADirectory
                                ) =>
                            {
                                continue
                            }
                            Err(error) => {
                                return Err(ExpandError::Unreadable {
                                    path: directory.clone(),
                                    message: error.to_string(),
                                })
                            }
                        };
                        for entry in entries {
                            let entry = entry.map_err(|error| ExpandError::Unreadable {
                                path: directory.clone(),
                                message: error.to_string(),
                            })?;
                            if !crate::rules::glob::matches(
                                pattern,
                                entry.file_name().as_encoded_bytes(),
                            ) {
                                continue;
                            }
                            let Ok(metadata) = std::fs::symlink_metadata(entry.path()) else {
                                continue;
                            };
                            if !metadata.is_dir() {
                                continue;
                            }
                            matched.push(entry.path());
                            if matched.len() > MAX_GLOB_MATCHES {
                                return Err(ExpandError::TooMany {
                                    root: self.raw.clone(),
                                    limit: MAX_GLOB_MATCHES,
                                });
                            }
                        }
                    }
                    if matched.is_empty() {
                        return Ok(Vec::new());
                    }
                    current = matched;
                }
            }
        }

        // A literal segment after a wildcard is appended without a listing, so
        // `*/cache` would otherwise name `<app>/cache` for an app that has no
        // cache directory. Keep only paths that are real directories now; the
        // rest are absent, not targets.
        current.retain(|path| {
            std::fs::symlink_metadata(path)
                .map(|metadata| metadata.is_dir())
                .unwrap_or(false)
        });
        current.sort();
        current.dedup();
        Ok(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xdg() -> Xdg {
        Xdg::resolve(|key| match key {
            "HOME" => Some("/home/u".into()),
            "XDG_CACHE_HOME" => Some("/mnt/cache".into()),
            _ => None,
        })
        .expect("home")
    }

    #[test]
    fn variables_expand_to_their_base() {
        let xdg = xdg();
        let runtime = format!("/run/user/{}/app", crate::sys::euid());
        let cases = [
            ("{home}/.cargo", "/home/u/.cargo".to_string()),
            ("{cache}/go-build", "/mnt/cache/go-build".to_string()),
            (
                "{config}/Code/Cache",
                "/home/u/.config/Code/Cache".to_string(),
            ),
            (
                "{data}/Trash/files",
                "/home/u/.local/share/Trash/files".to_string(),
            ),
            ("{state}/sweep", "/home/u/.local/state/sweep".to_string()),
            ("{runtime}/app", runtime),
        ];
        for (raw, expected) in cases {
            let template = Template::parse(raw).expect(raw);
            assert_eq!(template.expand(&xdg), PathBuf::from(expected), "{raw}");
        }
    }

    #[test]
    fn an_absolute_literal_root_is_allowed() {
        let template = Template::parse("/var/cache/fontconfig").unwrap();
        assert_eq!(
            template.expand(&xdg()),
            PathBuf::from("/var/cache/fontconfig")
        );
    }

    #[test]
    fn a_relative_root_is_refused() {
        assert!(matches!(
            Template::parse("var/cache"),
            Err(TemplateError::NotAbsolute(_))
        ));
    }

    #[test]
    fn a_parent_component_is_refused() {
        for raw in ["{cache}/../cargo", "/var/../etc", "{home}/a/.."] {
            assert!(
                matches!(Template::parse(raw), Err(TemplateError::Traversal(_))),
                "{raw} must be refused"
            );
        }
    }

    #[test]
    fn an_unknown_variable_is_refused_by_name() {
        let error = Template::parse("{xdg_cache}/x").unwrap_err();
        assert_eq!(error, TemplateError::UnknownBase("xdg_cache".into()));
        assert!(error.to_string().contains("{cache}"), "{error}");
    }

    #[test]
    fn a_variable_must_be_a_whole_segment() {
        assert!(matches!(
            Template::parse("{home}.cargo"),
            Err(TemplateError::BracesInsideSegment(_))
        ));
        assert!(matches!(
            Template::parse("{home}/.cargo-{base}"),
            Err(TemplateError::BracesInsideSegment(_))
        ));
    }

    #[test]
    fn an_unclosed_brace_is_refused() {
        assert!(matches!(
            Template::parse("{home/.cargo"),
            Err(TemplateError::UnclosedBrace(_))
        ));
    }

    #[test]
    fn empty_segments_are_refused() {
        assert!(matches!(
            Template::parse("{home}//cargo"),
            Err(TemplateError::EmptySegment(_))
        ));
    }

    #[test]
    fn bases_lists_only_the_variables_used() {
        let template = Template::parse("{cache}/x/{home}/y").unwrap();
        assert_eq!(template.bases(), vec![Base::Cache, Base::Home]);
    }

    #[test]
    fn control_bytes_are_refused() {
        let raw = format!("/var/{}/x", char::from(0x1b));
        assert_eq!(Template::parse(&raw), Err(TemplateError::ControlByte));
    }

    fn temp_xdg(root: &Path) -> Xdg {
        let home = root.to_string_lossy().into_owned();
        Xdg::resolve(move |key| match key {
            "HOME" => Some(home.clone().into()),
            _ => None,
        })
        .expect("home")
    }

    #[test]
    fn a_glob_root_expands_to_matching_directories_only() {
        let temp = tempfile::tempdir().unwrap();
        let xdg = temp_xdg(temp.path());
        let google = temp.path().join(".cache/Google");
        std::fs::create_dir_all(google.join("AndroidStudio2023.1/caches")).unwrap();
        std::fs::create_dir_all(google.join("AndroidStudio2024.2")).unwrap();
        std::fs::create_dir_all(google.join("Other")).unwrap();
        std::fs::write(google.join("AndroidStudio2024.2/not-a-dir"), b"x").unwrap();
        std::os::unix::fs::symlink(
            google.join("AndroidStudio2023.1"),
            google.join("AndroidStudio2025.1"),
        )
        .unwrap();

        let template = Template::parse("{cache}/Google/AndroidStudio*").unwrap();
        let roots = template.expand_all(&xdg).unwrap();
        assert_eq!(
            roots,
            vec![
                google.join("AndroidStudio2023.1"),
                google.join("AndroidStudio2024.2"),
            ],
            "a symlink is skipped and a file never matches"
        );
    }

    #[test]
    fn a_glob_in_the_middle_matches_each_child_directory() {
        let temp = tempfile::tempdir().unwrap();
        let xdg = temp_xdg(temp.path());
        std::fs::create_dir_all(temp.path().join(".var/app/com.a/cache/old")).unwrap();
        std::fs::create_dir_all(temp.path().join(".var/app/com.b/cache")).unwrap();
        std::fs::create_dir_all(temp.path().join(".var/app/com.c/data")).unwrap();

        let template = Template::parse("{home}/.var/app/*/cache").unwrap();
        let roots = template.expand_all(&xdg).unwrap();
        assert_eq!(
            roots,
            vec![
                temp.path().join(".var/app/com.a/cache"),
                temp.path().join(".var/app/com.b/cache"),
            ],
            "only the cache child of each app is a root"
        );
    }

    #[test]
    fn a_glob_root_with_no_match_is_absent_not_unknown() {
        let temp = tempfile::tempdir().unwrap();
        let xdg = temp_xdg(temp.path());
        std::fs::create_dir_all(temp.path().join(".cache/Google/Other")).unwrap();

        let template = Template::parse("{cache}/Google/AndroidStudio*").unwrap();
        assert_eq!(template.expand_all(&xdg).unwrap(), Vec::<PathBuf>::new());
    }

    #[test]
    fn a_glob_parent_that_is_a_file_is_absent() {
        let temp = tempfile::tempdir().unwrap();
        let xdg = temp_xdg(temp.path());
        std::fs::create_dir_all(temp.path().join(".cache")).unwrap();
        std::fs::write(temp.path().join(".cache/Google"), b"not a directory").unwrap();

        let template = Template::parse("{cache}/Google/AndroidStudio*").unwrap();
        assert_eq!(template.expand_all(&xdg).unwrap(), Vec::<PathBuf>::new());
    }

    #[test]
    fn too_many_matches_are_refused_rather_than_truncated() {
        let temp = tempfile::tempdir().unwrap();
        let xdg = temp_xdg(temp.path());
        let parent = temp.path().join(".cache/versions");
        std::fs::create_dir_all(&parent).unwrap();
        for index in 0..=MAX_GLOB_MATCHES {
            std::fs::create_dir(parent.join(format!("v{index}"))).unwrap();
        }

        let template = Template::parse("{cache}/versions/v*").unwrap();
        let error = template.expand_all(&xdg).unwrap_err();
        assert!(
            matches!(error, ExpandError::TooMany { limit, .. } if limit == MAX_GLOB_MATCHES),
            "{error}"
        );
    }

    #[test]
    fn recursive_and_bracketed_globs_are_refused() {
        for raw in ["{cache}/**/cache", "{cache}/[ab]*"] {
            assert!(
                matches!(Template::parse(raw), Err(TemplateError::UnsupportedGlob(_))),
                "{raw} must be refused"
            );
        }
    }

    #[test]
    fn a_literal_prefix_stops_at_the_first_wildcard() {
        let xdg = xdg();
        let template = Template::parse("{home}/.var/app/*/cache").unwrap();
        assert_eq!(
            template.literal_prefix(&xdg),
            PathBuf::from("/home/u/.var/app")
        );
        assert!(template.last_segment_has_literal());
        assert!(template.has_glob());

        let shallow = Template::parse("{home}/*/cache").unwrap();
        assert_eq!(shallow.literal_prefix(&xdg), PathBuf::from("/home/u"));
    }

    #[test]
    fn a_last_segment_of_only_wildcards_is_not_a_target() {
        for raw in ["{home}/.var/app/*", "{home}/snap/*/*"] {
            assert!(
                !Template::parse(raw).unwrap().last_segment_has_literal(),
                "{raw} names every child"
            );
        }
        assert!(Template::parse("{home}/snap/*/*/.cache")
            .unwrap()
            .last_segment_has_literal());
    }

    #[test]
    fn display_keeps_the_pattern_and_expands_the_base() {
        let xdg = xdg();
        let template = Template::parse("{cache}/Google/AndroidStudio*").unwrap();
        assert_eq!(template.display(&xdg), "/mnt/cache/Google/AndroidStudio*");
        let literal = Template::parse("{home}/.cargo").unwrap();
        assert_eq!(literal.display(&xdg), "/home/u/.cargo");
    }
}
