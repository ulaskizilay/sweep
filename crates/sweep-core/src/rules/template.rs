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
        }
    }
}

impl std::error::Error for TemplateError {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    Literal(String),
    Base(Base),
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
                Part::Literal(_) => None,
            })
            .collect()
    }

    pub fn expand(&self, xdg: &Xdg) -> PathBuf {
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
            }
        }
        out
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
}
