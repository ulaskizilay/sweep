//! Load-time validation: what a rule must prove before it exists.
//!
//! These are the checks that make the rule catalog safe to review rather than
//! safe to trust. They run on every start, so a hand-edited pack in
//! `~/.config/sweep/rules.d` is held to the same standard as the built-ins.
//!
//! Every check answers a question that a reader of the TOML would otherwise
//! have to answer by hand:
//!
//! 1. Is the root absolute, variable-free apart from the six bases, and free of
//!    `..`?
//! 2. Does the root land inside something sweep never deletes?
//! 3. Is the root so broad that a single rule would mean "clean everything"?
//! 4. Can the user read why this target is safe?
//! 5. Is the id unique, and does the section exist?
//! 6. Does `keep_days = 0` come with an explicit "this is regenerable"?
//! 7. Is privilege confined to the system section?

use std::path::Path;

use crate::paths::depth;
use crate::plan::RuleId;
use crate::policy;
use crate::rules::glob::Pattern;
use crate::rules::schema::{OneOrMany, RawRule};
use crate::rules::template::Template;
use crate::rules::{Kind, Privilege, Requirement, Rule, Section, Source};
use crate::Xdg;

/// A stable identifier for the kind of load failure, so `--json` consumers and
/// tests do not match on prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleErrorKind {
    Toml,
    NoRules,
    ReadFailed,
    BadId,
    DuplicateId,
    UnknownSection,
    UnknownKind,
    UnsupportedKind,
    BadPrivilege,
    Template,
    ProtectedRoot,
    BareRoot,
    MissingEvidence,
    ZeroKeepDays,
    UnsafeRetention,
    RootPrivilege,
    MissingPattern,
    UnusedPattern,
    BadPattern,
    MissingKeepVersions,
    UnusedKeepVersions,
    BadKeepVersions,
    IgnoredKeepDays,
    Requirement,
    BadDepth,
}

impl RuleErrorKind {
    pub fn code(self) -> &'static str {
        match self {
            RuleErrorKind::Toml => "toml",
            RuleErrorKind::NoRules => "no_rules",
            RuleErrorKind::ReadFailed => "read_failed",
            RuleErrorKind::BadId => "bad_id",
            RuleErrorKind::DuplicateId => "duplicate_id",
            RuleErrorKind::UnknownSection => "unknown_section",
            RuleErrorKind::UnknownKind => "unknown_kind",
            RuleErrorKind::UnsupportedKind => "unsupported_kind",
            RuleErrorKind::BadPrivilege => "bad_privilege",
            RuleErrorKind::Template => "template",
            RuleErrorKind::ProtectedRoot => "protected_root",
            RuleErrorKind::BareRoot => "bare_root",
            RuleErrorKind::MissingEvidence => "missing_evidence",
            RuleErrorKind::ZeroKeepDays => "zero_keep_days",
            RuleErrorKind::UnsafeRetention => "unsafe_retention",
            RuleErrorKind::RootPrivilege => "root_privilege",
            RuleErrorKind::MissingPattern => "missing_pattern",
            RuleErrorKind::UnusedPattern => "unused_pattern",
            RuleErrorKind::BadPattern => "bad_pattern",
            RuleErrorKind::MissingKeepVersions => "missing_keep_versions",
            RuleErrorKind::UnusedKeepVersions => "unused_keep_versions",
            RuleErrorKind::BadKeepVersions => "bad_keep_versions",
            RuleErrorKind::IgnoredKeepDays => "ignored_keep_days",
            RuleErrorKind::Requirement => "requirement",
            RuleErrorKind::BadDepth => "bad_depth",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleError {
    pub kind: RuleErrorKind,
    pub pack: String,
    pub rule: Option<String>,
    pub message: String,
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.rule {
            Some(rule) => write!(f, "{}: {rule}: {}", self.pack, self.message),
            None => write!(f, "{}: {}", self.pack, self.message),
        }
    }
}

impl std::error::Error for RuleError {}

fn fail(
    kind: RuleErrorKind,
    pack: &str,
    rule: Option<&str>,
    message: impl Into<String>,
) -> RuleError {
    RuleError {
        kind,
        pack: pack.to_string(),
        rule: rule.map(str::to_string),
        message: message.into(),
    }
}

/// Upper bound on `max_depth`. Eight levels cover every real cache layout; a
/// larger number is either a typo or an attempt to walk a home directory.
const MAX_DEPTH_LIMIT: usize = 32;

/// Compiles one raw rule, or explains exactly which invariant it broke.
pub fn compile(raw: RawRule, pack: &str, xdg: &Xdg) -> Result<Rule, RuleError> {
    let RawRule {
        id,
        section,
        kind,
        root,
        evidence,
        recoverable,
        keep_days,
        keep_versions,
        requires,
        privilege,
        exclude,
        pattern,
        enabled,
        max_depth,
    } = raw;

    let id = RuleId::new(&id)
        .map_err(|error| fail(RuleErrorKind::BadId, pack, Some(&id), error.to_string()))?;
    let label = id.as_str().to_string();

    let section = Section::parse(&section).ok_or_else(|| {
        fail(
            RuleErrorKind::UnknownSection,
            pack,
            Some(&label),
            format!(
                "unknown section {section:?}; expected one of {}",
                Section::ALL
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    })?;

    let kind = Kind::parse(&kind).map_err(|note| match note {
        Some(note) => fail(RuleErrorKind::UnsupportedKind, pack, Some(&label), note),
        None => fail(
            RuleErrorKind::UnknownKind,
            pack,
            Some(&label),
            format!(
                "unknown kind {kind:?}; expected one of {}",
                Kind::ALL
                    .iter()
                    .map(|k| k.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ),
    })?;

    let privilege = Privilege::parse(&privilege).ok_or_else(|| {
        fail(
            RuleErrorKind::BadPrivilege,
            pack,
            Some(&label),
            format!("privilege {privilege:?} must be \"user\" or \"root\""),
        )
    })?;

    let template = Template::parse(&root).map_err(|error| {
        fail(
            RuleErrorKind::Template,
            pack,
            Some(&label),
            error.to_string(),
        )
    })?;
    let expanded = template.expand(xdg);

    // Patterns are compiled before the root checks because the one home-rooted
    // shape that is allowed depends on what the patterns can match.
    let patterns: Vec<String> = pattern.map(OneOrMany::into_vec).unwrap_or_default();
    if kind == Kind::FilePattern && patterns.is_empty() {
        return Err(fail(
            RuleErrorKind::MissingPattern,
            pack,
            Some(&label),
            "kind = \"file-pattern\" needs at least one pattern".to_string(),
        ));
    }
    if kind != Kind::FilePattern && !patterns.is_empty() {
        return Err(fail(
            RuleErrorKind::UnusedPattern,
            pack,
            Some(&label),
            format!("pattern is only read by kind = \"file-pattern\", not \"{kind}\""),
        ));
    }
    let patterns = compile_patterns(patterns, pack, &label, "pattern")?;
    let exclude = compile_patterns(exclude, pack, &label, "exclude")?;

    // `keep_versions` is the retention of `pkg-cache`. It is required there and
    // refused everywhere else, for the same reason `pattern` is: a key the
    // engine does not read would be printed by `rules list` as a promise the
    // run never keeps.
    let keep_versions =
        match (kind, keep_versions) {
            (Kind::PkgCache, None) => return Err(fail(
                RuleErrorKind::MissingKeepVersions,
                pack,
                Some(&label),
                "kind = \"pkg-cache\" needs keep_versions: how many versions of each package stay"
                    .to_string(),
            )),
            (Kind::PkgCache, Some(0)) => {
                return Err(fail(
                    RuleErrorKind::BadKeepVersions,
                    pack,
                    Some(&label),
                    "keep_versions = 0 would leave no version of anything in the cache; \
                 use at least 1"
                        .to_string(),
                ))
            }
            (Kind::PkgCache, Some(count)) => Some(count),
            (_, Some(_)) => {
                return Err(fail(
                    RuleErrorKind::UnusedKeepVersions,
                    pack,
                    Some(&label),
                    format!("keep_versions is only read by kind = \"pkg-cache\", not \"{kind}\""),
                ))
            }
            (_, None) => None,
        };

    // The remaining checks are ordered from "this would be catastrophic" to
    // "this would be confusing", so a rule with several problems reports the
    // one that matters.
    if kind.deletes() {
        if let Some(protected) = policy::match_root(&expanded) {
            return Err(fail(
                RuleErrorKind::ProtectedRoot,
                pack,
                Some(&label),
                format!(
                    "root {} is protected ({}); a rule cannot opt out of the compile-time list",
                    expanded.display(),
                    protected.why
                ),
            ));
        }
        // `~/.cache` is the one base directory whose entire content is
        // disposable by the XDG definition. Everything else would let one rule
        // mean "delete the user's data". `$HOME` itself is handled below, where
        // it is narrow enough to be safe.
        if expanded != xdg.cache && expanded != xdg.home {
            if let Some(what) = policy::match_identity(&expanded, xdg) {
                return Err(fail(
                    RuleErrorKind::BareRoot,
                    pack,
                    Some(&label),
                    format!(
                        "root {} is the {what}; name a directory below it",
                        expanded.display()
                    ),
                ));
            }
        }
        // `$HOME` is the narrowest root that is still a home directory, and only
        // two kinds may name it. `file-pattern` names literal text
        // (`.xsession-errors*` is a target; `*` is a way to delete a home
        // directory one file at a time). `project-artifacts` has no pattern and
        // does not need one: it never names a file to delete, it finds a project
        // by its manifest and then removes the build output that manifest
        // produced. The bound is `max_depth <= 6` and, below, a retention that is
        // never zero.
        if expanded == xdg.home {
            let allowed = (kind == Kind::FilePattern || kind == Kind::ProjectArtifacts)
                && max_depth.unwrap_or(8) <= 6;
            let literal = patterns.iter().all(Pattern::has_literal);
            if !allowed {
                return Err(fail(
                    RuleErrorKind::BareRoot,
                    pack,
                    Some(&label),
                    format!(
                        "root {} is the home directory; only kind = \"file-pattern\" or \
                         \"project-artifacts\" with max_depth <= 6 may use it",
                        expanded.display()
                    ),
                ));
            }
            if kind == Kind::FilePattern && !literal {
                return Err(fail(
                    RuleErrorKind::BadPattern,
                    pack,
                    Some(&label),
                    "a home-rooted pattern must name literal text, not only wildcards".to_string(),
                ));
            }
        }
        if depth(&expanded) < 2 {
            return Err(fail(
                RuleErrorKind::BareRoot,
                pack,
                Some(&label),
                format!(
                    "root {} is too broad; a deleting rule needs a directory inside it",
                    expanded.display()
                ),
            ));
        }
        // A base directory may only be touched with a retention window, so a
        // broad rule can never become "empty the cache, always".
        if (expanded == xdg.cache || expanded == xdg.runtime) && !matches!(kind, Kind::DirAge) {
            return Err(fail(
                RuleErrorKind::BareRoot,
                pack,
                Some(&label),
                format!(
                    "root {} is a base directory; only kind = \"dir-age\" may sweep it",
                    expanded.display()
                ),
            ));
        }
    } else {
        // Report-only never deletes, so a protected root is readable. The
        // pseudo-filesystems are the exception: walking them can block on a
        // device read or descend into an unbounded kernel view.
        for pseudo in ["/proc", "/sys", "/dev"] {
            if crate::paths::is_within(Path::new(pseudo), &expanded) {
                return Err(fail(
                    RuleErrorKind::BareRoot,
                    pack,
                    Some(&label),
                    format!("root {} is a kernel pseudo-filesystem", expanded.display()),
                ));
            }
        }
        if expanded == Path::new("/") {
            return Err(fail(
                RuleErrorKind::BareRoot,
                pack,
                Some(&label),
                "root / would walk the whole filesystem".to_string(),
            ));
        }
    }

    if kind.needs_evidence() && evidence.trim().is_empty() {
        return Err(fail(
            RuleErrorKind::MissingEvidence,
            pack,
            Some(&label),
            "kind needs a non-empty evidence line: why is it safe to delete here?".to_string(),
        ));
    }

    // The hub writes a blob first and the snapshot link second, and its
    // `.incomplete` files are updated in place while a download runs. A
    // retention of zero would treat both as leftovers the instant they exist,
    // so the kind refuses to load without a real window.
    if kind == Kind::HfCache && keep_days == 0 {
        return Err(fail(
            RuleErrorKind::UnsafeRetention,
            pack,
            Some(&label),
            "kind = \"hf-cache\" needs keep_days > 0: a blob with no snapshot link may belong \
             to a download that has not finished, so \"everything right now\" is not a safe rule"
                .to_string(),
        ));
    }

    // A home-rooted project sweep removes build directories wherever the walk
    // finds them, and "everything right now" would take the `node_modules` of the
    // project the user is in the middle of. Any positive window is allowed; zero
    // is not, and the way to purge one directory now is to root a rule at it.
    if kind == Kind::ProjectArtifacts && expanded == xdg.home && keep_days == 0 {
        return Err(fail(
            RuleErrorKind::UnsafeRetention,
            pack,
            Some(&label),
            "a home-rooted kind = \"project-artifacts\" needs keep_days > 0: every build \
             directory below $HOME is a project someone may be working in right now"
                .to_string(),
        ));
    }

    if keep_days == 0 && !recoverable {
        return Err(fail(
            RuleErrorKind::ZeroKeepDays,
            pack,
            Some(&label),
            "keep_days = 0 deletes anything not currently open; set recoverable = true to say so"
                .to_string(),
        ));
    }

    // A declared retention that the engine never reads is worse than no
    // retention: `rules list` would print "30d" while the run deleted a file
    // downloaded an hour ago. `dir-sweep` and `tool-cache` mean "everything",
    // so a retention only belongs on `dir-age`, `file-pattern` or `report-only`.
    if keep_days > 0 && matches!(kind, Kind::DirSweep | Kind::ToolCache) {
        return Err(fail(
            RuleErrorKind::IgnoredKeepDays,
            pack,
            Some(&label),
            format!(
                "kind = \"{kind}\" removes everything it finds, so keep_days = {keep_days} \
                 would be reported but never applied; use kind = \"dir-age\" or set keep_days = 0"
            ),
        ));
    }

    // A `root` rule outside `system` would need the privilege boundary that
    // arrives in M4 to delete anything, so it is refused. Report-only is exempt:
    // it never contributes a plan item, and a root-owned tree such as
    // `/var/lib/docker` or `/.snapshots` cannot even be read without it.
    if privilege == Privilege::Root && section != Section::System && kind.deletes() {
        return Err(fail(
            RuleErrorKind::RootPrivilege,
            pack,
            Some(&label),
            format!(
                "privilege = \"root\" is only allowed in section \"system\", not \"{section}\""
            ),
        ));
    }

    let requires = requires
        .into_iter()
        .map(|raw| {
            Requirement::parse(&raw).map_err(|message| {
                fail(
                    RuleErrorKind::Requirement,
                    pack,
                    Some(&label),
                    format!("requirement {raw:?}: {message}"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let max_depth = max_depth.unwrap_or(8);
    if max_depth == 0 || max_depth > MAX_DEPTH_LIMIT {
        return Err(fail(
            RuleErrorKind::BadDepth,
            pack,
            Some(&label),
            format!("max_depth must be between 1 and {MAX_DEPTH_LIMIT}, got {max_depth}"),
        ));
    }

    Ok(Rule {
        id,
        section,
        kind,
        root: template,
        evidence,
        recoverable,
        keep_days,
        keep_versions,
        requires,
        privilege,
        exclude,
        patterns,
        enabled,
        max_depth,
    })
}

fn compile_patterns(
    raw: Vec<String>,
    pack: &str,
    rule: &str,
    field: &str,
) -> Result<Vec<Pattern>, RuleError> {
    raw.into_iter()
        .map(|source| {
            Pattern::new(&source).map_err(|error| {
                fail(
                    RuleErrorKind::BadPattern,
                    pack,
                    Some(rule),
                    format!("{field} {source:?}: {error}"),
                )
            })
        })
        .collect()
}

/// Reads `~/.config/sweep/rules.d/*.toml` in file-name order.
///
/// The overlay may add rules only. Replacing a built-in rule by id is refused in
/// [`crate::rules::RuleSet::from_sources`], because "same id, different root" is how a
/// configuration file would widen what the compile-time policy allows.
pub fn user_sources(xdg: &Xdg) -> Result<Vec<Source>, Vec<RuleError>> {
    let directory = xdg.config_dir().join("rules.d");
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(vec![fail(
                RuleErrorKind::ReadFailed,
                &directory.display().to_string(),
                None,
                error.to_string(),
            )])
        }
    };

    let mut paths = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                return Err(vec![fail(
                    RuleErrorKind::ReadFailed,
                    &directory.display().to_string(),
                    None,
                    error.to_string(),
                )])
            }
        };
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            paths.push(path);
        }
    }
    paths.sort();

    let mut sources = Vec::new();
    for path in paths {
        match std::fs::read_to_string(&path) {
            Ok(body) => sources.push(Source::new(path.display().to_string(), body)),
            Err(error) => {
                return Err(vec![fail(
                    RuleErrorKind::ReadFailed,
                    &path.display().to_string(),
                    None,
                    error.to_string(),
                )])
            }
        }
    }
    Ok(sources)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleSet;

    fn xdg() -> Xdg {
        Xdg::resolve(|key| match key {
            "HOME" => Some("/home/u".into()),
            _ => None,
        })
        .expect("home")
    }

    fn pack(body: &str) -> Result<RuleSet, Vec<RuleError>> {
        RuleSet::from_sources(&[Source::new("test.toml", body)], &xdg())
    }

    fn one(body: &str) -> Result<RuleSet, Vec<RuleError>> {
        pack(body)
    }

    fn base(id: &str) -> String {
        format!(
            r#"
[[rule]]
id = "{id}"
section = "dev-tools"
kind = "dir-age"
root = "{{cache}}/example"
evidence = "regenerated by the tool"
recoverable = true
keep_days = 30
privilege = "user"
"#
        )
    }

    fn first_error(set: Result<RuleSet, Vec<RuleError>>) -> RuleError {
        set.expect_err("must be refused").remove(0)
    }

    #[test]
    fn a_valid_rule_loads() {
        let set = one(&base("dev.example.cache")).expect("loads");
        let rule = &set.rules()[0];
        assert_eq!(rule.id.as_str(), "dev.example.cache");
        assert_eq!(rule.section, Section::DevTools);
        assert_eq!(rule.kind, Kind::DirAge);
        assert_eq!(rule.privilege, Privilege::User);
        assert_eq!(rule.max_depth, 8);
        assert!(rule.enabled);
    }

    #[test]
    fn a_typo_in_a_key_is_a_parse_error_not_a_default() {
        // `keep_day` would otherwise leave keep_days at 0, which means
        // "delete anything not open right now".
        let body = base("dev.example.cache").replace("keep_days", "keep_day");
        let error = first_error(one(&body));
        assert_eq!(error.kind, RuleErrorKind::Toml);
        assert!(error.message.contains("keep_day"), "{}", error.message);
    }

    #[test]
    fn a_protected_root_is_refused_with_the_reason() {
        let body = base("dev.bad").replace("{cache}/example", "/var/lib/pacman");
        let error = first_error(one(&body));
        assert_eq!(error.kind, RuleErrorKind::ProtectedRoot);
        assert!(error.message.contains("package"), "{}", error.message);
    }

    #[test]
    fn the_home_directory_cannot_be_a_root() {
        let body = base("dev.bad").replace("{cache}/example", "{home}");
        let error = first_error(one(&body));
        assert_eq!(error.kind, RuleErrorKind::BareRoot);
    }

    #[test]
    fn config_and_data_cannot_be_roots() {
        // `{runtime}` lands under `/run`, which is a protected root, so it is
        // refused one check earlier; either refusal is the point of the test.
        for root in ["{config}", "{data}", "{state}", "{runtime}"] {
            let body = base("dev.bad").replace("{cache}/example", root);
            let error = first_error(one(&body));
            assert!(
                matches!(
                    error.kind,
                    RuleErrorKind::BareRoot | RuleErrorKind::ProtectedRoot
                ),
                "{root}: {:?}",
                error.kind
            );
        }
    }

    #[test]
    fn the_cache_base_may_only_be_swept_by_age() {
        let sweep = base("dev.bad")
            .replace("{cache}/example", "{cache}")
            .replace("dir-age", "dir-sweep");
        let error = first_error(one(&sweep));
        assert_eq!(error.kind, RuleErrorKind::BareRoot);
        assert!(error.message.contains("dir-age"), "{}", error.message);

        let aged = base("dev.bad").replace("{cache}/example", "{cache}");
        assert!(one(&aged).is_ok());
    }

    #[test]
    fn identity_directories_cannot_be_roots() {
        let body = base("dev.bad").replace("{cache}/example", "{home}/.ssh");
        let error = first_error(one(&body));
        assert_eq!(error.kind, RuleErrorKind::BareRoot);
        assert!(error.message.contains("identity"), "{}", error.message);
    }

    #[test]
    fn a_shallow_root_is_refused() {
        let body = base("dev.bad").replace("{cache}/example", "/var");
        let error = first_error(one(&body));
        assert_eq!(error.kind, RuleErrorKind::BareRoot);
    }

    #[test]
    fn a_root_with_a_parent_component_is_refused() {
        let body = base("dev.bad").replace("{cache}/example", "{cache}/../cargo");
        let error = first_error(one(&body));
        assert_eq!(error.kind, RuleErrorKind::Template);
        assert!(error.message.contains("parent"), "{}", error.message);
    }

    #[test]
    fn a_deleting_rule_needs_evidence() {
        let body = base("dev.bad").replace("evidence = \"regenerated by the tool\"", "");
        let error = first_error(one(&body));
        assert_eq!(error.kind, RuleErrorKind::MissingEvidence);
    }

    #[test]
    fn a_report_only_rule_does_not_need_evidence() {
        let body = r#"
[[rule]]
id = "report.journal"
section = "system"
kind = "report-only"
root = "/var/log/journal"
keep_days = 7
privilege = "root"
"#;
        let set = one(body).expect("loads");
        assert_eq!(set.rules()[0].kind, Kind::ReportOnly);
    }

    #[test]
    fn a_pseudo_filesystem_cannot_be_reported_on() {
        let body = r#"
[[rule]]
id = "report.proc"
section = "system"
kind = "report-only"
root = "/proc"
keep_days = 7
privilege = "root"
"#;
        let error = first_error(one(body));
        assert_eq!(error.kind, RuleErrorKind::BareRoot);
        assert!(error.message.contains("pseudo"), "{}", error.message);
    }

    #[test]
    fn zero_keep_days_requires_an_explicitly_recoverable_target() {
        let body = base("dev.bad")
            .replace("keep_days = 30", "keep_days = 0")
            .replace("recoverable = true", "recoverable = false");
        let error = first_error(one(&body));
        assert_eq!(error.kind, RuleErrorKind::ZeroKeepDays);

        let body = base("dev.ok").replace("keep_days = 30", "keep_days = 0");
        assert!(one(&body).is_ok());
    }

    #[test]
    fn a_hub_cache_needs_a_real_retention() {
        // The hub writes a blob before the snapshot link that references it, and
        // an `.incomplete` file is only a leftover once it stops growing.
        let body = base("model.hub")
            .replace("dir-age", "hf-cache")
            .replace("keep_days = 30", "keep_days = 0");
        let error = first_error(one(&body));
        assert_eq!(error.kind, RuleErrorKind::UnsafeRetention);
        assert!(
            error.message.contains("hf-cache"),
            "the refusal must name the kind: {}",
            error.message
        );

        let ok = base("model.hub").replace("dir-age", "hf-cache");
        let set = one(&ok).expect("a retention makes the rule safe");
        assert_eq!(set.rules()[0].kind, Kind::HfCache);
        assert_eq!(set.rules()[0].keep_days, 30);
    }

    #[test]
    fn a_hub_cache_ignores_patterns_like_every_other_kind() {
        let body = format!(
            "{}\npattern = \"*.bin\"\n",
            base("model.hub").replace("dir-age", "hf-cache")
        );
        let error = first_error(one(&body));
        assert_eq!(error.kind, RuleErrorKind::UnusedPattern);
    }

    #[test]
    fn a_retention_the_kind_never_reads_is_refused() {
        // `rules list` prints keep_days, so a value the engine ignores would be
        // a report that disagrees with the run.
        for kind in ["dir-sweep", "tool-cache"] {
            let body = base("dev.bad").replace("dir-age", kind);
            let error = first_error(one(&body));
            assert_eq!(error.kind, RuleErrorKind::IgnoredKeepDays, "{kind}");
            assert!(error.message.contains("dir-age"), "{}", error.message);

            let body = base("dev.ok")
                .replace("dir-age", kind)
                .replace("keep_days = 30", "keep_days = 0");
            assert!(one(&body).is_ok(), "{kind} with keep_days = 0");
        }
    }

    #[test]
    fn root_privilege_outside_the_system_section_is_refused() {
        let body = base("dev.bad").replace("privilege = \"user\"", "privilege = \"root\"");
        let error = first_error(one(&body));
        assert_eq!(error.kind, RuleErrorKind::RootPrivilege);
    }

    #[test]
    fn an_unknown_section_is_refused() {
        let body = base("dev.bad").replace("dev-tools", "cleanup");
        let error = first_error(one(&body));
        assert_eq!(error.kind, RuleErrorKind::UnknownSection);
        assert!(
            error.message.contains("user-essentials"),
            "{}",
            error.message
        );
    }

    #[test]
    fn if_missing_owner_is_refused_with_a_date() {
        let body = base("dev.bad").replace("dir-age", "if-missing-owner");
        let error = first_error(one(&body));
        assert_eq!(error.kind, RuleErrorKind::UnsupportedKind);
        assert!(error.message.contains("M5"), "{}", error.message);
    }

    #[test]
    fn a_duplicate_id_is_refused_even_for_a_user_pack() {
        let body = format!(
            "{}{}",
            base("dev.same"),
            base("dev.same").replace("keep_days = 30", "keep_days = 7")
        );
        let error = first_error(one(&body));
        assert_eq!(error.kind, RuleErrorKind::DuplicateId);
        assert!(error.message.contains("add rules"), "{}", error.message);
    }

    #[test]
    fn an_empty_pack_is_refused() {
        let error = first_error(one("[meta]\nname = \"placeholder\"\n"));
        assert_eq!(error.kind, RuleErrorKind::NoRules);
    }

    #[test]
    fn file_pattern_requires_a_pattern_and_others_refuse_one() {
        let missing = base("dev.bad").replace("dir-age", "file-pattern");
        assert_eq!(
            first_error(one(&missing)).kind,
            RuleErrorKind::MissingPattern
        );

        let unused = base("dev.bad").replace(
            "privilege = \"user\"",
            "privilege = \"user\"\npattern = \"*.log\"",
        );
        assert_eq!(first_error(one(&unused)).kind, RuleErrorKind::UnusedPattern);
    }

    #[test]
    fn an_invalid_glob_is_reported_with_its_field() {
        let body = base("dev.bad").replace(
            "privilege = \"user\"",
            "privilege = \"user\"\nexclude = [\"/absolute\"]",
        );
        let error = first_error(one(&body));
        assert_eq!(error.kind, RuleErrorKind::BadPattern);
        assert!(error.message.contains("exclude"), "{}", error.message);
    }

    #[test]
    fn depth_bounds_are_enforced() {
        for depth in ["0", "33"] {
            let body = base("dev.bad").replace(
                "privilege = \"user\"",
                &format!("privilege = \"user\"\nmax_depth = {depth}"),
            );
            assert_eq!(
                first_error(one(&body)).kind,
                RuleErrorKind::BadDepth,
                "{depth}"
            );
        }
    }

    #[test]
    fn every_error_in_a_pack_is_reported_at_once() {
        let body = format!(
            "{}{}{}",
            base("UPPER"),
            base("dev.ok"),
            base("dev.bad").replace("{cache}/example", "/usr/share")
        );
        let errors = one(&body).expect_err("two bad rules");
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].kind, RuleErrorKind::BadId);
        assert_eq!(errors[1].kind, RuleErrorKind::ProtectedRoot);
    }

    #[test]
    fn error_codes_are_stable_and_unique() {
        let kinds = [
            RuleErrorKind::Toml,
            RuleErrorKind::NoRules,
            RuleErrorKind::ReadFailed,
            RuleErrorKind::BadId,
            RuleErrorKind::DuplicateId,
            RuleErrorKind::UnknownSection,
            RuleErrorKind::UnknownKind,
            RuleErrorKind::UnsupportedKind,
            RuleErrorKind::BadPrivilege,
            RuleErrorKind::Template,
            RuleErrorKind::ProtectedRoot,
            RuleErrorKind::BareRoot,
            RuleErrorKind::MissingEvidence,
            RuleErrorKind::ZeroKeepDays,
            RuleErrorKind::UnsafeRetention,
            RuleErrorKind::RootPrivilege,
            RuleErrorKind::MissingPattern,
            RuleErrorKind::UnusedPattern,
            RuleErrorKind::BadPattern,
            RuleErrorKind::Requirement,
            RuleErrorKind::BadDepth,
        ];
        let mut codes: Vec<&str> = kinds.iter().map(|kind| kind.code()).collect();
        let before = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), before);
    }

    #[test]
    fn a_user_pack_that_cannot_be_read_is_reported_not_ignored() {
        let temp = tempfile::tempdir().unwrap();
        let xdg = Xdg::resolve(|key| match key {
            "HOME" => Some(temp.path().as_os_str().to_os_string()),
            _ => None,
        })
        .unwrap();
        // A file where the directory should be: read_dir fails with ENOTDIR,
        // which must not read as "no overlay".
        std::fs::create_dir_all(xdg.config_dir()).unwrap();
        std::fs::write(xdg.config_dir().join("rules.d"), b"not a directory").unwrap();
        let errors = user_sources(&xdg).expect_err("must be reported");
        assert_eq!(errors[0].kind, RuleErrorKind::ReadFailed);
    }

    #[test]
    fn a_missing_overlay_directory_is_not_an_error() {
        let temp = tempfile::tempdir().unwrap();
        let xdg = Xdg::resolve(|key| match key {
            "HOME" => Some(temp.path().as_os_str().to_os_string()),
            _ => None,
        })
        .unwrap();
        assert!(user_sources(&xdg).expect("missing dir is fine").is_empty());
    }

    #[test]
    fn an_overlay_adds_rules_and_cannot_replace_a_builtin() {
        let temp = tempfile::tempdir().unwrap();
        let xdg = Xdg::resolve(|key| match key {
            "HOME" => Some(temp.path().as_os_str().to_os_string()),
            _ => None,
        })
        .unwrap();
        let rules = xdg.config_dir().join("rules.d");
        std::fs::create_dir_all(&rules).unwrap();

        let extra = base("user.extra.cache").replace("{cache}/example", "{cache}/mine");
        std::fs::write(rules.join("10-extra.toml"), extra).unwrap();
        let set = RuleSet::load(&xdg).expect("builtins plus overlay");
        assert!(set
            .rules()
            .iter()
            .any(|rule| rule.id.as_str() == "user.extra.cache"));
    }
}
