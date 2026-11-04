//! The rule engine: TOML packs compiled into validated rules.
//!
//! A rule is data. It names a root, a kind, a retention and the evidence that
//! deleting there is safe. Nothing in this module deletes: a rule only describes
//! what *may* be scanned, and every candidate still goes through
//! [`crate::plan::Plan::push`] and its twenty checks.
//!
//! Load-time validation is the other half of the safety story. A rule that
//! points at `/usr`, that has no evidence, or whose id collides with another
//! rule stops the program before a single directory is read. The checks are in
//! [`check`], and [`RuleSet::load`] refuses to return a set that failed any of
//! them.

pub mod builtin;
pub mod check;
pub mod glob;
pub mod schema;
pub mod template;

pub use check::{RuleError, RuleErrorKind};
pub use glob::{Pattern, PatternError};
pub use template::{Base, Template, TemplateError};

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::PathBuf;

use crate::plan::RuleId;
use crate::Xdg;

/// The sixteen sections a rule may belong to.
///
/// The list is closed on purpose: a new section is a product decision (it needs
/// a place in `clean`'s report), not something a rule file can invent by typing
/// a new string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Section {
    System,
    UserEssentials,
    AppCaches,
    Browsers,
    CloudOffice,
    DevTools,
    Apps,
    Virtualization,
    LocalData,
    Orphans,
    Aur,
    Firmware,
    Snapshots,
    Installers,
    ProjectArtifacts,
    ModelCaches,
}

impl Section {
    pub const ALL: [Section; 16] = [
        Section::System,
        Section::UserEssentials,
        Section::AppCaches,
        Section::Browsers,
        Section::CloudOffice,
        Section::DevTools,
        Section::Apps,
        Section::Virtualization,
        Section::LocalData,
        Section::Orphans,
        Section::Aur,
        Section::Firmware,
        Section::Snapshots,
        Section::Installers,
        Section::ProjectArtifacts,
        Section::ModelCaches,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Section::System => "system",
            Section::UserEssentials => "user-essentials",
            Section::AppCaches => "app-caches",
            Section::Browsers => "browsers",
            Section::CloudOffice => "cloud-office",
            Section::DevTools => "dev-tools",
            Section::Apps => "apps",
            Section::Virtualization => "virtualization",
            Section::LocalData => "local-data",
            Section::Orphans => "orphans",
            Section::Aur => "aur",
            Section::Firmware => "firmware",
            Section::Snapshots => "snapshots",
            Section::Installers => "installers",
            Section::ProjectArtifacts => "project-artifacts",
            Section::ModelCaches => "model-caches",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|section| section.as_str() == name)
    }

    /// True when the section needs privilege for every rule in it.
    pub fn is_privileged(self) -> bool {
        matches!(self, Section::System)
    }

    /// True when nothing in the section is swept unless the user names it.
    ///
    /// Model weights are the one target that may not be re-downloadable: a
    /// gated repository needs a licence acceptance, a private one needs a token,
    /// and an offline machine can reach neither. So the section is skipped in a
    /// bare run and listed as skipped, and `--only model-caches` is the consent
    /// that turns it on. The rules stay enabled so that naming the section is
    /// enough; there is no separate switch to keep in sync.
    pub fn is_opt_in(self) -> bool {
        matches!(self, Section::ModelCaches)
    }

    /// The command that owns the section, when it is not one `clean` sweeps.
    ///
    /// A bare `sweep clean` sweeps caches whose root the rule itself names. A
    /// project directory is not that: it is found by walking the user's home,
    /// and the walk needs its own preview and its own command. The owner is
    /// named here so that the skip message and the section filter cannot
    /// disagree about who owns it.
    pub fn command(self) -> Option<&'static str> {
        match self {
            Section::Aur => Some("aur"),
            Section::Installers => Some("installer"),
            Section::ProjectArtifacts => Some("purge"),
            _ => None,
        }
    }

    /// True when the section belongs to a command of its own rather than to
    /// `clean`.
    ///
    /// Naming it with `--only` is still allowed, because that is a user asking
    /// for it by name.
    pub fn is_command_scoped(self) -> bool {
        self.command().is_some()
    }
}

impl std::fmt::Display for Section {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Section {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Section::parse(value).ok_or_else(|| {
            format!(
                "unknown section {value:?}; expected one of {}",
                Section::ALL
                    .iter()
                    .map(|section| section.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
    }
}

/// What a rule does with the entries it finds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Remove every entry below the root; the root stays.
    DirSweep,
    /// Remove each top-level entry whose whole subtree is older than the
    /// retention; the root stays.
    DirAge,
    /// Remove files below the root whose name matches `pattern`.
    FilePattern,
    /// Remove every entry below the root, then the root itself.
    ToolCache,
    /// Empty the freedesktop trash: each entry's payload, then the
    /// `.trashinfo` record that names it, so no restore entry outlives the file
    /// it points at.
    TrashEmpty,
    /// Remove what a Hugging Face hub cache has left behind: blobs no snapshot
    /// links to, and abandoned `*.incomplete` downloads.
    HfCache,
    /// Keep the newest N versions of every package in a package-manager cache
    /// and remove the rest; `keep_days` acts as a recency floor.
    PkgCache,
    /// Remove build artifacts inside project directories, found by manifest.
    /// `node_modules` alone is not evidence; the `package.json` beside it is.
    ProjectArtifacts,
    /// Count and describe; never contributes a plan item.
    ReportOnly,
}

impl Kind {
    pub const ALL: [Kind; 9] = [
        Kind::DirSweep,
        Kind::DirAge,
        Kind::FilePattern,
        Kind::ToolCache,
        Kind::TrashEmpty,
        Kind::HfCache,
        Kind::PkgCache,
        Kind::ProjectArtifacts,
        Kind::ReportOnly,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::DirSweep => "dir-sweep",
            Kind::DirAge => "dir-age",
            Kind::FilePattern => "file-pattern",
            Kind::ToolCache => "tool-cache",
            Kind::TrashEmpty => "trash-empty",
            Kind::HfCache => "hf-cache",
            Kind::PkgCache => "pkg-cache",
            Kind::ProjectArtifacts => "project-artifacts",
            Kind::ReportOnly => "report-only",
        }
    }

    /// `Err(Some(note))` for a kind that is recognised but not implemented, so
    /// the message can name the supported alternative instead of "unknown kind".
    pub fn parse(name: &str) -> Result<Self, Option<&'static str>> {
        Ok(match name {
            "dir-sweep" => Kind::DirSweep,
            "dir-age" => Kind::DirAge,
            "file-pattern" => Kind::FilePattern,
            "tool-cache" => Kind::ToolCache,
            "trash-empty" => Kind::TrashEmpty,
            "hf-cache" => Kind::HfCache,
            "pkg-cache" => Kind::PkgCache,
            "project-artifacts" => Kind::ProjectArtifacts,
            "report-only" => Kind::ReportOnly,
            "if-missing-owner" => {
                return Err(Some(
                    "kind \"if-missing-owner\" is not supported: the rule engine does not read \
                     the package database; use kind = \"report-only\" and confirm the owner \
                     yourself",
                ))
            }
            _ => return Err(None),
        })
    }

    /// True when the kind contributes plan items and therefore gets the full
    /// protected-root and bare-root checks.
    pub fn deletes(self) -> bool {
        !matches!(self, Kind::ReportOnly)
    }

    pub fn needs_evidence(self) -> bool {
        self.deletes()
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    User,
    Root,
}

impl Privilege {
    pub fn as_str(self) -> &'static str {
        match self {
            Privilege::User => "user",
            Privilege::Root => "root",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "user" => Some(Privilege::User),
            "root" => Some(Privilege::Root),
            _ => None,
        }
    }
}

impl std::fmt::Display for Privilege {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A precondition: a command on `PATH`, or a directory that must exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requirement {
    Bin(String),
    Dir(Template),
}

impl Requirement {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let Some((prefix, value)) = raw.split_once(':') else {
            return Err(format!(
                "requirement {raw:?} needs a prefix; expected bin:<name> or dir:<path>"
            ));
        };
        match prefix {
            "bin" => {
                if value.is_empty() {
                    return Err("requirement bin: needs a command name".to_string());
                }
                if value.contains('/') {
                    return Err(format!(
                        "requirement {raw:?} names a path; bin: takes a command name"
                    ));
                }
                if value.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
                    return Err("requirement contains a control byte".to_string());
                }
                Ok(Requirement::Bin(value.to_string()))
            }
            "dir" => {
                let template = Template::parse(value).map_err(|error| error.to_string())?;
                Ok(Requirement::Dir(template))
            }
            "pkg" => Err(
                "the pkg: prefix is not supported: the rule engine does not read the package \
                 database; use bin: or dir:"
                    .to_string(),
            ),
            other => Err(format!(
                "unknown requirement prefix {other:?}; expected bin: or dir:"
            )),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Requirement::Bin(name) => format!("bin:{name}"),
            Requirement::Dir(template) => format!("dir:{}", template.raw()),
        }
    }

    /// Resolved against the machine, for the rule report.
    pub fn satisfied(&self, xdg: &Xdg) -> bool {
        self.satisfied_with(xdg, std::env::var_os("PATH").as_deref())
    }

    fn satisfied_with(&self, xdg: &Xdg, path_var: Option<&OsStr>) -> bool {
        match self {
            Requirement::Bin(name) => command_on_path(name, path_var),
            Requirement::Dir(template) => template.expand(xdg).is_dir(),
        }
    }
}

impl std::fmt::Display for Requirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label())
    }
}

fn command_on_path(name: &str, path_var: Option<&OsStr>) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Some(path_var) = path_var else {
        return false;
    };
    std::env::split_paths(path_var).any(|dir| {
        let candidate = dir.join(name);
        std::fs::metadata(&candidate)
            .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    })
}

/// A compiled rule. Construction is in [`check::compile`], which cannot skip a
/// validation: the fields are private to the crate only for mutation, not for
/// reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: RuleId,
    pub section: Section,
    pub kind: Kind,
    pub root: Template,
    pub evidence: String,
    pub recoverable: bool,
    pub keep_days: u32,
    /// How many versions of a package to keep. `Some` only for `pkg-cache`.
    pub keep_versions: Option<u32>,
    pub requires: Vec<Requirement>,
    pub privilege: Privilege,
    pub exclude: Vec<Pattern>,
    pub patterns: Vec<Pattern>,
    pub enabled: bool,
    pub max_depth: usize,
}

impl Rule {
    pub fn expanded_root(&self, xdg: &Xdg) -> PathBuf {
        self.root.expand(xdg)
    }

    /// Files older than this instant are candidates. `keep_days = 0` means
    /// "everything that already exists".
    pub fn cutoff(&self, now: i64) -> i64 {
        now.saturating_sub(i64::from(self.keep_days) * 86_400)
    }

    /// The first unmet precondition, if any.
    pub fn missing_requirement(&self, xdg: &Xdg) -> Option<&Requirement> {
        self.requires
            .iter()
            .find(|requirement| !requirement.satisfied(xdg))
    }

    pub fn matches_pattern(&self, relative: &std::path::Path) -> bool {
        self.patterns
            .iter()
            .any(|pattern| pattern.matches_relative(relative))
    }

    pub fn excludes(&self, relative: &std::path::Path) -> bool {
        self.exclude
            .iter()
            .any(|pattern| pattern.matches_relative(relative))
    }

    /// True when the rule is switched off by its own declaration.
    pub fn is_declared_disabled(&self) -> bool {
        !self.enabled
    }
}

/// A rule pack read from disk (or from the binary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// Display name, e.g. `rules/06-dev-tools.toml`.
    pub name: String,
    pub body: String,
}

impl Source {
    pub fn new(name: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            body: body.into(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionSummary {
    pub section: Section,
    pub rules: usize,
    pub enabled: usize,
}

impl RuleSet {
    /// Built-in packs plus `~/.config/sweep/rules.d/*.toml`.
    pub fn load(xdg: &Xdg) -> Result<Self, Vec<RuleError>> {
        let mut sources = builtin::sources();
        sources.extend(check::user_sources(xdg)?);
        Self::from_sources(&sources, xdg)
    }

    /// Built-in packs only, for `rules verify` on a machine whose user config is
    /// suspect and for tests that must not read the developer's home.
    pub fn load_builtin(xdg: &Xdg) -> Result<Self, Vec<RuleError>> {
        Self::from_sources(&builtin::sources(), xdg)
    }

    /// Compiles every pack. Returns every error rather than the first, because a
    /// rule file with three typos should take one run to fix, not three.
    pub fn from_sources(sources: &[Source], xdg: &Xdg) -> Result<Self, Vec<RuleError>> {
        let mut errors = Vec::new();
        let mut rules: Vec<Rule> = Vec::new();
        let mut seen: BTreeSet<RuleId> = BTreeSet::new();

        for source in sources {
            let pack: schema::RulePack = match toml::from_str(&source.body) {
                Ok(pack) => pack,
                Err(error) => {
                    errors.push(RuleError {
                        kind: RuleErrorKind::Toml,
                        pack: source.name.clone(),
                        rule: None,
                        message: error.to_string(),
                    });
                    continue;
                }
            };

            if pack.rules.is_empty() {
                errors.push(RuleError {
                    kind: RuleErrorKind::NoRules,
                    pack: source.name.clone(),
                    rule: None,
                    message: "pack contains no [[rule]] entries".to_string(),
                });
                continue;
            }

            for raw in pack.rules {
                match check::compile(raw, &source.name, xdg) {
                    Ok(rule) => {
                        if !seen.insert(rule.id.clone()) {
                            errors.push(RuleError {
                                kind: RuleErrorKind::DuplicateId,
                                pack: source.name.clone(),
                                rule: Some(rule.id.to_string()),
                                message:
                                    "id is already defined; a user pack may add rules, not replace one"
                                        .to_string(),
                            });
                            continue;
                        }
                        rules.push(rule);
                    }
                    Err(error) => errors.push(error),
                }
            }
        }

        if errors.is_empty() {
            Ok(Self { rules })
        } else {
            Err(errors)
        }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn get(&self, id: &RuleId) -> Option<&Rule> {
        self.rules.iter().find(|rule| &rule.id == id)
    }

    /// Per-section totals in the canonical section order.
    pub fn sections(&self) -> Vec<SectionSummary> {
        Section::ALL
            .into_iter()
            .filter_map(|section| {
                let rules: Vec<&Rule> = self
                    .rules
                    .iter()
                    .filter(|rule| rule.section == section)
                    .collect();
                if rules.is_empty() {
                    return None;
                }
                Some(SectionSummary {
                    section,
                    rules: rules.len(),
                    enabled: rules.iter().filter(|rule| rule.enabled).count(),
                })
            })
            .collect()
    }

    /// Rules in the selected sections, deepest root first so a narrow rule wins
    /// the deduplication against a broader one that would cover it.
    pub fn select(&self, sections: &[Section], xdg: &Xdg) -> Vec<&Rule> {
        let mut selected: Vec<&Rule> = self
            .rules
            .iter()
            .filter(|rule| sections.is_empty() || sections.contains(&rule.section))
            .collect();
        selected.sort_by_key(|rule| {
            let depth = rule.expanded_root(xdg).components().count();
            // Descending depth: sort by the negated depth, then by id for a
            // deterministic order.
            (std::cmp::Reverse(depth), rule.id.clone())
        });
        selected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn xdg() -> Xdg {
        Xdg::resolve(|key| match key {
            "HOME" => Some("/home/u".into()),
            _ => None,
        })
        .expect("home")
    }

    #[test]
    fn every_section_round_trips_through_its_name() {
        assert_eq!(Section::ALL.len(), 16);
        for section in Section::ALL {
            assert_eq!(Section::parse(section.as_str()), Some(section));
            assert_eq!(
                section.as_str().parse::<Section>().ok(),
                Some(section),
                "{section}"
            );
        }
    }

    #[test]
    fn an_unknown_section_lists_the_valid_ones() {
        let error = "cleanup".parse::<Section>().unwrap_err();
        assert!(error.contains("user-essentials"), "{error}");
    }

    #[test]
    fn section_names_are_unique() {
        let mut names: Vec<&str> = Section::ALL.iter().map(|s| s.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before);
    }

    #[test]
    fn every_kind_round_trips_through_its_name() {
        for kind in Kind::ALL {
            assert_eq!(Kind::parse(kind.as_str()), Ok(kind));
        }
    }

    #[test]
    fn if_missing_owner_names_the_alternative() {
        let error = Kind::parse("if-missing-owner").unwrap_err();
        let note = error.expect("note");
        assert!(note.contains("not supported"), "{note}");
        assert!(note.contains("report-only"), "{note}");
        assert!(Kind::parse("dir_sweep").unwrap_err().is_none());
    }

    #[test]
    fn requirements_parse_by_prefix() {
        assert_eq!(
            Requirement::parse("bin:cargo").unwrap(),
            Requirement::Bin("cargo".into())
        );
        assert!(matches!(
            Requirement::parse("dir:{home}/.cargo").unwrap(),
            Requirement::Dir(_)
        ));
        assert!(Requirement::parse("cargo").is_err());
        assert!(Requirement::parse("bin:/usr/bin/cargo").is_err());
        let error = Requirement::parse("pkg:pacman").unwrap_err();
        assert!(error.contains("not supported"), "{error}");
        assert!(error.contains("bin: or dir:"), "{error}");
    }

    #[test]
    fn a_bin_requirement_checks_the_executable_bit() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let bin = temp.path().join("tool");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        let requirement = Requirement::Bin("tool".into());
        assert!(requirement.satisfied_with(&xdg(), Some(temp.path().as_os_str())));

        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!requirement.satisfied_with(&xdg(), Some(temp.path().as_os_str())));
        assert!(!requirement.satisfied_with(&xdg(), None));
    }

    #[test]
    fn a_dir_requirement_expands_the_template() {
        let temp = tempfile::tempdir().unwrap();
        let xdg = Xdg::resolve(|key| match key {
            "HOME" => Some(temp.path().as_os_str().to_os_string()),
            _ => None,
        })
        .unwrap();
        std::fs::create_dir_all(temp.path().join(".cargo")).unwrap();
        let requirement = Requirement::parse("dir:{home}/.cargo").unwrap();
        assert!(requirement.satisfied(&xdg));
        let missing = Requirement::parse("dir:{home}/.rustup").unwrap();
        assert!(!missing.satisfied(&xdg));
    }

    #[test]
    fn select_puts_the_deeper_root_first() {
        let xdg = xdg();
        let sources = vec![Source::new(
            "test.toml",
            r#"
[[rule]]
id = "broad"
section = "user-essentials"
kind = "dir-age"
root = "{cache}"
evidence = "cache"
recoverable = true
keep_days = 7
privilege = "user"

[[rule]]
id = "narrow"
section = "user-essentials"
kind = "dir-age"
root = "{cache}/thumbnails"
evidence = "thumbnails"
recoverable = true
keep_days = 30
privilege = "user"
"#,
        )];
        let set = RuleSet::from_sources(&sources, &xdg).expect("loads");
        let selected = set.select(&[], &xdg);
        assert_eq!(selected[0].id.as_str(), "narrow");
        assert_eq!(selected[1].id.as_str(), "broad");
    }

    #[test]
    fn select_filters_by_section() {
        let xdg = xdg();
        let sources = builtin::sources();
        let set = RuleSet::from_sources(&sources, &xdg).expect("builtins load");
        let selected = set.select(&[Section::DevTools], &xdg);
        assert!(!selected.is_empty());
        assert!(selected
            .iter()
            .all(|rule| rule.section == Section::DevTools));
    }

    #[test]
    fn section_totals_count_disabled_rules() {
        // The section header says "N rules, M enabled": a rule that is switched
        // off is still part of the catalog and must not disappear from the
        // total, or a reviewer cannot see what exists.
        let xdg = xdg();
        let body = r#"
[[rule]]
id = "test.on"
section = "user-essentials"
kind = "dir-sweep"
root = "{cache}/on"
evidence = "a fixture that exists only in this test"
recoverable = true
privilege = "user"

[[rule]]
id = "test.off"
section = "user-essentials"
kind = "dir-sweep"
root = "{cache}/off"
evidence = "a fixture that exists only in this test"
recoverable = true
privilege = "user"
enabled = false
"#;
        let set =
            RuleSet::from_sources(&[Source::new("test.toml", body)], &xdg).expect("fixture loads");
        let summary = set
            .sections()
            .into_iter()
            .find(|summary| summary.section == Section::UserEssentials)
            .expect("the fixture section");
        assert_eq!(summary.rules, 2, "the total includes what is switched off");
        assert_eq!(summary.enabled, 1);
    }

    #[test]
    fn expanded_roots_are_absolute() {
        let xdg = xdg();
        let set = RuleSet::from_sources(&builtin::sources(), &xdg).expect("builtins load");
        for rule in set.rules() {
            let root = rule.expanded_root(&xdg);
            assert!(root.is_absolute(), "{} -> {}", rule.id, root.display());
            assert!(
                !root
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir)),
                "{} -> {}",
                rule.id,
                root.display()
            );
        }
    }

    #[test]
    fn builtin_ids_are_unique_and_sections_are_covered() {
        let xdg = xdg();
        let set = RuleSet::from_sources(&builtin::sources(), &xdg).expect("builtins load");
        let mut ids: Vec<String> = set.rules().iter().map(|r| r.id.to_string()).collect();
        ids.sort();
        let before = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), before, "duplicate built-in rule id");
        let covered: BTreeSet<Section> = set.rules().iter().map(|r| r.section).collect();
        assert_eq!(covered.len(), 16, "every section needs at least one rule");
    }

    #[test]
    fn rule_cutoffs_are_in_the_past() {
        let xdg = xdg();
        let set = RuleSet::from_sources(&builtin::sources(), &xdg).expect("builtins load");
        let now = 1_700_000_000;
        for rule in set.rules() {
            assert!(rule.cutoff(now) <= now, "{}", rule.id);
        }
    }

    #[test]
    fn pattern_and_exclude_lookup_work_through_the_rule() {
        let xdg = xdg();
        let sources = vec![Source::new(
            "test.toml",
            r#"
[[rule]]
id = "a.b"
section = "dev-tools"
kind = "file-pattern"
root = "{cache}/x"
evidence = "crates"
recoverable = true
keep_days = 30
privilege = "user"
pattern = ["*.crate", "*.tmp"]
exclude = ["keep/**"]
"#,
        )];
        let set = RuleSet::from_sources(&sources, &xdg).expect("loads");
        let rule = &set.rules()[0];
        assert!(rule.matches_pattern(Path::new("a/x.crate")));
        assert!(rule.matches_pattern(Path::new("b/y.tmp")));
        assert!(!rule.matches_pattern(Path::new("b/y.zip")));
        assert!(rule.excludes(Path::new("keep")));
        assert!(rule.excludes(Path::new("keep/deep/file")));
        assert!(!rule.excludes(Path::new("other")));
    }
}
