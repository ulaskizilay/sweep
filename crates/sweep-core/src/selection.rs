//! What one rule would select, re-derived where the selection is enforced.
//!
//! The parent process builds the plan; the elevated child applies it. If the
//! child trusted the path list, every rule whose root is a shared directory
//! would become a way to delete anything in it: `/var/log` is inside the
//! `system.log.rotated` root, but `wtmp` is not a rotated log, and no path check
//! in `validate` knows the difference. Path checks prove *where* a file is; only
//! the rule knows *which* files it meant.
//!
//! So the child re-runs the rule's own selection and applies nothing outside it.
//! Two properties make that safe rather than decorative:
//!
//! * **Independent of the request.** The set comes from the compiled rule and
//!   the filesystem, never from the item the parent sent.
//! * **Unknown means empty.** A walk that was cut short, a root that could not
//!   be read, or a kind with no selection rule admits nothing. The elevated
//!   process must not "try anyway" on a cache it could not list.
//!
//! The selection is recomputed at apply time, so a file whose age or version
//! ranking changed between plan and apply is no longer in the set, and the item
//! is refused rather than removed. That direction is the safe one: the child can
//! only ever delete fewer paths than the parent planned.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::model_cache;
use crate::paths::first_component;
use crate::pkg_cache;
use crate::probe::FsProbe;
use crate::rules::{Kind, Rule};
use crate::scan::{self, Collect, Limits, Select, Spec, Stop};
use crate::Xdg;

/// The paths one rule would plan, or a refusal to answer.
#[derive(Debug, Clone, Default)]
pub struct Selection {
    paths: std::collections::BTreeSet<PathBuf>,
    /// `.trashinfo` records, each mapped to the payload it names. A record may
    /// only be removed after its payload is gone, which the funnel enforces.
    paired: BTreeMap<PathBuf, PathBuf>,
    /// False when the selection could not be derived completely. `paths` is then
    /// empty, and every lookup refuses: partial knowledge of a cache cannot
    /// order versions or ages.
    complete: bool,
}

impl Selection {
    /// Derives the selection of `rule` for the current filesystem state.
    ///
    /// `xdg` is only consulted for a templated root. The child compiles the
    /// system pack with a synthetic `$HOME` and only accepts literal roots, so
    /// in that path expansion is the identity function.
    ///
    /// A glob root returns an empty, incomplete selection: it names several
    /// concrete directories and this function has one walk to derive, so the
    /// honest answer is "unknown". Nothing is deleted from an unknown.
    pub fn derive(rule: &Rule, xdg: &Xdg, now: i64, limits: &Limits, probe: &dyn FsProbe) -> Self {
        // This answer is consumed by the elevated child, which only accepts
        // literal system roots, and by tests. A glob root has many concrete
        // roots and no single walk to derive; refusing is the honest answer.
        if rule.root.has_glob() {
            return Self::default();
        }
        let root = rule.expanded_root(xdg);
        match rule.kind {
            // The two scanners decide over the whole root at once: a version's
            // rank or a blob's reference count has no local answer.
            Kind::PkgCache => {
                let keep_versions = rule.keep_versions.unwrap_or(u32::MAX);
                let found =
                    pkg_cache::scan(&root, keep_versions, rule.keep_days, now, limits, probe);
                if found.stop != Stop::Complete
                    || found.missing_root
                    || found.root_is_symlink
                    || found.not_a_directory
                    || found.root_unreadable
                {
                    return Self::default();
                }
                Self {
                    paths: found
                        .candidates
                        .into_iter()
                        .map(|found| found.path)
                        .collect(),
                    paired: BTreeMap::new(),
                    complete: true,
                }
            }
            Kind::HfCache => {
                let found = model_cache::scan(&root, rule.keep_days, now, limits, probe);
                if found.stop != Stop::Complete
                    || found.missing_root
                    || found.root_is_symlink
                    || found.not_a_directory
                    || found.root_unreadable
                {
                    return Self::default();
                }
                Self {
                    paths: found
                        .candidates
                        .into_iter()
                        .map(|found| found.path)
                        .collect(),
                    paired: BTreeMap::new(),
                    complete: true,
                }
            }
            Kind::DirSweep | Kind::DirAge | Kind::FilePattern | Kind::ToolCache => {
                Self::from_walk(rule, &root, now, limits, probe)
            }
            // The trash is not a tree with one root: it is a list of entries, each
            // with a payload and a restore record. The pair is what makes the
            // deletion safe, so the selection carries both halves.
            Kind::TrashEmpty => {
                // The child re-derives what the rule selects, not what the
                // parent planned: the ignore file is a narrowing the parent
                // already applied, so it is not part of this answer.
                let found = crate::trash::scan(&root, limits, probe, None);
                if found.stop != Stop::Complete
                    || found.missing_root
                    || found.not_a_directory
                    || found.root_unreadable
                {
                    return Self::default();
                }
                let mut paths = std::collections::BTreeSet::new();
                let mut paired = BTreeMap::new();
                for entry in found.entries {
                    for path in entry.paths {
                        paths.insert(path);
                    }
                    paired.insert(entry.record, entry.payload);
                }
                Self {
                    paths,
                    paired,
                    complete: true,
                }
            }
            // Nothing to select is a complete answer for a rule that deletes
            // nothing, but an empty set is also what an unknown walk returns, so
            // say "complete" explicitly and let the empty set do the refusing.
            Kind::ReportOnly => Self {
                paths: Default::default(),
                paired: BTreeMap::new(),
                complete: true,
            },
            // A project sweep never crosses the privilege boundary: a build
            // directory lives in `$HOME`, which the child cannot see, and the
            // compiler refuses `privilege = "root"` for it outside `system`.
            // An empty set is the honest answer if one ever arrives here.
            Kind::ProjectArtifacts => Self::default(),
        }
    }

    fn from_walk(rule: &Rule, root: &Path, now: i64, limits: &Limits, probe: &dyn FsProbe) -> Self {
        let mut spec = Spec::new(rule.max_depth, limits);
        spec.exclude = &rule.exclude;
        if rule.kind == Kind::FilePattern {
            spec.select = Select::Files(&rule.patterns);
        }

        let collected = scan::collect(root, root, 0, &spec, probe);
        if collected.stop != Stop::Complete
            || collected.missing_root
            || collected.not_a_directory
            || collected.root_unreadable
        {
            return Self::default();
        }

        let cutoff = rule.cutoff(now);
        match rule.kind {
            Kind::DirSweep => Self {
                paths: collected
                    .entries
                    .iter()
                    .map(|entry| entry.path.clone())
                    .collect(),
                paired: BTreeMap::new(),
                complete: true,
            },
            Kind::ToolCache => {
                let mut paths: std::collections::BTreeSet<PathBuf> = collected
                    .entries
                    .iter()
                    .map(|entry| entry.path.clone())
                    .collect();
                paths.insert(root.to_path_buf());
                Self {
                    paths,
                    paired: BTreeMap::new(),
                    complete: true,
                }
            }
            Kind::FilePattern => Self {
                paths: collected
                    .entries
                    .iter()
                    .filter(|entry| !entry.is_dir && entry.mtime < cutoff)
                    .map(|entry| entry.path.clone())
                    .collect(),
                paired: BTreeMap::new(),
                complete: true,
            },
            Kind::DirAge => Self {
                paths: aged_paths(&collected, root, cutoff),
                paired: BTreeMap::new(),
                complete: true,
            },
            // Handled by the scanners, or never reached by this process.
            Kind::PkgCache
            | Kind::HfCache
            | Kind::ProjectArtifacts
            | Kind::TrashEmpty
            | Kind::ReportOnly => Self::default(),
        }
    }

    /// True when the rule would plan `path` in its current state.
    pub fn admits(&self, path: &Path) -> bool {
        self.complete && self.paths.contains(path)
    }

    /// The payload a `.trashinfo` record depends on, when the selection paired it.
    ///
    /// The planner marks the record with this path so the funnel can refuse to
    /// remove a record whose payload survived.
    pub fn payload_for(&self, record: &Path) -> Option<&Path> {
        self.paired.get(record).map(PathBuf::as_path)
    }

    pub fn complete(&self) -> bool {
        self.complete
    }

    pub fn len(&self) -> usize {
        self.paths.len()
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

/// Every entry of a `dir-age` subtree whose newest entry is older than `cutoff`.
///
/// The unit is the top-level subtree, not the file: a directory with one recent
/// file inside is not old, and deleting its siblings one by one would leave a
/// directory that cannot be removed. A subtree holding an entry the walk
/// deliberately skipped is excluded outright - the newest part of it is unknown,
/// and unknown keeps it.
fn aged_paths(
    collected: &Collect,
    root: &Path,
    cutoff: i64,
) -> std::collections::BTreeSet<PathBuf> {
    let mut groups: BTreeMap<PathBuf, i64> = BTreeMap::new();
    for entry in &collected.entries {
        let relative = entry.path.strip_prefix(root).unwrap_or(&entry.path);
        let Some(top) = first_component(relative) else {
            continue;
        };
        let newest = groups.entry(top).or_insert(i64::MIN);
        *newest = (*newest).max(entry.mtime);
    }

    let mut paths = std::collections::BTreeSet::new();
    for (top, newest) in &groups {
        if newest >= &cutoff {
            continue;
        }
        if !collected.blocked_under(top).is_empty() {
            continue;
        }
        for entry in &collected.entries {
            let relative = entry.path.strip_prefix(root).unwrap_or(&entry.path);
            if first_component(relative).as_deref() == Some(top.as_path()) {
                paths.insert(entry.path.clone());
            }
        }
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::RealProbe;
    use crate::rules::{RuleSet, Source};
    use std::fs::{File, FileTimes};
    use std::time::{Duration, SystemTime};

    fn xdg() -> Xdg {
        Xdg::resolve(|key| match key {
            "HOME" => Some("/nonexistent".into()),
            _ => None,
        })
        .expect("a synthetic home is enough")
    }

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64
    }

    fn age(path: &Path, days: i64) {
        let when = SystemTime::now() - Duration::from_secs((days.max(0) as u64) * 86_400);
        let file = File::open(path).expect("open");
        file.set_times(FileTimes::new().set_modified(when))
            .expect("set mtime");
    }

    fn cache(files: &[&str]) -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("tempdir");
        for name in files {
            let path = temp.path().join(name);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(&path, "body").expect("write");
        }
        temp
    }

    /// One compiled rule, built the way a pack would build it.
    fn rule(body: &str) -> Rule {
        let set = RuleSet::from_sources(&[Source::new("fixture", body)], &xdg())
            .expect("the fixture rule compiles");
        set.rules()[0].clone()
    }

    fn pkg_rule(root: &Path, keep_versions: u32, keep_days: u32) -> Rule {
        rule(&format!(
            r#"
[[rule]]
id = "system.test.pkg"
section = "system"
kind = "pkg-cache"
root = "{}"
evidence = "fixture"
privilege = "root"
recoverable = true
keep_versions = {keep_versions}
keep_days = {keep_days}
"#,
            root.display()
        ))
    }

    fn pattern_rule(root: &Path, pattern: &str, keep_days: u32) -> Rule {
        rule(&format!(
            r#"
[[rule]]
id = "system.test.log"
section = "system"
kind = "file-pattern"
root = "{}"
evidence = "fixture"
privilege = "root"
recoverable = true
pattern = "{pattern}"
keep_days = {keep_days}
"#,
            root.display()
        ))
    }

    fn derive(rule: &Rule) -> Selection {
        let probe = RealProbe::new().expect("probe").with_open_scan();
        Selection::derive(rule, &xdg(), now(), &Limits::default(), &probe)
    }

    fn names(selection: &Selection, root: &Path) -> Vec<String> {
        let mut names: Vec<String> = selection
            .paths
            .iter()
            .filter_map(|path| {
                path.strip_prefix(root)
                    .ok()
                    .map(|relative| relative.display().to_string())
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_package_cache_admits_only_the_versions_past_the_keep_count() {
        let temp = cache(&[
            "foo-1.0-1-x86_64.pkg.tar.zst",
            "foo-1.0-1-x86_64.pkg.tar.zst.sig",
            "foo-2.0-1-x86_64.pkg.tar.zst",
            "foo-3.0-1-x86_64.pkg.tar.zst",
        ]);
        for entry in std::fs::read_dir(temp.path()).expect("read") {
            age(&entry.expect("entry").path(), 90);
        }

        let selection = derive(&pkg_rule(temp.path(), 2, 0));
        assert!(selection.complete());
        assert_eq!(
            names(&selection, temp.path()),
            [
                "foo-1.0-1-x86_64.pkg.tar.zst",
                "foo-1.0-1-x86_64.pkg.tar.zst.sig",
            ],
            "the third-newest version and its signature, not the newest"
        );
        assert!(
            !selection.admits(&temp.path().join("foo-3.0-1-x86_64.pkg.tar.zst")),
            "the newest version is what the rule keeps"
        );
    }

    #[test]
    fn a_pattern_rule_admits_the_pattern_and_not_its_neighbours() {
        // The confused-deputy case this module exists for: same directory, same
        // age, different name.
        let temp = cache(&["boot.log.1", "wtmp", "pacman.log"]);
        age(&temp.path().join("boot.log.1"), 30);
        age(&temp.path().join("wtmp"), 30);
        age(&temp.path().join("pacman.log"), 30);

        let selection = derive(&pattern_rule(temp.path(), "*.log.*", 7));
        assert_eq!(names(&selection, temp.path()), ["boot.log.1"]);
        assert!(!selection.admits(&temp.path().join("wtmp")));
        assert!(!selection.admits(&temp.path().join("pacman.log")));
    }

    #[test]
    fn a_pattern_rule_keeps_a_fresh_match() {
        let temp = cache(&["boot.log.1"]);
        let selection = derive(&pattern_rule(temp.path(), "*.log.*", 7));
        assert!(
            selection.is_empty(),
            "a rotated log from this morning is still the one a user wants after a reboot"
        );
    }

    #[test]
    fn a_directory_sweep_admits_every_entry_but_not_its_own_root() {
        let temp = cache(&["tree/one", "tree/deep/two"]);
        std::fs::create_dir_all(temp.path().join("tree/deep")).expect("mkdir");
        std::fs::write(temp.path().join("tree/deep/two"), "body").expect("write");

        let rule = rule(&format!(
            r#"
[[rule]]
id = "system.test.sweep"
section = "system"
kind = "dir-sweep"
root = "{}"
evidence = "fixture"
privilege = "root"
recoverable = true
"#,
            temp.path().join("tree").display()
        ));
        let selection = derive(&rule);
        assert!(selection.admits(&temp.path().join("tree/one")));
        assert!(selection.admits(&temp.path().join("tree/deep/two")));
        assert!(
            !selection.admits(&temp.path().join("tree")),
            "a dir-sweep keeps the root it was pointed at"
        );
    }

    #[test]
    fn an_excluded_entry_is_never_admitted() {
        let temp = cache(&["tree/keep", "tree/drop"]);
        let rule = rule(&format!(
            r#"
[[rule]]
id = "system.test.sweep"
section = "system"
kind = "dir-sweep"
root = "{}"
evidence = "fixture"
privilege = "root"
recoverable = true
exclude = ["keep"]
"#,
            temp.path().join("tree").display()
        ));
        let selection = derive(&rule);
        assert!(!selection.admits(&temp.path().join("tree/keep")));
        assert!(selection.admits(&temp.path().join("tree/drop")));
    }

    #[test]
    fn a_subtree_with_one_recent_file_is_not_old() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(temp.path().join("cache/old/sub")).expect("mkdir");
        std::fs::create_dir_all(temp.path().join("cache/fresh")).expect("mkdir");
        std::fs::write(temp.path().join("cache/old/one"), "body").expect("write");
        std::fs::write(temp.path().join("cache/old/sub/two"), "body").expect("write");
        std::fs::write(temp.path().join("cache/fresh/three"), "body").expect("write");
        // A directory's own mtime is part of the newest-entry question, exactly
        // as it is on a real disk: a directory touched today is not old.
        age(&temp.path().join("cache/old"), 90);
        age(&temp.path().join("cache/old/sub"), 90);
        age(&temp.path().join("cache/old/one"), 90);
        age(&temp.path().join("cache/old/sub/two"), 90);
        age(&temp.path().join("cache/fresh/three"), 1);

        let rule = rule(&format!(
            r#"
[[rule]]
id = "system.test.age"
section = "system"
kind = "dir-age"
root = "{}"
evidence = "fixture"
privilege = "root"
recoverable = true
keep_days = 30
"#,
            temp.path().join("cache").display()
        ));
        let selection = derive(&rule);
        assert!(selection.admits(&temp.path().join("cache/old/one")));
        assert!(selection.admits(&temp.path().join("cache/old/sub/two")));
        assert!(
            !selection.admits(&temp.path().join("cache/fresh/three")),
            "one recent file makes the whole subtree recent"
        );
    }

    #[test]
    fn a_root_that_cannot_be_read_admits_nothing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing = temp.path().join("gone");
        let selection = derive(&pkg_rule(&missing, 1, 0));
        assert!(!selection.complete());
        assert!(
            !selection.admits(&missing),
            "an unreadable cache is not an empty one"
        );
    }

    #[test]
    fn a_report_only_rule_admits_nothing() {
        let temp = cache(&["tree/one"]);
        let rule = rule(&format!(
            r#"
[[rule]]
id = "system.test.report"
section = "system"
kind = "report-only"
root = "{}"
privilege = "user"
recoverable = true
"#,
            temp.path().join("tree").display()
        ));
        let selection = derive(&rule);
        assert!(selection.complete());
        assert!(!selection.admits(&temp.path().join("tree/one")));
    }
}
