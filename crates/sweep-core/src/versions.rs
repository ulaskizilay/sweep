//! A directory that holds one entry per installed version of a tool.
//!
//! Some tools install each release beside the last one and leave a launcher
//! symlink pointing at the release in use: `~/.local/share/claude/versions/2.1.319`
//! for the `claude` binary, `~/.local/share/cursor-agent/versions/<build>/` for a
//! whole tree. The old entries are not caches - nothing regenerates them - but
//! they are also not the installed tool any more, and they are large: a single
//! entry is the size of the program.
//!
//! So the retention is a count, not an age, exactly like [`crate::pkg_cache`]:
//! the newest `keep_versions` entries stay, and so does the entry the launcher
//! resolves to. That second half is the safety property. "Newest" is a guess
//! about which release is live; the launcher is the statement. A user who pinned
//! an older version, or an update that has unpacked the new entry but not yet
//! moved the link, would both lose the working binary if only the newest stayed.
//!
//! Two floors apply on top of the count:
//!
//! * `keep_days` is a recency floor, as it is for `pkg-cache`: an entry written
//!   in the last few days is an install or a downgrade in progress.
//! * A launcher that cannot be read - missing, not a symlink, dangling, or
//!   pointing outside the root - means the live entry is unknown, and unknown
//!   plans nothing. The caller reports which of those happened.
//!
//! A child whose name does not look like a version is left alone and counted.
//! The root may also hold a `current` link or a `README`; a name this scanner
//! does not understand is not evidence of anything.

use std::io;
use std::path::{Path, PathBuf};

use crate::probe::FsProbe;
use crate::scan::{self, Limits, Spec, Stop};
use crate::version::vercmp;

/// Why the launcher could not name the live entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepLinkProblem {
    /// The launcher does not exist, so the tool may not be installed at all.
    Missing,
    /// The path exists but is not a symbolic link, so it cannot name an entry.
    NotALink,
    /// The link resolves outside the version directory, so it says nothing about
    /// which entry here is live.
    OutsideRoot,
    /// The link could not be resolved: dangling, unreadable, or looping.
    Unresolved,
}

impl KeepLinkProblem {
    pub fn message(self) -> &'static str {
        match self {
            KeepLinkProblem::Missing => {
                "the launcher named by keep_link does not exist, so the live version is unknown"
            }
            KeepLinkProblem::NotALink => {
                "the path named by keep_link is not a symbolic link, so it does not name a version"
            }
            KeepLinkProblem::OutsideRoot => {
                "the launcher named by keep_link does not point at an entry inside this \
                 directory, so the live version is unknown"
            }
            KeepLinkProblem::Unresolved => {
                "the launcher named by keep_link could not be resolved, so the live version is \
                 unknown"
            }
        }
    }
}

/// One entry this scan would delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The entry itself: a file, or a directory to be emptied and removed.
    pub path: PathBuf,
    /// The version name the entry carries, for the report.
    pub version: String,
    /// True when the entry is a directory, which the planner has to walk.
    pub is_dir: bool,
}

/// Everything the scan found. Default is "nothing seen yet".
#[derive(Debug, Clone, Default)]
pub struct Scan {
    pub stop: Stop,
    pub missing_root: bool,
    pub root_is_symlink: bool,
    pub not_a_directory: bool,
    pub root_unreadable: bool,
    /// Set when the launcher did not answer, which stops the sweep.
    pub keep_link_problem: Option<KeepLinkProblem>,
    /// The entry the launcher resolves to, when it resolved inside the root.
    pub live: Option<PathBuf>,
    pub candidates: Vec<Candidate>,
    /// Entries kept: the newest `keep_versions`, the live one, and anything
    /// inside the recency floor.
    pub kept: usize,
    /// Every child of the root.
    pub entries: usize,
    /// Children whose name is not a version, or that are links. Left alone.
    pub unrecognised: usize,
    pub bytes_visited: u64,
}

/// True when `name` looks like a version rather than a file a tool left behind.
///
/// Both shapes in the wild start with a digit: `2.1.319` and
/// `2026.10.01-e373342`. The rest of the check is what keeps `README`, `current`
/// and `.DS_Store` out: only ASCII letters, digits and the separators a version
/// uses, and never a leading separator.
pub fn is_version_name(name: &[u8]) -> bool {
    if name.is_empty() || !name[0].is_ascii_digit() {
        return false;
    }
    name.iter().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+' | b'~')
    })
}

/// Walks one version directory. Read-only: nothing is unlinked or followed.
pub fn scan(
    root: &Path,
    keep_versions: u32,
    keep_link: &Path,
    keep_days: u32,
    now: i64,
    limits: &Limits,
    probe: &dyn FsProbe,
) -> Scan {
    let mut out = Scan::default();
    let cutoff = now.saturating_sub(i64::from(keep_days) * 86_400);

    let root_meta = match probe.symlink_metadata(root) {
        Ok(meta) => meta,
        Err(error) => {
            if error.kind() == io::ErrorKind::NotFound {
                out.missing_root = true;
            } else {
                out.root_unreadable = true;
            }
            return out;
        }
    };
    if root_meta.is_symlink() {
        out.root_is_symlink = true;
        return out;
    }
    if !root_meta.is_dir() {
        out.not_a_directory = true;
        return out;
    }

    // The walk goes one level below the entries themselves so a directory entry
    // is emitted rather than blocked as "too deep"; the ranking below then keeps
    // only the direct children of the root. The walker's budget, mount and
    // device checks apply to that pass like they do to every other rule.
    let collected = scan::collect(root, root, 0, &Spec::new(2, limits), probe);
    out.stop = collected.stop;
    out.missing_root = collected.missing_root;
    out.not_a_directory = collected.not_a_directory;
    out.root_unreadable = collected.root_unreadable;
    out.bytes_visited = collected.bytes;
    if out.stop != Stop::Complete || out.missing_root || out.not_a_directory || out.root_unreadable
    {
        // Ranking versions from a partial listing would compare the newest
        // against a set that may be missing entries, so nothing is planned.
        return out;
    }

    // Direct children only: anything deeper belongs to an entry, not to the
    // ranking.
    let direct: Vec<&scan::Entry> = collected
        .entries
        .iter()
        .filter(|entry| entry.path.parent() == Some(root))
        .collect();
    let blocked: Vec<&scan::Block> = collected
        .blocked
        .iter()
        .filter(|block| block.path.components().count() == 1)
        .collect();
    out.entries = direct.len() + blocked.len();
    // A mount point, an unreadable child or a link is not a version entry and is
    // left alone; counting it keeps the detail line honest about what was seen.
    out.unrecognised = blocked.len();

    // The launcher is read before any ranking, because a missing answer makes
    // every ranking a guess. `canonicalize` resolves the whole chain, so a
    // launcher that is itself a link to a link still lands on the entry.
    let canonical_root = match probe.canonicalize(root) {
        Ok(path) => path,
        Err(_) => {
            out.keep_link_problem = Some(KeepLinkProblem::Unresolved);
            return out;
        }
    };
    match probe.symlink_metadata(keep_link) {
        Ok(meta) if !meta.is_symlink() => {
            out.keep_link_problem = Some(KeepLinkProblem::NotALink);
            return out;
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            out.keep_link_problem = Some(KeepLinkProblem::Missing);
            return out;
        }
        Err(_) => {
            out.keep_link_problem = Some(KeepLinkProblem::Unresolved);
            return out;
        }
    }
    let resolved = match probe.canonicalize(keep_link) {
        Ok(path) => path,
        Err(_) => {
            out.keep_link_problem = Some(KeepLinkProblem::Unresolved);
            return out;
        }
    };
    // The entry name, not the full path: the walk below produces paths built
    // from `root`, while `canonicalize` returns the physical path. If an
    // ancestor such as `~/.local` is a symlink the two spellings differ, and
    // comparing whole paths would silently stop protecting the live entry -
    // which is the one deletion this kind exists to prevent.
    let live_name = match resolved.strip_prefix(&canonical_root) {
        Ok(relative) => relative
            .components()
            .next()
            .map(|component| component.as_os_str().to_owned()),
        Err(_) => None,
    };
    let Some(live_name) = live_name else {
        out.keep_link_problem = Some(KeepLinkProblem::OutsideRoot);
        return out;
    };
    out.live = Some(root.join(&live_name));

    // Group the children that are versions, keeping the index so the candidate
    // can carry the metadata the walk already read.
    let mut versions: Vec<(Vec<u8>, &scan::Entry)> = Vec::new();
    for entry in direct {
        // A link is never a version entry: it may point anywhere, and the sink
        // would unlink the link rather than the tree the name suggests.
        if entry.is_symlink {
            out.unrecognised += 1;
            continue;
        }
        let name = entry
            .path
            .file_name()
            .map(|name| name.as_encoded_bytes())
            .unwrap_or_default();
        if !is_version_name(name) {
            out.unrecognised += 1;
            continue;
        }
        versions.push((name.to_vec(), entry));
    }

    // Newest first. `vercmp` is the ordering the rest of the catalog uses for
    // version strings, and it gets `1.10` after `1.9` right where text order
    // does not.
    versions.sort_by(|left, right| vercmp(&right.0, &left.0));

    let keep = keep_versions.max(1) as usize;
    for (rank, (name, entry)) in versions.iter().enumerate() {
        // A tie in `vercmp` (`1.0` and `1.0-1`) means the order does not
        // separate these two, so "rank 2 is older than rank 1" is not known.
        // Keeping both is the only answer that cannot delete the live one.
        let tied_with_a_kept_one = rank >= keep
            && versions[..keep.min(versions.len())]
                .iter()
                .any(|(kept, _)| vercmp(kept, name) == std::cmp::Ordering::Equal);
        if entry.path.file_name() == Some(live_name.as_os_str())
            || entry.mtime >= cutoff
            || rank < keep
            || tied_with_a_kept_one
        {
            out.kept += 1;
            continue;
        }
        out.candidates.push(Candidate {
            path: entry.path.clone(),
            version: String::from_utf8_lossy(name).into_owned(),
            is_dir: entry.is_dir,
        });
    }

    out.candidates
        .sort_by(|left, right| left.path.cmp(&right.path));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::RealProbe;
    use std::fs::{File, FileTimes};
    use std::time::{Duration, SystemTime};

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

    fn run(root: &Path, keep_link: &Path, keep_versions: u32, keep_days: u32) -> Scan {
        let probe = RealProbe::new().expect("probe").with_open_scan();
        scan(
            root,
            keep_versions,
            keep_link,
            keep_days,
            now(),
            &Limits::default(),
            &probe,
        )
    }

    fn names(scan: &Scan) -> Vec<String> {
        scan.candidates
            .iter()
            .map(|candidate| candidate.version.clone())
            .collect()
    }

    #[test]
    fn version_names_are_recognised_and_everything_else_is_not() {
        assert!(is_version_name(b"2.1.319"));
        assert!(is_version_name(b"2026.10.01-e373342"));
        assert!(is_version_name(b"1.0+r50"));
        assert!(is_version_name(b"2"));
        for name in [
            &b""[..],
            b"README",
            b"current",
            b".DS_Store",
            b"v2.0",
            b"2.0/../x",
            b"2 0",
            b"-1.0",
        ] {
            assert!(!is_version_name(name), "{name:?} must not be a version");
        }
    }

    /// A versions directory with a launcher beside it, both below one temp root.
    struct Fixture {
        temp: tempfile::TempDir,
    }

    impl Fixture {
        fn new(versions: &[(&str, bool)]) -> Self {
            let temp = tempfile::tempdir().expect("tempdir");
            let root = temp.path().join("share/versions");
            std::fs::create_dir_all(&root).expect("mkdir");
            for (name, dir) in versions {
                let path = root.join(name);
                if *dir {
                    std::fs::create_dir_all(&path).expect("mkdir");
                    std::fs::write(path.join("binary"), b"body").expect("write");
                } else {
                    std::fs::write(&path, b"body").expect("write");
                }
                age(&path, 90);
            }
            let bin = temp.path().join("bin");
            std::fs::create_dir_all(&bin).expect("mkdir");
            Self { temp }
        }

        fn root(&self) -> PathBuf {
            self.temp.path().join("share/versions")
        }

        fn link_to(&self, name: &str) {
            let link = self.temp.path().join("bin/tool");
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(self.root().join(name), &link).expect("symlink");
        }

        fn scan(&self, keep_versions: u32, keep_days: u32) -> Scan {
            run(
                &self.root(),
                &self.temp.path().join("bin/tool"),
                keep_versions,
                keep_days,
            )
        }
    }

    #[test]
    fn the_newest_versions_are_kept_and_the_rest_are_planned() {
        let fixture = Fixture::new(&[("2.1.317", false), ("2.1.318", false), ("2.1.319", false)]);
        fixture.link_to("2.1.319");

        let scan = fixture.scan(1, 0);
        assert_eq!(names(&scan), ["2.1.317", "2.1.318"]);
        assert_eq!(scan.kept, 1);
        assert!(scan.candidates.iter().all(|candidate| !candidate.is_dir));
    }

    #[test]
    fn versions_are_compared_the_way_the_catalog_compares_them() {
        let fixture = Fixture::new(&[("2.1.9", false), ("2.1.10", false)]);
        fixture.link_to("2.1.10");

        let scan = fixture.scan(1, 0);
        assert_eq!(
            names(&scan),
            ["2.1.9"],
            "2.1.10 is newer than 2.1.9: text order would have kept the wrong one"
        );
    }

    #[test]
    fn the_launcher_target_survives_even_when_it_is_not_the_newest() {
        // A pinned or not-yet-switched launcher is the reason this kind reads a
        // link at all: deleting the entry in use breaks the command.
        let fixture = Fixture::new(&[("2.1.317", false), ("2.1.318", false), ("2.1.319", false)]);
        fixture.link_to("2.1.317");

        let scan = fixture.scan(1, 0);
        assert_eq!(
            scan.live.as_deref(),
            Some(fixture.root().join("2.1.317").as_path())
        );
        assert_eq!(
            names(&scan),
            ["2.1.318"],
            "the live entry and the newest stay"
        );
    }

    #[test]
    fn a_directory_entry_is_a_candidate_and_flagged_as_one() {
        let fixture = Fixture::new(&[("2026.09.26-dd393fe", true), ("2026.10.01-e373342", true)]);
        fixture.link_to("2026.10.01-e373342");

        let scan = fixture.scan(1, 0);
        assert_eq!(names(&scan), ["2026.09.26-dd393fe"]);
        assert!(scan.candidates[0].is_dir);
    }

    #[test]
    fn a_missing_launcher_plans_nothing() {
        let fixture = Fixture::new(&[("2.1.317", false), ("2.1.319", false)]);
        let scan = fixture.scan(1, 0);
        assert_eq!(
            scan.keep_link_problem,
            Some(KeepLinkProblem::Missing),
            "without a launcher the live version is unknown"
        );
        assert!(scan.candidates.is_empty());
    }

    #[test]
    fn a_launcher_that_is_not_a_link_plans_nothing() {
        let fixture = Fixture::new(&[("2.1.317", false), ("2.1.319", false)]);
        let link = fixture.temp.path().join("bin/tool");
        std::fs::write(&link, b"a copy, not a link").expect("write");

        let scan = fixture.scan(1, 0);
        assert_eq!(scan.keep_link_problem, Some(KeepLinkProblem::NotALink));
        assert!(scan.candidates.is_empty());
    }

    #[test]
    fn a_launcher_outside_the_root_plans_nothing() {
        let fixture = Fixture::new(&[("2.1.317", false), ("2.1.319", false)]);
        let outside = fixture.temp.path().join("elsewhere");
        std::fs::write(&outside, b"body").expect("write");
        let link = fixture.temp.path().join("bin/tool");
        std::os::unix::fs::symlink(&outside, &link).expect("symlink");

        let scan = fixture.scan(1, 0);
        assert_eq!(scan.keep_link_problem, Some(KeepLinkProblem::OutsideRoot));
        assert!(scan.candidates.is_empty());
    }

    #[test]
    fn a_dangling_launcher_plans_nothing() {
        let fixture = Fixture::new(&[("2.1.317", false), ("2.1.319", false)]);
        let link = fixture.temp.path().join("bin/tool");
        std::os::unix::fs::symlink(fixture.root().join("9.9.9"), &link).expect("symlink");

        let scan = fixture.scan(1, 0);
        assert_eq!(scan.keep_link_problem, Some(KeepLinkProblem::Unresolved));
        assert!(scan.candidates.is_empty());
    }

    #[test]
    fn the_recency_floor_keeps_a_version_that_was_just_installed() {
        let fixture = Fixture::new(&[("2.1.317", false), ("2.1.318", false), ("2.1.319", false)]);
        fixture.link_to("2.1.319");
        // The oldest entry is the one written yesterday: a downgrade in progress
        // looks exactly like this, and age alone must save it.
        age(&fixture.root().join("2.1.317"), 1);

        let scan = fixture.scan(1, 7);
        assert_eq!(
            names(&scan),
            ["2.1.318"],
            "the entry written yesterday stays; the old one that is neither newest nor live goes"
        );
    }

    #[test]
    fn a_link_inside_the_root_is_never_a_candidate() {
        let fixture = Fixture::new(&[("2.1.317", false), ("2.1.319", false)]);
        fixture.link_to("2.1.319");
        std::os::unix::fs::symlink(fixture.root().join("2.1.317"), fixture.root().join("1.0.0"))
            .expect("symlink");

        let scan = fixture.scan(1, 0);
        assert_eq!(scan.unrecognised, 1, "the link is counted, not planned");
        assert_eq!(names(&scan), ["2.1.317"]);
    }

    #[test]
    fn a_name_that_is_not_a_version_is_left_alone() {
        let fixture = Fixture::new(&[("2.1.317", false), ("2.1.319", false)]);
        fixture.link_to("2.1.319");
        std::fs::write(fixture.root().join("README"), b"notes").expect("write");

        let scan = fixture.scan(1, 0);
        assert_eq!(scan.unrecognised, 1);
        assert_eq!(names(&scan), ["2.1.317"]);
    }

    #[test]
    fn a_symlinked_ancestor_does_not_stop_the_launcher_target_being_kept() {
        // `~/.local` is a symlink on plenty of machines. The walk produces
        // paths built from the rule root while `canonicalize` returns the
        // physical path, so a comparison on whole paths would silently delete
        // the entry the launcher uses.
        let temp = tempfile::tempdir().expect("tempdir");
        let real = temp.path().join("real");
        let root_real = real.join("share/versions");
        std::fs::create_dir_all(&root_real).expect("mkdir");
        for name in ["2.1.317", "2.1.318", "2.1.319"] {
            let path = root_real.join(name);
            std::fs::write(&path, b"body").expect("write");
            age(&path, 90);
        }
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let root = link.join("share/versions");
        let bin = link.join("bin");
        std::fs::create_dir_all(&bin).expect("mkdir");
        let launcher = bin.join("tool");
        std::os::unix::fs::symlink(root.join("2.1.317"), &launcher).expect("symlink");

        let probe = RealProbe::new().expect("probe").with_open_scan();
        let scan = scan(&root, 1, &launcher, 0, now(), &Limits::default(), &probe);
        assert_eq!(
            scan.live.as_deref(),
            Some(root.join("2.1.317").as_path()),
            "the live entry is reported against the rule root"
        );
        assert_eq!(
            names(&scan),
            ["2.1.318"],
            "the launcher target and the newest stay, whatever the ancestor spelling"
        );
    }

    #[test]
    fn a_missing_root_is_reported_rather_than_treated_as_empty() {
        let temp = tempfile::tempdir().expect("tempdir");
        let probe = RealProbe::new().expect("probe");
        let scan = scan(
            &temp.path().join("nope"),
            1,
            &temp.path().join("bin/tool"),
            0,
            now(),
            &Limits::default(),
            &probe,
        );
        assert!(scan.missing_root);
        assert!(scan.candidates.is_empty());
        assert!(!scan.root_is_symlink);
    }

    #[test]
    fn two_runs_produce_the_same_list() {
        let fixture = Fixture::new(&[("2.1.317", false), ("2.1.318", false), ("2.1.319", false)]);
        fixture.link_to("2.1.319");
        let first = fixture.scan(1, 0);
        let second = fixture.scan(1, 0);
        assert_eq!(names(&first), names(&second));
        assert_eq!(first.kept, second.kept);
    }
}
