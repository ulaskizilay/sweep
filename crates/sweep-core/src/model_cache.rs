//! The Hugging Face hub cache: the one layout a generic sweep cannot touch.
//!
//! `huggingface_hub` stores each file once as `blobs/<etag>` and links it into
//! `snapshots/<revision>/<path>`. Sweeping `blobs/` like an ordinary cache
//! directory leaves every snapshot pointing at nothing: the model still looks
//! installed, fails at load time, and never re-downloads, because its revision
//! is still in `refs/`. That is worse than not cleaning at all, so the hub gets
//! its own scanner.
//!
//! It plans only what nothing points at:
//!
//! * a complete blob that no symlink below `snapshots/` resolves to, once it is
//!   older than the retention;
//! * an `*.incomplete` download older than the retention.
//!
//! The retention is mandatory for this kind at load time, because the hub writes
//! the blob first and the snapshot link second: for a moment every download is
//! an unreferenced blob.
//!
//! A repository whose snapshot tree cannot be read completely is preserved
//! whole. An unreadable reference set is not an empty one, and the cost of being
//! wrong is a silently broken model. Links are read with `read_link` and
//! resolved lexically; nothing is followed, so a snapshot entry pointing at
//! `/etc/shadow` is a string this scanner compares against blob paths, never a
//! file it opens.

use std::collections::HashSet;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::probe::FsProbe;
use crate::scan::{Budget, Limits, Stop};

/// Directory name prefixes `huggingface_hub` uses for the repositories it caches.
pub const REPO_PREFIXES: [&str; 3] = ["models--", "datasets--", "spaces--"];

/// A snapshot tree deeper than this is not one we understand, so it is preserved.
const MAX_SNAPSHOT_DEPTH: usize = 32;

/// What kind of leftover a candidate is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leftover {
    /// A complete blob that no snapshot entry points at.
    UnreferencedBlob,
    /// An abandoned `<etag>.incomplete` download.
    Incomplete,
}

impl Leftover {
    pub fn code(self) -> &'static str {
        match self {
            Leftover::UnreferencedBlob => "unreferenced_blob",
            Leftover::Incomplete => "incomplete_download",
        }
    }
}

/// One path this scan would delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub path: PathBuf,
    pub bytes: u64,
    pub leftover: Leftover,
}

/// Everything the hub scan found. Default is "nothing seen yet".
#[derive(Debug, Clone, Default)]
pub struct Scan {
    pub stop: Stop,
    pub missing_root: bool,
    pub root_is_symlink: bool,
    pub not_a_directory: bool,
    /// The root itself could not be read, which is not "there is nothing there".
    pub root_unreadable: bool,
    pub candidates: Vec<Candidate>,
    /// Repositories left untouched because their snapshot tree was incomplete.
    pub preserved: Vec<String>,
    pub repos: usize,
    /// Blobs a snapshot still points at.
    pub referenced: usize,
    pub bytes_visited: u64,
}

impl Scan {
    pub fn candidates_of(&self, leftover: Leftover) -> usize {
        self.candidates
            .iter()
            .filter(|candidate| candidate.leftover == leftover)
            .count()
    }
}

/// Walks one hub root. Read-only: no `unlinkat`, no `chmod`, no link followed.
pub fn scan(root: &Path, keep_days: u32, now: i64, limits: &Limits, probe: &dyn FsProbe) -> Scan {
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
        // `hub -> /mnt/big/hub` is a legitimate layout, but following it here
        // would decide the rule applies to a tree the rule never named.
        out.root_is_symlink = true;
        return out;
    }
    if !root_meta.is_dir() {
        out.not_a_directory = true;
        return out;
    }

    let mut budget = Budget::new(limits);
    let entries = match read_sorted(root) {
        Ok(entries) => entries,
        Err(_) => {
            out.root_unreadable = true;
            return out;
        }
    };

    for entry in entries {
        if let Err(stop) = budget.charge() {
            out.stop = stop;
            return out;
        }
        let Some(name) = entry.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !REPO_PREFIXES.iter().any(|prefix| name.starts_with(prefix)) {
            continue;
        }
        let display = name.to_string();

        let meta = match probe.symlink_metadata(&entry) {
            Ok(meta) => meta,
            // A repository we cannot stat is one we cannot judge.
            Err(_) => {
                out.preserved.push(display);
                continue;
            }
        };
        // A symlinked repository, or one on another device, is not ours to
        // enumerate: `is_dir` is false for a link, which is exactly what we want.
        if !meta.is_dir() || meta.dev != root_meta.dev {
            continue;
        }

        out.repos += 1;
        match scan_repo(&entry, cutoff, &mut budget, probe, &mut out) {
            Ok(()) => {}
            Err(RepoStop::Budget(stop)) => {
                out.stop = stop;
                return out;
            }
            Err(RepoStop::Unknown) => out.preserved.push(display),
        }
    }

    out
}

enum RepoStop {
    /// The shared entry or time budget ran out.
    Budget(Stop),
    /// Something in this repository could not be read completely.
    Unknown,
}

fn scan_repo(
    repo: &Path,
    cutoff: i64,
    budget: &mut Budget<'_>,
    probe: &dyn FsProbe,
    out: &mut Scan,
) -> Result<(), RepoStop> {
    // 1. Which blobs does a snapshot still use?
    let mut referenced: HashSet<PathBuf> = HashSet::new();
    match read_sorted(&repo.join("snapshots")) {
        Ok(entries) => {
            for entry in entries {
                collect_references(&entry, 1, budget, &mut referenced)?;
            }
        }
        // No snapshot directory: the download never completed. Nothing points
        // at anything, and the retention is what makes that safe to believe.
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(RepoStop::Unknown),
    }
    out.referenced += referenced.len();

    // 2. Which blobs are left over?
    let blobs = match read_sorted(&repo.join("blobs")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(RepoStop::Unknown),
    };

    for path in blobs {
        budget.charge().map_err(RepoStop::Budget)?;
        let meta = match probe.symlink_metadata(&path) {
            Ok(meta) => meta,
            // One blob we cannot stat is one blob we skip, not a reason to
            // give up on the repository.
            Err(_) => continue,
        };
        // A directory here is not a blob; `*.incomplete` written as a
        // directory is left alone rather than recursed into.
        if !meta.is_file() {
            continue;
        }
        out.bytes_visited = out.bytes_visited.saturating_add(meta.accounted_bytes());
        if meta.mtime >= cutoff {
            continue;
        }

        let leftover = if is_incomplete(&path) {
            Leftover::Incomplete
        } else if referenced.contains(&path) {
            continue;
        } else {
            Leftover::UnreferencedBlob
        };
        out.candidates.push(Candidate {
            path,
            bytes: meta.accounted_bytes(),
            leftover,
        });
    }

    Ok(())
}

/// Reads every symlink below `directory`, adding its lexically resolved target.
fn collect_references(
    directory: &Path,
    depth: usize,
    budget: &mut Budget<'_>,
    referenced: &mut HashSet<PathBuf>,
) -> Result<(), RepoStop> {
    if depth > MAX_SNAPSHOT_DEPTH {
        return Err(RepoStop::Unknown);
    }
    let entries = read_sorted(directory).map_err(|_| RepoStop::Unknown)?;

    for entry in entries {
        budget.charge().map_err(RepoStop::Budget)?;
        let meta = std::fs::symlink_metadata(&entry).map_err(|_| RepoStop::Unknown)?;
        if meta.is_symlink() {
            let target = std::fs::read_link(&entry).map_err(|_| RepoStop::Unknown)?;
            let base = entry.parent().unwrap_or(directory);
            referenced.insert(lexical_resolve(base, &target));
        } else if meta.is_dir() {
            collect_references(&entry, depth + 1, budget, referenced)?;
        }
        // A regular file here is a copy, not a link: the model is kept in the
        // snapshot itself, and any blob beside it really is a leftover.
    }
    Ok(())
}

/// Resolves `target` against `base` without touching the filesystem.
///
/// `read_link` returns what the hub wrote, which is `../../blobs/<etag>`; the
/// lexical answer is the exact path the link denotes, and it cannot be
/// redirected by a mount or a rename between planning and deletion because the
/// result is only ever compared, never opened.
fn lexical_resolve(base: &Path, target: &Path) -> PathBuf {
    let mut out = if target.is_absolute() {
        PathBuf::new()
    } else {
        base.to_path_buf()
    };
    for component in target.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn is_incomplete(path: &Path) -> bool {
    path.extension()
        .map(|extension| extension == "incomplete")
        .unwrap_or(false)
}

fn read_sorted(directory: &Path) -> io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        paths.push(entry?.path());
    }
    // Sorted so two runs see the same order and produce the same plan hash.
    paths.sort();
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::RealProbe;
    use std::fs::{File, FileTimes};
    use std::time::{Duration, SystemTime};

    fn hub(files: &[(&str, &str)]) -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("tempdir");
        for (relative, body) in files {
            let path = temp.path().join(relative);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(&path, body).expect("write");
        }
        temp
    }

    fn age(path: &Path, days: i64) {
        let when = SystemTime::now() - Duration::from_secs((days.max(0) as u64) * 86_400);
        let file = File::open(path).expect("open");
        file.set_times(FileTimes::new().set_modified(when))
            .expect("set mtime");
    }

    fn link(target: &str, at: &Path) {
        std::fs::create_dir_all(at.parent().expect("parent")).expect("mkdir");
        std::os::unix::fs::symlink(target, at).expect("symlink");
    }

    fn run(root: &Path, keep_days: u32) -> Scan {
        let probe = RealProbe::new().expect("probe").with_open_scan();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64;
        scan(root, keep_days, now, &Limits::default(), &probe)
    }

    /// `models--org--name` with one snapshot still linking one blob.
    struct Repo {
        temp: tempfile::TempDir,
    }

    impl Repo {
        fn new() -> Self {
            let temp = hub(&[
                ("hub/models--org--name/blobs/used", "used"),
                ("hub/models--org--name/blobs/orphan", "orphan"),
                ("hub/models--org--name/blobs/half.incomplete", "half"),
                ("hub/models--org--name/refs/main", "deadbee"),
            ]);
            let root = temp.path().join("hub/models--org--name");
            link(
                "../../blobs/used",
                &root.join("snapshots/deadbee/config.json"),
            );
            for path in [
                root.join("blobs/used"),
                root.join("blobs/orphan"),
                root.join("blobs/half.incomplete"),
                root.join("snapshots/deadbee/config.json"),
                root.join("snapshots/deadbee"),
                root.join("snapshots"),
            ] {
                age(&path, 200);
            }
            Self { temp }
        }

        fn root(&self) -> PathBuf {
            self.temp.path().join("hub")
        }
    }

    #[test]
    fn a_linked_blob_is_kept_and_an_orphan_is_not() {
        let repo = Repo::new();
        let scan = run(&repo.root(), 90);
        assert_eq!(scan.stop, Stop::Complete);
        assert_eq!(scan.referenced, 1);

        let paths: Vec<PathBuf> = scan
            .candidates
            .iter()
            .map(|candidate| candidate.path.clone())
            .collect();
        let blobs = repo.root().join("models--org--name/blobs");
        assert!(
            paths.contains(&blobs.join("orphan")),
            "the unreferenced blob must be planned: {paths:?}"
        );
        assert!(
            !paths.contains(&blobs.join("used")),
            "a blob a snapshot links to is the model, not a leftover: {paths:?}"
        );
        assert_eq!(scan.candidates_of(Leftover::UnreferencedBlob), 1);
        assert_eq!(scan.candidates_of(Leftover::Incomplete), 1);
    }

    #[test]
    fn a_fresh_orphan_is_kept_by_the_retention() {
        let repo = Repo::new();
        let blob = repo.root().join("models--org--name/blobs/orphan");
        age(&blob, 3);
        let scan = run(&repo.root(), 90);
        assert_eq!(
            scan.candidates_of(Leftover::UnreferencedBlob),
            0,
            "a blob written yesterday may be a download whose link does not exist yet"
        );
    }

    #[test]
    fn a_repository_with_an_unreadable_snapshot_tree_is_preserved() {
        let repo = Repo::new();
        let snapshots = repo.root().join("models--org--name/snapshots");
        std::fs::remove_dir_all(&snapshots).expect("remove");
        // A file where the snapshot directory belongs: `read_dir` fails, and a
        // failed reference read must never be read as "no references".
        std::fs::write(&snapshots, "not a directory").expect("write");

        let scan = run(&repo.root(), 90);
        assert_eq!(scan.candidates.len(), 0, "{:?}", scan.candidates);
        assert_eq!(scan.preserved.len(), 1);
        assert!(scan.preserved[0].starts_with("models--org--name"));
    }

    #[test]
    fn a_nested_snapshot_link_still_counts_as_a_reference() {
        let repo = Repo::new();
        let nested = repo.root().join("models--org--name/snapshots/deadbee/onnx");
        link("../../../blobs/used", &nested.join("model.onnx"));
        age(&nested.join("model.onnx"), 200);
        age(&nested, 200);
        // The blob was referenced once already, so make a second one and point
        // only the nested link at it: depth must not break the resolution.
        std::fs::write(repo.root().join("models--org--name/blobs/deep"), "deep").unwrap();
        age(&repo.root().join("models--org--name/blobs/deep"), 200);
        std::fs::remove_file(nested.join("model.onnx")).unwrap();
        link("../../../blobs/deep", &nested.join("model.onnx"));
        age(&nested.join("model.onnx"), 200);

        let scan = run(&repo.root(), 90);
        let deep = repo.root().join("models--org--name/blobs/deep");
        assert!(
            !scan
                .candidates
                .iter()
                .any(|candidate| candidate.path == deep),
            "a link two levels down must resolve to ../../..: {:?}",
            scan.candidates
        );
    }

    #[test]
    fn a_symlinked_repository_is_not_followed() {
        let temp = hub(&[("elsewhere/models--x--y/blobs/orphan", "x")]);
        let root = temp.path().join("hub");
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(
            temp.path().join("elsewhere/models--x--y"),
            root.join("models--linked"),
        )
        .unwrap();
        age(
            &temp.path().join("elsewhere/models--x--y/blobs/orphan"),
            200,
        );

        let scan = run(&root, 90);
        assert_eq!(scan.candidates.len(), 0);
        assert_eq!(scan.repos, 0, "a link is not a repository to enumerate");
    }

    #[test]
    fn a_missing_root_is_reported_not_guessed() {
        let temp = hub(&[("hub/keep", "x")]);
        let scan = run(&temp.path().join("absent"), 90);
        assert!(scan.missing_root);
        assert_eq!(scan.candidates.len(), 0);
    }

    #[test]
    fn an_entry_budget_that_runs_out_stops_the_scan() {
        let repo = Repo::new();
        let probe = RealProbe::new().expect("probe").with_open_scan();
        let limits = Limits {
            max_entries: 0,
            time_budget: Duration::from_secs(30),
        };
        let scan = scan(&repo.root(), 90, 1_800_000_000, &limits, &probe);
        assert_ne!(scan.stop, Stop::Complete);
    }

    #[test]
    fn lexical_resolution_matches_the_hub_layout() {
        assert_eq!(
            lexical_resolve(
                Path::new("/hub/models--a--b/snapshots/rev"),
                Path::new("../../blobs/etag")
            ),
            Path::new("/hub/models--a--b/blobs/etag")
        );
        assert_eq!(
            lexical_resolve(
                Path::new("/hub/models--a--b/snapshots/rev/onnx"),
                Path::new("../../../blobs/etag")
            ),
            Path::new("/hub/models--a--b/blobs/etag")
        );
        assert_eq!(
            lexical_resolve(Path::new("/a/b"), Path::new("/etc/shadow")),
            Path::new("/etc/shadow"),
            "an absolute target resolves to itself and is only ever compared"
        );
        assert_eq!(
            lexical_resolve(Path::new("/a/b"), Path::new("./x/../y")),
            Path::new("/a/b/y")
        );
    }

    #[test]
    fn a_leftover_carries_its_reason_code() {
        assert_eq!(Leftover::UnreferencedBlob.code(), "unreferenced_blob");
        assert_eq!(Leftover::Incomplete.code(), "incomplete_download");
    }
}
