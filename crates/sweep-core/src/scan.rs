//! The read-only walker.
//!
//! This module enumerates entries below a rule root. It never deletes, never
//! follows a symbolic link, never crosses a mount boundary, and never returns
//! partial output as if it were complete: a budget that runs out sets
//! [`Stop`], and the caller is expected to say so.
//!
//! Ordering matters. Entries are emitted **post-order** - a directory after its
//! children - because the funnel deletes one entry per `unlinkat` and can never
//! recurse. A directory emitted before its children would fail with `ENOTEMPTY`
//! and be reported as skipped, which is worse than not trying.
//!
//! The walker also refuses to descend into a directory that another rule claims.
//! That is what makes `user.cache.residual` safe: it covers the cache entries the
//! catalog does not know about, and every catalogued cache keeps its own
//! retention instead of being swept by the broad rule.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::paths::is_within;
use crate::probe::FsProbe;
use crate::rules::Pattern;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// Entries visited before the walk stops and says so.
    pub max_entries: usize,
    /// Wall-clock budget. A cache tree on a slow disk can take minutes.
    pub time_budget: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // Large enough for a package manager cache, small enough that a
            // mistaken root cannot turn a preview into a coffee break.
            max_entries: 200_000,
            time_budget: Duration::from_secs(30),
        }
    }
}

/// Why a walk stopped. Only [`Stop::Complete`] means the entry list is the whole
/// subtree.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Stop {
    #[default]
    Complete,
    EntryBudget,
    TimeBudget,
}

impl Stop {
    pub fn is_complete(self) -> bool {
        matches!(self, Stop::Complete)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Stats {
    /// Entries emitted.
    pub emitted: usize,
    /// Symbolic links skipped: never followed, never deleted.
    pub symlinks: usize,
    /// Entries matched by an `exclude` pattern.
    pub excluded: usize,
    /// Entries below a root another rule claims.
    pub claimed: usize,
    /// Entries on a different device than the rule root.
    pub other_device: usize,
    /// Entries that are themselves mount points.
    pub mount_points: usize,
    /// Directories whose contents could not be read.
    pub unreadable: usize,
    /// Directories at the depth limit, therefore not emitted.
    pub too_deep: usize,
    /// Entries not covered by the mount table. Unknown is refused, not assumed.
    pub unknown_mount: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: PathBuf,
    pub is_dir: bool,
    /// A symbolic link the walk was asked to include. Only `Spec::include_links`
    /// sets this, and only a whole-tree sweep asks: the sink unlinks the link
    /// itself and never what it points at.
    pub is_symlink: bool,
    /// Bytes accounted on disk (`st_blocks * 512`), the number `du` reports.
    pub bytes: u64,
    /// Modification time, seconds since the Unix epoch.
    pub mtime: i64,
}

/// Why an entry was left alone.
///
/// These are not refusals by the policy - validation has its own reasons - but
/// facts the walker discovered. They matter to the caller because a directory
/// that still holds a blocked entry cannot be emptied, so planning it would only
/// produce a `directory_not_empty` refusal at the funnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BlockKind {
    Excluded,
    Claimed,
    Symlink,
    OtherDevice,
    MountPoint,
    UnknownMount,
    Unreadable,
    TooDeep,
}

impl BlockKind {
    pub fn code(self) -> &'static str {
        match self {
            BlockKind::Excluded => "excluded",
            BlockKind::Claimed => "claimed_by_another_rule",
            BlockKind::Symlink => "symlink",
            BlockKind::OtherDevice => "other_device",
            BlockKind::MountPoint => "mount_point",
            BlockKind::UnknownMount => "unknown_mount",
            BlockKind::Unreadable => "unreadable",
            BlockKind::TooDeep => "depth_limit",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// Relative to the walk base, so the caller can group by subtree.
    pub path: PathBuf,
    pub kind: BlockKind,
}

#[derive(Debug, Clone, Default)]
pub struct Collect {
    /// Post-order: every child appears before its parent.
    pub entries: Vec<Entry>,
    pub stop: Stop,
    pub stats: Stats,
    /// Entries that were deliberately not included, with the reason.
    pub blocked: Vec<Block>,
    /// Newest modification time seen, including the root of this walk.
    pub newest: i64,
    /// Accounted bytes of everything visited, for report-only lines.
    pub bytes: u64,
    pub missing_root: bool,
    pub not_a_directory: bool,
    /// The root itself could not be read (permissions, I/O). Distinct from a
    /// missing root: "we were denied" is not "there is nothing there".
    pub root_unreadable: bool,
}

impl Collect {
    /// True when the walk saw everything below `relative`.
    ///
    /// An exclusion, an unreadable directory or a depth limit means "there is
    /// more here than this list", and a directory whose contents are only partly
    /// known must not be scheduled for deletion.
    pub fn blocked_within(&self, relative: &Path) -> Option<&Block> {
        self.blocked
            .iter()
            .find(|block| block.path.starts_with(relative))
    }

    /// Blocked entries grouped by their top-level component, for age decisions.
    pub fn blocked_under(&self, top: &Path) -> Vec<&Block> {
        self.blocked
            .iter()
            .filter(|block| block.path.starts_with(top))
            .collect()
    }
}

/// What to emit.
#[derive(Debug, Clone, Copy)]
pub enum Select<'a> {
    /// Every descendant, files and directories.
    Everything,
    /// Only files whose name matches one of `patterns`.
    Files(&'a [Pattern]),
}

/// Everything a walk needs besides the rule root and the probe.
pub struct Spec<'a> {
    /// Levels below the rule root to visit. 1 means the root's children.
    pub depth: usize,
    pub select: Select<'a>,
    pub exclude: &'a [Pattern],
    /// Roots claimed by other rules; their subtrees are never entered.
    pub skip_roots: &'a [PathBuf],
    /// Emit symbolic links instead of blocking their parents.
    ///
    /// Off by default, and that default is deliberate: a link inside a cache
    /// root is often the user's own arrangement (`~/.cache/foo -> /mnt/big/foo`)
    /// and deleting it frees nothing while breaking the setup. A build artifact
    /// is the other case: `node_modules/.bin` and a virtualenv's `bin/python3`
    /// are links the package manager writes, and a sweep that leaves them
    /// behind leaves a tree that looks installed but is not.
    pub include_links: bool,
    pub limits: &'a Limits,
}

impl<'a> Spec<'a> {
    pub fn new(depth: usize, limits: &'a Limits) -> Self {
        Self {
            depth,
            select: Select::Everything,
            exclude: &[],
            skip_roots: &[],
            include_links: false,
            limits,
        }
    }
}

pub(crate) struct Budget<'a> {
    limits: &'a Limits,
    charged: usize,
    started: Instant,
}

impl<'a> Budget<'a> {
    pub(crate) fn new(limits: &'a Limits) -> Self {
        Self {
            limits,
            charged: 0,
            started: Instant::now(),
        }
    }

    pub(crate) fn charge(&mut self) -> Result<(), Stop> {
        if self.charged >= self.limits.max_entries {
            return Err(Stop::EntryBudget);
        }
        self.charged += 1;
        if self.started.elapsed() >= self.limits.time_budget {
            return Err(Stop::TimeBudget);
        }
        Ok(())
    }
}

/// Walks `path`, emitting entries that live below `base`.
///
/// `base` is the rule root and is used for two things: `exclude` patterns are
/// matched against the path relative to it, and the depth limit is counted from
/// it. Passing a child of `base` lets the caller age-test one top-level entry at
/// a time while keeping pattern semantics identical.
///
/// `level` is the depth of `path` below `base`: `0` when the two are the same
/// directory, `1` for a direct child. The caller supplies it because aging one
/// top-level entry at a time re-roots the walk at that entry while the depth
/// limit keeps counting from the rule root.
pub fn collect(
    base: &Path,
    path: &Path,
    level: usize,
    spec: &Spec<'_>,
    probe: &dyn FsProbe,
) -> Collect {
    let mut out = Collect::default();
    let mut budget = Budget::new(spec.limits);

    let root_meta = match probe.symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) => {
            if error.kind() == std::io::ErrorKind::NotFound {
                out.missing_root = true;
            } else {
                out.stats.unreadable += 1;
            }
            return out;
        }
    };
    if root_meta.is_symlink() {
        out.stats.symlinks += 1;
        return out;
    }
    out.newest = root_meta.mtime;
    if !root_meta.is_dir() {
        out.not_a_directory = true;
        return out;
    }

    // `st_dev` of the root, not mountinfo's `major:minor`: a btrfs subvolume has
    // an anonymous device number that the mount table does not report, and a
    // mountinfo comparison would let the walk descend into one.
    let device = root_meta.dev;

    walk(
        base,
        path,
        level,
        device,
        spec,
        probe,
        &mut budget,
        &mut out,
    );
    out
}

#[allow(clippy::too_many_arguments)]
fn walk(
    base: &Path,
    directory: &Path,
    level: usize,
    device: u64,
    spec: &Spec<'_>,
    probe: &dyn FsProbe,
    budget: &mut Budget<'_>,
    out: &mut Collect,
) {
    let read = match std::fs::read_dir(directory) {
        Ok(read) => read,
        Err(_) => {
            out.stats.unreadable += 1;
            if directory == base {
                out.root_unreadable = true;
            } else {
                block(out, base, directory, BlockKind::Unreadable);
            }
            return;
        }
    };

    let mut children = Vec::new();
    for entry in read {
        match entry {
            Ok(entry) => children.push(entry.path()),
            Err(_) => {
                out.stats.unreadable += 1;
                block(out, base, directory, BlockKind::Unreadable);
            }
        }
    }
    // Sorted so two runs produce the same plan and the same hash, and so the
    // post-order grouping is stable.
    children.sort();

    for child in children {
        if let Err(stop) = budget.charge() {
            out.stop = stop;
            return;
        }

        let relative = child.strip_prefix(base).unwrap_or(&child);
        let meta = match probe.symlink_metadata(&child) {
            Ok(meta) => meta,
            Err(_) => {
                out.stats.unreadable += 1;
                block(out, base, &child, BlockKind::Unreadable);
                continue;
            }
        };
        if meta.is_symlink() {
            // Never followed. Whether the link itself is emitted depends on the
            // caller: a cache keeps its links, a build artifact does not.
            out.stats.symlinks += 1;
            if !spec.include_links || !matches!(spec.select, Select::Everything) {
                // A blocked link also blocks its parent from being emptied.
                block(out, base, &child, BlockKind::Symlink);
                continue;
            }
            out.entries.push(Entry {
                path: child,
                is_dir: false,
                is_symlink: true,
                bytes: meta.accounted_bytes(),
                mtime: meta.mtime,
            });
            out.stats.emitted += 1;
            out.bytes = out.bytes.saturating_add(meta.accounted_bytes());
            out.newest = out.newest.max(meta.mtime);
            continue;
        }

        if spec
            .exclude
            .iter()
            .any(|pattern| pattern.matches_relative(relative))
        {
            out.stats.excluded += 1;
            block(out, base, &child, BlockKind::Excluded);
            continue;
        }
        if spec.skip_roots.iter().any(|root| is_within(root, &child)) {
            out.stats.claimed += 1;
            block(out, base, &child, BlockKind::Claimed);
            continue;
        }

        if meta.dev != device {
            // A different `st_dev` below the root is a nested mount or another
            // btrfs subvolume. Its contents are not covered by this rule's
            // evidence, and validation would refuse each item anyway.
            out.stats.other_device += 1;
            block(out, base, &child, BlockKind::OtherDevice);
            continue;
        }
        if probe.mount_table().facts(&child).is_none() {
            out.stats.unknown_mount += 1;
            block(out, base, &child, BlockKind::UnknownMount);
            continue;
        }
        if probe.mount_table().is_mount_point(&child) {
            // A bind mount keeps the source device, so `st_dev` cannot see it.
            out.stats.mount_points += 1;
            block(out, base, &child, BlockKind::MountPoint);
            continue;
        }

        if meta.is_dir() {
            // `child_level` is the level of `child`. A directory at the depth
            // limit is not descended into, so it cannot be fully enumerated and
            // must not be emitted: `unlinkat` would fail with ENOTEMPTY.
            let child_level = level + 1;
            if child_level < spec.depth {
                walk(base, &child, child_level, device, spec, probe, budget, out);
                if matches!(spec.select, Select::Everything) {
                    out.entries.push(Entry {
                        path: child,
                        is_dir: true,
                        is_symlink: false,
                        bytes: meta.accounted_bytes(),
                        mtime: meta.mtime,
                    });
                    out.stats.emitted += 1;
                    out.bytes = out.bytes.saturating_add(meta.accounted_bytes());
                }
            } else if matches!(spec.select, Select::Everything) {
                out.stats.too_deep += 1;
                block(out, base, &child, BlockKind::TooDeep);
            }
            out.newest = out.newest.max(meta.mtime);
            if out.stop != Stop::Complete {
                return;
            }
            continue;
        }

        out.newest = out.newest.max(meta.mtime);
        if let Select::Files(patterns) = spec.select {
            if !patterns
                .iter()
                .any(|pattern| pattern.matches_relative(relative))
            {
                continue;
            }
        }
        out.entries.push(Entry {
            path: child,
            is_dir: false,
            is_symlink: false,
            bytes: meta.accounted_bytes(),
            mtime: meta.mtime,
        });
        out.stats.emitted += 1;
        out.bytes = out.bytes.saturating_add(meta.accounted_bytes());
    }
}

fn block(out: &mut Collect, base: &Path, path: &Path, kind: BlockKind) {
    // A block is only interesting as "something below this point was left
    // alone", so the path is stored relative to the rule root.
    if let Ok(relative) = path.strip_prefix(base) {
        if relative.as_os_str().is_empty() {
            return;
        }
        out.blocked.push(Block {
            path: relative.to_path_buf(),
            kind,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::RealProbe;
    use std::fs::{File, FileTimes};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture() -> (tempfile::TempDir, RealProbe) {
        let temp = tempfile::tempdir().expect("temp dir");
        let probe = RealProbe::new().expect("probe").with_open_scan();
        (temp, probe)
    }

    fn touch(root: &Path, relative: &str, body: &str) -> PathBuf {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("parents");
        std::fs::write(&path, body).expect("write");
        path
    }

    fn age(path: &Path, days: i64) {
        let when = SystemTime::now() - Duration::from_secs((days.max(0) as u64) * 86_400);
        // Read-only is enough for `futimens`, and the target may be a directory.
        let file = File::open(path).expect("open");
        file.set_times(FileTimes::new().set_modified(when))
            .expect("set mtime");
    }

    fn limits() -> Limits {
        Limits {
            max_entries: 10_000,
            time_budget: Duration::from_secs(30),
        }
    }

    #[test]
    fn children_are_emitted_before_their_parent() {
        let (temp, probe) = fixture();
        let root = temp.path().join("cache");
        touch(&root, "a/one.txt", "1");
        touch(&root, "a/two.txt", "2");
        touch(&root, "b/three.txt", "3");

        let specs = limits();
        let spec = Spec::new(8, &specs);
        let collected = collect(&root, &root, 0, &spec, &probe);
        assert_eq!(collected.stop, Stop::Complete);

        let paths: Vec<String> = collected
            .entries
            .iter()
            .map(|entry| {
                entry
                    .path
                    .strip_prefix(&root)
                    .unwrap()
                    .display()
                    .to_string()
            })
            .collect();
        assert_eq!(
            paths,
            vec!["a/one.txt", "a/two.txt", "a", "b/three.txt", "b"]
        );
    }

    #[test]
    fn symbolic_links_are_never_followed_or_emitted() {
        let (temp, probe) = fixture();
        let root = temp.path().join("cache");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("keep.txt"), "keep").unwrap();
        touch(&root, "real.txt", "x");
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();

        let specs = limits();
        let spec = Spec::new(8, &specs);
        let collected = collect(&root, &root, 0, &spec, &probe);
        assert_eq!(collected.stats.symlinks, 1);
        assert!(collected
            .entries
            .iter()
            .all(|entry| entry.path.file_name() != Some("keep.txt".as_ref())));
        assert!(std::fs::symlink_metadata(root.join("link")).is_ok());
    }

    #[test]
    fn a_link_is_emitted_only_when_the_caller_asks_for_links() {
        // Two callers, two answers. A cache keeps the user's own arrangement
        // untouched; a build artifact has to take the links the package manager
        // wrote, or the tree still looks installed.
        let (temp, probe) = fixture();
        let root = temp.path().join("node_modules");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("keep.txt"), "keep").unwrap();
        touch(&root, ".bin/tool", "#!/bin/sh\n");
        std::os::unix::fs::symlink(&outside, root.join(".bin/link")).unwrap();

        let specs = limits();
        let strict = Spec::new(8, &specs);
        let kept = collect(&root, &root, 0, &strict, &probe);
        assert!(
            kept.entries
                .iter()
                .all(|entry| entry.path.file_name() != Some("link".as_ref())),
            "a link is not emitted by default"
        );
        assert_eq!(
            kept.blocked_within(Path::new(".bin"))
                .map(|block| block.kind),
            Some(BlockKind::Symlink),
            "and its parent cannot be reported empty"
        );

        let mut loose = Spec::new(8, &specs);
        loose.include_links = true;
        let taken = collect(&root, &root, 0, &loose, &probe);
        let link = taken
            .entries
            .iter()
            .find(|entry| entry.path.file_name() == Some("link".as_ref()))
            .expect("the link itself is emitted");
        assert!(link.is_symlink, "and it is recorded as a link");
        assert!(
            taken
                .entries
                .iter()
                .all(|entry| entry.path.file_name() != Some("keep.txt".as_ref())),
            "emitting a link must never follow it"
        );
        assert!(
            taken.blocked.is_empty(),
            "a walk that takes its links has nothing blocked: {:?}",
            taken.blocked
        );
    }

    #[test]
    fn exclude_prunes_a_whole_subtree() {
        let (temp, probe) = fixture();
        let root = temp.path().join("cache");
        touch(&root, "keep/a.txt", "a");
        touch(&root, "virtualenvs/lib/python/x.py", "x");

        let exclude = vec![Pattern::new("virtualenvs").unwrap()];
        let specs = limits();
        let mut spec = Spec::new(8, &specs);
        spec.exclude = &exclude;
        let collected = collect(&root, &root, 0, &spec, &probe);

        assert_eq!(collected.stats.excluded, 1);
        let names: Vec<String> = collected
            .entries
            .iter()
            .map(|entry| {
                entry
                    .path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();
        assert!(!names.iter().any(|name| name == "virtualenvs"));
        assert!(names.iter().any(|name| name == "a.txt"));
    }

    #[test]
    fn a_claimed_root_is_never_entered() {
        let (temp, probe) = fixture();
        let root = temp.path().join("cache");
        touch(&root, "uv/archive.bin", "u");
        touch(&root, "unknown/blob.bin", "b");

        let claimed = vec![root.join("uv")];
        let specs = limits();
        let mut spec = Spec::new(8, &specs);
        spec.skip_roots = &claimed;
        let collected = collect(&root, &root, 0, &spec, &probe);

        assert_eq!(collected.stats.claimed, 1);
        assert!(collected
            .entries
            .iter()
            .all(|entry| !entry.path.starts_with(root.join("uv"))));
        assert!(collected
            .entries
            .iter()
            .any(|entry| entry.path.ends_with("blob.bin")));
    }

    #[test]
    fn the_entry_budget_stops_the_walk_and_says_so() {
        let (temp, probe) = fixture();
        let root = temp.path().join("cache");
        for index in 0..50 {
            touch(&root, &format!("f{index}.txt"), "x");
        }

        let specs = Limits {
            max_entries: 10,
            time_budget: Duration::from_secs(30),
        };
        let spec = Spec::new(8, &specs);
        let collected = collect(&root, &root, 0, &spec, &probe);
        assert_eq!(collected.stop, Stop::EntryBudget);
        assert!(collected.entries.len() < 50);
        assert!(!collected.stop.is_complete());
    }

    #[test]
    fn the_time_budget_stops_the_walk() {
        let (temp, probe) = fixture();
        let root = temp.path().join("cache");
        touch(&root, "a.txt", "x");

        let specs = Limits {
            max_entries: 1_000,
            time_budget: Duration::ZERO,
        };
        let spec = Spec::new(8, &specs);
        let collected = collect(&root, &root, 0, &spec, &probe);
        assert_eq!(collected.stop, Stop::TimeBudget);
    }

    #[test]
    fn the_depth_limit_skips_a_directory_it_cannot_empty() {
        let (temp, probe) = fixture();
        let root = temp.path().join("cache");
        touch(&root, "one/two/three.txt", "x");

        let specs = limits();
        let spec = Spec::new(2, &specs);
        let collected = collect(&root, &root, 0, &spec, &probe);
        // `one` is emitted (its child `two` is at the limit and is not).
        assert!(collected
            .entries
            .iter()
            .any(|entry| entry.path.ends_with("one")));
        assert!(!collected
            .entries
            .iter()
            .any(|entry| entry.path.ends_with("two")));
        assert!(collected.stats.too_deep >= 1);
    }

    #[test]
    fn file_selection_never_emits_directories() {
        let (temp, probe) = fixture();
        let root = temp.path().join("cache");
        touch(&root, "a/x.log", "x");
        touch(&root, "a/y.txt", "y");

        let patterns = vec![Pattern::new("*.log").unwrap()];
        let specs = limits();
        let mut spec = Spec::new(8, &specs);
        spec.select = Select::Files(&patterns);
        let collected = collect(&root, &root, 0, &spec, &probe);

        assert_eq!(collected.entries.len(), 1);
        assert!(collected.entries[0].path.ends_with("x.log"));
        assert!(collected.entries.iter().all(|entry| !entry.is_dir));
    }

    #[test]
    fn newest_mtime_covers_the_whole_subtree() {
        let (temp, probe) = fixture();
        let root = temp.path().join("cache");
        let old = touch(&root, "app/old.bin", "o");
        let fresh = touch(&root, "app/nested/fresh.bin", "f");
        age(&old, 90);
        age(&root.join("app/nested"), 90);
        age(&root.join("app"), 90);

        let specs = limits();
        let spec = Spec::new(8, &specs);
        let collected = collect(&root, &root.join("app"), 1, &spec, &probe);
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - 30 * 86_400;
        assert!(
            collected.newest > cutoff,
            "a fresh nested file must keep the subtree"
        );
        assert!(std::fs::metadata(fresh).is_ok());
    }

    #[test]
    fn an_excluded_entry_blocks_every_ancestor_up_to_the_root() {
        let (temp, probe) = fixture();
        let root = temp.path().join("cache");
        touch(&root, "app/old.txt", "old");
        touch(&root, "app/keep/fresh.txt", "fresh");

        let exclude = vec![Pattern::new("app/keep").unwrap()];
        let specs = limits();
        let mut spec = Spec::new(8, &specs);
        spec.exclude = &exclude;
        let collected = collect(&root, &root, 1, &spec, &probe);

        let block = collected
            .blocked_within(Path::new("app"))
            .expect("an excluded child blocks its parent");
        assert_eq!(block.kind, BlockKind::Excluded);
        assert!(collected.blocked_within(Path::new("app/keep")).is_some());
        assert!(collected.blocked_within(Path::new("app/other")).is_none());
    }

    #[test]
    fn a_symlink_blocks_the_directory_that_contains_it() {
        let (temp, probe) = fixture();
        let root = temp.path().join("cache");
        touch(&root, "app/old.txt", "old");
        std::os::unix::fs::symlink("/etc/passwd", root.join("app/link")).unwrap();

        let specs = limits();
        let spec = Spec::new(8, &specs);
        let collected = collect(&root, &root, 1, &spec, &probe);
        let block = collected
            .blocked_within(Path::new("app"))
            .expect("a symlink blocks its parent");
        assert_eq!(block.kind, BlockKind::Symlink);
    }

    #[test]
    fn a_missing_root_is_reported_not_guessed() {
        let (temp, probe) = fixture();
        let specs = limits();
        let spec = Spec::new(8, &specs);
        let collected = collect(temp.path(), &temp.path().join("absent"), 1, &spec, &probe);
        assert!(collected.missing_root);
        assert!(collected.entries.is_empty());
        assert_eq!(collected.stop, Stop::Complete);
    }

    #[test]
    fn a_file_root_is_not_a_directory_to_sweep() {
        let (temp, probe) = fixture();
        let file = touch(temp.path(), "file.txt", "x");
        let specs = limits();
        let spec = Spec::new(8, &specs);
        let collected = collect(temp.path(), &file, 1, &spec, &probe);
        assert!(collected.not_a_directory);
        assert!(collected.entries.is_empty());
    }
}
