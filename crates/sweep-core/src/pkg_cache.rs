//! The pacman package cache: keep versions, not days.
//!
//! `/var/cache/pacman/pkg` holds compressed package archives so a downgrade
//! needs no network. Its retention is not an age: `paccache` keeps the newest
//! *N* versions of each package, because the archive that matters is the newest
//! one, whatever its date. An age cutoff would eventually delete the only copy
//! of the running kernel's package on a machine that has not been upgraded in a
//! while, which is exactly when a rollback is the thing you want.
//!
//! So this scanner groups the cache the way pacman names it:
//!
//! ```text
//! name-[epoch:]pkgver-pkgrel-arch.pkg.tar.<compression>[.sig]
//! ```
//!
//! It parses from the right, because a package name may contain hyphens and a
//! version may not. Every generation — one archive plus its detached signature —
//! is ordered with [`crate::version::vercmp`] and the newest `keep_versions` of
//! each `(name, arch)` are kept.
//!
//! A file that does not parse is left alone and counted. The cache also holds
//! `download-XXXXXX` partial downloads while pacman runs, and a filename this
//! scanner does not understand is not evidence of anything.
//!
//! Two floors apply on top of the version count:
//!
//! * `keep_days` is a recency floor: a generation modified more recently than
//!   the cutoff is never deleted, even if it is the fourth-newest. This is what
//!   `paccache --min-mtime` does, and it covers the case where a user has just
//!   downloaded an old version to downgrade to.
//! * A scan that did not complete plans nothing. Partial knowledge of the cache
//!   is not enough to order its versions.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use crate::probe::FsProbe;
use crate::scan::{self, Limits, Spec, Stop};
use crate::version::vercmp;

/// Suffix every package archive shares, before the compression extension.
const ARCHIVE_MARKER: &str = ".pkg.tar";

/// What one planned path is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A package archive.
    Archive,
    /// The detached signature of a package archive.
    Signature,
}

impl Kind {
    pub fn code(self) -> &'static str {
        match self {
            Kind::Archive => "old_package",
            Kind::Signature => "orphan_signature",
        }
    }
}

/// One path this scan would delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub path: PathBuf,
    pub bytes: u64,
    pub kind: Kind,
}

/// Everything the cache scan found. Default is "nothing seen yet".
#[derive(Debug, Clone, Default)]
pub struct Scan {
    pub stop: Stop,
    pub missing_root: bool,
    pub root_is_symlink: bool,
    pub not_a_directory: bool,
    /// The root itself could not be read, which is not "there is nothing there".
    pub root_unreadable: bool,
    pub candidates: Vec<Candidate>,
    /// Distinct `(name, arch)` pairs seen.
    pub packages: usize,
    /// Archives kept because they are among the newest `keep_versions`.
    pub kept: usize,
    /// Files that are not package archives and were left alone.
    pub unrecognised: usize,
    pub bytes_visited: u64,
}

/// One archive or signature, as the file name describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// The package name, which may itself contain hyphens.
    pub name: Vec<u8>,
    /// `[epoch:]pkgver-pkgrel`, the string `vercmp` orders.
    pub evr: Vec<u8>,
    /// The architecture field, part of the grouping key: a `any` and an
    /// `x86_64` build of one name are different files to keep.
    pub arch: Vec<u8>,
    pub signature: bool,
}

/// Parses a cache file name, or returns `None` when it is not a package.
///
/// Splitting is from the right: the architecture, the release and the version
/// cannot contain a hyphen, and the name can. A name with fewer than four
/// fields is not a package this scanner understands.
pub fn parse(name: &[u8]) -> Option<Parsed> {
    let (body, signature) = match name.strip_suffix(b".sig".as_slice()) {
        Some(body) => (body, true),
        None => (name, false),
    };

    let marker = find_last(body, ARCHIVE_MARKER.as_bytes())?;
    let compression = &body[marker + ARCHIVE_MARKER.len()..];
    // `.pkg.tar` alone, or `.pkg.tar.zst`: exactly one extension. Two dots means
    // something else entirely (`…pkg.tar.zst.part`), which must not be parsed as
    // the package it is a partial copy of.
    if !compression.is_empty() {
        let rest = compression.strip_prefix(b".")?;
        if rest.is_empty() || rest.contains(&b'.') {
            return None;
        }
    }

    let body = &body[..marker];
    // `rsplitn` keeps the remainder as one field, so `python-requests` stays
    // whole: with three separators pulled from the right, everything to the left
    // of the third is the name, hyphens included.
    let mut fields = body.rsplitn(4, |byte| *byte == b'-');
    let arch = fields.next()?;
    let release = fields.next()?;
    let version = fields.next()?;
    let name = fields.next()?;
    // An empty field is not a package: `acl-2.4.0-1.pkg.tar.zst` has only three
    // fields, and a leading hyphen would give an empty name.
    if name.is_empty() || version.is_empty() || release.is_empty() || arch.is_empty() {
        return None;
    }

    let mut evr = version.to_vec();
    evr.push(b'-');
    evr.extend_from_slice(release);

    Some(Parsed {
        name: name.to_vec(),
        evr,
        arch: arch.to_vec(),
        signature,
    })
}

/// `rfind` that returns a byte index, for slices.
fn find_last(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .rev()
        .find(|start| &haystack[*start..*start + needle.len()] == needle)
}

/// One generation: the archive of a version, and its signature if cached.
#[derive(Debug)]
struct Generation {
    archive: Option<usize>,
    signature: Option<usize>,
    /// Newest mtime in the generation; the age floor applies to the whole thing.
    newest: i64,
}

impl Default for Generation {
    fn default() -> Self {
        Self {
            archive: None,
            signature: None,
            // Not 0: a file with a pre-1970 mtime is older than the epoch, and
            // `max` against a zero would silently make it look current.
            newest: i64::MIN,
        }
    }
}

/// Walks one package cache. Read-only: no `unlinkat`, no link followed.
pub fn scan(
    root: &Path,
    keep_versions: u32,
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
        // `pkg -> /mnt/big/pkg` is a legitimate layout, but following it would
        // decide the rule applies to a tree the rule never named.
        out.root_is_symlink = true;
        return out;
    }
    if !root_meta.is_dir() {
        out.not_a_directory = true;
        return out;
    }

    // The cache is flat: depth 1 reads its children and refuses to follow a
    // symlink into somewhere else. The walker's budget applies here too.
    let collected = scan::collect(root, root, 0, &Spec::new(1, limits), probe);
    out.stop = collected.stop;
    out.missing_root = collected.missing_root;
    out.not_a_directory = collected.not_a_directory;
    out.root_unreadable = collected.root_unreadable;
    out.bytes_visited = collected.bytes;

    if out.stop != Stop::Complete || out.missing_root || out.not_a_directory || out.root_unreadable
    {
        // Ordering versions from a partial listing would rank the newest
        // generation against a set that may be missing entries, so nothing is
        // planned. The caller reports why, and the exit path is "keep".
        return out;
    }

    type Key = (Vec<u8>, Vec<u8>, Vec<u8>);
    let mut generations: BTreeMap<Key, Generation> = BTreeMap::new();
    let mut is_archive: Vec<Option<bool>> = vec![None; collected.entries.len()];

    for (index, entry) in collected.entries.iter().enumerate() {
        if entry.is_dir {
            out.unrecognised += 1;
            continue;
        }
        let file_name = entry
            .path
            .file_name()
            .map(|name| name.as_encoded_bytes())
            .unwrap_or_default();
        let Some(fields) = parse(file_name) else {
            out.unrecognised += 1;
            continue;
        };
        let key = (fields.name.clone(), fields.arch.clone(), fields.evr.clone());
        let generation = generations.entry(key).or_default();
        generation.newest = generation.newest.max(entry.mtime);
        if fields.signature {
            generation.signature = Some(index);
        } else {
            generation.archive = Some(index);
        }
        is_archive[index] = Some(!fields.signature);
    }

    // Group by `(name, arch)` and rank each group's generations newest first.
    // `(name, arch)` is the key; each value is that package's generations as
    // `(evr, files)` pairs, ready to be ordered by `vercmp`.
    type Package = (Vec<u8>, Vec<u8>);
    type GenerationKey = (Vec<u8>, Generation);
    let mut groups: BTreeMap<Package, Vec<GenerationKey>> = BTreeMap::new();
    for ((name, arch, evr), generation) in generations {
        groups
            .entry((name, arch))
            .or_default()
            .push((evr, generation));
    }
    out.packages = groups.len();

    let keep = keep_versions.max(1) as usize;
    for (_, mut versions) in groups {
        // `vercmp` is the ordering pacman uses; sorting with it reversed puts the
        // newest generation first, which is what "keep the newest N" means.
        versions.sort_by(|left, right| vercmp(&right.0, &left.0));

        for (rank, (_, generation)) in versions.into_iter().enumerate() {
            // A signature whose archive is gone is dead weight: nothing can
            // verify it against, and it is not a version worth keeping. It still
            // has to be old enough, because it may belong to an archive being
            // written right now.
            if generation.archive.is_none() {
                if generation.newest < cutoff {
                    if let Some(index) = generation.signature {
                        out.candidates
                            .push(candidate(&collected, &is_archive, index));
                    }
                }
                continue;
            }

            if rank < keep || generation.newest >= cutoff {
                out.kept += 1;
                continue;
            }
            for index in [generation.archive, generation.signature]
                .into_iter()
                .flatten()
            {
                out.candidates
                    .push(candidate(&collected, &is_archive, index));
            }
        }
    }

    out.candidates
        .sort_by(|left, right| left.path.cmp(&right.path));
    out
}

/// One planned path, with the bytes and the kind the report needs.
fn candidate(collected: &scan::Collect, is_archive: &[Option<bool>], index: usize) -> Candidate {
    let entry = &collected.entries[index];
    let kind = match is_archive.get(index).copied().flatten() {
        Some(true) => Kind::Archive,
        // Unreachable: only parsed entries become candidates. A signature is the
        // safer default, because it is never the file that matters.
        _ => Kind::Signature,
    };
    Candidate {
        path: entry.path.clone(),
        bytes: entry.bytes,
        kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_real_archive_parses_into_four_fields() {
        let parsed = parse(b"glibc-2.44+r50+g1848099f063e-3-x86_64_v3.pkg.tar.zst").unwrap();
        assert_eq!(parsed.name, b"glibc");
        assert_eq!(parsed.evr, b"2.44+r50+g1848099f063e-3");
        assert_eq!(parsed.arch, b"x86_64_v3");
        assert!(!parsed.signature);
    }

    #[test]
    fn a_hyphenated_name_keeps_its_hyphens() {
        let parsed = parse(b"python-requests-2.32.3-1-any.pkg.tar.zst").unwrap();
        assert_eq!(parsed.name, b"python-requests");
        assert_eq!(parsed.evr, b"2.32.3-1");
        assert_eq!(parsed.arch, b"any");
    }

    #[test]
    fn an_epoch_is_part_of_the_version() {
        let parsed = parse(b"foo-1:2.0-3-x86_64.pkg.tar.zst").unwrap();
        assert_eq!(parsed.name, b"foo");
        assert_eq!(parsed.evr, b"1:2.0-3");
    }

    #[test]
    fn a_signature_is_the_same_generation() {
        let signed = parse(b"acl-2.4.0-1.1-x86_64_v3.pkg.tar.zst.sig").unwrap();
        let archive = parse(b"acl-2.4.0-1.1-x86_64_v3.pkg.tar.zst").unwrap();
        assert!(signed.signature);
        assert!(!archive.signature);
        assert_eq!(signed.name, archive.name);
        assert_eq!(signed.evr, archive.evr);
        assert_eq!(signed.arch, archive.arch);
    }

    #[test]
    fn every_compression_suffix_is_recognised() {
        for suffix in [
            ".pkg.tar",
            ".pkg.tar.gz",
            ".pkg.tar.bz2",
            ".pkg.tar.xz",
            ".pkg.tar.zst",
            ".pkg.tar.lrz",
            ".pkg.tar.lzo",
            ".pkg.tar.Z",
        ] {
            let name = format!("acl-2.4.0-1-x86_64{suffix}");
            assert!(parse(name.as_bytes()).is_some(), "{suffix} must parse");
        }
    }

    #[test]
    fn everything_else_is_left_alone() {
        for name in [
            // pacman's in-progress downloads
            "download-0tOPpQ",
            "download-2R9JUo.part",
            // a partial copy of a package: not the package
            "acl-2.4.0-1-x86_64.pkg.tar.zst.part",
            // not an archive at all
            "acl-2.4.0-1-x86_64.tar.zst",
            "acl.pkg.tar.zst",
            "README",
            "",
            // too few fields to be an archive
            "acl-2.4.0-x86_64.pkg.tar.zst",
            // empty fields
            "-2.4.0-1-x86_64.pkg.tar.zst",
            "acl-2.4.0-1.pkg.tar.zst",
        ] {
            assert!(parse(name.as_bytes()).is_none(), "{name:?} must not parse");
        }
    }

    #[test]
    fn a_non_utf8_name_parses_like_any_other() {
        let mut name = b"acl-2.4.0-1-x86_64.pkg.tar.zst".to_vec();
        name[0] = 0xff;
        let parsed = parse(&name).expect("bytes are bytes");
        assert_eq!(parsed.name, &[0xff, b'c', b'l']);
    }

    // ------------------------------------------------------------- scanning ---

    use crate::probe::RealProbe;
    use std::fs::{File, FileTimes};
    use std::time::{Duration, SystemTime};

    fn cache(files: &[&str]) -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("tempdir");
        for name in files {
            std::fs::write(temp.path().join(name), "archive body").expect("write");
        }
        temp
    }

    fn age(path: &Path, days: i64) {
        let when = SystemTime::now() - Duration::from_secs((days.max(0) as u64) * 86_400);
        let file = File::open(path).expect("open");
        file.set_times(FileTimes::new().set_modified(when))
            .expect("set mtime");
    }

    fn run(root: &Path, keep_versions: u32, keep_days: u32) -> Scan {
        let probe = RealProbe::new().expect("probe").with_open_scan();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64;
        scan(
            root,
            keep_versions,
            keep_days,
            now,
            &Limits::default(),
            &probe,
        )
    }

    fn names(scan: &Scan) -> Vec<String> {
        scan.candidates
            .iter()
            .map(|candidate| {
                candidate
                    .path
                    .file_name()
                    .expect("name")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    #[test]
    fn the_newest_versions_are_kept_and_the_rest_are_planned() {
        let temp = cache(&[
            "foo-1.0-1-x86_64.pkg.tar.zst",
            "foo-1.1-1-x86_64.pkg.tar.zst",
            "foo-1.10-1-x86_64.pkg.tar.zst",
        ]);
        for name in [
            "foo-1.0-1-x86_64.pkg.tar.zst",
            "foo-1.1-1-x86_64.pkg.tar.zst",
            "foo-1.10-1-x86_64.pkg.tar.zst",
        ] {
            age(&temp.path().join(name), 90);
        }

        let scan = run(temp.path(), 2, 0);
        assert_eq!(scan.packages, 1);
        assert_eq!(scan.kept, 2);
        assert_eq!(
            names(&scan),
            ["foo-1.0-1-x86_64.pkg.tar.zst"],
            "1.10 is newer than 1.9: text order would have kept the wrong two"
        );
    }

    #[test]
    fn versions_are_compared_the_way_pacman_compares_them() {
        let temp = cache(&["bar-1.9-1-any.pkg.tar.zst", "bar-1.10-1-any.pkg.tar.zst"]);
        age(&temp.path().join("bar-1.9-1-any.pkg.tar.zst"), 90);
        age(&temp.path().join("bar-1.10-1-any.pkg.tar.zst"), 90);

        let scan = run(temp.path(), 1, 0);
        assert_eq!(names(&scan), ["bar-1.9-1-any.pkg.tar.zst"]);
    }

    #[test]
    fn a_signature_never_uses_up_a_kept_slot() {
        // The archive and its `.sig` are one generation. Counting them as two
        // versions would keep `1.0` and delete `0.9` while the user asked for two.
        let temp = cache(&[
            "baz-0.9-1-x86_64.pkg.tar.zst",
            "baz-0.9-1-x86_64.pkg.tar.zst.sig",
            "baz-1.0-1-x86_64.pkg.tar.zst",
            "baz-1.0-1-x86_64.pkg.tar.zst.sig",
        ]);
        for entry in std::fs::read_dir(temp.path()).expect("read") {
            age(&entry.expect("entry").path(), 90);
        }

        let scan = run(temp.path(), 2, 0);
        assert!(scan.candidates.is_empty(), "{:?}", names(&scan));
        assert_eq!(scan.kept, 2, "two generations, each with its signature");
    }

    #[test]
    fn a_deleted_generation_takes_its_signature_with_it() {
        let temp = cache(&[
            "qux-1.0-1-x86_64.pkg.tar.zst",
            "qux-1.0-1-x86_64.pkg.tar.zst.sig",
            "qux-2.0-1-x86_64.pkg.tar.zst",
            "qux-2.0-1-x86_64.pkg.tar.zst.sig",
            "qux-3.0-1-x86_64.pkg.tar.zst",
        ]);
        for entry in std::fs::read_dir(temp.path()).expect("read") {
            age(&entry.expect("entry").path(), 90);
        }

        let scan = run(temp.path(), 2, 0);
        assert_eq!(
            names(&scan),
            [
                "qux-1.0-1-x86_64.pkg.tar.zst",
                "qux-1.0-1-x86_64.pkg.tar.zst.sig",
            ]
        );
    }

    #[test]
    fn a_signature_without_its_archive_is_dead_weight() {
        let temp = cache(&[
            "old-1.0-1-x86_64.pkg.tar.zst.sig",
            "old-2.0-1-x86_64.pkg.tar.zst",
        ]);
        age(&temp.path().join("old-1.0-1-x86_64.pkg.tar.zst.sig"), 90);
        age(&temp.path().join("old-2.0-1-x86_64.pkg.tar.zst"), 90);

        let scan = run(temp.path(), 5, 0);
        assert_eq!(
            names(&scan),
            ["old-1.0-1-x86_64.pkg.tar.zst.sig"],
            "keeping five versions must not keep a signature nothing verifies"
        );
        assert_eq!(scan.candidates[0].kind, Kind::Signature);
    }

    #[test]
    fn the_recency_floor_keeps_what_was_just_downloaded() {
        // `keep_days` is part of this kind, not decoration: a freshly
        // downloaded old version is a downgrade in progress, not a leftover.
        let temp = cache(&[
            "down-1.0-1-x86_64.pkg.tar.zst",
            "down-2.0-1-x86_64.pkg.tar.zst",
            "down-3.0-1-x86_64.pkg.tar.zst",
        ]);
        age(&temp.path().join("down-1.0-1-x86_64.pkg.tar.zst"), 1);
        age(&temp.path().join("down-2.0-1-x86_64.pkg.tar.zst"), 90);
        age(&temp.path().join("down-3.0-1-x86_64.pkg.tar.zst"), 90);

        let scan = run(temp.path(), 1, 7);
        assert_eq!(
            names(&scan),
            ["down-2.0-1-x86_64.pkg.tar.zst"],
            "the old version downloaded yesterday stays"
        );
    }

    #[test]
    fn architectures_are_kept_apart() {
        let temp = cache(&[
            "multi-1.0-1-any.pkg.tar.zst",
            "multi-2.0-1-x86_64.pkg.tar.zst",
        ]);
        age(&temp.path().join("multi-1.0-1-any.pkg.tar.zst"), 90);
        age(&temp.path().join("multi-2.0-1-x86_64.pkg.tar.zst"), 90);

        let scan = run(temp.path(), 1, 0);
        assert!(
            scan.candidates.is_empty(),
            "one version of each arch is within the keep count: {:?}",
            names(&scan)
        );
    }

    #[test]
    fn files_that_are_not_packages_are_counted_and_left_alone() {
        let temp = cache(&[
            "download-0tOPpQ",
            "acl-2.4.0-1-x86_64.pkg.tar.zst.part",
            "acl-2.4.0-1-x86_64.pkg.tar.zst",
            "acl-2.5.0-1-x86_64.pkg.tar.zst",
        ]);
        age(&temp.path().join("acl-2.4.0-1-x86_64.pkg.tar.zst"), 90);
        age(&temp.path().join("acl-2.5.0-1-x86_64.pkg.tar.zst"), 90);

        let scan = run(temp.path(), 1, 0);
        assert_eq!(scan.unrecognised, 2);
        assert_eq!(names(&scan), ["acl-2.4.0-1-x86_64.pkg.tar.zst"]);
    }

    #[test]
    fn a_symlink_in_the_cache_is_not_followed() {
        let temp = cache(&["link-1.0-1-x86_64.pkg.tar.zst"]);
        let target = temp.path().join("link-1.0-1-x86_64.pkg.tar.zst");
        std::fs::remove_file(&target).expect("remove");
        std::os::unix::fs::symlink("/etc/passwd", &target).expect("symlink");

        let scan = run(temp.path(), 1, 0);
        assert!(
            scan.candidates.is_empty(),
            "a symlink is never the archive the rule is about"
        );
    }

    #[test]
    fn a_missing_cache_is_reported_rather_than_treated_as_empty() {
        let temp = tempfile::tempdir().expect("tempdir");
        let scan = run(&temp.path().join("nope"), 1, 0);
        assert!(scan.missing_root);
        assert!(scan.candidates.is_empty());
        assert!(!scan.root_is_symlink);
    }

    #[test]
    fn two_runs_produce_the_same_list() {
        let temp = cache(&[
            "same-1.0-1-x86_64.pkg.tar.zst",
            "same-2.0-1-x86_64.pkg.tar.zst",
            "same-3.0-1-x86_64.pkg.tar.zst",
            "other-1.0-1-any.pkg.tar.zst",
            "other-2.0-1-any.pkg.tar.zst",
        ]);
        for entry in std::fs::read_dir(temp.path()).expect("read") {
            age(&entry.expect("entry").path(), 90);
        }
        let first = run(temp.path(), 1, 0);
        let second = run(temp.path(), 1, 0);
        assert_eq!(names(&first), names(&second));
        assert_eq!(first.kept, second.kept);
    }
}
