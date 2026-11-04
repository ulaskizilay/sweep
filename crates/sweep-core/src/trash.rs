//! Reading the freedesktop trash, as pairs.
//!
//! The trash is two directories: `files/` holds the payload, and `info/` holds
//! one `<name>.trashinfo` record per entry, which is what the desktop's own
//! "Restore" reads to put the file back. Emptying the trash therefore means
//! removing both, and in that order. A record whose payload survived would offer
//! a restore that cannot work; a payload whose record is gone is a file the user
//! can no longer see, so it is neither visible nor restorable.
//!
//! That is why this module answers with pairs rather than a path list. The
//! selection turns each pair into the set the elevated child re-derives, the
//! planner marks the record with the payload it depends on, and the funnel
//! removes the record only after the payload is gone.
//!
//! Scope is the user's home trash (`$XDG_DATA_HOME/Trash`) only. A per-mount
//! `.Trash-<uid>` directory belongs to a filesystem this command never inspected,
//! and emptying one from here is how a removable disk loses files it was holding
//! for another session.
//!
//! Nothing in this module deletes or moves anything. It reads.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::probe::FsProbe;
use crate::scan::{self, Limits, Spec, Stop};

/// How deep a trashed tree is walked.
///
/// Deeper than any cache rule: a trashed home directory is the reason the trash
/// exists, and stopping at the cache depth would leave its parent unremovable and
/// the whole entry skipped. The bound still exists so a pathological tree cannot
/// recurse without end.
const DEPTH: usize = 64;

/// One trash entry: the payload, its restore record, and the payload's own
/// post-order path list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The top-level entry below `files/`.
    pub payload: PathBuf,
    /// The matching `info/<name>.trashinfo`.
    pub record: PathBuf,
    /// Children before parents, ending with `payload` itself.
    pub paths: Vec<PathBuf>,
    pub bytes: u64,
}

/// What the trash holds, and why anything was left alone.
#[derive(Debug, Clone, Default)]
pub struct Scan {
    pub entries: Vec<Entry>,
    /// Payloads that were not paired, or whose walk was cut short. They stay:
    /// deleting a payload without its record is the failure this module exists
    /// to prevent, and a partly known tree cannot be removed in one pass.
    pub skipped: usize,
    pub stop: Stop,
    pub missing_root: bool,
    pub not_a_directory: bool,
    pub root_unreadable: bool,
}

/// Reads `root/files` and pairs every entry with `root/info/<name>.trashinfo`.
pub fn scan(root: &Path, limits: &Limits, probe: &dyn FsProbe) -> Scan {
    let files = root.join("files");
    let info = root.join("info");

    let mut out = Scan::default();
    match probe.symlink_metadata(&files) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            out.not_a_directory = true;
            return out;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            out.missing_root = true;
            return out;
        }
        Err(_) => {
            out.root_unreadable = true;
            return out;
        }
    }
    match probe.symlink_metadata(&info) {
        Ok(meta) if meta.is_dir() => {}
        // A trash whose records are gone cannot be emptied safely: every payload
        // would be unpaired. Reporting the layout as unrecognised is the honest
        // answer, and it keeps the payloads where they are.
        Ok(_) => {
            out.not_a_directory = true;
            return out;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            out.missing_root = true;
            return out;
        }
        Err(_) => {
            out.root_unreadable = true;
            return out;
        }
    }

    let listing = match std::fs::read_dir(&files) {
        Ok(listing) => listing,
        Err(_) => {
            out.root_unreadable = true;
            return out;
        }
    };

    // One budget for the whole trash, not one per entry: five thousand entries of
    // a hundred files each would otherwise each get a fresh allowance.
    let started = Instant::now();
    let mut visited = 0usize;

    for entry in listing {
        let Ok(entry) = entry else {
            out.stop = Stop::EntryBudget;
            return out;
        };
        if visited >= limits.max_entries {
            out.stop = Stop::EntryBudget;
            return out;
        }
        if started.elapsed() >= limits.time_budget {
            out.stop = Stop::TimeBudget;
            return out;
        }

        let payload = entry.path();
        let record = info.join(with_suffix(&entry.file_name(), ".trashinfo"));
        if probe.symlink_metadata(&record).is_err() {
            out.skipped += 1;
            continue;
        }
        let Ok(meta) = probe.symlink_metadata(&payload) else {
            // Gone between the listing and the stat: the next run sees the
            // record without a payload, which is a stale record, not an entry.
            out.skipped += 1;
            continue;
        };

        if meta.is_dir() {
            let mut spec = Spec::new(DEPTH, limits);
            // A trashed tree is user data, not a cache: a symbolic link inside it
            // is an entry to remove, never a subtree to skip. The funnel unlinks
            // the link and never its target.
            spec.include_links = true;
            let collected = scan::collect(&payload, &payload, 0, &spec, probe);
            if collected.stop != Stop::Complete {
                out.stop = collected.stop;
                return out;
            }
            if collected.missing_root || collected.not_a_directory || collected.root_unreadable {
                out.skipped += 1;
                continue;
            }
            // A blocked child (a depth limit, a mount, an unreadable directory)
            // means the parent cannot be removed in one pass, and removing part
            // of an entry leaves a payload that no longer matches its record.
            if !collected.blocked.is_empty() {
                out.skipped += 1;
                continue;
            }
            visited += collected.entries.len() + 1;
            let paths = collected
                .entries
                .iter()
                .map(|found| found.path.clone())
                .chain(std::iter::once(payload.clone()))
                .collect();
            out.entries.push(Entry {
                payload,
                record,
                paths,
                bytes: collected.bytes,
            });
        } else {
            visited += 1;
            out.entries.push(Entry {
                paths: vec![payload.clone()],
                payload,
                record,
                bytes: meta.accounted_bytes(),
            });
        }
    }

    out
}

/// `name` + `suffix`, byte for byte.
///
/// `OsString::push` is the only way to append to a non-UTF-8 name without
/// guessing at its encoding, which is why the record name is built here rather
/// than with `format!`.
fn with_suffix(name: &std::ffi::OsStr, suffix: &str) -> std::ffi::OsString {
    let mut out = name.to_os_string();
    out.push(suffix);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::RealProbe;
    use std::fs;

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("Trash");
        fs::create_dir_all(root.join("files")).unwrap();
        fs::create_dir_all(root.join("info")).unwrap();
        (temp, root)
    }

    fn entry(root: &Path, name: &str, body: &str) {
        fs::create_dir_all(root.join("files").join(name)).unwrap();
        fs::write(root.join("files").join(name).join("inner.txt"), body).unwrap();
        fs::write(
            root.join("info").join(format!("{name}.trashinfo")),
            "[Trash Info]\n",
        )
        .unwrap();
    }

    fn probe() -> RealProbe {
        RealProbe::new().unwrap()
    }

    #[test]
    fn a_pair_lists_the_payload_before_its_record() {
        let (_temp, root) = fixture();
        entry(&root, "project", "body");

        let found = scan(&root, &Limits::default(), &probe());
        assert_eq!(found.stop, Stop::Complete);
        assert_eq!(found.entries.len(), 1);
        let entry = &found.entries[0];
        assert_eq!(entry.payload, root.join("files/project"));
        assert_eq!(entry.record, root.join("info/project.trashinfo"));
        // Children first, payload last: the funnel cannot recurse.
        assert_eq!(
            entry.paths,
            vec![
                root.join("files/project/inner.txt"),
                root.join("files/project"),
            ]
        );
    }

    #[test]
    fn a_payload_without_a_record_is_left_alone() {
        let (_temp, root) = fixture();
        fs::create_dir_all(root.join("files/orphan")).unwrap();

        let found = scan(&root, &Limits::default(), &probe());
        assert!(found.entries.is_empty());
        assert_eq!(found.skipped, 1);
    }

    #[test]
    fn a_trash_without_an_info_directory_is_not_a_trash() {
        let (_temp, root) = fixture();
        entry(&root, "project", "body");
        fs::remove_dir_all(root.join("info")).unwrap();

        let found = scan(&root, &Limits::default(), &probe());
        assert!(found.entries.is_empty());
        assert!(found.missing_root);
    }

    #[test]
    fn a_missing_trash_is_empty_rather_than_an_error() {
        let temp = tempfile::tempdir().unwrap();
        let found = scan(&temp.path().join("Trash"), &Limits::default(), &probe());
        assert!(found.entries.is_empty());
        assert!(found.missing_root);
        assert_eq!(found.stop, Stop::Complete);
    }

    #[test]
    fn a_regular_file_payload_is_one_path() {
        let (_temp, root) = fixture();
        fs::write(root.join("files/notes.txt"), "body").unwrap();
        fs::write(root.join("info/notes.txt.trashinfo"), "[Trash Info]\n").unwrap();

        let found = scan(&root, &Limits::default(), &probe());
        assert_eq!(found.entries.len(), 1);
        assert_eq!(found.entries[0].paths, vec![root.join("files/notes.txt")]);
    }

    #[test]
    fn a_name_that_is_not_utf8_still_pairs() {
        use std::os::unix::ffi::OsStrExt;
        let (_temp, root) = fixture();
        let name = std::ffi::OsStr::from_bytes(b"bad\xffname");
        fs::write(root.join("files").join(name), "body").unwrap();
        let mut record = name.to_os_string();
        record.push(".trashinfo");
        fs::write(root.join("info").join(record), "[Trash Info]\n").unwrap();

        let found = scan(&root, &Limits::default(), &probe());
        assert_eq!(found.entries.len(), 1);
        assert_eq!(found.entries[0].payload, root.join("files").join(name));
    }
}
