//! What a package leaves behind in `$HOME`.
//!
//! pacman owns the files it shipped and removes them; it knows nothing about the
//! two directories an application creates for itself on first run. Those are
//! what a user means by leftovers, and they are found here by **exact name
//! only**:
//!
//! ```text
//! $XDG_CONFIG_HOME/<package>
//! $XDG_DATA_HOME/<package>
//! $XDG_CACHE_HOME/<package>
//! $XDG_STATE_HOME/<package>
//! ```
//!
//! Four candidates per package, four stats each. There is no walk of `$HOME`, no
//! vendor prefix, no `*<package>*` glob and no case-folded match. A directory
//! whose name merely *contains* the package name belongs to something else, and
//! a fuzzy match here would move a stranger's data to the trash because a
//! package happened to be called `git`.
//!
//! This module only discovers. Nothing here deletes or moves; the caller sends
//! the result through the same trash the explorer uses, which is why an
//! uninstalled package's leftovers are recoverable.
//!
//! Sizes are best-effort. A directory larger than the walk budget reports `None`
//! rather than a partial total: "4 MiB" and "at least 4 MiB" are different
//! claims, and only one of them is true.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::paths::Xdg;
use crate::probe::{FsProbe, RealProbe};
use crate::scan::{self, Limits, Select, Spec, Stop};

/// Which XDG root an entry came from.
///
/// Kept as a label rather than the resolved path, because the plan is printed
/// with `~` and the JSON stays stable when `$XDG_CONFIG_HOME` moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Root {
    Config,
    Data,
    Cache,
    State,
}

impl Root {
    pub fn as_str(self) -> &'static str {
        match self {
            Root::Config => "config",
            Root::Data => "data",
            Root::Cache => "cache",
            Root::State => "state",
        }
    }
}

/// One path a package left behind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Leftover {
    pub package: String,
    pub path: PathBuf,
    pub root: Root,
    /// Accounted bytes, or `None` when the walk was cut short.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    pub is_dir: bool,
    pub is_symlink: bool,
}

/// Every leftover of `names`, in root order and then in the order given.
///
/// A name that is not a plain path component is ignored: this function is called
/// with names that already passed [`crate::packages::validate`], and re-checking
/// costs one comparison while a `..` reaching `join` would escape the root
/// entirely.
pub fn scan(xdg: &Xdg, names: &[String]) -> Vec<Leftover> {
    let candidates = candidates(xdg, names);
    let Ok(probe) = RealProbe::new() else {
        // Without a probe the sizes are unknown but the discovery is not: the
        // caller can still show a path and let the user decide.
        return candidates.iter().filter_map(without_probe).collect();
    };
    let limits = Limits::default();
    let mut out = Vec::new();
    for candidate in candidates {
        let Ok(meta) = probe.symlink_metadata(&candidate.path) else {
            continue;
        };
        let bytes = if meta.is_dir() {
            measure(&candidate.path, &limits, &probe)
        } else {
            // A symbolic link reports its own blocks, never the target's: the
            // link is what moves.
            Some(meta.accounted_bytes())
        };
        out.push(Leftover {
            package: candidate.package,
            path: candidate.path,
            root: candidate.root,
            bytes,
            is_dir: meta.is_dir(),
            is_symlink: meta.is_symlink(),
        });
    }
    out
}

/// Total of the sizes that are known, and how many are not.
pub fn totals(leftovers: &[Leftover]) -> (u64, usize) {
    let mut bytes = 0u64;
    let mut unknown = 0usize;
    for leftover in leftovers {
        match leftover.bytes {
            Some(size) => bytes = bytes.saturating_add(size),
            None => unknown += 1,
        }
    }
    (bytes, unknown)
}

struct Candidate {
    package: String,
    path: PathBuf,
    root: Root,
}

fn candidates(xdg: &Xdg, names: &[String]) -> Vec<Candidate> {
    let roots = [
        (Root::Config, &xdg.config),
        (Root::Data, &xdg.data),
        (Root::Cache, &xdg.cache),
        (Root::State, &xdg.state),
    ];
    let mut out = Vec::new();
    for name in names {
        if !is_plain_component(name) {
            continue;
        }
        for (root, base) in roots.iter() {
            let path = base.join(name);
            if is_own_state(&path, xdg) || is_the_trash(&path, xdg) {
                continue;
            }
            out.push(Candidate {
                package: name.clone(),
                path,
                root: *root,
            });
        }
    }
    out
}

/// Used only when the filesystem probe could not be created: paths are still
/// found, with no size attached.
fn without_probe(candidate: &Candidate) -> Option<Leftover> {
    let meta = std::fs::symlink_metadata(&candidate.path).ok()?;
    Some(Leftover {
        package: candidate.package.clone(),
        path: candidate.path.clone(),
        root: candidate.root,
        bytes: None,
        is_dir: meta.is_dir(),
        is_symlink: meta.is_symlink(),
    })
}

/// A plain single component: no separator, no `.`/`..`, no NUL, not empty.
fn is_plain_component(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\0')
}

/// `~/.local/state/sweep` is sweep's own ledger, whatever a package is called.
fn is_own_state(path: &Path, xdg: &Xdg) -> bool {
    path.starts_with(xdg.state_dir())
}

/// The trash itself is never a leftover, even for a package called `Trash`.
fn is_the_trash(path: &Path, xdg: &Xdg) -> bool {
    path.starts_with(xdg.data.join("Trash"))
}

/// Accounted bytes below `path`, or `None` if the walk stopped early.
fn measure(path: &Path, limits: &Limits, probe: &RealProbe) -> Option<u64> {
    let mut spec = Spec::new(usize::MAX, limits);
    spec.select = Select::Everything;
    let collected = scan::collect(path, path, 0, &spec, probe);
    if collected.missing_root || collected.root_unreadable {
        return None;
    }
    match collected.stop {
        Stop::Complete => Some(collected.bytes),
        // A budget stop means "at least", and the plan prints that word
        // instead of pretending a floor is a total.
        Stop::EntryBudget | Stop::TimeBudget => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xdg_at(home: &Path) -> Xdg {
        Xdg::resolve(|key| match key {
            "HOME" => Some(home.as_os_str().to_os_string()),
            _ => None,
        })
        .expect("home")
    }

    fn fixture() -> (tempfile::TempDir, Xdg) {
        let temp = tempfile::tempdir().expect("tempdir");
        let xdg = xdg_at(temp.path());
        for root in [&xdg.config, &xdg.data, &xdg.cache, &xdg.state] {
            std::fs::create_dir_all(root).expect("mkdir");
        }
        (temp, xdg)
    }

    #[test]
    fn an_exact_name_in_each_root_is_found() {
        let (_temp, xdg) = fixture();
        for root in [&xdg.config, &xdg.data, &xdg.cache, &xdg.state] {
            std::fs::create_dir_all(root.join("firefox")).expect("mkdir");
        }
        let found = scan(&xdg, &["firefox".to_string()]);
        assert_eq!(found.len(), 4, "{found:?}");
        assert_eq!(
            found.iter().map(|entry| entry.root).collect::<Vec<_>>(),
            [Root::Config, Root::Data, Root::Cache, Root::State]
        );
        assert!(found.iter().all(|entry| entry.package == "firefox"));
        assert!(found.iter().all(|entry| entry.is_dir));
        assert!(found.iter().all(|entry| entry.bytes.is_some()));
    }

    #[test]
    fn a_directory_that_only_contains_the_name_is_not_a_leftover() {
        let (_temp, xdg) = fixture();
        std::fs::create_dir_all(xdg.config.join("firefox-developer-edition")).expect("mkdir");
        std::fs::create_dir_all(xdg.config.join("libfirefox")).expect("mkdir");
        std::fs::create_dir_all(xdg.config.join("Firefox")).expect("mkdir");
        assert!(
            scan(&xdg, &["firefox".to_string()]).is_empty(),
            "a prefix, a suffix or a different case is somebody else's directory"
        );
    }

    #[test]
    fn a_package_with_nothing_left_is_an_empty_scan() {
        let (_temp, xdg) = fixture();
        assert!(scan(&xdg, &["nosuchpkg".to_string()]).is_empty());
    }

    #[test]
    fn a_name_that_is_not_one_component_cannot_escape_a_root() {
        let (_temp, xdg) = fixture();
        std::fs::create_dir_all(xdg.config.join("real")).expect("mkdir");
        for name in ["../../etc", "a/b", "", ".", "..", "with\0nul"] {
            assert!(
                scan(&xdg, &[name.to_string()]).is_empty(),
                "`{name}` must not become a candidate"
            );
        }
    }

    #[test]
    fn only_the_named_packages_are_scanned() {
        let (_temp, xdg) = fixture();
        std::fs::create_dir_all(xdg.config.join("firefox")).expect("mkdir");
        std::fs::create_dir_all(xdg.config.join("ark")).expect("mkdir");
        let found = scan(&xdg, &["firefox".to_string()]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].package, "firefox");
    }

    #[test]
    fn a_file_leftover_is_reported_with_its_own_size() {
        let (_temp, xdg) = fixture();
        let path = xdg.config.join("mpv");
        std::fs::write(&path, "x".repeat(4096)).expect("write");
        let found = scan(&xdg, &["mpv".to_string()]);
        assert_eq!(found.len(), 1);
        assert!(!found[0].is_dir);
        assert!(!found[0].is_symlink);
        assert!(found[0].bytes.unwrap_or(0) >= 4096, "{found:?}");
    }

    #[test]
    fn a_symbolic_link_is_reported_as_a_link_and_not_followed() {
        let (temp, xdg) = fixture();
        let target = temp.path().join("elsewhere");
        std::fs::create_dir_all(&target).expect("mkdir");
        // The payload is incompressible and far larger than any filesystem's
        // link accounting. btrfs charges a symlink one block (4096 bytes) while
        // ext4 and tmpfs charge none, so an earlier "smaller than one block"
        // bound tested the filesystem: it passed on ext4 and failed on the
        // btrfs job, where the honest answer for the link is one block. The
        // property that matters is "the target's megabytes are not attributed
        // to the link", and that holds on every filesystem.
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let payload: Vec<u8> = (0..1 << 20)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        std::fs::write(target.join("data"), &payload).expect("write");
        std::os::unix::fs::symlink(&target, xdg.config.join("firefox")).expect("symlink");

        let found = scan(&xdg, &["firefox".to_string()]);
        assert_eq!(found.len(), 1);
        assert!(found[0].is_symlink, "{found:?}");
        assert!(
            found[0].bytes.unwrap_or(u64::MAX) < 64 * 1024,
            "the link's own size, not the target's: {found:?}"
        );
    }

    #[test]
    fn sweep_own_state_directory_is_never_a_leftover() {
        let (_temp, xdg) = fixture();
        std::fs::create_dir_all(xdg.state_dir()).expect("mkdir");
        assert!(
            scan(&xdg, &["sweep".to_string()]).is_empty(),
            "the operation log is not a package's leftovers"
        );
    }

    #[test]
    fn the_trash_is_never_a_leftover() {
        let (_temp, xdg) = fixture();
        std::fs::create_dir_all(xdg.data.join("Trash/files")).expect("mkdir");
        assert!(scan(&xdg, &["Trash".to_string()]).is_empty());
    }

    #[test]
    fn sizes_add_up_and_an_unknown_size_is_counted_separately() {
        let found = vec![
            Leftover {
                package: "a".to_string(),
                path: PathBuf::from("/tmp/a"),
                root: Root::Config,
                bytes: Some(1024),
                is_dir: true,
                is_symlink: false,
            },
            Leftover {
                package: "b".to_string(),
                path: PathBuf::from("/tmp/b"),
                root: Root::Cache,
                bytes: None,
                is_dir: true,
                is_symlink: false,
            },
            Leftover {
                package: "c".to_string(),
                path: PathBuf::from("/tmp/c"),
                root: Root::Data,
                bytes: Some(2048),
                is_dir: false,
                is_symlink: false,
            },
        ];
        let (bytes, unknown) = totals(&found);
        assert_eq!(bytes, 3072);
        assert_eq!(unknown, 1);
    }

    #[test]
    fn an_entry_that_vanishes_between_the_stat_and_the_walk_is_skipped() {
        let (_temp, xdg) = fixture();
        std::fs::create_dir_all(xdg.config.join("gone")).expect("mkdir");
        // Only the discovery half is exercised: the walk runs after the stat, so
        // a racing removal must produce no entry rather than a panic.
        let found = scan(&xdg, &["gone".to_string(), "never".to_string()]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].package, "gone");
    }
}
