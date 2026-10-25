//! The filesystem probe: every syscall `validate` depends on, behind one trait.
//!
//! Validation must be testable without root and without touching `/var`, so all
//! I/O goes through [`FsProbe`]. Production uses [`RealProbe`]; tests use the
//! fake in `sweep-testkit`.
//!
//! Two behaviours here are load-bearing:
//!
//! * `canonicalize` resolves a symlinked ancestor. Sweep does not blanket-deny
//!   symlinked parents, because `~/.cache -> /mnt/ssd/cache` and
//!   `/home -> /var/home` are legitimate layouts. It resolves the parent once
//!   and re-checks the *physical* path, then deletes through that physical path
//!   with `RESOLVE_NO_SYMLINKS`, so the link cannot be swapped later.
//! * `open_inodes` is a single `/proc` pass. It replaces `lsof`, costs a few
//!   milliseconds, and answers "is this file open right now?" without a fork.

use std::collections::HashMap;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::fs_facts::MountTable;
use crate::meta::Meta;
use crate::paths::ancestors;

/// A process holding a file open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcRef {
    pub pid: u32,
    pub name: String,
}

/// Open file handles, indexed by `(device, inode)`.
#[derive(Debug, Clone, Default)]
pub struct OpenInodes {
    map: HashMap<(u64, u64), ProcRef>,
}

impl OpenInodes {
    /// Scans `/proc/<pid>/fd` for every visible process.
    ///
    /// Unreadable processes are skipped: we can only prove a file is open, never
    /// the opposite, and a permission error must not stop a cleanup of the
    /// user's own caches.
    pub fn scan() -> Self {
        let mut map = HashMap::new();
        let mut budget: usize = 200_000;
        for pid in crate::sys::list_pids() {
            let name = crate::sys::read_process_name(pid).unwrap_or_default();
            for fd in crate::sys::list_fds(pid) {
                if budget == 0 {
                    break;
                }
                budget -= 1;
                // The metadata of `/proc/<pid>/fd/<n>` is the metadata of the
                // open file, so no extra resolution is needed.
                let Ok(metadata) = std::fs::metadata(format!("/proc/{pid}/fd/{fd}")) else {
                    continue;
                };
                let key = (metadata.dev(), metadata.ino());
                map.entry(key).or_insert_with(|| ProcRef {
                    pid,
                    name: name.clone(),
                });
            }
        }
        Self { map }
    }

    pub fn from_pairs(pairs: impl IntoIterator<Item = ((u64, u64), ProcRef)>) -> Self {
        Self {
            map: pairs.into_iter().collect(),
        }
    }

    pub fn get(&self, dev: u64, ino: u64) -> Option<&ProcRef> {
        self.map.get(&(dev, ino))
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Everything validation needs from the operating system.
pub trait FsProbe {
    /// `lstat`: never follows the final component.
    fn symlink_metadata(&self, path: &Path) -> io::Result<Meta>;

    /// Resolves every symlinked component. Used once per candidate parent.
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf>;

    fn mount_table(&self) -> &MountTable;

    fn euid(&self) -> u32;

    /// `FS_IOC_GETFLAGS & FS_IMMUTABLE_FL`; `false` when unsupported.
    fn is_immutable(&self, path: &Path) -> io::Result<bool>;

    /// `None` when the scan was not performed, which validation treats as
    /// "cannot prove it is open" and therefore as a refusal.
    fn open_inodes(&self) -> Option<&OpenInodes>;
}

/// The real operating system.
pub struct RealProbe {
    mounts: MountTable,
    euid: u32,
    open: Option<OpenInodes>,
}

impl RealProbe {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            mounts: MountTable::load()?,
            // SAFETY-free wrapper: `sys::euid` is the only place that calls it.
            euid: crate::sys::euid(),
            open: None,
        })
    }

    /// Runs the `/proc` scan. Call once per command, before planning.
    pub fn with_open_scan(mut self) -> Self {
        self.open = Some(OpenInodes::scan());
        self
    }

    pub fn mounts(&self) -> &MountTable {
        &self.mounts
    }
}

impl FsProbe for RealProbe {
    fn symlink_metadata(&self, path: &Path) -> io::Result<Meta> {
        std::fs::symlink_metadata(path).map(|metadata| Meta::from_metadata(&metadata))
    }

    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        std::fs::canonicalize(path)
    }

    fn mount_table(&self) -> &MountTable {
        &self.mounts
    }

    fn euid(&self) -> u32 {
        self.euid
    }

    fn is_immutable(&self, path: &Path) -> io::Result<bool> {
        crate::sys::is_immutable(path)
    }

    fn open_inodes(&self) -> Option<&OpenInodes> {
        self.open.as_ref()
    }
}

/// True when any ancestor of `path` is a symbolic link, deepest first.
///
/// Kept as a helper for diagnostics; validation uses [`FsProbe::canonicalize`]
/// so a legitimate symlinked base directory does not disable cleanup.
pub fn symlink_ancestor(probe: &dyn FsProbe, path: &Path) -> Option<PathBuf> {
    for ancestor in ancestors(path) {
        match probe.symlink_metadata(&ancestor) {
            Ok(meta) if meta.is_symlink() => return Some(ancestor),
            _ => continue,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_inodes_lookup_is_exact() {
        let inodes = OpenInodes::from_pairs([(
            (8, 42),
            ProcRef {
                pid: 7,
                name: "sqlite".into(),
            },
        )]);
        assert_eq!(inodes.get(8, 42).map(|p| p.pid), Some(7));
        assert!(inodes.get(8, 43).is_none());
        assert_eq!(inodes.len(), 1);
    }

    #[test]
    fn real_probe_loads_a_mount_table() {
        let probe = RealProbe::new().expect("mount table");
        assert!(!probe.mount_table().mounts().is_empty());
        assert!(!probe.mount_table().facts(Path::new("/")).is_none());
    }

    #[test]
    fn symlink_ancestor_finds_the_link() {
        let temp = tempfile::tempdir().expect("tempdir");
        let real = temp.path().join("real");
        std::fs::create_dir(&real).expect("mkdir");
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let probe = RealProbe::new().expect("mount table");
        let found = symlink_ancestor(&probe, &link.join("child")).expect("link found");
        assert_eq!(found, link);
        assert!(symlink_ancestor(&probe, &real.join("child")).is_none());
    }
}
