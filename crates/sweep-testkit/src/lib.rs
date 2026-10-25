//! Test doubles for `sweep-core`.
//!
//! The point is to describe filesystems that cannot be built in CI: read-only
//! mounts, foreign ownership, immutable files, other devices, symlink trees.
//! Real-filesystem tests still exist (tempdirs); these cover the shapes a
//! non-root test process cannot create.

use std::collections::{BTreeSet, HashMap};
use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};

use sweep_core::fs_facts::MountTable;
use sweep_core::probe::{FsProbe, OpenInodes, ProcRef};
use sweep_core::Meta;

/// A filesystem probe backed by an in-memory description.
#[derive(Debug, Clone)]
pub struct FakeProbe {
    mounts: MountTable,
    metas: HashMap<PathBuf, Meta>,
    symlinks: HashMap<PathBuf, PathBuf>,
    euid: u32,
    immutable: BTreeSet<PathBuf>,
    open_pairs: Vec<((u64, u64), ProcRef)>,
    open: Option<OpenInodes>,
}

impl FakeProbe {
    /// `mounts_text` is `/proc/self/mountinfo` content.
    pub fn new(mounts_text: &str) -> Self {
        Self {
            mounts: MountTable::parse(mounts_text),
            metas: HashMap::new(),
            symlinks: HashMap::new(),
            euid: 1000,
            immutable: BTreeSet::new(),
            open_pairs: Vec::new(),
            open: None,
        }
    }

    pub fn euid(mut self, euid: u32) -> Self {
        self.euid = euid;
        self
    }

    pub fn file(mut self, path: impl Into<PathBuf>) -> Self {
        self.insert(
            path.into(),
            Meta {
                dev: 1,
                mode: libc::S_IFREG | 0o644,
                nlink: 1,
                blocks: 1,
                size: 512,
                ..Meta::default()
            },
        );
        self
    }

    pub fn dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.insert(
            path.into(),
            Meta {
                dev: 1,
                mode: libc::S_IFDIR | 0o755,
                nlink: 2,
                blocks: 0,
                size: 4096,
                ..Meta::default()
            },
        );
        self
    }

    pub fn dir_with_mode(mut self, path: impl Into<PathBuf>, mode: u32) -> Self {
        self.insert(
            path.into(),
            Meta {
                dev: 1,
                mode: libc::S_IFDIR | mode,
                nlink: 2,
                blocks: 0,
                size: 4096,
                ..Meta::default()
            },
        );
        self
    }

    /// Declares `link` as a symlink pointing at `target`.
    pub fn symlink(mut self, link: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self {
        let link = link.into();
        self.insert(
            link.clone(),
            Meta {
                dev: 1,
                mode: libc::S_IFLNK | 0o777,
                nlink: 1,
                blocks: 0,
                size: 8,
                ..Meta::default()
            },
        );
        self.symlinks.insert(link, target.into());
        self
    }

    pub fn owned_by(mut self, path: impl Into<PathBuf>, uid: u32) -> Self {
        if let Some(meta) = self.metas.get_mut(&path.into()) {
            meta.uid = uid;
        }
        self
    }

    pub fn on_device(mut self, path: impl Into<PathBuf>, dev: u64) -> Self {
        if let Some(meta) = self.metas.get_mut(&path.into()) {
            meta.dev = dev;
        }
        self
    }

    pub fn with_blocks(mut self, path: impl Into<PathBuf>, blocks: u64) -> Self {
        if let Some(meta) = self.metas.get_mut(&path.into()) {
            meta.blocks = blocks;
        }
        self
    }

    pub fn immutable(mut self, path: impl Into<PathBuf>) -> Self {
        self.immutable.insert(path.into());
        self
    }

    /// Marks `path` as held open by `pid`.
    pub fn open_by(mut self, path: impl Into<PathBuf>, pid: u32, name: &str) -> Self {
        let path = path.into();
        let Some(meta) = self.metas.get(&path).copied() else {
            return self;
        };
        self.open_pairs.push((
            (meta.dev, meta.ino),
            ProcRef {
                pid,
                name: name.to_string(),
            },
        ));
        self.open = Some(OpenInodes::from_pairs(self.open_pairs.clone()));
        self
    }

    /// Models "the open-file scan was not run".
    pub fn without_open_scan(mut self) -> Self {
        self.open = None;
        self
    }

    /// Models a scan that found no open handles.
    pub fn with_empty_scan(mut self) -> Self {
        self.open = Some(OpenInodes::default());
        self
    }

    fn insert(&mut self, path: PathBuf, meta: Meta) {
        let ino = next_ino();
        self.metas.insert(
            path,
            Meta {
                ino,
                uid: self.euid,
                mtime: 0,
                ..meta
            },
        );
    }

    /// Resolves symlinks the way the kernel would, with a hop limit.
    ///
    /// Walks from `/` so the result is always absolute: a relative result would
    /// silently break every caller that re-checks the resolved path against the
    /// mount table or the protected-root list.
    fn resolve(&self, path: &Path) -> PathBuf {
        if !path.is_absolute() {
            // `canonicalize` is only ever called on absolute parent paths; a
            // relative one is a caller bug, and returning it unchanged keeps
            // that bug visible instead of hiding it.
            return path.to_path_buf();
        }
        let mut out = PathBuf::from("/");
        let mut queue: Vec<OsString> = components_of(path);
        let mut hops: usize = 0;
        let mut index = 0;
        while index < queue.len() {
            let candidate = out.join(&queue[index]);
            if let Some(target) = self.symlinks.get(&candidate) {
                hops += 1;
                if hops > 40 {
                    return candidate;
                }
                let rest: Vec<OsString> = queue[index + 1..].to_vec();
                let mut replaced = components_of(target);
                replaced.extend(rest);
                queue = replaced;
                out = if target.is_absolute() {
                    PathBuf::from("/")
                } else {
                    out
                };
                index = 0;
                continue;
            }
            out = candidate;
            index += 1;
        }
        out
    }
}

fn components_of(path: &Path) -> Vec<OsString> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_os_string()),
            _ => None,
        })
        .collect()
}

fn next_ino() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

impl FsProbe for FakeProbe {
    fn symlink_metadata(&self, path: &Path) -> io::Result<Meta> {
        self.metas
            .get(path)
            .copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, path.display().to_string()))
    }

    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        Ok(self.resolve(path))
    }

    fn mount_table(&self) -> &MountTable {
        &self.mounts
    }

    fn euid(&self) -> u32 {
        self.euid
    }

    fn is_immutable(&self, path: &Path) -> io::Result<bool> {
        Ok(self.immutable.contains(path))
    }

    fn open_inodes(&self) -> Option<&OpenInodes> {
        self.open.as_ref()
    }
}

/// A probe that fails chosen operations on purpose.
///
/// The interesting refusals in `validate` are the ones caused by an error rather
/// than by a fact: "we could not stat this" must be a denial, not a pass. A real
/// filesystem will not produce those on demand in a test, so the failure is
/// injected here.
#[derive(Debug)]
pub struct FaultyProbe {
    inner: FakeProbe,
    fail_metadata: BTreeSet<PathBuf>,
    fail_canonicalize: BTreeSet<PathBuf>,
    fail_immutable: BTreeSet<PathBuf>,
}

impl FaultyProbe {
    pub fn new(mounts_text: &str) -> Self {
        Self {
            inner: FakeProbe::new(mounts_text),
            fail_metadata: BTreeSet::new(),
            fail_canonicalize: BTreeSet::new(),
            fail_immutable: BTreeSet::new(),
        }
    }

    /// Delegates a builder call to the wrapped probe.
    pub fn with(mut self, edit: impl FnOnce(FakeProbe) -> FakeProbe) -> Self {
        self.inner = edit(self.inner);
        self
    }

    pub fn metadata_error(mut self, path: impl Into<PathBuf>) -> Self {
        self.fail_metadata.insert(path.into());
        self
    }

    pub fn canonicalize_error(mut self, path: impl Into<PathBuf>) -> Self {
        self.fail_canonicalize.insert(path.into());
        self
    }

    pub fn immutable_error(mut self, path: impl Into<PathBuf>) -> Self {
        self.fail_immutable.insert(path.into());
        self
    }
}

/// The error an injected fault reports. Not `NotFound`: a missing path has its
/// own reason code and would hide the branch this double exists to reach.
fn injected() -> io::Error {
    io::Error::from_raw_os_error(libc::EIO)
}

impl FsProbe for FaultyProbe {
    fn symlink_metadata(&self, path: &Path) -> io::Result<Meta> {
        if self.fail_metadata.contains(path) {
            return Err(injected());
        }
        self.inner.symlink_metadata(path)
    }

    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        if self.fail_canonicalize.contains(path) {
            return Err(injected());
        }
        self.inner.canonicalize(path)
    }

    fn mount_table(&self) -> &MountTable {
        self.inner.mount_table()
    }

    fn euid(&self) -> u32 {
        // Qualified: `FakeProbe::euid` is also an inherent builder method, so an
        // unqualified call would resolve to that instead of the trait method.
        FsProbe::euid(&self.inner)
    }

    fn is_immutable(&self, path: &Path) -> io::Result<bool> {
        if self.fail_immutable.contains(path) {
            return Err(injected());
        }
        self.inner.is_immutable(path)
    }

    fn open_inodes(&self) -> Option<&OpenInodes> {
        self.inner.open_inodes()
    }
}

/// A representative mount table: `/` ext4, `/home` btrfs, `/tmp` tmpfs,
/// `/mnt/usb` read-only.
pub const SAMPLE_MOUNTS: &str = "\
22 1 0:20 / /proc rw,nosuid,nodev,noexec - proc proc rw
30 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw
31 30 8:3 / /home rw,relatime - btrfs /dev/sda3 rw,subvol=/@home
32 30 0:21 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw
33 30 8:9 / /mnt/usb ro,relatime - vfat /dev/sdb1 rw
";

/// A probe that reports **every** path as an existing, owned, mutable entry.
///
/// Used by property tests that must generate arbitrary paths: without it, each
/// generated path would need a matching fixture entry and the property would
/// only exercise "not found".
#[derive(Debug)]
pub struct PermissiveProbe {
    mounts: MountTable,
    euid: u32,
    dev: u64,
    mode: u32,
    open: OpenInodes,
}

impl PermissiveProbe {
    pub fn new(mounts_text: &str) -> Self {
        Self {
            mounts: MountTable::parse(mounts_text),
            euid: 1000,
            dev: 1,
            mode: libc::S_IFREG | 0o644,
            open: OpenInodes::default(),
        }
    }

    pub fn as_dir(mut self) -> Self {
        self.mode = libc::S_IFDIR | 0o755;
        self
    }
}

impl FsProbe for PermissiveProbe {
    fn symlink_metadata(&self, _path: &Path) -> io::Result<Meta> {
        Ok(Meta {
            dev: self.dev,
            ino: 1,
            mode: self.mode,
            uid: self.euid,
            nlink: 1,
            blocks: 1,
            size: 512,
            mtime: 0,
        })
    }

    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        Ok(path.to_path_buf())
    }

    fn mount_table(&self) -> &MountTable {
        &self.mounts
    }

    fn euid(&self) -> u32 {
        self.euid
    }

    fn is_immutable(&self, _path: &Path) -> io::Result<bool> {
        Ok(false)
    }

    fn open_inodes(&self) -> Option<&OpenInodes> {
        Some(&self.open)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_probe_resolves_a_parent_symlink() {
        let probe = FakeProbe::new(SAMPLE_MOUNTS)
            .dir("/home/u/real")
            .file("/home/u/real/x.bin")
            .symlink("/home/u/link", "/home/u/real");
        assert_eq!(
            probe.canonicalize(Path::new("/home/u/link")).unwrap(),
            PathBuf::from("/home/u/real")
        );
        assert_eq!(
            probe.canonicalize(Path::new("/home/u/link/x.bin")).unwrap(),
            PathBuf::from("/home/u/real/x.bin")
        );
    }

    #[test]
    fn missing_paths_report_not_found() {
        let probe = FakeProbe::new(SAMPLE_MOUNTS);
        let error = probe
            .symlink_metadata(Path::new("/home/u/none"))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn open_handles_are_indexed_by_inode() {
        let probe = FakeProbe::new(SAMPLE_MOUNTS)
            .with_empty_scan()
            .file("/home/u/a.db")
            .open_by("/home/u/a.db", 42, "sqlite");
        let open = probe.open_inodes().expect("scan performed");
        let meta = probe.symlink_metadata(Path::new("/home/u/a.db")).unwrap();
        assert_eq!(open.get(meta.dev, meta.ino).map(|p| p.pid), Some(42));
    }
}
