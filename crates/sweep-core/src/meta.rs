//! A `stat(2)` result decoupled from `std::fs::Metadata`.
//!
//! Tests need to describe a filesystem without creating it (foreign owners,
//! immutable files, other devices), so validation reads this type instead of
//! touching `std` directly.

use std::os::unix::fs::MetadataExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Meta {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub uid: u32,
    pub nlink: u64,
    /// 512-byte blocks actually allocated, the number `du` reports.
    pub blocks: u64,
    pub size: u64,
    pub mtime: i64,
}

impl Meta {
    pub fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            nlink: metadata.nlink(),
            blocks: metadata.blocks(),
            size: metadata.size(),
            mtime: metadata.mtime(),
        }
    }

    pub fn is_dir(&self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFDIR
    }

    pub fn is_file(&self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFREG
    }

    pub fn is_symlink(&self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFLNK
    }

    /// Sticky bit: `/tmp`, `/var/tmp`, `/dev/shm`. Deleting another user's
    /// entry there is exactly what the kernel forbids, so we refuse early.
    pub fn is_sticky(&self) -> bool {
        self.mode & libc::S_ISVTX != 0
    }

    /// Bytes accounted for on disk. `st_blocks` is used instead of `st_size`
    /// because it reflects sparse files and compression; on CoW filesystems it
    /// still over-counts shared extents, which is why the summary reports
    /// reclaimed space from `statvfs` separately.
    pub fn accounted_bytes(&self) -> u64 {
        self.blocks.saturating_mul(512)
    }

    /// A path that is a mount point must never be deleted: unlinking it would
    /// fail, and recursive removal would cross into the mounted filesystem.
    pub fn is_root_owned(&self) -> bool {
        self.uid == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounted_bytes_uses_blocks_not_size() {
        let meta = Meta {
            blocks: 8,
            size: 100_000,
            ..Meta::default()
        };
        assert_eq!(meta.accounted_bytes(), 4096);
    }

    #[test]
    fn type_predicates_read_the_mode_bits() {
        let dir = Meta {
            mode: libc::S_IFDIR | 0o755,
            ..Meta::default()
        };
        let link = Meta {
            mode: libc::S_IFLNK | 0o777,
            ..Meta::default()
        };
        assert!(dir.is_dir());
        assert!(!dir.is_file());
        assert!(link.is_symlink());
        assert!(!dir.is_sticky());
    }
}
