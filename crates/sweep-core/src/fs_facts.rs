//! Filesystem facts measured at runtime, never assumed.
//!
//! Two questions must be answered before a delete is allowed:
//!
//! * Which mount does this path live on, and is it read-only, a mount point, or
//!   a different device than the rule root?
//! * Is this a copy-on-write filesystem, and does the path live under a
//!   snapshot directory?
//!
//! The second one is the reason this module exists at all: on btrfs, deleting a
//! file inside a snapshot's ancestry frees nothing and can destroy a rollback
//! point. The whole family is therefore report-only, decided from measured
//! facts rather than from a build-time assumption.

use std::io;
use std::path::{Path, PathBuf};

use crate::paths::{is_within, normalize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsType {
    Btrfs,
    Ext2,
    Ext3,
    Ext4,
    Xfs,
    Zfs,
    Bcachefs,
    Nilfs2,
    F2fs,
    Tmpfs,
    Overlay,
    Squashfs,
    Vfat,
    Ntfs,
    Other(String),
}

impl FsType {
    pub fn parse(name: &str) -> Self {
        match name {
            "btrfs" => Self::Btrfs,
            "ext2" => Self::Ext2,
            "ext3" => Self::Ext3,
            "ext4" => Self::Ext4,
            "xfs" => Self::Xfs,
            "zfs" => Self::Zfs,
            "bcachefs" => Self::Bcachefs,
            "nilfs2" => Self::Nilfs2,
            "f2fs" => Self::F2fs,
            "tmpfs" => Self::Tmpfs,
            "overlay" => Self::Overlay,
            "squashfs" => Self::Squashfs,
            "vfat" => Self::Vfat,
            "ntfs" | "ntfs3" => Self::Ntfs,
            other => Self::Other(other.to_string()),
        }
    }

    /// Copy-on-write families where freed bytes and reclaimed bytes differ.
    pub fn is_cow(&self) -> bool {
        matches!(
            self,
            Self::Btrfs | Self::Zfs | Self::Bcachefs | Self::Nilfs2
        )
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Btrfs => "btrfs",
            Self::Ext2 => "ext2",
            Self::Ext3 => "ext3",
            Self::Ext4 => "ext4",
            Self::Xfs => "xfs",
            Self::Zfs => "zfs",
            Self::Bcachefs => "bcachefs",
            Self::Nilfs2 => "nilfs2",
            Self::F2fs => "f2fs",
            Self::Tmpfs => "tmpfs",
            Self::Overlay => "overlay",
            Self::Squashfs => "squashfs",
            Self::Vfat => "vfat",
            Self::Ntfs => "ntfs",
            Self::Other(name) => name,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MountOptions {
    pub read_only: bool,
    pub no_suid: bool,
    pub no_dev: bool,
    pub no_exec: bool,
}

/// One line of `/proc/self/mountinfo`, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountInfo {
    pub id: u32,
    pub parent_id: u32,
    pub device: (u32, u32),
    pub root: PathBuf,
    pub mount_point: PathBuf,
    pub options: MountOptions,
    pub fstype: FsType,
    pub source: String,
    pub super_options: Vec<String>,
}

impl MountInfo {
    /// Subvolume name from `subvol=` / `subvolid=` if the mount declares one.
    pub fn subvolume(&self) -> Option<&str> {
        self.super_options
            .iter()
            .find_map(|option| option.strip_prefix("subvol="))
    }
}

/// All mounts, sorted so lookups can find the longest matching prefix.
#[derive(Debug, Clone, Default)]
pub struct MountTable {
    mounts: Vec<MountInfo>,
}

impl MountTable {
    pub fn load() -> io::Result<Self> {
        let raw = crate::sys::read_mountinfo()?;
        Ok(Self::parse(&raw))
    }

    /// Parses mountinfo text. Malformed lines are skipped, never fatal: a
    /// partially readable table still gives us the mounts we need, and an
    /// unknown path is refused later by the "unknown mount" rule.
    pub fn parse(raw: &str) -> Self {
        let mut mounts: Vec<MountInfo> = raw.lines().filter_map(parse_line).collect();
        // Longest mount point first, so the first match is the closest mount.
        mounts.sort_by_key(|mount| std::cmp::Reverse(mount.mount_point.components().count()));
        Self { mounts }
    }

    pub fn mounts(&self) -> &[MountInfo] {
        &self.mounts
    }

    /// The mount whose mount point is the longest prefix of `path`.
    pub fn find(&self, path: &Path) -> Option<&MountInfo> {
        let normalized = normalize(path);
        self.mounts
            .iter()
            .find(|mount| is_within(&mount.mount_point, &normalized))
    }

    /// True when `path` is exactly a mount point. Such a path is never a
    /// deletion target: removing it would either fail or cross a boundary.
    pub fn is_mount_point(&self, path: &Path) -> bool {
        let normalized = normalize(path);
        self.mounts
            .iter()
            .any(|mount| mount.mount_point == normalized)
    }

    /// Measured facts for `path`, or `None` when no mount covers it.
    pub fn facts(&self, path: &Path) -> Option<FsFacts> {
        let mount = self.find(path)?;
        Some(FsFacts {
            fstype: mount.fstype.clone(),
            options: mount.options,
            is_cow: mount.fstype.is_cow(),
            snapshot_candidates: snapshot_candidates(&mount.mount_point),
            mount_point: mount.mount_point.clone(),
            device: mount.device,
        })
    }
}

/// Directories that hold whole-filesystem snapshots. They are protected even
/// when they do not exist yet, so a snapshot created mid-run cannot be swept.
fn snapshot_candidates(mount_point: &Path) -> Vec<PathBuf> {
    let mut out = vec![
        PathBuf::from("/.snapshots"),
        PathBuf::from("/@snapshots"),
        PathBuf::from("/timeshift"),
        PathBuf::from("/var/lib/timeshift"),
    ];
    for name in [".snapshots", "@snapshots"] {
        let candidate = mount_point.join(name);
        if !out.contains(&candidate) {
            out.push(candidate);
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsFacts {
    pub fstype: FsType,
    pub options: MountOptions,
    pub is_cow: bool,
    pub snapshot_candidates: Vec<PathBuf>,
    pub mount_point: PathBuf,
    pub device: (u32, u32),
}

impl FsFacts {
    /// True when `path` is inside a snapshot directory. Report-only territory.
    pub fn is_snapshot_path(&self, path: &Path) -> bool {
        let normalized = normalize(path);
        self.snapshot_candidates
            .iter()
            .any(|candidate| is_within(candidate, &normalized))
    }
}

fn parse_line(line: &str) -> Option<MountInfo> {
    let (before, after) = line.split_once(" - ")?;
    let mut fields = before.split(' ');
    let id = fields.next()?.parse().ok()?;
    let parent_id = fields.next()?.parse().ok()?;
    let device = parse_device(fields.next()?)?;
    let root = PathBuf::from(unescape(fields.next()?));
    let mount_point = PathBuf::from(unescape(fields.next()?));
    let options = parse_options(fields.next()?);

    let mut rest = after.split(' ');
    let fstype = FsType::parse(rest.next()?);
    let source = unescape(rest.next()?);
    let super_options = rest
        .flat_map(|field| field.split(','))
        .map(str::to_string)
        .collect();

    Some(MountInfo {
        id,
        parent_id,
        device,
        root,
        mount_point,
        options,
        fstype,
        source,
        super_options,
    })
}

fn parse_device(field: &str) -> Option<(u32, u32)> {
    let (major, minor) = field.split_once(':')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

fn parse_options(field: &str) -> MountOptions {
    let mut options = MountOptions::default();
    for option in field.split(',') {
        match option {
            "ro" => options.read_only = true,
            "nosuid" => options.no_suid = true,
            "nodev" => options.no_dev = true,
            "noexec" => options.no_exec = true,
            _ => {}
        }
    }
    options
}

/// Decodes the octal escapes mountinfo uses for space, tab, newline and
/// backslash. A literal `\040` in a directory name arrives escaped twice, which
/// is why this only looks at exactly three octal digits.
pub fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 3 < bytes.len() {
            let digits = &bytes[index + 1..index + 4];
            if digits.iter().all(|digit| (b'0'..=b'7').contains(digit)) {
                let value = (digits[0] - b'0') * 64 + (digits[1] - b'0') * 8 + (digits[2] - b'0');
                out.push(value);
                index += 4;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
23 1 0:22 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
36 35 8:2 / / rw,noatime - ext4 /dev/sda2 rw
41 36 8:5 / /home rw,relatime - btrfs /dev/sda5 rw,subvol=/@home
52 36 0:45 / /var/cache rw,relatime - tmpfs tmpfs rw
";

    #[test]
    fn parses_the_documented_fields() {
        let table = MountTable::parse(SAMPLE);
        assert_eq!(table.mounts().len(), 4);
        let root = table.find(Path::new("/etc/hosts")).unwrap();
        assert_eq!(root.mount_point, PathBuf::from("/"));
        assert_eq!(root.fstype, FsType::Ext4);
        assert_eq!(root.device, (8, 2));
        assert!(!root.options.read_only);
    }

    #[test]
    fn finds_the_longest_matching_mount() {
        let table = MountTable::parse(SAMPLE);
        let home = table.find(Path::new("/home/u/.cache")).unwrap();
        assert_eq!(home.mount_point, PathBuf::from("/home"));
        assert_eq!(home.fstype, FsType::Btrfs);
        assert_eq!(home.subvolume(), Some("/@home"));
    }

    #[test]
    fn detects_mount_points_exactly() {
        let table = MountTable::parse(SAMPLE);
        assert!(table.is_mount_point(Path::new("/home")));
        assert!(!table.is_mount_point(Path::new("/home/u")));
    }

    #[test]
    fn cow_families_are_reported() {
        let table = MountTable::parse(SAMPLE);
        let facts = table.facts(Path::new("/home/u")).unwrap();
        assert!(facts.is_cow);
        let root = table.facts(Path::new("/etc")).unwrap();
        assert!(!root.is_cow);
    }

    #[test]
    fn snapshot_paths_are_recognised() {
        let table = MountTable::parse(SAMPLE);
        let facts = table.facts(Path::new("/home/u")).unwrap();
        assert!(facts.is_snapshot_path(Path::new("/home/.snapshots/17/snapshot")));
        assert!(facts.is_snapshot_path(Path::new("/.snapshots/3/snapshot/home/u")));
        assert!(!facts.is_snapshot_path(Path::new("/home/u/.cache")));
    }

    #[test]
    fn read_only_flag_is_parsed() {
        let line = "1 0 8:1 / /mnt rw,relatime - ext4 /dev/sdb1 ro";
        let table = MountTable::parse(line);
        // `ro` in the super options is not the per-mount flag; the per-mount
        // field stays authoritative.
        assert!(!table.mounts()[0].options.read_only);
        let mounted_ro = "1 0 8:1 / /mnt ro,relatime - ext4 /dev/sdb1 rw";
        assert!(MountTable::parse(mounted_ro).mounts()[0].options.read_only);
    }

    #[test]
    fn escaped_paths_are_decoded() {
        let line = "1 0 8:1 / /media/My\\040Disk rw - ext4 /dev/sdb1 rw";
        let table = MountTable::parse(line);
        assert_eq!(
            table.mounts()[0].mount_point,
            PathBuf::from("/media/My Disk")
        );
    }

    #[test]
    fn malformed_lines_are_skipped_not_fatal() {
        let table = MountTable::parse("garbage\n\nno separator here\n");
        assert!(table.mounts().is_empty());
    }

    #[test]
    fn unknown_path_without_a_mount_is_none() {
        let table = MountTable::default();
        assert!(table.facts(Path::new("/home/u")).is_none());
    }
}
