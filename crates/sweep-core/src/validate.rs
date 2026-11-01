//! The single decision point: may this path be deleted?
//!
//! Order is deliberate. Every check that can be answered without I/O runs
//! first, so an obviously forbidden path costs nanoseconds. Every check that
//! needs the filesystem runs once, on the physical path, and any error is a
//! refusal — "we could not prove it is safe" is never "it is safe".
//!
//! The verdict carries the **physical** path (symlinked ancestors resolved with
//! `canonicalize`) because the funnel then deletes through a directory handle
//! opened with `RESOLVE_NO_SYMLINKS`. Validating the literal path and deleting
//! the literal path would leave a rename window between the two.

use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use crate::fs_facts::MountTable;
use crate::meta::Meta;
use crate::paths::{has_control_bytes, has_parent_component, is_within, normalize, Xdg};
use crate::policy;
use crate::probe::FsProbe;

/// Who must own everything a root's deletions touch.
///
/// The default is the uid this process runs as. A system cache is the other
/// case: `/var/cache/pacman/pkg` is root-owned, and the run that removes it is
/// the elevated child, so the expected owner is 0 rather than whoever asked.
/// Pinning it either way is a refusal to delete a file whose owner changed
/// between planning and removal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    Caller,
    Root,
}

/// A rule root that deletions are allowed inside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedRoot {
    pub path: PathBuf,
    /// When set, a target on another device is refused even if it is inside the
    /// rule root string (a bind mount or a nested mount hides there).
    pub device: Option<u64>,
    /// Whether the root directory itself may be deleted. Always `false` for
    /// cache roots: the sweep removes their children.
    pub allow_root_itself: bool,
    /// Which uid every target below this root must carry.
    pub owner: Owner,
}

impl AllowedRoot {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: normalize(&path.into()),
            device: None,
            allow_root_itself: false,
            owner: Owner::Caller,
        }
    }

    /// Requires every target to be owned by uid 0.
    ///
    /// Only the privilege boundary constructs this, and the child applies it
    /// again with its own eyes: the parent's belief about who owns a file is
    /// never the last word.
    pub fn owned_by_root(mut self) -> Self {
        self.owner = Owner::Root;
        self
    }

    /// Pins the root to the device it currently lives on.
    ///
    /// `st_dev` of the root itself, not the device the mount table reports. On
    /// btrfs a subvolume carries an anonymous device number that mountinfo never
    /// mentions, so a mountinfo-pinned root would refuse every one of its own
    /// children. The mount table stays as a fallback for a root that cannot be
    /// `stat`ed, which validation refuses anyway for being missing.
    pub fn pinned_to_current_device(mut self, table: &MountTable) -> Self {
        if let Ok(metadata) = std::fs::metadata(&self.path) {
            use std::os::unix::fs::MetadataExt;
            self.device = Some(metadata.dev());
        } else if let Some(facts) = table.facts(&self.path) {
            self.device = Some(crate::sys::makedev(facts.device.0, facts.device.1));
        }
        self
    }
}

/// Knobs that only exist for tests and for a later `--allow-snapshots` escape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub require_same_device: bool,
    pub require_open_scan: bool,
    pub allow_snapshot_paths: bool,
    /// Whether a target that is itself a symbolic link may be unlinked.
    ///
    /// Off for `clean`: a link inside a cache root is usually the user's own
    /// arrangement, and removing it frees nothing. On for a whole-tree sweep of
    /// a build artifact, where the package manager wrote the links and the tree
    /// is not rebuildable while they remain.
    ///
    /// Even when allowed, only the link is removed. The sink unlinks with
    /// `unlinkat(..., 0)`, which never follows, and the plan records that the
    /// item *was* a link so a file swapped for one between plan and apply is
    /// still refused.
    pub allow_leaf_symlink: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            require_same_device: true,
            require_open_scan: true,
            allow_snapshot_paths: false,
            allow_leaf_symlink: false,
        }
    }
}

/// Everything the decision needs.
pub struct ValidateCtx<'a> {
    pub xdg: &'a Xdg,
    pub probe: &'a dyn FsProbe,
    pub allowed: &'a [AllowedRoot],
    pub policy: Policy,
}

/// Why a path was refused. Machine-readable and stable: this string appears in
/// `--json` output and in the operation log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    Empty,
    NotAbsolute,
    Traversal,
    ControlByte,
    RootItself,
    ProtectedRoot(&'static str),
    ProtectedIdentity(String),
    NotInAllowedRoot,
    AllowedRootItself,
    NotFound,
    LeafSymlink,
    SymlinkAncestorEscape(PathBuf),
    ReadOnlyMount,
    UnknownMount,
    SnapshotPath,
    Mounted,
    OtherDevice,
    ForeignOwner(u32),
    StickyDir,
    Immutable,
    OpenByProcess {
        pid: u32,
        name: String,
    },
    RaceChanged,
    DirectoryNotEmpty,
    ProbeUnknown(String),
    AlreadyGone,
    /// The path is inside the rule's root but is not one of the entries the rule
    /// selects: a rotated log the pattern does not name, a package version still
    /// within the keep count. Reached only by the elevated child, which
    /// re-derives the selection instead of trusting the request.
    NotSelected,
}

impl Reason {
    /// Stable identifier for logs and JSON.
    pub fn code(&self) -> &'static str {
        match self {
            Reason::Empty => "empty",
            Reason::NotAbsolute => "not_absolute",
            Reason::Traversal => "traversal",
            Reason::ControlByte => "control_byte",
            Reason::RootItself => "root_itself",
            Reason::ProtectedRoot(_) => "protected_root",
            Reason::ProtectedIdentity(_) => "protected_identity",
            Reason::NotInAllowedRoot => "not_in_allowed_root",
            Reason::AllowedRootItself => "allowed_root_itself",
            Reason::NotFound => "not_found",
            Reason::LeafSymlink => "leaf_symlink",
            Reason::SymlinkAncestorEscape(_) => "symlink_ancestor_escape",
            Reason::ReadOnlyMount => "read_only_mount",
            Reason::UnknownMount => "unknown_mount",
            Reason::SnapshotPath => "snapshot_path",
            Reason::Mounted => "mounted",
            Reason::OtherDevice => "other_device",
            Reason::ForeignOwner(_) => "foreign_owner",
            Reason::StickyDir => "sticky_dir",
            Reason::Immutable => "immutable",
            Reason::OpenByProcess { .. } => "open_by_process",
            Reason::RaceChanged => "race_changed",
            Reason::DirectoryNotEmpty => "directory_not_empty",
            Reason::ProbeUnknown(_) => "probe_unknown",
            Reason::AlreadyGone => "already_gone",
            Reason::NotSelected => "not_selected",
        }
    }

    /// True when the refusal is caused by "we do not know", not by "we know it
    /// is forbidden". Callers surface these differently.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Reason::ProbeUnknown(_) | Reason::UnknownMount)
    }
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reason::Empty => f.write_str("empty path"),
            Reason::NotAbsolute => f.write_str("path is not absolute"),
            Reason::Traversal => f.write_str("path contains a parent component"),
            Reason::ControlByte => f.write_str("path contains a control byte"),
            Reason::RootItself => f.write_str("path is the filesystem root"),
            Reason::ProtectedRoot(why) => write!(f, "protected system path ({why})"),
            Reason::ProtectedIdentity(what) => write!(f, "protected user data ({what})"),
            Reason::NotInAllowedRoot => f.write_str("path is outside every rule root"),
            Reason::AllowedRootItself => f.write_str("path is a rule root, not a child of one"),
            Reason::NotFound => f.write_str("path does not exist"),
            Reason::LeafSymlink => f.write_str("path is a symbolic link"),
            Reason::SymlinkAncestorEscape(resolved) => {
                write!(f, "symlinked ancestor resolves into {}", resolved.display())
            }
            Reason::ReadOnlyMount => f.write_str("path is on a read-only mount"),
            Reason::UnknownMount => f.write_str("path is not covered by a known mount"),
            Reason::SnapshotPath => f.write_str("path is inside a snapshot directory"),
            Reason::Mounted => f.write_str("path is a mount point"),
            Reason::OtherDevice => f.write_str("path is on a different device than its rule root"),
            Reason::ForeignOwner(uid) => write!(f, "path is owned by uid {uid}"),
            Reason::StickyDir => f.write_str("parent directory is sticky"),
            Reason::Immutable => f.write_str("path is marked immutable"),
            Reason::OpenByProcess { pid, name } => {
                write!(f, "file is open by pid {pid} ({name})")
            }
            Reason::RaceChanged => f.write_str("path changed between validation and deletion"),
            Reason::DirectoryNotEmpty => f.write_str("directory still has children"),
            Reason::ProbeUnknown(detail) => write!(f, "could not verify: {detail}"),
            Reason::AlreadyGone => f.write_str("path was already removed"),
            Reason::NotSelected => {
                f.write_str("path is not one the rule selects in its current state")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Allowed; `physical` is the path the funnel should act on.
    Allow {
        physical: PathBuf,
    },
    Deny(Reason),
}

impl Verdict {
    pub fn is_allow(&self) -> bool {
        matches!(self, Verdict::Allow { .. })
    }

    pub fn reason(&self) -> Option<&Reason> {
        match self {
            Verdict::Allow { .. } => None,
            Verdict::Deny(reason) => Some(reason),
        }
    }

    pub fn physical(&self) -> Option<&Path> {
        match self {
            Verdict::Allow { physical } => Some(physical),
            Verdict::Deny(_) => None,
        }
    }
}

fn deny(reason: Reason) -> Verdict {
    Verdict::Deny(reason)
}

/// Decides whether `path` may be deleted.
pub fn validate(path: &Path, ctx: &ValidateCtx<'_>) -> Verdict {
    // ---- 1. Lexical checks: no I/O, cheapest first. ----
    if path.as_os_str().is_empty() {
        return deny(Reason::Empty);
    }
    if !path.is_absolute() {
        return deny(Reason::NotAbsolute);
    }
    if has_control_bytes(path.as_os_str()) {
        return deny(Reason::ControlByte);
    }
    if has_parent_component(path) {
        return deny(Reason::Traversal);
    }

    let literal = normalize(path);
    if literal == Path::new("/") {
        return deny(Reason::RootItself);
    }
    let Some(leaf) = literal.file_name().map(|name| name.to_os_string()) else {
        return deny(Reason::RootItself);
    };

    // ---- 2. Static policy. ----
    if let Some(root) = policy::match_root(&literal) {
        return deny(Reason::ProtectedRoot(root.why));
    }
    if let Some(what) = policy::match_identity(&literal, ctx.xdg) {
        return deny(Reason::ProtectedIdentity(what));
    }

    let Some(allowed) = ctx
        .allowed
        .iter()
        .find(|root| is_within(&root.path, &literal))
    else {
        return deny(Reason::NotInAllowedRoot);
    };
    if literal == allowed.path && !allowed.allow_root_itself {
        return deny(Reason::AllowedRootItself);
    }

    // ---- 3. Literal metadata. ----
    let meta = match ctx.probe.symlink_metadata(&literal) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return deny(Reason::NotFound),
        Err(error) => return deny(Reason::ProbeUnknown(error.to_string())),
    };
    if meta.is_symlink() && !ctx.policy.allow_leaf_symlink {
        return deny(Reason::LeafSymlink);
    }

    // ---- 4. Mount facts on the literal path. ----
    let Some(facts) = ctx.probe.mount_table().facts(&literal) else {
        return deny(Reason::UnknownMount);
    };
    if facts.options.read_only {
        return deny(Reason::ReadOnlyMount);
    }
    if facts.is_snapshot_path(&literal) && !ctx.policy.allow_snapshot_paths {
        return deny(Reason::SnapshotPath);
    }
    if ctx.probe.mount_table().is_mount_point(&literal) {
        return deny(Reason::Mounted);
    }

    // ---- 5. Physical path: resolve symlinked ancestors exactly once. ----
    let literal_parent = literal.parent().unwrap_or(Path::new("/")).to_path_buf();
    let physical_parent = match ctx.probe.canonicalize(&literal_parent) {
        Ok(parent) => parent,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return deny(Reason::NotFound),
        Err(error) => return deny(Reason::ProbeUnknown(error.to_string())),
    };
    let physical = physical_parent.join(&leaf);
    let escaped = physical != literal;

    if escaped {
        // Deny-only re-check: resolving never grants permission the literal path
        // did not already have.
        if policy::match_root(&physical).is_some() {
            return deny(Reason::SymlinkAncestorEscape(physical.clone()));
        }
        if policy::match_identity(&physical, ctx.xdg).is_some() {
            return deny(Reason::SymlinkAncestorEscape(physical.clone()));
        }
        let Some(physical_facts) = ctx.probe.mount_table().facts(&physical) else {
            return deny(Reason::UnknownMount);
        };
        if physical_facts.options.read_only {
            return deny(Reason::ReadOnlyMount);
        }
        if physical_facts.is_snapshot_path(&physical) && !ctx.policy.allow_snapshot_paths {
            return deny(Reason::SnapshotPath);
        }
    }

    // ---- 6. Device pinning. ----
    let physical_meta = match ctx.probe.symlink_metadata(&physical) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return deny(Reason::NotFound),
        Err(error) => return deny(Reason::ProbeUnknown(error.to_string())),
    };
    if physical_meta.is_symlink() && !ctx.policy.allow_leaf_symlink {
        // A race already, or a link inside a resolved directory.
        return deny(Reason::LeafSymlink);
    }
    if ctx.policy.require_same_device {
        if let Some(expected) = allowed.device {
            if physical_meta.dev != expected {
                return deny(Reason::OtherDevice);
            }
        }
    }

    // ---- 7. Ownership. ----
    let required_uid = match allowed.owner {
        Owner::Caller => ctx.probe.euid(),
        // A system cache is root-owned by definition; anything else below the
        // root is somebody else's file and stays.
        Owner::Root => 0,
    };
    if physical_meta.uid != required_uid {
        return deny(Reason::ForeignOwner(physical_meta.uid));
    }

    // ---- 8. Parent permissions. ----
    match ctx.probe.symlink_metadata(&physical_parent) {
        Ok(parent_meta) => {
            if parent_meta.is_sticky() {
                return deny(Reason::StickyDir);
            }
        }
        Err(error) => return deny(Reason::ProbeUnknown(error.to_string())),
    }

    // ---- 9. Immutable flag. ----
    //
    // A symbolic link has no inode flags of its own to read: the probe opens
    // with `O_NOFOLLOW` and a link refuses it, and the target's flags are not
    // this deletion's business because the sink never touches the target.
    if !physical_meta.is_symlink() {
        match ctx.probe.is_immutable(&physical) {
            Ok(true) => return deny(Reason::Immutable),
            Ok(false) => {}
            Err(error) => return deny(Reason::ProbeUnknown(error.to_string())),
        }
    }

    // ---- 10. Live handles. ----
    match ctx.probe.open_inodes() {
        Some(open) => {
            if let Some(holder) = open.get(physical_meta.dev, physical_meta.ino) {
                return deny(Reason::OpenByProcess {
                    pid: holder.pid,
                    name: holder.name.clone(),
                });
            }
            // A SQLite sidecar is meaningless without its main database, and the
            // main database may be the file that is open while the sidecar is
            // not. Refuse the sidecar too.
            if let Some(base) = sqlite_base_name(&leaf) {
                let base_path = physical_parent.join(&base);
                if let Ok(base_meta) = ctx.probe.symlink_metadata(&base_path) {
                    if let Some(holder) = open.get(base_meta.dev, base_meta.ino) {
                        return deny(Reason::OpenByProcess {
                            pid: holder.pid,
                            name: holder.name.clone(),
                        });
                    }
                }
            }
        }
        None if ctx.policy.require_open_scan => {
            return deny(Reason::ProbeUnknown(
                "open-file scan was not performed".to_string(),
            ))
        }
        None => {}
    }

    Verdict::Allow { physical }
}

/// `foo.db-wal` → `foo.db`. SQLite keeps committed data in the sidecar until a
/// checkpoint, so deleting it out from under a live connection loses writes.
fn sqlite_base_name(name: &std::ffi::OsStr) -> Option<OsString> {
    const SUFFIXES: [&[u8]; 3] = [b"-wal", b"-shm", b"-journal"];
    let bytes = name.as_bytes();
    for suffix in SUFFIXES {
        if bytes.len() > suffix.len() && bytes.ends_with(suffix) {
            return Some(OsString::from_vec(
                bytes[..bytes.len() - suffix.len()].to_vec(),
            ));
        }
    }
    None
}

/// Convenience wrapper used by callers that only need a yes/no answer.
pub fn is_deletable(path: &Path, ctx: &ValidateCtx<'_>) -> bool {
    validate(path, ctx).is_allow()
}

/// Metadata the funnel needs, re-read at delete time.
pub fn stat_for_plan(probe: &dyn FsProbe, physical: &Path) -> io::Result<Meta> {
    probe.symlink_metadata(physical)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_sidecars_map_to_their_database() {
        use std::ffi::OsStr;
        assert_eq!(
            sqlite_base_name(OsStr::new("history.db-wal")),
            Some(OsString::from("history.db"))
        );
        assert_eq!(
            sqlite_base_name(OsStr::new("x-shm")),
            Some(OsString::from("x"))
        );
        assert_eq!(sqlite_base_name(OsStr::new("wal")), None);
        assert_eq!(sqlite_base_name(OsStr::new("data.db")), None);
    }

    #[test]
    fn reason_codes_are_unique() {
        let reasons = [
            Reason::Empty,
            Reason::NotAbsolute,
            Reason::Traversal,
            Reason::ControlByte,
            Reason::RootItself,
            Reason::ProtectedRoot("x"),
            Reason::NotInAllowedRoot,
            Reason::LeafSymlink,
            Reason::ReadOnlyMount,
            Reason::SnapshotPath,
            Reason::Mounted,
            Reason::OtherDevice,
            Reason::StickyDir,
            Reason::Immutable,
            Reason::RaceChanged,
            Reason::DirectoryNotEmpty,
            Reason::AlreadyGone,
        ];
        let mut codes: Vec<&str> = reasons.iter().map(Reason::code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), reasons.len());
    }
}
