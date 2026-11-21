//! Moving a chosen entry to the freedesktop trash.
//!
//! Two commands delete, and both delete recoverably because both delete by
//! moving: `analyze` sends the entry the user picked, and `uninstall` sends the
//! leftover directories of a package that is already gone. Either way the entry
//! leaves the directory it was in and arrives in a trash directory with a
//! `.trashinfo` record that says where it came from, so the desktop's own
//! "Restore" puts it back.
//!
//! There are two trash directories in play, and which one is used is decided by
//! the filesystem, not by a preference:
//!
//! * **The home trash**, `$XDG_DATA_HOME/Trash`, for everything on the mount the
//!   home trash itself is on. That is the common case and the one with the
//!   shortest restore path.
//! * **The top-directory trash**, `<mount>/.Trash/<uid>` or `<mount>/.Trash-<uid>`,
//!   for an entry on another filesystem. `renameat` cannot cross a mount, so the
//!   only way to keep the move atomic is a trash directory on the entry's own
//!   filesystem, which is exactly what the specification defines. sweep uses such
//!   a directory when it already exists, and creates its own `<uid>` directory
//!   inside a shared `.Trash` that the administrator marked sticky. It never
//!   creates `<mount>/.Trash-<uid>`: that one belongs to whoever administers the
//!   mount, and a missing one is a refusal that says what to create.
//!
//! Two things are still deliberately not implemented:
//!
//! * **No copy-and-delete fallback.** When no trash directory can be reached on
//!   the entry's filesystem, the answer is "the entry is still where it was".
//!   Copying a tree and then deleting the original turns one recoverable move
//!   into a slow operation that can be interrupted halfway.
//! * **No following.** Both directory handles are opened with
//!   `RESOLVE_NO_SYMLINKS` and both names are single components, so a changed
//!   ancestor cannot redirect the move. A symbolic link is moved as a link; its
//!   target is never touched. That extends to the trash directories themselves:
//!   a `.Trash`, `.Trash/<uid>`, `.Trash-<uid>` or `files/` that is a symbolic
//!   link is refused rather than followed.
//!
//! Nothing here unlinks anything except a `.trashinfo` file written a moment
//! earlier when the move that followed it failed.
//!
//! Emptying a per-mount trash is not part of this: `sweep clean` empties the home
//! trash, and a removable disk's trash belongs to whichever session filled it.

use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Component, Path, PathBuf};

use sweep_core::fs_facts::MountTable;
use sweep_core::paths::Xdg;
use sweep_core::policy;
use sweep_core::sys;

/// Why an entry was not moved. Every variant is a sentence a user can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    NotAbsolute,
    Traversal,
    ControlByte,
    Root,
    Protected(String),
    Identity(String),
    TheTrashItself,
    SymlinkAncestor,
    Gone,
    CrossDevice(String),
    /// No trash directory exists on the entry's own filesystem.
    NoTopdirTrash {
        mount: PathBuf,
        uid: u32,
    },
    Mounted,
    Permission(String),
    Other(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::NotAbsolute => f.write_str("the path is not absolute"),
            Refusal::Traversal => f.write_str("the path contains `..`"),
            Refusal::ControlByte => f.write_str("the name contains a control byte"),
            Refusal::Root => f.write_str("that is the root directory"),
            Refusal::Protected(why) => write!(f, "protected path: {why}"),
            Refusal::Identity(why) => write!(f, "not swept or trashed by any command: {why}"),
            Refusal::TheTrashItself => f.write_str("that is the trash directory"),
            Refusal::SymlinkAncestor => {
                f.write_str("a directory above it is a symbolic link; sweep does not follow links")
            }
            Refusal::Gone => f.write_str("it is no longer there"),
            Refusal::CrossDevice(device) => write!(
                f,
                "it lives on {device}, which is a different filesystem from the trash; move it yourself or empty it another way"
            ),
            Refusal::NoTopdirTrash { mount, uid } => write!(
                f,
                "it lives on {}, a different filesystem from the home trash, and that filesystem has no trash directory for you; an administrator can create {} (owned by you, mode 0700), or move the entry yourself",
                mount.display(),
                mount.join(format!(".Trash-{uid}")).display()
            ),
            Refusal::Mounted => f.write_str("it is a mount point"),
            Refusal::Permission(what) => write!(f, "permission denied: {what}"),
            Refusal::Other(message) => f.write_str(message),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moved {
    pub from: PathBuf,
    pub to: PathBuf,
}

/// One trash directory: the payload half and the record half.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Destination {
    files: PathBuf,
    info: PathBuf,
}

/// The home trash, with both directories already open.
pub struct Trash {
    files: PathBuf,
    info: PathBuf,
}

impl Trash {
    /// Creates `Trash/files` and `Trash/info` if they do not exist.
    ///
    /// Called when the explorer starts, not per move: a first trash can fail for
    /// a reason the user should hear before they press the key.
    pub fn open(xdg: &Xdg) -> io::Result<Self> {
        let root = xdg.data.join("Trash");
        let files = root.join("files");
        let info = root.join("info");
        std::fs::create_dir_all(&files)?;
        std::fs::create_dir_all(&info)?;
        Ok(Self { files, info })
    }

    /// Where a moved entry lands. Read by the tests that assert on it.
    #[cfg(test)]
    pub fn files(&self) -> &Path {
        &self.files
    }

    /// Moves `path` into the trash its filesystem can reach.
    ///
    /// `bytes` is only used by the caller for the operation log; the move itself
    /// does not measure anything, because the explorer already showed the size
    /// the user agreed to.
    pub fn send(&self, path: &Path, xdg: &Xdg) -> Result<Moved, Refusal> {
        let mounts = MountTable::load().map_err(|error| {
            Refusal::Other(format!(
                "cannot read the list of mounted filesystems: {error}"
            ))
        })?;
        self.send_within(path, xdg, &mounts, sys::euid())
    }

    /// [`Trash::send`] with the mount table and the user id supplied.
    ///
    /// The two arguments are what the tests cannot obtain from a real machine: a
    /// second filesystem is not something an unprivileged test can assume, so the
    /// selection and the top-directory rules are exercised against a table that
    /// says where the mounts are.
    fn send_within(
        &self,
        path: &Path,
        xdg: &Xdg,
        mounts: &MountTable,
        uid: u32,
    ) -> Result<Moved, Refusal> {
        guard(path, xdg)?;
        let Some(name) = path.file_name() else {
            return Err(Refusal::Root);
        };
        let Some(parent) = path.parent() else {
            return Err(Refusal::Root);
        };

        // The source handle first. Opening a directory can only refuse; it never
        // moves anything, so nothing below this line runs for a path that is gone
        // or that sits under a symbolic link.
        let from_dir = sys::open_dir_nofollow(parent).map_err(|error| match error {
            sys::OpenDirError::SymlinkRefused => Refusal::SymlinkAncestor,
            sys::OpenDirError::Io(io) => map_io(&io, parent),
        })?;

        let destination = self.destination(parent, mounts, uid)?;
        if path.starts_with(&destination.files) || path.starts_with(&destination.info) {
            return Err(Refusal::TheTrashItself);
        }

        let (candidate, info_path) = free_name(&destination.files, &destination.info, name)
            .ok_or_else(|| Refusal::Other("no free name in the trash".to_string()))?;

        // Both handles first. The record still precedes the move: a payload
        // without a record would be invisible to every restore tool, while a
        // record whose move then failed is removed below.
        let to_dir = sys::open_dir_nofollow(&destination.files).map_err(|error| match error {
            sys::OpenDirError::SymlinkRefused => Refusal::SymlinkAncestor,
            sys::OpenDirError::Io(io) => map_io(&io, &destination.files),
        })?;

        write_info(&info_path, path)?;

        match sys::rename_beneath(&from_dir, name, &to_dir, &candidate) {
            Ok(()) => Ok(Moved {
                from: path.to_path_buf(),
                to: destination.files.join(&candidate),
            }),
            Err(error) => {
                // The record is ours and was written seconds ago; leaving it
                // behind would show a restore entry with no payload.
                let _ = std::fs::remove_file(&info_path);
                Err(match error.raw_os_error() {
                    Some(libc::EXDEV) => Refusal::CrossDevice(
                        device_of(parent).unwrap_or_else(|| "another mount".to_string()),
                    ),
                    Some(libc::EBUSY) => Refusal::Mounted,
                    Some(libc::ENOENT) => Refusal::Gone,
                    Some(libc::EACCES) | Some(libc::EPERM) => Refusal::Permission(
                        "the directory or the trash refuses the move".to_string(),
                    ),
                    _ => Refusal::Other(error.to_string()),
                })
            }
        }
    }

    /// The home trash when the entry shares its filesystem, otherwise the one the
    /// entry's own mount can offer.
    ///
    /// "Shares its filesystem" is a mount-point comparison rather than a device
    /// comparison: on btrfs every subvolume carries an anonymous device number
    /// that `/proc/self/mountinfo` never mentions, so the device numbers never
    /// match even when both paths are plainly on the same mount.
    fn destination(
        &self,
        parent: &Path,
        mounts: &MountTable,
        uid: u32,
    ) -> Result<Destination, Refusal> {
        let home = mounts
            .find(&self.files)
            .map(|mount| mount.mount_point.clone());
        let Some(entry) = mounts.find(parent).map(|mount| mount.mount_point.clone()) else {
            return Err(Refusal::Other(format!(
                "cannot tell which filesystem {} is on, so there is no trash to move it to",
                parent.display()
            )));
        };
        if Some(&entry) == home.as_ref() {
            return Ok(Destination {
                files: self.files.clone(),
                info: self.info.clone(),
            });
        }
        topdir_trash(&entry, uid)
    }
}

/// What a directory that should hold trash turned out to be.
enum DirState {
    Missing,
    Dir {
        owner: u32,
        mode: u32,
    },
    /// Something is there, and it must not be used: a link, a file, a socket.
    Unusable(String),
}

fn dir_state(path: &Path) -> Result<DirState, Refusal> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Ok(DirState::Unusable(format!(
            "{} is a symbolic link; a trash directory is never followed",
            path.display()
        ))),
        Ok(meta) if meta.is_dir() => Ok(DirState::Dir {
            owner: meta.uid(),
            mode: meta.mode(),
        }),
        Ok(_) => Ok(DirState::Unusable(format!(
            "{} exists but is not a directory",
            path.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(DirState::Missing),
        Err(error) => Err(map_io(&error, path)),
    }
}

/// The trash directory on the mount the entry lives on, prepared for this user.
///
/// The order is the specification's: a sticky, shared `<mount>/.Trash` first,
/// with a `<uid>` directory inside it that this user owns; otherwise the
/// administrator-created `<mount>/.Trash-<uid>`. Nothing is created outside the
/// two places the specification names, and `<mount>/.Trash-<uid>` is never
/// created: a directory in a mount's root belongs to whoever administers it.
fn topdir_trash(mount: &Path, uid: u32) -> Result<Destination, Refusal> {
    let shared = mount.join(".Trash");
    let owned = match dir_state(&shared)? {
        DirState::Missing => {
            let private = mount.join(format!(".Trash-{uid}"));
            match dir_state(&private)? {
                DirState::Missing => {
                    return Err(Refusal::NoTopdirTrash {
                        mount: mount.to_path_buf(),
                        uid,
                    })
                }
                DirState::Dir { owner, .. } => {
                    if owner != uid {
                        return Err(Refusal::Permission(format!(
                            "{} is owned by uid {owner}, not by you",
                            private.display()
                        )));
                    }
                    private
                }
                DirState::Unusable(why) => return Err(Refusal::Other(why)),
            }
        }
        DirState::Dir { mode, .. } => {
            // A `.Trash` that is not sticky would let one user's directory be
            // renamed away by another; the specification requires the bit.
            if mode & 0o1000 == 0 {
                return Err(Refusal::Other(format!(
                    "{} is a shared trash directory without the sticky bit, so it is not used; ask an administrator to set it, or to create {}",
                    shared.display(),
                    mount.join(format!(".Trash-{uid}")).display()
                )));
            }
            let mine = shared.join(uid.to_string());
            ensure_owned_dir(&mine, uid)?;
            mine
        }
        DirState::Unusable(why) => return Err(Refusal::Other(why)),
    };

    let files = owned.join("files");
    let info = owned.join("info");
    ensure_owned_dir(&files, uid)?;
    ensure_owned_dir(&info, uid)?;
    Ok(Destination { files, info })
}

/// Makes sure `path` is a directory this user owns, creating it when it is not.
///
/// The creation is `0700` and refuses to follow anything: these directories hold
/// the user's own trash, and a world-readable one would leak what was thrown
/// away. `create` rather than `create_dir_all`, because every parent was already
/// checked by the caller and a missing one is a state this function should not
/// paper over.
fn ensure_owned_dir(path: &Path, uid: u32) -> Result<(), Refusal> {
    match dir_state(path)? {
        DirState::Dir { owner, .. } if owner == uid => Ok(()),
        DirState::Dir { owner, .. } => Err(Refusal::Permission(format!(
            "{} is owned by uid {owner}, not by you",
            path.display()
        ))),
        DirState::Unusable(why) => Err(Refusal::Other(why)),
        DirState::Missing => std::fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|error| map_io(&error, path)),
    }
}

/// The first name that is free in both `files/` and `info/`.
///
/// "Free" means no directory entry, so the test does not follow a link: a
/// dangling link in `files/` still occupies the name, and `renameat` would
/// replace that entry rather than put the payload beside it.
fn free_name(files: &Path, info: &Path, name: &OsStr) -> Option<(OsString, PathBuf)> {
    for suffix in 0..1_000u32 {
        let candidate = if suffix == 0 {
            name.to_os_string()
        } else {
            let mut bytes = name.as_bytes().to_vec();
            bytes.extend_from_slice(format!(".{suffix}").as_bytes());
            OsString::from_vec(bytes)
        };
        let mut info_name = candidate.clone();
        info_name.push(".trashinfo");
        let info_path = info.join(&info_name);
        let taken = std::fs::symlink_metadata(files.join(&candidate)).is_ok()
            || std::fs::symlink_metadata(&info_path).is_ok();
        if !taken {
            return Some((candidate, info_path));
        }
    }
    None
}

/// The refusals shared by every caller, including tests that never move a file.
pub fn guard(path: &Path, xdg: &Xdg) -> Result<(), Refusal> {
    if !path.is_absolute() {
        return Err(Refusal::NotAbsolute);
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(Refusal::Traversal);
    }
    for component in path.components() {
        if component
            .as_os_str()
            .as_bytes()
            .iter()
            .any(|byte| *byte < 0x20 || *byte == 0x7f)
        {
            return Err(Refusal::ControlByte);
        }
    }
    if path == Path::new("/") {
        return Err(Refusal::Root);
    }
    if path.starts_with(xdg.data.join("Trash")) || inside_a_trash(path) {
        return Err(Refusal::TheTrashItself);
    }
    if let Some(root) = policy::match_root(path) {
        return Err(Refusal::Protected(root.why.to_string()));
    }
    if let Some(why) = policy::match_identity(path, xdg) {
        return Err(Refusal::Identity(why));
    }
    Ok(())
}

/// True when a path component is a trash directory, by name.
///
/// The home trash is known by its full path; a per-mount one is recognised by the
/// two names the specification gives it, `.Trash` and `.Trash-<uid>`, because the
/// mount table is not available to every caller of [`guard`].
fn inside_a_trash(path: &Path) -> bool {
    path.components().any(|component| {
        let name = component.as_os_str().as_bytes();
        if name == b".Trash" {
            return true;
        }
        match name.strip_prefix(b".Trash-".as_slice()) {
            Some(rest) => !rest.is_empty() && rest.iter().all(u8::is_ascii_digit),
            None => false,
        }
    })
}

fn map_io(error: &io::Error, path: &Path) -> Refusal {
    match error.raw_os_error() {
        Some(libc::ENOENT) => Refusal::Gone,
        Some(libc::EACCES) | Some(libc::EPERM) => {
            Refusal::Permission(format!("{} cannot be opened", path.display()))
        }
        Some(libc::ENOTDIR) => Refusal::Other(format!("{} is not a directory", path.display())),
        _ => Refusal::Other(error.to_string()),
    }
}

fn device_of(path: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).ok()?;
    Some(format!("device {}", meta.dev()))
}

fn write_info(info_path: &Path, original: &Path) -> Result<(), Refusal> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(info_path)
        .map_err(|error| map_io(&error, info_path))?;
    let body = format!(
        "[Trash Info]\nPath={}\nDeletionDate={}\n",
        encode_path(original),
        sys::local_timestamp()
    );
    file.write_all(body.as_bytes())
        .map_err(|error| Refusal::Other(error.to_string()))?;
    file.flush()
        .map_err(|error| Refusal::Other(error.to_string()))
}

/// Percent-encodes a path the way the trash specification expects.
///
/// Unreserved characters and `/` stay literal; every other byte becomes `%XX`.
/// Encoding is per byte, so a name that is not UTF-8 still round-trips into a
/// restorable record.
pub fn encode_path(path: &Path) -> String {
    let mut out = String::new();
    for byte in path.as_os_str().as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
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

    fn fixture() -> (tempfile::TempDir, Xdg, Trash) {
        let temp = tempfile::tempdir().expect("tempdir");
        let xdg = xdg_at(temp.path());
        std::fs::create_dir_all(xdg.home.join("work")).expect("mkdir");
        let trash = Trash::open(&xdg).expect("trash");
        (temp, xdg, trash)
    }

    #[test]
    fn a_file_arrives_in_the_trash_with_a_restore_record() {
        let (_temp, xdg, trash) = fixture();
        let file = xdg.home.join("work/notes.txt");
        std::fs::write(&file, b"hello").expect("write");

        let moved = trash.send(&file, &xdg).expect("moved");
        assert!(!file.exists(), "the entry left the directory");
        assert_eq!(
            std::fs::read_to_string(&moved.to).expect("payload"),
            "hello"
        );
        assert_eq!(moved.to, trash.files().join("notes.txt"));

        let info =
            std::fs::read_to_string(xdg.data.join("Trash/info/notes.txt.trashinfo")).expect("info");
        assert!(info.starts_with("[Trash Info]\n"), "{info}");
        assert!(
            info.contains(&format!("Path={}", file.display())),
            "the record says where it came from: {info}"
        );
        assert!(
            info.contains("DeletionDate=") && info.ends_with('\n'),
            "the record says when: {info}"
        );
    }

    #[test]
    fn a_directory_moves_whole() {
        let (_temp, xdg, trash) = fixture();
        let dir = xdg.home.join("work/project");
        std::fs::create_dir_all(dir.join("src")).expect("mkdir");
        std::fs::write(dir.join("src/main.rs"), b"fn main() {}").expect("write");

        let moved = trash.send(&dir, &xdg).expect("moved");
        assert!(!dir.exists());
        assert!(
            moved.to.join("src/main.rs").exists(),
            "the subtree came along"
        );
    }

    #[test]
    fn a_name_already_in_the_trash_gets_a_suffix() {
        let (_temp, xdg, trash) = fixture();
        let first = xdg.home.join("work/collision");
        std::fs::write(&first, b"one").expect("write");
        trash.send(&first, &xdg).expect("first");

        let second = xdg.home.join("work/collision");
        std::fs::write(&second, b"two").expect("write");
        let moved = trash.send(&second, &xdg).expect("second");

        assert_eq!(moved.to, trash.files().join("collision.1"));
        assert_eq!(std::fs::read_to_string(&moved.to).expect("payload"), "two");
        assert!(
            xdg.data.join("Trash/info/collision.1.trashinfo").exists(),
            "the record follows the payload's name"
        );
    }

    #[test]
    fn a_dangling_link_in_the_trash_still_occupies_its_name() {
        let (_temp, xdg, trash) = fixture();
        // A link that points nowhere is invisible to `exists()`, but the name is
        // still taken: renaming onto it would replace the entry instead of
        // placing the payload beside it.
        std::os::unix::fs::symlink(xdg.home.join("gone"), trash.files().join("notes.txt"))
            .expect("link");
        let file = xdg.home.join("work/notes.txt");
        std::fs::write(&file, b"body").expect("write");

        let moved = trash.send(&file, &xdg).expect("moved");
        assert_eq!(moved.to, trash.files().join("notes.txt.1"));
        assert_eq!(std::fs::read_to_string(&moved.to).expect("payload"), "body");
        assert!(
            std::fs::symlink_metadata(trash.files().join("notes.txt"))
                .expect("link")
                .is_symlink(),
            "the dangling link was left where it was"
        );
    }

    #[test]
    fn a_symlink_moves_as_a_link_and_its_target_survives() {
        use std::os::unix::fs::MetadataExt;
        let (_temp, xdg, trash) = fixture();
        let target = xdg.home.join("work/target.txt");
        std::fs::write(&target, b"precious").expect("write");
        let before = std::fs::metadata(&target).expect("meta").ino();
        let link = xdg.home.join("work/link.txt");
        std::os::unix::fs::symlink(&target, &link).expect("link");

        let moved = trash.send(&link, &xdg).expect("moved");
        assert!(
            std::fs::symlink_metadata(&moved.to)
                .expect("meta")
                .is_symlink(),
            "the entry in the trash is still a link"
        );
        assert_eq!(
            std::fs::metadata(&target).expect("meta").ino(),
            before,
            "the target is untouched"
        );
        assert_eq!(std::fs::read(&target).expect("read"), b"precious");
    }

    #[test]
    fn protected_and_identity_paths_are_refused_before_any_move() {
        let (_temp, xdg, _) = fixture();
        let identity = xdg.home.join(".ssh");
        std::fs::create_dir_all(&identity).expect("mkdir");
        assert!(matches!(guard(&identity, &xdg), Err(Refusal::Identity(_)),));
        assert!(matches!(
            guard(Path::new("/etc/passwd"), &xdg),
            Err(Refusal::Protected(_))
        ));
        assert_eq!(guard(Path::new("/"), &xdg), Err(Refusal::Root));
        assert_eq!(
            guard(&xdg.home.join("work/../../etc"), &xdg),
            Err(Refusal::Traversal)
        );
        assert_eq!(
            guard(&xdg.data.join("Trash/files/x"), &xdg),
            Err(Refusal::TheTrashItself)
        );
        assert!(identity.exists(), "a refused path is never moved");
    }

    #[test]
    fn a_symlinked_ancestor_refuses_rather_than_redirecting() {
        let (_temp, xdg, trash) = fixture();
        let real = xdg.home.join("real");
        std::fs::create_dir_all(&real).expect("mkdir");
        std::fs::write(real.join("file"), b"body").expect("write");
        let linkdir = xdg.home.join("work/linkdir");
        std::os::unix::fs::symlink(&real, &linkdir).expect("link");

        let error = trash
            .send(&linkdir.join("file"), &xdg)
            .expect_err("a link above the entry is a refusal");
        assert_eq!(error, Refusal::SymlinkAncestor);
        assert!(real.join("file").exists(), "nothing moved");
        assert_eq!(
            record_count(&xdg),
            0,
            "a refusal before the move leaves no restore record"
        );
    }

    fn record_count(xdg: &Xdg) -> usize {
        std::fs::read_dir(xdg.data.join("Trash/info"))
            .expect("info")
            .count()
    }

    /// A mount table that says the home trash and `mnt/data` are separate mounts.
    ///
    /// The test process cannot assume a second filesystem, so the table is the
    /// only part that lies: the paths are real, the move is real, and the
    /// selection sees two different mount points.
    fn two_mounts(root: &Path) -> MountTable {
        let text = format!(
            "1 0 0:1 / {} rw - ext4 /dev/home rw\n\
             2 1 0:2 / {} rw - ext4 /dev/data rw\n",
            root.display(),
            root.join("mnt/data").display()
        );
        MountTable::parse(&text)
    }

    fn other_mount(root: &Path) -> PathBuf {
        let mount = root.join("mnt/data");
        std::fs::create_dir_all(&mount).expect("mount point");
        mount
    }

    #[test]
    fn an_entry_on_another_mount_lands_in_that_mounts_trash() {
        let (temp, xdg, trash) = fixture();
        let root = temp.path().canonicalize().expect("root");
        let mount = other_mount(&root);
        let shared = mount.join(".Trash");
        std::fs::DirBuilder::new()
            .mode(0o1777)
            .create(&shared)
            .expect("shared trash");
        let uid = sys::euid();
        let file = mount.join("notes.txt");
        std::fs::write(&file, b"hello").expect("write");

        let moved = trash
            .send_within(&file, &xdg, &two_mounts(&root), uid)
            .expect("moved into the top directory trash");

        assert!(!file.exists(), "the entry left its directory");
        assert_eq!(
            moved.to,
            shared.join(uid.to_string()).join("files/notes.txt")
        );
        assert_eq!(std::fs::read(&moved.to).expect("payload"), b"hello");

        let record = std::fs::read_to_string(
            shared
                .join(uid.to_string())
                .join("info/notes.txt.trashinfo"),
        )
        .expect("record");
        assert!(
            record.contains(&format!("Path={}", file.display())),
            "the record names the original path, so the desktop can restore it: {record}"
        );

        let mine = std::fs::metadata(shared.join(uid.to_string())).expect("meta");
        assert_eq!(mine.mode() & 0o777, 0o700, "only the owner may read it");
        assert_eq!(
            record_count(&xdg),
            0,
            "the home trash is not used for another mount"
        );
    }

    #[test]
    fn a_mount_without_a_trash_directory_refuses_and_names_the_one_to_create() {
        let (temp, xdg, trash) = fixture();
        let root = temp.path().canonicalize().expect("root");
        let mount = other_mount(&root);
        let uid = sys::euid();
        let file = mount.join("notes.txt");
        std::fs::write(&file, b"hello").expect("write");

        let refusal = trash
            .send_within(&file, &xdg, &two_mounts(&root), uid)
            .expect_err("no trash on that mount");
        assert!(
            matches!(refusal, Refusal::NoTopdirTrash { .. }),
            "{refusal:?}"
        );
        let message = refusal.to_string();
        assert!(
            message.contains(&mount.join(format!(".Trash-{uid}")).display().to_string()),
            "the refusal must name the directory that would fix it: {message}"
        );
        assert!(file.exists(), "a refused move leaves the entry alone");
        assert_eq!(record_count(&xdg), 0, "and writes no record anywhere");
    }

    #[test]
    fn an_administrators_private_trash_directory_is_used() {
        let (temp, xdg, trash) = fixture();
        let root = temp.path().canonicalize().expect("root");
        let mount = other_mount(&root);
        let uid = sys::euid();
        let private = mount.join(format!(".Trash-{uid}"));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&private)
            .expect("private trash");
        let file = mount.join("notes.txt");
        std::fs::write(&file, b"hello").expect("write");

        let moved = trash
            .send_within(&file, &xdg, &two_mounts(&root), uid)
            .expect("moved");
        assert_eq!(moved.to, private.join("files/notes.txt"));
        assert!(
            std::fs::read_to_string(private.join("info/notes.txt.trashinfo"))
                .expect("record")
                .contains("[Trash Info]")
        );
    }

    #[test]
    fn a_shared_trash_without_the_sticky_bit_is_refused() {
        let (temp, xdg, trash) = fixture();
        let root = temp.path().canonicalize().expect("root");
        let mount = other_mount(&root);
        let shared = mount.join(".Trash");
        std::fs::DirBuilder::new()
            .mode(0o777)
            .create(&shared)
            .expect("shared trash");
        let file = mount.join("notes.txt");
        std::fs::write(&file, b"hello").expect("write");

        let refusal = trash
            .send_within(&file, &xdg, &two_mounts(&root), sys::euid())
            .expect_err("not sticky");
        assert!(
            refusal.to_string().contains("sticky bit"),
            "the refusal says which rule stopped it: {refusal}"
        );
        assert!(file.exists(), "nothing moved");
        assert!(
            !shared.join(sys::euid().to_string()).exists(),
            "and no directory was created inside it"
        );
    }

    #[test]
    fn a_shared_trash_directory_owned_by_another_user_is_refused() {
        let (temp, xdg, trash) = fixture();
        let root = temp.path().canonicalize().expect("root");
        let mount = other_mount(&root);
        let shared = mount.join(".Trash");
        std::fs::DirBuilder::new()
            .mode(0o1777)
            .create(&shared)
            .expect("shared trash");
        // The test process owns this directory, and the move claims a different
        // user id: the ownership check has to notice, which is the case a real
        // second user would create.
        let stranger = sys::euid() + 1;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(shared.join(stranger.to_string()))
            .expect("dir");
        let file = mount.join("notes.txt");
        std::fs::write(&file, b"hello").expect("write");

        let refusal = trash
            .send_within(&file, &xdg, &two_mounts(&root), stranger)
            .expect_err("not ours");
        assert!(
            matches!(refusal, Refusal::Permission(_)),
            "the owner check refuses rather than moving into it: {refusal:?}"
        );
        assert!(file.exists(), "nothing moved");
    }

    #[test]
    fn a_symlinked_trash_directory_is_refused_rather_than_followed() {
        let (temp, xdg, trash) = fixture();
        let root = temp.path().canonicalize().expect("root");
        let mount = other_mount(&root);
        let real = mount.join("elsewhere");
        std::fs::create_dir_all(&real).expect("mkdir");
        std::os::unix::fs::symlink(&real, mount.join(".Trash")).expect("link");
        let file = mount.join("notes.txt");
        std::fs::write(&file, b"hello").expect("write");

        let refusal = trash
            .send_within(&file, &xdg, &two_mounts(&root), sys::euid())
            .expect_err("link");
        assert!(
            refusal.to_string().contains("symbolic link"),
            "the refusal names the link: {refusal}"
        );
        assert!(file.exists(), "nothing moved");
        assert_eq!(
            std::fs::read_dir(&real).expect("dir").count(),
            0,
            "nothing was created on the other side of the link"
        );
    }

    #[test]
    fn a_path_inside_a_trash_directory_is_never_trashed_again() {
        let (temp, xdg, _) = fixture();
        let inside = temp.path().join(".Trash-1000/files/notes");
        assert_eq!(
            guard(&inside, &xdg),
            Err(Refusal::TheTrashItself),
            "a trashed payload is refused by name, without a mount table"
        );
        assert_eq!(
            guard(&temp.path().join(".Trash/1000/files/notes"), &xdg),
            Err(Refusal::TheTrashItself)
        );
        assert!(
            guard(&temp.path().join(".Trash-can/notes"), &xdg).is_ok(),
            "a directory that only looks similar is not a trash"
        );
    }

    #[test]
    fn a_missing_entry_is_gone_not_an_empty_trash_entry() {
        let (_temp, xdg, trash) = fixture();
        let ghost = xdg.home.join("work/ghost");
        let error = trash.send(&ghost, &xdg).expect_err("missing");
        assert!(
            matches!(error, Refusal::Gone | Refusal::Other(_)),
            "{error:?}"
        );
        let info_entries = std::fs::read_dir(xdg.data.join("Trash/info"))
            .expect("info")
            .count();
        assert_eq!(info_entries, 0, "a failed move leaves no restore record");
    }

    #[test]
    fn encoding_escapes_everything_but_unreserved_bytes_and_slashes() {
        assert_eq!(
            encode_path(Path::new("/home/u/my file (1).txt")),
            "/home/u/my%20file%20%281%29.txt"
        );
        assert_eq!(encode_path(Path::new("/home/u/café")), "/home/u/caf%C3%A9");
        assert_eq!(
            encode_path(Path::new("/home/u/a-b_c.d~e")),
            "/home/u/a-b_c.d~e"
        );
    }

    #[test]
    fn the_local_timestamp_has_the_shape_the_spec_wants() {
        let stamp = sys::local_timestamp();
        assert_eq!(stamp.len(), 19, "{stamp}");
        assert_eq!(stamp.as_bytes()[4], b'-');
        assert_eq!(stamp.as_bytes()[7], b'-');
        assert_eq!(stamp.as_bytes()[10], b'T');
        assert_eq!(stamp.as_bytes()[13], b':');
        assert_eq!(stamp.as_bytes()[16], b':');
        assert!(stamp[0..4].parse::<i32>().expect("year") >= 2024);
    }
}
