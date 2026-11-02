//! Moving a chosen entry to the freedesktop trash.
//!
//! `analyze` is the one command whose deletion is recoverable, and it is
//! recoverable because it is a move: the entry leaves the directory the user is
//! looking at and arrives in `$XDG_DATA_HOME/Trash`, with a `.trashinfo` record
//! that says where it came from. The desktop's own "Restore" does the rest.
//!
//! Three things are deliberately not implemented:
//!
//! * **No cross-filesystem fallback.** `renameat` refuses to cross a mount, and
//!   the honest answer is "the entry is still where it was". Copying a tree and
//!   then deleting the original turns one recoverable move into a slow operation
//!   that can be interrupted halfway, and the freedesktop "top directory trash"
//!   that would solve it properly is a second implementation with its own
//!   permissions and its own restore semantics.
//! * **No deletion.** Nothing here unlinks anything; the only removal is of a
//!   `.trashinfo` file written a moment earlier when the move that followed it
//!   failed.
//! * **No following.** Both directory handles are opened with
//!   `RESOLVE_NO_SYMLINKS` and both names are single components, so a changed
//!   ancestor cannot redirect the move. A symbolic link is moved as a link; its
//!   target is never touched.

use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

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

    /// Moves `path` into the trash.
    ///
    /// `bytes` is only used by the caller for the operation log; the move itself
    /// does not measure anything, because the explorer already showed the size
    /// the user agreed to.
    pub fn send(&self, path: &Path, xdg: &Xdg) -> Result<Moved, Refusal> {
        guard(path, xdg)?;
        let Some(name) = path.file_name() else {
            return Err(Refusal::Root);
        };
        let Some(parent) = path.parent() else {
            return Err(Refusal::Root);
        };

        let (destination, info_path) = self
            .available(name)
            .ok_or_else(|| Refusal::Other("no free name in the trash".to_string()))?;

        // The record comes first: if the move fails, a `.trashinfo` without a
        // payload is deleted below, whereas a payload without a record would be
        // invisible to every restore tool.
        write_info(&info_path, path)?;

        let from_dir = sys::open_dir_nofollow(parent).map_err(|error| match error {
            sys::OpenDirError::SymlinkRefused => Refusal::SymlinkAncestor,
            sys::OpenDirError::Io(io) => map_io(&io, parent),
        })?;
        let to_dir = sys::open_dir_nofollow(&self.files).map_err(|error| match error {
            sys::OpenDirError::SymlinkRefused => Refusal::SymlinkAncestor,
            sys::OpenDirError::Io(io) => map_io(&io, &self.files),
        })?;

        match sys::rename_beneath(&from_dir, name, &to_dir, &destination) {
            Ok(()) => Ok(Moved {
                from: path.to_path_buf(),
                to: self.files.join(&destination),
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

    /// The first name that is free in both `files/` and `info/`.
    fn available(&self, name: &OsStr) -> Option<(OsString, PathBuf)> {
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
            let info = self.info.join(&info_name);
            if !self.files.join(&candidate).exists() && !info.exists() {
                return Some((candidate, info));
            }
        }
        None
    }
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
    if path.starts_with(xdg.data.join("Trash")) {
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
