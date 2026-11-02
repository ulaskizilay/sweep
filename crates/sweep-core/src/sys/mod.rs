//! The only module in this workspace allowed to contain `unsafe`.
//!
//! Every entry point here is a thin, audited wrapper around one syscall. The
//! safety argument for each block is written next to it with a `// SAFETY:`
//! comment; `clippy::undocumented_unsafe_blocks` is deny-by-default.
//!
//! Two guarantees matter more than speed:
//!
//! 1. **Directory handles never follow symbolic links.** `openat2` is used with
//!    `RESOLVE_NO_SYMLINKS`, so a redirected `~/.cache` cannot make a delete
//!    walk into `~/Documents`.
//! 2. **Deletion is one non-recursive syscall per item.** `unlinkat(2)` removes
//!    a single entry. Recursion is the scanner's job, so an unexpected directory
//!    fails with `ENOTEMPTY` instead of being wiped.

#![allow(unsafe_code)]

use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

/// `openat2(2)` resolve flag: reject any symbolic link in any component.
const RESOLVE_NO_SYMLINKS: u64 = 0x04;

/// `openat2` is syscall 437 on the architectures we build for.
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
))]
const SYS_OPENAT2: libc::c_long = 437;

#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64"
)))]
compile_error!("sweep supports x86_64, aarch64 and riscv64; add SYS_OPENAT2 for this architecture");

/// `ioctl(FS_IOC_GETFLAGS)` — read the inode flags (immutable, append-only).
const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;

/// `FS_IMMUTABLE_FL` from `linux/fs.h`.
const FS_IMMUTABLE_FL: libc::c_int = 0x0000_0010;

/// Kernel struct passed to `openat2(2)`. Layout is part of the ABI.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// Why a directory handle could not be opened.
#[derive(Debug)]
pub enum OpenDirError {
    /// A path component is a symbolic link (or a magic link such as `/proc/self`).
    SymlinkRefused,
    Io(io::Error),
}

impl std::fmt::Display for OpenDirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenDirError::SymlinkRefused => f.write_str("path contains a symbolic link"),
            OpenDirError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for OpenDirError {}

/// Opens an absolute directory path without following any symbolic link.
///
/// The returned handle is used as the `dirfd` for `unlinkat`, which pins the
/// parent directory so a concurrent `rename` cannot redirect the delete.
pub fn open_dir_nofollow(path: &Path) -> Result<OwnedFd, OpenDirError> {
    if !path.is_absolute() {
        return Err(OpenDirError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must be absolute",
        )));
    }
    match openat2_dir(path) {
        Ok(fd) => Ok(fd),
        Err(err) if is_unsupported(&err) => component_walk_dir(path),
        Err(err) => Err(err),
    }
}

fn is_unsupported(err: &OpenDirError) -> bool {
    match err {
        OpenDirError::Io(e) => matches!(e.raw_os_error(), Some(libc::ENOSYS) | Some(libc::EINVAL)),
        OpenDirError::SymlinkRefused => false,
    }
}

fn openat2_dir(path: &Path) -> Result<OwnedFd, OpenDirError> {
    let hoist_guard = path_contains_nul(path);
    if hoist_guard {
        return Err(OpenDirError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains a NUL byte",
        )));
    }
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| OpenDirError::Io(io::Error::new(io::ErrorKind::InvalidInput, "NUL byte")))?;
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_NO_SYMLINKS,
    };

    // SAFETY: `c_path` is a valid NUL-terminated string, `how` is a valid
    // `open_how` for the declared size, and both pointers stay live for the
    // duration of the call. The return value is checked before any use.
    let ret = unsafe {
        libc::syscall(
            SYS_OPENAT2,
            libc::AT_FDCWD,
            c_path.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };

    if ret >= 0 {
        // SAFETY: a non-negative return from openat2 is a freshly owned fd that
        // nothing else in this process holds, so taking ownership is sound.
        return Ok(unsafe { OwnedFd::from_raw_fd(ret as libc::c_int) });
    }

    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        // ELOOP is what RESOLVE_NO_SYMLINKS reports; report it as a refusal.
        Some(libc::ELOOP) | Some(libc::EXDEV) => Err(OpenDirError::SymlinkRefused),
        _ => Err(OpenDirError::Io(err)),
    }
}

/// Fallback for kernels older than 5.6: open every component with `O_NOFOLLOW`.
///
/// This must reach the same verdict as `openat2`; the differential test
/// `kernels_agree` in `tests/properties.rs` pins that.
fn component_walk_dir(path: &Path) -> Result<OwnedFd, OpenDirError> {
    let mut current = open_root()?;
    for component in path.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        let c_name = CString::new(name.as_bytes()).map_err(|_| {
            OpenDirError::Io(io::Error::new(io::ErrorKind::InvalidInput, "NUL byte"))
        })?;
        // SAFETY: `current` is a live directory fd and `c_name` is a valid
        // NUL-terminated name. O_NOFOLLOW turns a symlink into ELOOP instead of
        // following it, and O_PATH avoids requiring read permission.
        let fd = unsafe {
            libc::openat(
                current.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = io::Error::last_os_error();
            return Err(match err.raw_os_error() {
                Some(libc::ELOOP) => OpenDirError::SymlinkRefused,
                // `O_PATH|O_NOFOLLOW` reports a symlink as ENOTDIR rather than
                // ELOOP, because `O_DIRECTORY` rejects the link instead of
                // following it. Probe the entry so a symlink and a plain file
                // in the middle of the path stay distinguishable: `openat2`
                // reports ELOOP for the first and ENOTDIR for the second, and
                // this fallback must not merge them.
                Some(libc::ENOTDIR) => {
                    if is_symlink_at(current.as_raw_fd(), &c_name) {
                        OpenDirError::SymlinkRefused
                    } else {
                        OpenDirError::Io(err)
                    }
                }
                _ => OpenDirError::Io(err),
            });
        }
        // SAFETY: `fd` is a fresh descriptor from openat and is not stored
        // anywhere else, so wrapping it in OwnedFd closes it exactly once.
        current = unsafe { OwnedFd::from_raw_fd(fd) };
    }
    Ok(current)
}

fn open_root() -> Result<OwnedFd, OpenDirError> {
    let root = CString::new("/").expect("static path has no NUL");
    // SAFETY: `root` is a valid NUL-terminated string of a static path; the
    // returned fd is checked before being wrapped in an OwnedFd.
    let fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(OpenDirError::Io(io::Error::last_os_error()));
    }
    // SAFETY: fresh descriptor owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn path_contains_nul(path: &Path) -> bool {
    path.as_os_str().as_bytes().contains(&0)
}

/// True when `name` inside `dirfd` is a symbolic link, without following it.
///
/// Only used to disambiguate an `ENOTDIR` from the fallback open, so it is
/// deliberately cheap and reports `false` on any error: the caller already has a
/// failure to report and only needs to pick which kind.
fn is_symlink_at(dirfd: std::os::fd::RawFd, name: &CString) -> bool {
    // SAFETY: `stat` is fully initialised before the call so every field is
    // defined, and `fstatat` writes into it only on success, which is checked.
    let mut raw: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `dirfd` is a live directory handle and `name` is a valid
    // NUL-terminated single component. AT_SYMLINK_NOFOLLOW keeps the probe from
    // following the very link it is trying to identify.
    let rc = unsafe { libc::fstatat(dirfd, name.as_ptr(), &mut raw, libc::AT_SYMLINK_NOFOLLOW) };
    rc == 0 && (raw.st_mode & libc::S_IFMT) == libc::S_IFLNK
}

/// Removes one entry relative to an already-open parent directory.
///
/// Directories are removed with `AT_REMOVEDIR`, which fails with `ENOTEMPTY`
/// when the directory still has children. That failure is the safety net that
/// makes accidental recursive deletion impossible from this layer.
pub fn unlink_beneath(dirfd: &OwnedFd, name: &OsStr, is_dir: bool) -> io::Result<()> {
    let c_name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL byte in file name"))?;
    let flags = if is_dir { libc::AT_REMOVEDIR } else { 0 };
    // SAFETY: `dirfd` is a live directory handle, `c_name` is a valid
    // NUL-terminated single component with no separator, and the flags value is
    // one of the two documented constants.
    let rc = unsafe { libc::unlinkat(dirfd.as_raw_fd(), c_name.as_ptr(), flags) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Renames one entry between two already-open directories.
///
/// Both handles were opened without following a symbolic link, and both names
/// are single components, so the move cannot be redirected through an ancestor
/// that changed between the decision and the call. `renameat` also refuses to
/// cross a filesystem, which is the honest answer for a move into a trash
/// directory on another mount: copying and deleting would turn a recoverable
/// move into a slow, half-finished one.
pub fn rename_beneath(
    from_dir: &OwnedFd,
    from: &OsStr,
    to_dir: &OwnedFd,
    to: &OsStr,
) -> io::Result<()> {
    let c_from = CString::new(from.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL byte in file name"))?;
    let c_to = CString::new(to.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL byte in file name"))?;
    // SAFETY: both descriptors are live directory handles and both names are
    // valid NUL-terminated single components with no separator.
    let rc = unsafe {
        libc::renameat(
            from_dir.as_raw_fd(),
            c_from.as_ptr(),
            to_dir.as_raw_fd(),
            c_to.as_ptr(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `YYYY-MM-DDTHH:MM:SS` in local time, the shape the trash specification asks
/// for.
///
/// Local rather than UTC because a desktop read of the record shows the deletion
/// date to the user, and a UTC stamp would be wrong by their offset. A zone that
/// cannot be resolved falls back to UTC rather than refusing the move.
pub fn local_timestamp() -> String {
    // SAFETY: `time` with a null pointer only reads the clock.
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    // SAFETY: all-zero is a valid `tm`, and `localtime_r` fills it in.
    let mut broken: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are valid for the duration of the call, and the
    // out-parameter is owned by this frame.
    let rc = unsafe { libc::localtime_r(&now, &mut broken) };
    if rc.is_null() {
        let utc = crate::oplog::rfc3339(now as i64);
        return utc.trim_end_matches('Z').to_string();
    }
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        broken.tm_year + 1900,
        broken.tm_mon + 1,
        broken.tm_mday,
        broken.tm_hour,
        broken.tm_min,
        broken.tm_sec
    )
}

/// Filesystem space counters, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Space {
    pub total: u64,
    pub free: u64,
    pub avail: u64,
    /// Bytes available to unprivileged users, the number `df` shows.
    pub block_size: u64,
    /// Inode capacity, or 0 on a filesystem that does not track inodes.
    pub files: u64,
    /// Inodes still free, or 0 when unknown.
    pub files_free: u64,
}

/// `statvfs(3)` for a path. Used to report *reclaimed* space separately from
/// *removed* bytes, because on CoW filesystems the two differ.
pub fn statvfs_space(path: &Path) -> io::Result<Space> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL byte"))?;
    // SAFETY: `statvfs` is all-zero-initialised before the call and only read
    // afterwards; `c_path` outlives the call.
    let mut raw: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `raw` is a valid, properly aligned out-parameter of the exact
    // type the libc signature expects.
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut raw) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Space {
        total: raw.f_blocks as u64 * raw.f_frsize as u64,
        free: raw.f_bfree as u64 * raw.f_frsize as u64,
        avail: raw.f_bavail as u64 * raw.f_frsize as u64,
        block_size: raw.f_frsize as u64,
        files: raw.f_files as u64,
        files_free: raw.f_ffree as u64,
    })
}

/// Reads inode flags and reports whether `FS_IMMUTABLE_FL` is set.
///
/// Filesystems that do not implement the ioctl report `false`; a user-marked
/// immutable file is protected, but an unsupported ioctl must not block cleanup.
///
/// Opening a directory with `O_RDONLY` succeeds on Linux, so no separate
/// directory path is needed; an earlier `EISDIR` retry never fired and was
/// removed rather than left as a branch that cannot run.
pub fn is_immutable(path: &Path) -> io::Result<bool> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL byte"))?;
    // SAFETY: `c_path` is a valid NUL-terminated string. O_NOFOLLOW keeps a
    // symlink from being opened rather than inspected, and O_NONBLOCK keeps a
    // FIFO or a device node from hanging the probe.
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is fresh and owned here; it is closed exactly once.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    read_immutable_flags(&owned)
}

fn read_immutable_flags(fd: &OwnedFd) -> io::Result<bool> {
    let mut flags: libc::c_int = 0;
    // SAFETY: `fd` is a live, read-only descriptor and `flags` is a valid,
    // aligned out-parameter for FS_IOC_GETFLAGS, which writes a c_int.
    let rc = unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            FS_IOC_GETFLAGS,
            &mut flags as *mut libc::c_int,
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::ENOTTY)
            | Some(libc::EOPNOTSUPP)
            | Some(libc::ENOSYS)
            | Some(libc::EPERM) => Ok(false),
            _ => Err(err),
        };
    }
    Ok(flags & FS_IMMUTABLE_FL != 0)
}

/// Effective user id. Separate from `std` so tests can reason about the same
/// value the kernel uses for ownership checks.
pub fn euid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// Lets the default `SIGPIPE` disposition kill the process again.
///
/// Rust starts every program with `SIGPIPE` ignored, so a write to a closed
/// pipe returns `EPIPE` instead of ending the process. That is the right default
/// for a library and the wrong one for a CLI: `sweep uninstall | head` would
/// print a panic message and exit 101, where every other Unix tool stops
/// quietly at the first broken write. Restoring the default makes the shell
/// pipeline behave the way the shell expects.
pub fn die_on_broken_pipe() {
    // SAFETY: `signal` with a valid signal number and `SIG_DFL` has no
    // preconditions and no side effects beyond this process's disposition.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

/// glibc's `makedev`: encodes a `(major, minor)` pair into a `dev_t`.
///
/// `st_dev` and `/proc/self/mountinfo` report the same device differently, and
/// comparing them without this conversion is a silent bug: every path would
/// look like it lives on another device.
pub fn makedev(major: u32, minor: u32) -> u64 {
    let major = major as u64;
    let minor = minor as u64;
    ((major & 0xfff) << 8) | (minor & 0xff) | ((minor & !0xff) << 12) | ((major & !0xfff) << 32)
}

/// Reads `/proc/self/mountinfo` contents.
pub fn read_mountinfo() -> io::Result<String> {
    std::fs::read_to_string("/proc/self/mountinfo")
}

/// Reads `/proc/<pid>/comm`, the process name the kernel reports.
pub fn read_process_name(pid: u32) -> io::Result<String> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/comm"))?;
    Ok(raw.trim_end_matches('\n').to_string())
}

/// Lists `/proc/<pid>/fd` entries. Returns an empty vector when the directory
/// is unreadable (another user's process), never an error: an unreadable fd
/// table only means "we cannot prove the file is open".
pub fn list_fds(pid: u32) -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .collect()
}

/// Lists visible process ids.
pub fn list_pids() -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .collect()
}

/// True when the kernel or filesystem rejected `openat2` itself, in which case
/// the component-walk fallback is required for correctness.
pub fn openat2_supported() -> bool {
    let Some(path) = std::env::var_os("HOME") else {
        return false;
    };
    let path = Path::new(&path);
    if !path.is_absolute() {
        return false;
    }
    match openat2_dir(path) {
        Ok(_) => true,
        Err(OpenDirError::Io(e)) => {
            !matches!(e.raw_os_error(), Some(libc::ENOSYS) | Some(libc::EINVAL))
        }
        Err(OpenDirError::SymlinkRefused) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    /// The only three outcomes that matter to the caller.
    #[derive(Debug, PartialEq, Eq)]
    enum Opened {
        Yes,
        Symlink,
        Failed,
    }

    fn classify(result: &Result<OwnedFd, OpenDirError>) -> Opened {
        match result {
            Ok(_) => Opened::Yes,
            Err(OpenDirError::SymlinkRefused) => Opened::Symlink,
            Err(OpenDirError::Io(_)) => Opened::Failed,
        }
    }

    /// Both directory-open paths must reach the same verdict.
    ///
    /// `openat2` is the fast path and the only one that carries
    /// `RESOLVE_NO_SYMLINKS` natively; the component walk emulates it with
    /// `O_NOFOLLOW` per component. If they ever disagree, a kernel without
    /// `openat2` would silently lose a safety property, so this runs against the
    /// real filesystem rather than a fixture.
    #[test]
    fn kernels_agree_on_every_component_shape() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        let real = root.join("real");
        std::fs::create_dir_all(real.join("inner")).expect("mkdir");
        let link = root.join("link");
        symlink(&real, &link).expect("symlink");
        let dangling = root.join("dangling");
        symlink(root.join("does-not-exist"), &dangling).expect("symlink");
        let file = root.join("a-file");
        std::fs::write(&file, b"x").expect("write");

        let cases: Vec<PathBuf> = vec![
            PathBuf::from("/"),
            root.to_path_buf(),
            real.clone(),
            real.join("inner"),
            link.clone(),
            link.join("inner"),
            dangling.clone(),
            file.clone(),
            file.join("beneath-a-file"),
            root.join("missing"),
        ];

        for path in cases {
            assert_eq!(
                classify(&openat2_dir(&path)),
                classify(&component_walk_dir(&path)),
                "{}: openat2 and the component walk disagree",
                path.display()
            );
        }
    }

    #[test]
    fn a_symlinked_component_is_refused_by_both_paths() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        let real = root.join("real");
        std::fs::create_dir_all(&real).expect("mkdir");
        let link = root.join("link");
        symlink(&real, &link).expect("symlink");

        assert!(matches!(
            openat2_dir(&link),
            Err(OpenDirError::SymlinkRefused)
        ));
        assert!(matches!(
            component_walk_dir(&link),
            Err(OpenDirError::SymlinkRefused)
        ));
    }

    #[test]
    fn a_plain_directory_is_opened_by_both_paths() {
        let temp = tempfile::tempdir().expect("tempdir");
        let nested = temp.path().join("a/b/c");
        std::fs::create_dir_all(&nested).expect("mkdir");
        assert!(openat2_dir(&nested).is_ok());
        assert!(component_walk_dir(&nested).is_ok());
    }

    #[test]
    fn unlink_beneath_removes_one_entry_and_stops() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dir = temp.path().join("d");
        std::fs::create_dir_all(dir.join("child")).expect("mkdir");
        std::fs::write(dir.join("child/keep"), b"x").expect("write");

        let fd = open_dir_nofollow(&dir).expect("open");
        // A non-empty directory must fail rather than recurse.
        let error = unlink_beneath(&fd, OsStr::new("child"), true).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOTEMPTY));
        assert!(dir.join("child/keep").exists());

        std::fs::remove_file(dir.join("child/keep")).expect("cleanup");
        unlink_beneath(&fd, OsStr::new("child"), true).expect("empty directory goes");
        assert!(!dir.join("child").exists());
    }

    #[test]
    fn makedev_matches_the_glibc_encoding() {
        // Compare against glibc's own encoder: `st_dev` and the `major:minor`
        // pair in mountinfo must be encoded identically or every path looks
        // like it lives on another device.
        for (major, minor) in [(0, 0), (8, 2), (0, 20), (8, 300), (259, 7), (4095, 255)] {
            assert_eq!(
                makedev(major, minor),
                libc::makedev(major, minor),
                "dev_t encoding differs for {major}:{minor}"
            );
        }
    }
}

#[cfg(test)]
mod space_tests {
    use super::*;

    #[test]
    fn statvfs_reports_a_sane_space_profile() {
        // Real syscall on the real root: a wrapper that cannot report free space
        // is not a wrapper anyone can build a summary from.
        let space = statvfs_space(Path::new("/")).expect("statvfs on /");
        assert!(space.total > 0, "total: {space:?}");
        assert!(space.block_size > 0, "block_size: {space:?}");
        assert!(space.free <= space.total, "free: {space:?}");
        assert!(
            space.avail <= space.free,
            "available-to-user must not exceed free: {space:?}"
        );
    }

    #[test]
    fn statvfs_on_a_missing_path_is_an_error_not_a_zero() {
        // A zeroed `Space` would report "this filesystem is full", which is a
        // worse lie than an error the caller can report.
        let error = statvfs_space(Path::new("/definitely/not/here"))
            .expect_err("a missing path must error");
        assert_eq!(error.raw_os_error(), Some(libc::ENOENT));
    }

    #[test]
    fn a_path_with_a_nul_byte_is_rejected_before_the_syscall() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(OsStr::from_bytes(b"/tmp/a\0b"));
        assert_eq!(
            statvfs_space(path).expect_err("NUL must be refused").kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            is_immutable(path).expect_err("NUL must be refused").kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(matches!(open_dir_nofollow(path), Err(OpenDirError::Io(_))));
    }

    #[test]
    fn a_relative_path_is_refused_by_the_directory_opener() {
        // A relative parent would be resolved against a working directory the
        // caller did not choose, so it must never reach a syscall.
        let error = open_dir_nofollow(Path::new("relative/dir"))
            .expect_err("relative paths must be refused");
        match error {
            OpenDirError::Io(error) => {
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput)
            }
            OpenDirError::SymlinkRefused => panic!("a relative path is not a symlink"),
        }
    }

    #[test]
    fn immutable_flag_is_readable_for_files_and_directories() {
        // Both shapes must answer, because sweep validates both. `false` is the
        // expected answer for a file we just created; the point is that the probe
        // completes instead of erroring out and blocking every cleanup.
        let temp = tempfile::tempdir().expect("tempdir");
        let file = temp.path().join("plain.txt");
        std::fs::write(&file, b"x").expect("write");

        assert!(!is_immutable(&file).expect("file probe"));
        assert!(!is_immutable(temp.path()).expect("dir probe"));
        assert_eq!(
            is_immutable(&temp.path().join("missing"))
                .expect_err("missing path must error")
                .raw_os_error(),
            Some(libc::ENOENT)
        );
    }

    #[test]
    fn a_symlink_is_never_followed_when_reading_the_flag() {
        // O_NOFOLLOW makes the probe report the link itself (ELOOP), never the
        // target's flags. Following it would let a link decide whether a delete
        // is allowed.
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join("target");
        std::fs::write(&target, b"x").expect("write");
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let error = is_immutable(&link).expect_err("a symlink must not be followed");
        assert_eq!(error.raw_os_error(), Some(libc::ELOOP));
    }

    #[test]
    fn open_dir_errors_describe_themselves() {
        // These strings surface in `--json` detail fields.
        let symlink = OpenDirError::SymlinkRefused.to_string();
        assert!(symlink.contains("symbolic link"), "{symlink}");

        let io = OpenDirError::Io(io::Error::from_raw_os_error(libc::EACCES)).to_string();
        assert!(!io.is_empty());
    }

    #[test]
    fn process_inspection_finds_this_process() {
        // The `/proc` helpers are how "is this file open" is answered; a
        // missing `/proc` must degrade to an empty result, not a panic.
        let pids = list_pids();
        assert!(!pids.is_empty(), "no processes visible in /proc");
        let me = std::process::id();
        assert!(pids.contains(&me), "this process missing from /proc");

        let name = read_process_name(me).expect("/proc/self/comm");
        assert!(!name.is_empty(), "process name is empty");
        assert!(!name.contains('\n'), "name must be trimmed: {name:?}");

        // An unreadable fd table belongs to another user; it yields nothing
        // rather than failing the whole scan.
        assert_eq!(list_fds(0), Vec::<u32>::new());
    }
}
