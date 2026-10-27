//! Pure path arithmetic: no syscalls, no allocation-heavy globbing.
//!
//! Everything here is total (never panics) and cheap, because it runs on every
//! candidate path. The system's real behaviour is checked later by
//! [`crate::probe::FsProbe`]; this module only reasons about the string form.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

/// Control bytes cannot be logged or displayed unambiguously, and a path that
/// contains one is very likely an injection attempt rather than a real file.
pub fn has_control_bytes(value: &OsStr) -> bool {
    value
        .as_bytes()
        .iter()
        .any(|byte| *byte < 0x20 || *byte == 0x7f)
}

/// A `..` component, which no cleanup target legitimately needs.
///
/// Checked component-wise, so a *file name* such as `name..files` stays valid.
pub fn has_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

/// Lexically normalises a path: drops `.` components and collapses `//`.
///
/// `..` is **not** resolved, because [`has_parent_component`] rejects it
/// upstream; resolving it lexically would hide a traversal instead of refusing
/// it.
pub fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) => {}
            Component::RootDir => out.push("/"),
            Component::CurDir => {}
            Component::ParentDir => out.push(".."),
            Component::Normal(name) => out.push(name),
        }
    }
    if out.as_os_str().is_empty() {
        out.push("/");
    }
    out
}

/// True when `child` is `parent` or lives underneath it.
///
/// Component-wise, so `/home/u2` is **not** considered inside `/home/u`
/// (a prefix test on the string would get this wrong).
pub fn is_within(parent: &Path, child: &Path) -> bool {
    if parent == child {
        return true;
    }
    let mut parent_components = parent.components();
    for child_component in child.components() {
        match parent_components.next() {
            Some(expected) if expected == child_component => {}
            Some(_) => return false,
            None => return true,
        }
    }
    // Child ran out first: it is an ancestor of parent, not the other way round.
    parent_components.next().is_none()
}

/// Number of components below `/`.
pub fn depth(path: &Path) -> usize {
    path.components()
        .filter(|component| matches!(component, Component::Normal(_)))
        .count()
}

/// The first named component of a relative path, ignoring the root marker.
///
/// `a/b/c` gives `a`, and `/a` gives `None`: an absolute path has no component
/// below a rule root, so it cannot name a top-level subtree of one. Used to
/// group a walk by its top-level entries for age decisions, and by
/// [`crate::selection`] to re-derive the same groups as the elevated child.
pub fn first_component(path: &Path) -> Option<PathBuf> {
    path.components()
        .next()
        .and_then(|component| match component {
            Component::Normal(name) => Some(PathBuf::from(name)),
            _ => None,
        })
}

/// Returns the ancestors of `path`, deepest first, excluding the path itself.
///
/// Used by the symlink-ancestor guard, which must inspect every parent and not
/// just the leaf.
pub fn ancestors(path: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    let mut current = path.parent();
    while let Some(parent) = current {
        result.push(parent.to_path_buf());
        current = parent.parent();
    }
    result
}

/// Appends a single component when the parent is a directory path.
pub fn join_component(base: &Path, name: &OsStr) -> PathBuf {
    let mut out = base.to_path_buf();
    out.push(name);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn parent_component_is_component_wise() {
        assert!(has_parent_component(Path::new("/a/../b")));
        assert!(has_parent_component(Path::new("../b")));
        // A file whose name merely contains dots is not a traversal.
        assert!(!has_parent_component(Path::new("/a/name..files")));
        assert!(!has_parent_component(Path::new("/a/..b")));
    }

    #[test]
    fn within_is_not_a_string_prefix() {
        assert!(is_within(Path::new("/home/u"), Path::new("/home/u/.cache")));
        assert!(is_within(Path::new("/home/u"), Path::new("/home/u")));
        assert!(!is_within(
            Path::new("/home/u"),
            Path::new("/home/u2/.cache")
        ));
        assert!(!is_within(Path::new("/home/u"), Path::new("/home")));
    }

    #[test]
    fn root_contains_everything() {
        assert!(is_within(Path::new("/"), Path::new("/home/u/.cache")));
    }

    #[test]
    fn normalize_keeps_trailing_meaning_but_drops_noise() {
        assert_eq!(normalize(Path::new("/a/./b//c")), PathBuf::from("/a/b/c"));
        assert_eq!(normalize(Path::new("/a/b/")), PathBuf::from("/a/b"));
        assert_eq!(normalize(Path::new("/")), PathBuf::from("/"));
    }

    #[test]
    fn control_bytes_are_detected_for_any_byte_below_space() {
        for byte in 0u8..0x20 {
            let value = OsString::from_vec(vec![b'a', byte, b'b']);
            assert!(has_control_bytes(&value), "byte {byte:#04x} not detected");
        }
        assert!(has_control_bytes(OsStr::from_bytes(&[0x7f])));
        assert!(!has_control_bytes(OsStr::new("normal-name.txt")));
    }

    #[test]
    fn ancestors_walk_to_the_root() {
        let list = ancestors(Path::new("/a/b/c"));
        assert_eq!(
            list,
            vec![
                PathBuf::from("/a/b"),
                PathBuf::from("/a"),
                PathBuf::from("/")
            ]
        );
    }

    #[test]
    fn depth_counts_only_normal_components() {
        assert_eq!(depth(Path::new("/")), 0);
        assert_eq!(depth(Path::new("/a")), 1);
        assert_eq!(depth(Path::new("/a/b/c")), 3);
    }
}
