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

/// True when `child` is `parent` or lives underneath it, for two paths that are
/// already [`normalize`]d.
///
/// The answer is the one [`is_within`] gives, decided by a byte prefix plus a
/// separator boundary instead of a component walk. It exists because this
/// question is asked a few hundred times per candidate - once per mount in the
/// table, once per protected root, once per identity directory - and a cache
/// with a million files makes the difference between 140ns and 5ns visible:
/// it was two thirds of the time `sweep clean` spent deciding.
///
/// `parent` and `child` must be absolute, without `.` or `..` components and
/// without a trailing separator; [`normalize`] produces exactly that. Use
/// [`is_within`] for anything else.
pub fn is_within_normalized(parent: &Path, child: &Path) -> bool {
    let parent = without_trailing_separator(parent.as_os_str().as_bytes());
    let child = child.as_os_str().as_bytes();
    if !child.starts_with(parent) {
        return false;
    }
    if child.len() == parent.len() {
        return true;
    }
    // A prefix that stops in the middle of a name is not a directory boundary:
    // `/home/u` does not cover `/home/u2`.
    parent.is_empty() || parent == b"/" || child[parent.len()] == b'/'
}

/// True when `child` is `base/name` or lives underneath it.
///
/// `base` must be absolute and [`normalize`]d; `name` is one component or a
/// `a/b` suffix with no leading or trailing separator. Equivalent to
/// `is_within(&base.join(name), child)` without building the joined path, which
/// is what makes it usable once per candidate in [`crate::policy`].
pub fn is_within_named(base: &Path, child: &Path, name: &str) -> bool {
    let base = without_trailing_separator(base.as_os_str().as_bytes());
    let child = child.as_os_str().as_bytes();
    let name = name.as_bytes();
    if base.is_empty() {
        // `Path::new("").join("a")` is relative, so it covers no absolute path.
        return false;
    }
    let offset = if base == b"/" {
        if !child.starts_with(b"/") {
            return false;
        }
        1
    } else {
        if !child.starts_with(base) {
            return false;
        }
        match child.get(base.len()) {
            Some(b'/') => base.len() + 1,
            _ => return false,
        }
    };
    let rest = &child[offset..];
    rest.starts_with(name) && (rest.len() == name.len() || rest[name.len()] == b'/')
}

/// Drops one trailing separator, keeping the root marker itself intact.
fn without_trailing_separator(bytes: &[u8]) -> &[u8] {
    match bytes.split_last() {
        Some((b'/', rest)) if !rest.is_empty() => rest,
        _ => bytes,
    }
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

    /// Every normalized absolute path of up to three components drawn from a
    /// set that contains the pairs a byte prefix gets wrong: `a` / `ab`,
    /// `a` / `a.b`, `a` / `a-b`, and a name with a multi-byte character.
    fn normalized_corpus() -> Vec<PathBuf> {
        let names = ["a", "ab", "a.b", "a-b", "b", "@snapshots", "é"];
        let mut out = vec![PathBuf::from("/")];
        for first in names {
            out.push(PathBuf::from(format!("/{first}")));
            for second in names {
                out.push(PathBuf::from(format!("/{first}/{second}")));
                for third in names {
                    out.push(PathBuf::from(format!("/{first}/{second}/{third}")));
                }
            }
        }
        out
    }

    #[test]
    fn the_byte_prefix_test_agrees_with_the_component_walk() {
        let corpus = normalized_corpus();
        for parent in &corpus {
            for child in &corpus {
                assert_eq!(
                    is_within(parent, child),
                    is_within_normalized(parent, child),
                    "{} vs {}",
                    parent.display(),
                    child.display()
                );
            }
        }
    }

    #[test]
    fn the_named_child_test_agrees_with_a_joined_path() {
        let corpus = normalized_corpus();
        for base in &corpus {
            for name in ["a", "a.b", "ab", "@snapshots", "a/b"] {
                let joined = base.join(name);
                for child in &corpus {
                    assert_eq!(
                        is_within(&joined, child),
                        is_within_named(base, child, name),
                        "{} joined with {} vs {}",
                        base.display(),
                        name,
                        child.display()
                    );
                }
            }
        }
    }
}
