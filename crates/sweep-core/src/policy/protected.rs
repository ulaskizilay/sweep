//! Protected paths: the static "never" list, plus the user's own identity.
//!
//! This table is deliberately a constant. It cannot be narrowed by
//! configuration: a rule that points at `/usr` fails at load time, and a
//! user whitelist only ever adds entries. The dynamic complements (read-only
//! mounts, snapshot directories, mount points) are decided in `validate`.

use std::path::Path;

use crate::paths::{is_within_named, is_within_normalized, normalize, Xdg};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedRoot {
    pub path: &'static str,
    pub why: &'static str,
}

/// Roots that sweep never deletes inside, on any command.
pub const PROTECTED_ROOTS: &[ProtectedRoot] = &[
    ProtectedRoot {
        path: "/usr",
        why: "owned by the package manager",
    },
    ProtectedRoot {
        path: "/bin",
        why: "owned by the package manager",
    },
    ProtectedRoot {
        path: "/sbin",
        why: "owned by the package manager",
    },
    ProtectedRoot {
        path: "/lib",
        why: "owned by the package manager",
    },
    ProtectedRoot {
        path: "/lib32",
        why: "owned by the package manager",
    },
    ProtectedRoot {
        path: "/lib64",
        why: "owned by the package manager",
    },
    ProtectedRoot {
        path: "/libx32",
        why: "owned by the package manager",
    },
    ProtectedRoot {
        path: "/opt",
        why: "installed software",
    },
    ProtectedRoot {
        path: "/etc",
        why: "system configuration",
    },
    ProtectedRoot {
        path: "/boot",
        why: "bootloader and kernels",
    },
    ProtectedRoot {
        path: "/efi",
        why: "EFI system partition",
    },
    ProtectedRoot {
        path: "/var/lib",
        why: "package, service and container state",
    },
    ProtectedRoot {
        path: "/var/log/journal",
        why: "journald owns rotation; use journalctl --vacuum",
    },
    ProtectedRoot {
        path: "/proc",
        why: "kernel pseudo-filesystem",
    },
    ProtectedRoot {
        path: "/sys",
        why: "kernel pseudo-filesystem",
    },
    ProtectedRoot {
        path: "/dev",
        why: "device nodes",
    },
    ProtectedRoot {
        path: "/run",
        why: "runtime state",
    },
    ProtectedRoot {
        path: "/snap",
        why: "snapd-managed tree",
    },
    ProtectedRoot {
        path: "/nix",
        why: "immutable store",
    },
    ProtectedRoot {
        path: "/gnu",
        why: "immutable store",
    },
    ProtectedRoot {
        path: "/lost+found",
        why: "filesystem recovery",
    },
    ProtectedRoot {
        path: "/timeshift",
        why: "snapshot storage",
    },
];

/// Returns the protected root that contains `path`, if any.
///
/// This runs on every candidate, against every entry in the table, so the test
/// is the byte comparison from [`is_within_normalized`]: the table is a
/// constant of normalized absolute paths.
pub fn match_root(path: &Path) -> Option<&'static ProtectedRoot> {
    match_root_normalized(&normalize(path))
}

/// [`match_root`] for a path that is already [`normalize`]d.
///
/// The validator normalizes the candidate once and asks both tables about that
/// same value, so normalizing again here was one allocation per candidate that
/// could not change the answer.
pub fn match_root_normalized(normalized: &Path) -> Option<&'static ProtectedRoot> {
    PROTECTED_ROOTS
        .iter()
        .find(|root| is_within_normalized(Path::new(root.path), normalized))
}

/// Paths whose contents are the user, not a cache.
///
/// These are protected inside the home directory, so a broad `~/.cache` or
/// `~/.local/share` sweep cannot reach credentials, keyrings or the operation
/// log itself.
pub const IDENTITY_DIRS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".password-store",
    ".local/share/keyrings",
    ".local/share/pacman",
    ".config/sweep",
    ".local/state/sweep",
];

/// Returns a reason string when `path` is the user's own data or tool state.
pub fn match_identity(path: &Path, xdg: &Xdg) -> Option<String> {
    match_identity_normalized(&normalize(path), xdg)
}

/// [`match_identity`] for a path that is already [`normalize`]d.
pub fn match_identity_normalized(normalized: &Path, xdg: &Xdg) -> Option<String> {
    // The base directories themselves are targets for their *children*, never
    // for deletion: removing `~/.cache` would take the whole tree with it.
    for (_, base) in xdg.bases() {
        if normalized == base {
            return Some(format!("base directory {}", base.display()));
        }
    }
    if normalized == xdg.home.as_path() {
        return Some("home directory".to_string());
    }

    // The suffix test does not build `home.join(suffix)`: this runs once per
    // candidate, and eight joined paths per item was a measurable share of a
    // million-file plan. `is_within_named` is the same test without the
    // allocation.
    for suffix in IDENTITY_DIRS {
        if is_within_named(&xdg.home, normalized, suffix) {
            return Some(format!("identity path ~/{suffix}"));
        }
    }

    // The tool's own runtime directory.
    if is_within_named(&xdg.runtime, normalized, "sweep") {
        return Some("sweep runtime directory".to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn xdg() -> Xdg {
        Xdg::resolve(|key| match key {
            "HOME" => Some("/home/u".into()),
            _ => None,
        })
        .expect("home")
    }

    #[test]
    fn package_owned_roots_are_protected() {
        for path in [
            "/usr/bin/sweep",
            "/usr/lib/firmware",
            "/etc/pacman.conf",
            "/var/lib/pacman/local",
            "/boot/vmlinuz-linux",
            "/opt/app/bin",
        ] {
            assert!(
                match_root(Path::new(path)).is_some(),
                "{path} should be protected"
            );
        }
    }

    #[test]
    fn cache_and_home_targets_are_not_protected_roots() {
        for path in ["/var/cache/pacman", "/var/tmp/x", "/home/u/.cache/x"] {
            assert!(match_root(Path::new(path)).is_none(), "{path}");
        }
    }

    #[test]
    fn prefix_lookalikes_do_not_match() {
        assert!(match_root(Path::new("/usrlocal/bin")).is_none());
        assert!(match_root(Path::new("/etcetera")).is_none());
        assert!(match_root(Path::new("/varlib/x")).is_none());
    }

    #[test]
    fn identity_dirs_are_protected_inside_home() {
        let xdg = xdg();
        assert!(match_identity(Path::new("/home/u/.ssh/id_ed25519"), &xdg).is_some());
        assert!(match_identity(Path::new("/home/u/.local/share/keyrings/a"), &xdg).is_some());
        assert!(match_identity(
            Path::new("/home/u/.local/state/sweep/operations.jsonl"),
            &xdg
        )
        .is_some());
    }

    #[test]
    fn base_directories_are_protected_but_their_children_are_not() {
        let xdg = xdg();
        assert!(match_identity(Path::new("/home/u"), &xdg).is_some());
        assert!(match_identity(Path::new("/home/u/.cache"), &xdg).is_some());
        assert!(match_identity(Path::new("/home/u/.cache/thumbnails"), &xdg).is_none());
    }

    #[test]
    fn identity_lookalikes_do_not_match() {
        let xdg = xdg();
        assert!(match_identity(Path::new("/home/u/.sshfoo/key"), &xdg).is_none());
        assert!(match_identity(Path::new("/home/u2/.ssh/key"), &xdg).is_none());
    }

    /// The normalized entry points are the same decision as the public ones.
    ///
    /// They exist only so the validator can normalize once per candidate
    /// instead of three times, so a drift between the pair would be a silent
    /// change of what is protected.
    #[test]
    fn the_normalized_entry_points_agree_with_the_public_ones() {
        let xdg = xdg();
        for path in [
            "/usr/bin/sweep",
            "/usrlocal/bin",
            "/etc/pacman.conf",
            "/etcetera",
            "/var/lib/pacman/local",
            "/varlib/x",
            "/home/u/.ssh/id_ed25519",
            "/home/u/.sshfoo/key",
            "/home/u/.cache/x",
            "/home/u",
            "/var/cache/pacman",
            "/home/u/.local/state/sweep/operations.jsonl",
        ] {
            let path = Path::new(path);
            let normalized = normalize(path);
            assert_eq!(
                match_root(path).map(|root| root.path),
                match_root_normalized(&normalized).map(|root| root.path),
                "{path:?}"
            );
            assert_eq!(
                match_identity(path, &xdg),
                match_identity_normalized(&normalized, &xdg),
                "{path:?}"
            );
        }
    }

    #[test]
    fn protected_root_join_is_stable() {
        // Guard against a future entry that is not absolute.
        for root in PROTECTED_ROOTS {
            assert!(
                PathBuf::from(root.path).is_absolute(),
                "{} must be absolute",
                root.path
            );
            assert!(!root.why.is_empty());
        }
    }
}
