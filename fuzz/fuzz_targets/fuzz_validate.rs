//! Fuzz target: `validate` on arbitrary path bytes.
//!
//! The property under test is not "a bad path is refused in a specific way" but
//! the weaker, more important one:
//!
//! 1. no input panics, including invalid UTF-8, embedded NULs and 4 KiB of
//!    random bytes;
//! 2. whatever comes back is either an `Allow` that really is inside a declared
//!    rule root, or a `Deny` whose reason is one of the documented codes.
//!
//! Point 2 is where a future refactor could go wrong: adding an early `return`
//! that skips a check would still compile and would still return a `Deny`, so
//! the assertion is on the *reason*, not just the discriminant.

#![no_main]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use libfuzzer_sys::fuzz_target;
use sweep_core::paths::is_within;
use sweep_core::{AllowedRoot, Policy, Reason, ValidateCtx, Verdict, Xdg};
use sweep_testkit::{PermissiveProbe, SAMPLE_MOUNTS};

const REASON_CODES: &[&str] = &[
    "empty",
    "not_absolute",
    "traversal",
    "control_byte",
    "root_itself",
    "protected_root",
    "protected_identity",
    "not_in_allowed_root",
    "allowed_root_itself",
    "not_found",
    "leaf_symlink",
    "symlink_ancestor_escape",
    "read_only_mount",
    "unknown_mount",
    "snapshot_path",
    "mounted",
    "other_device",
    "foreign_owner",
    "sticky_dir",
    "immutable",
    "open_by_process",
    "race_changed",
    "directory_not_empty",
    "probe_unknown",
    "already_gone",
];

fuzz_target!(|data: &[u8]| {
    let path = PathBuf::from(OsStr::from_bytes(data));

    let xdg = Xdg::resolve(|key| match key {
        "HOME" => Some("/home/u".into()),
        _ => None,
    })
    .expect("home");

    // A probe that claims every path exists and is owned by us, so the fuzzer
    // reaches the deep checks instead of stopping at "not found".
    let probe = PermissiveProbe::new(SAMPLE_MOUNTS);

    let allowed = vec![
        AllowedRoot::new("/home/u/.cache"),
        AllowedRoot::new("/tmp"),
        AllowedRoot::new("/var/cache/pacman"),
    ];
    let ctx = ValidateCtx {
        xdg: &xdg,
        probe: &probe,
        allowed: &allowed,
        policy: Policy::default(),
    };

    match sweep_core::validate(&path, &ctx) {
        Verdict::Allow { physical } => {
            assert!(
                allowed.iter().any(|root| is_within(&root.path, &physical)),
                "allowed a path outside every rule root: {}",
                physical.display()
            );
            assert!(
                !matches!(physical, p if p == Path::new("/")),
                "allowed the filesystem root"
            );
        }
        Verdict::Deny(reason) => {
            let code = reason.code();
            assert!(
                REASON_CODES.contains(&code),
                "undocumented refusal reason: {code}"
            );
            assert_eq!(
                Reason::Empty.code(),
                "empty",
                "reason code table drifted from the enum"
            );
        }
    }
});
