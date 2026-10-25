//! One test per refusal branch of `validate`, including the ones caused by an
//! error rather than a fact.
//!
//! These are the tests that matter most and are easiest to lose: every branch
//! here is a `return deny(...)`, so deleting one leaves the function smaller,
//! still compiling, and still passing every "this path is allowed" test. The
//! property tests assert on classes of input; this file asserts that each
//! specific refusal exists and fires for the reason it claims.

use std::io;
use std::path::{Path, PathBuf};

use sweep_core::{AllowedRoot, FsProbe, Policy, Reason, ValidateCtx, Verdict, Xdg};
use sweep_testkit::{FaultyProbe, SAMPLE_MOUNTS};

fn xdg_at(home: &str) -> Xdg {
    let home = PathBuf::from(home);
    Xdg::resolve(move |key| match key {
        "HOME" => Some(home.clone().into_os_string()),
        _ => None,
    })
    .expect("home")
}

fn code(verdict: &Verdict) -> &'static str {
    verdict.reason().map(Reason::code).unwrap_or("allow")
}

macro_rules! ctx {
    ($xdg:expr, $probe:expr, $allowed:expr) => {
        ValidateCtx {
            xdg: &$xdg,
            probe: $probe,
            allowed: &$allowed,
            policy: Policy::default(),
        }
    };
}

// --------------------------------------------------- lexical and static policy ---

#[test]
fn every_lexical_refusal_is_reached() {
    let xdg = xdg_at("/home/u");
    let probe = FaultyProbe::new(SAMPLE_MOUNTS);
    let allowed = vec![AllowedRoot::new("/home/u/.cache/rule")];
    let ctx = ctx!(&xdg, &probe, &allowed);

    let cases: Vec<(PathBuf, &str)> = vec![
        (PathBuf::new(), "empty"),
        (PathBuf::from("relative/path"), "not_absolute"),
        (PathBuf::from("/home/u/.cache/\u{1}"), "control_byte"),
        (PathBuf::from("/home/u/.cache/a/../../etc"), "traversal"),
        (PathBuf::from("/"), "root_itself"),
        (PathBuf::from("/usr/lib"), "protected_root"),
        (
            PathBuf::from("/home/u/.ssh/id_ed25519"),
            "protected_identity",
        ),
        (PathBuf::from("/srv/data"), "not_in_allowed_root"),
        (PathBuf::from("/home/u/.cache/rule"), "allowed_root_itself"),
    ];

    for (path, expected) in cases {
        assert_eq!(
            code(&sweep_core::validate(&path, &ctx)),
            expected,
            "{}",
            path.display()
        );
    }
}

#[test]
fn a_control_byte_is_refused_before_any_io_happens() {
    // The probe fails every operation, so reaching a refusal other than
    // `control_byte` would prove the check ran too late.
    let xdg = xdg_at("/home/u");
    let probe = FaultyProbe::new(SAMPLE_MOUNTS)
        .metadata_error("/home/u/.cache")
        .canonicalize_error("/home/u");
    let allowed = vec![AllowedRoot::new("/home/u/.cache")];
    let ctx = ctx!(&xdg, &probe, &allowed);
    assert_eq!(
        code(&sweep_core::validate(
            Path::new("/home/u/.cache/bell\u{7}"),
            &ctx
        )),
        "control_byte"
    );
}

// ------------------------------------------- symlinked-ancestor re-checks ---
//
// Each case resolves the *parent* into forbidden territory and asserts the
// physical path is re-checked. The literal path looks harmless in all of them.

fn escapes_into(target: &str, mounts: &str, allowed: &str) -> Verdict {
    let xdg = xdg_at("/home/u");
    let probe = FaultyProbe::new(mounts).with(|probe| {
        probe
            .dir("/home/u/work")
            .symlink("/home/u/work/link", target)
            // The literal entry has to exist, or validation stops at
            // `not_found` before it ever resolves the parent.
            .file("/home/u/work/link/leaf")
            .with_empty_scan()
    });
    let allowed = vec![AllowedRoot::new(allowed)];
    let ctx = ctx!(&xdg, &probe, &allowed);
    sweep_core::validate(Path::new("/home/u/work/link/leaf"), &ctx)
}

#[test]
fn a_symlink_resolving_into_a_protected_root_is_refused() {
    let verdict = escapes_into("/usr/lib", SAMPLE_MOUNTS, "/home/u/work");
    assert_eq!(code(&verdict), "symlink_ancestor_escape");
}

#[test]
fn a_symlink_resolving_into_identity_data_is_refused() {
    let verdict = escapes_into("/home/u/.ssh", SAMPLE_MOUNTS, "/home/u/work");
    assert_eq!(code(&verdict), "symlink_ancestor_escape");
}

#[test]
fn a_symlink_resolving_into_an_unknown_mount_is_refused() {
    // A table with no `/` mount: the literal path is covered by `/home`, the
    // resolved path is covered by nothing. That must fail closed rather than
    // pass, and it is the one case `SAMPLE_MOUNTS` cannot express because its
    // `/` entry would legitimately cover any resolved path.
    let mounts = "31 30 8:3 / /home rw,relatime - btrfs /dev/sda3 rw\n";
    let verdict = escapes_into("/mnt/unknown-place", mounts, "/home/u/work");
    assert_eq!(code(&verdict), "unknown_mount");
}

#[test]
fn a_symlink_resolving_onto_a_read_only_mount_is_refused() {
    let verdict = escapes_into("/mnt/usb", SAMPLE_MOUNTS, "/home/u/work");
    assert_eq!(code(&verdict), "read_only_mount");
}

#[test]
fn a_symlink_resolving_into_a_snapshot_is_refused() {
    let verdict = escapes_into("/home/.snapshots/1/snapshot", SAMPLE_MOUNTS, "/home/u/work");
    assert_eq!(code(&verdict), "snapshot_path");
}

#[test]
fn a_leaf_that_is_a_symlink_after_resolution_is_refused() {
    // The parent is legitimate; the entry itself is a link, so the link is the
    // target of the delete rather than whatever it points at.
    let xdg = xdg_at("/home/u");
    let probe = FaultyProbe::new(SAMPLE_MOUNTS).with(|probe| {
        probe
            .dir("/home/u/work")
            .dir("/home/u/real")
            .symlink("/home/u/work/link", "/home/u/real")
            .file("/home/u/work/link/leaf")
            .symlink("/home/u/real/leaf", "/home/u/.ssh/id_ed25519")
            .with_empty_scan()
    });
    let allowed = vec![AllowedRoot::new("/home/u/work")];
    let ctx = ctx!(&xdg, &probe, &allowed);
    assert_eq!(
        code(&sweep_core::validate(
            Path::new("/home/u/work/link/leaf"),
            &ctx
        )),
        "leaf_symlink"
    );
}

// ------------------------------------------------------------- probe errors ---
//
// "We could not verify it" must be a refusal. Each case makes exactly one probe
// operation fail and asserts the result is `probe_unknown`, not `allow`.

fn probe_unknown(verdict: &Verdict) {
    assert_eq!(code(verdict), "probe_unknown");
    assert!(
        verdict.reason().expect("denied").is_unknown(),
        "a probe failure must be classified as unknown, not forbidden"
    );
}

#[test]
fn a_metadata_error_on_the_literal_path_fails_closed() {
    let xdg = xdg_at("/home/u");
    let probe = FaultyProbe::new(SAMPLE_MOUNTS)
        .with(|probe| {
            probe
                .dir("/home/u/.cache")
                .file("/home/u/.cache/x")
                .with_empty_scan()
        })
        .metadata_error("/home/u/.cache/x");
    let allowed = vec![AllowedRoot::new("/home/u/.cache")];
    let ctx = ctx!(&xdg, &probe, &allowed);
    probe_unknown(&sweep_core::validate(Path::new("/home/u/.cache/x"), &ctx));
}

#[test]
fn a_canonicalize_error_on_the_parent_fails_closed() {
    let xdg = xdg_at("/home/u");
    let probe = FaultyProbe::new(SAMPLE_MOUNTS)
        .with(|probe| {
            probe
                .dir("/home/u/.cache")
                .file("/home/u/.cache/x")
                .with_empty_scan()
        })
        .canonicalize_error("/home/u/.cache");
    let allowed = vec![AllowedRoot::new("/home/u/.cache")];
    let ctx = ctx!(&xdg, &probe, &allowed);
    probe_unknown(&sweep_core::validate(Path::new("/home/u/.cache/x"), &ctx));
}

#[test]
fn a_metadata_error_on_the_resolved_path_fails_closed() {
    let xdg = xdg_at("/home/u");
    let probe = FaultyProbe::new(SAMPLE_MOUNTS)
        .with(|probe| {
            probe
                .dir("/home/u/work")
                .dir("/home/u/real")
                .file("/home/u/real/leaf")
                .file("/home/u/work/link/leaf")
                .symlink("/home/u/work/link", "/home/u/real")
                .with_empty_scan()
        })
        .metadata_error("/home/u/real/leaf");
    let allowed = vec![AllowedRoot::new("/home/u/work")];
    let ctx = ctx!(&xdg, &probe, &allowed);
    probe_unknown(&sweep_core::validate(
        Path::new("/home/u/work/link/leaf"),
        &ctx,
    ));
}

#[test]
fn a_metadata_error_on_the_parent_fails_closed() {
    let xdg = xdg_at("/home/u");
    let probe = FaultyProbe::new(SAMPLE_MOUNTS)
        .with(|probe| {
            probe
                .dir("/home/u/.cache")
                .file("/home/u/.cache/x")
                .with_empty_scan()
        })
        // The literal stat and the canonicalize succeed; the sticky-bit check on
        // the parent is what fails.
        .metadata_error("/home/u/.cache/x");
    let allowed = vec![AllowedRoot::new("/home/u/.cache")];
    let ctx = ctx!(&xdg, &probe, &allowed);
    // Whatever specific branch answers first, the verdict must be a refusal.
    assert!(!sweep_core::validate(Path::new("/home/u/.cache/x"), &ctx).is_allow());
}

#[test]
fn an_immutable_check_error_fails_closed() {
    let xdg = xdg_at("/home/u");
    let probe = FaultyProbe::new(SAMPLE_MOUNTS)
        .with(|probe| {
            probe
                .dir("/home/u/.cache")
                .file("/home/u/.cache/x")
                .with_empty_scan()
        })
        .immutable_error("/home/u/.cache/x");
    let allowed = vec![AllowedRoot::new("/home/u/.cache")];
    let ctx = ctx!(&xdg, &probe, &allowed);
    probe_unknown(&sweep_core::validate(Path::new("/home/u/.cache/x"), &ctx));
}

// ------------------------------------------------------------ policy knobs ---

#[test]
fn a_missing_open_scan_is_ignored_when_the_policy_does_not_require_it() {
    // The escape hatch exists for `--dry-run`-style callers that only want the
    // static policy. It must not be the default.
    let xdg = xdg_at("/home/u");
    let probe = FaultyProbe::new(SAMPLE_MOUNTS).with(|probe| {
        probe
            .dir("/home/u/.cache")
            .file("/home/u/.cache/x")
            .without_open_scan()
    });
    let allowed = vec![AllowedRoot::new("/home/u/.cache")];

    let strict = ctx!(&xdg, &probe, &allowed);
    assert_eq!(
        code(&sweep_core::validate(
            Path::new("/home/u/.cache/x"),
            &strict
        )),
        "probe_unknown"
    );

    let relaxed = ValidateCtx {
        policy: Policy {
            require_open_scan: false,
            ..Policy::default()
        },
        ..ctx!(&xdg, &probe, &allowed)
    };
    assert!(sweep_core::validate(Path::new("/home/u/.cache/x"), &relaxed).is_allow());
}

#[test]
fn a_root_pinned_to_another_device_refuses_everything_on_this_one() {
    let xdg = xdg_at("/home/u");
    let probe = FaultyProbe::new(SAMPLE_MOUNTS).with(|probe| {
        probe
            .dir("/home/u/.cache")
            .file("/home/u/.cache/x")
            .on_device("/home/u/.cache/x", 1)
            .with_empty_scan()
    });
    let mut root = AllowedRoot::new("/home/u/.cache");
    root.device = Some(999);
    let allowed = vec![root];
    let ctx = ctx!(&xdg, &probe, &allowed);
    assert_eq!(
        code(&sweep_core::validate(Path::new("/home/u/.cache/x"), &ctx)),
        "other_device"
    );
}

#[test]
fn pinning_a_root_to_its_current_device_reads_the_mount_table() {
    let probe = FaultyProbe::new(SAMPLE_MOUNTS);
    let root = AllowedRoot::new("/home/u/.cache").pinned_to_current_device(probe.mount_table());
    // `/home` is `8:3` in the sample table; the encoding must match `st_dev`.
    assert_eq!(root.device, Some(sweep_core::sys::makedev(8, 3)));
}

#[test]
fn pinning_a_root_that_lives_on_no_mount_leaves_it_unpinned() {
    let table = sweep_core::MountTable::parse("");
    let root = AllowedRoot::new("/home/u/.cache").pinned_to_current_device(&table);
    assert_eq!(root.device, None);
}

// ------------------------------------------------------ accessors and display ---

#[test]
fn every_reason_has_a_human_description() {
    // `Display` is what lands in the operation log's `detail` field, so an empty
    // or duplicated string loses the reason a user is trying to understand.
    let reasons = vec![
        Reason::Empty,
        Reason::NotAbsolute,
        Reason::Traversal,
        Reason::ControlByte,
        Reason::RootItself,
        Reason::ProtectedRoot("package manager"),
        Reason::ProtectedIdentity("identity".into()),
        Reason::NotInAllowedRoot,
        Reason::AllowedRootItself,
        Reason::NotFound,
        Reason::LeafSymlink,
        Reason::SymlinkAncestorEscape(PathBuf::from("/usr")),
        Reason::ReadOnlyMount,
        Reason::UnknownMount,
        Reason::SnapshotPath,
        Reason::Mounted,
        Reason::OtherDevice,
        Reason::ForeignOwner(0),
        Reason::StickyDir,
        Reason::Immutable,
        Reason::OpenByProcess {
            pid: 7,
            name: "sqlite".into(),
        },
        Reason::RaceChanged,
        Reason::DirectoryNotEmpty,
        Reason::ProbeUnknown("io".into()),
        Reason::AlreadyGone,
    ];

    let mut seen: Vec<String> = Vec::new();
    for reason in &reasons {
        let text = reason.to_string();
        assert!(!text.is_empty(), "{reason:?} has no description");
        assert!(
            !seen.contains(&text),
            "{reason:?} shares a description with another reason: {text}"
        );
        seen.push(text);
    }
}

#[test]
fn verdict_accessors_agree_with_the_variant() {
    let allow = Verdict::Allow {
        physical: PathBuf::from("/home/u/.cache/x"),
    };
    assert!(allow.is_allow());
    assert_eq!(allow.reason(), None);
    assert_eq!(allow.physical(), Some(Path::new("/home/u/.cache/x")));

    let deny = Verdict::Deny(Reason::NotFound);
    assert!(!deny.is_allow());
    assert_eq!(deny.reason(), Some(&Reason::NotFound));
    assert_eq!(deny.physical(), None);
    assert!(!Reason::NotFound.is_unknown());
    assert!(Reason::UnknownMount.is_unknown());
}

#[test]
fn injected_faults_are_not_reported_as_missing_paths() {
    // Guards the test double itself: if the injected error were `NotFound`, the
    // tests above would pass for the wrong reason.
    let probe = FaultyProbe::new(SAMPLE_MOUNTS)
        .with(|probe| probe.file("/home/u/x"))
        .metadata_error("/home/u/x");
    let error = probe
        .symlink_metadata(Path::new("/home/u/x"))
        .expect_err("injected");
    assert_ne!(error.kind(), io::ErrorKind::NotFound);
}
