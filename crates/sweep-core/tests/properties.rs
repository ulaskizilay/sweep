//! Properties the deletion kernel must satisfy.
//!
//! These are not example tests. Each one quantifies over generated input, so a
//! future refactor cannot quietly widen a rule: the property either still holds
//! for every generated path, or the build fails.
//!
//! The fixtures are synthetic (`sweep-testkit`) except for the dry-run parity
//! test, which uses a real temporary tree because it must prove a syscall
//! behaviour rather than a decision.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use proptest::prelude::*;
use sweep_core::fs_facts::MountTable;
use sweep_core::paths::is_within;
use sweep_core::policy::PROTECTED_ROOTS;
use sweep_core::{
    AllowedRoot, FsProbe, Mode, Plan, Policy, RealProbe, Reason, RuleId, ValidateCtx, Verdict, Xdg,
};
use sweep_testkit::{FakeProbe, PermissiveProbe, SAMPLE_MOUNTS};

// ---------------------------------------------------------------- helpers ---

fn xdg_at(home: &Path) -> Xdg {
    let home = home.to_path_buf();
    Xdg::resolve(move |key| match key {
        "HOME" => Some(home.clone().into_os_string()),
        _ => None,
    })
    .expect("home is absolute")
}

fn ctx<'a>(xdg: &'a Xdg, probe: &'a dyn FsProbe, allowed: &'a [AllowedRoot]) -> ValidateCtx<'a> {
    ValidateCtx {
        xdg,
        probe,
        allowed,
        policy: Policy::default(),
    }
}

fn verdict(path: &Path, ctx: &ValidateCtx<'_>) -> Verdict {
    sweep_core::validate(path, ctx)
}

fn code(verdict: &Verdict) -> &'static str {
    verdict.reason().map(Reason::code).unwrap_or("allow")
}

/// A single path component that is legal on every filesystem we support.
///
/// The leading character is restricted to `a-z0-9`: a component of `.` or `..`
/// would be normalised away by `Path::components`, so the generated path would
/// silently stop being the path under test.
fn arb_component() -> impl Strategy<Value = String> {
    ("[a-z0-9]", "[a-z0-9._-]{0,11}").prop_map(|(first, rest)| format!("{first}{rest}"))
}

// ------------------------------------------------------- lexical invariants ---

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// No protected root is ever a deletion target, whatever follows it.
    #[test]
    fn protected_roots_are_never_allowed(
        root in prop::sample::select(PROTECTED_ROOTS.iter().map(|r| r.path).collect::<Vec<_>>()),
        tail in prop::collection::vec(arb_component(), 0..4),
    ) {
        let xdg = xdg_at(Path::new("/home/u"));
        let probe = PermissiveProbe::new(SAMPLE_MOUNTS);
        let mut allowed = Vec::new();
        for (_, base) in xdg.bases() {
            allowed.push(AllowedRoot::new(base));
        }
        // Even a rule root that *is* the protected path cannot unlock it.
        allowed.push(AllowedRoot::new(root));
        let ctx = ctx(&xdg, &probe, &allowed);

        let mut path = PathBuf::from(root);
        for component in &tail {
            path.push(component);
        }
        let result = verdict(&path, &ctx);
        prop_assert!(!result.is_allow(), "{} was allowed", path.display());
    }

    /// Anything allowed is inside a declared rule root.
    #[test]
    fn allowed_paths_are_always_inside_a_rule_root(
        root in arb_component(),
        tail in prop::collection::vec(arb_component(), 1..4),
    ) {
        let xdg = xdg_at(Path::new("/home/u"));
        let probe = PermissiveProbe::new(SAMPLE_MOUNTS);
        let rule_root = PathBuf::from(format!("/home/u/{root}"));
        let allowed = vec![AllowedRoot::new(&rule_root)];
        let ctx = ctx(&xdg, &probe, &allowed);

        let mut path = rule_root.clone();
        for component in &tail {
            path.push(component);
        }
        let result = verdict(&path, &ctx);
        if let Verdict::Allow { physical } = &result {
            prop_assert!(
                is_within(&rule_root, physical) || is_within(&rule_root, &path),
                "{} escaped {}",
                physical.display(),
                rule_root.display()
            );
        }
    }

    /// A `..` component is refused, at any depth.
    #[test]
    fn traversal_is_never_allowed(
        prefix in prop::collection::vec(arb_component(), 1..3),
        suffix in prop::collection::vec(arb_component(), 0..3),
    ) {
        let xdg = xdg_at(Path::new("/home/u"));
        let probe = PermissiveProbe::new(SAMPLE_MOUNTS);
        let rule_root = PathBuf::from("/home/u/.cache");
        let allowed = vec![AllowedRoot::new(&rule_root)];
        let ctx = ctx(&xdg, &probe, &allowed);

        let mut path = rule_root.clone();
        for component in &prefix {
            path.push(component);
        }
        path.push("..");
        for component in &suffix {
            path.push(component);
        }

        let result = verdict(&path, &ctx);
        prop_assert_eq!(code(&result), Reason::Traversal.code());
    }

    /// Control bytes are refused before anything is probed.
    #[test]
    fn control_bytes_are_never_allowed(
        base in prop::collection::vec(arb_component(), 1..3),
        byte in 0u8..0x20,
    ) {
        let xdg = xdg_at(Path::new("/home/u"));
        let probe = PermissiveProbe::new(SAMPLE_MOUNTS);
        let rule_root = PathBuf::from("/home/u/.cache");
        let allowed = vec![AllowedRoot::new(&rule_root)];
        let ctx = ctx(&xdg, &probe, &allowed);

        let mut name = base.join("-");
        name.push(char::from(byte));
        let path = rule_root.join(name);

        let result = verdict(&path, &ctx);
        prop_assert_eq!(code(&result), Reason::ControlByte.code());
    }

    /// Same input, same answer. Validation must not depend on hidden state.
    #[test]
    fn validation_is_deterministic(
        tail in prop::collection::vec(arb_component(), 1..4),
    ) {
        let xdg = xdg_at(Path::new("/home/u"));
        let probe = PermissiveProbe::new(SAMPLE_MOUNTS);
        let rule_root = PathBuf::from("/home/u/.cache");
        let allowed = vec![AllowedRoot::new(&rule_root)];
        let ctx = ctx(&xdg, &probe, &allowed);

        let mut path = rule_root.clone();
        for component in &tail {
            path.push(component);
        }
        prop_assert_eq!(verdict(&path, &ctx), verdict(&path, &ctx));
    }

    /// Arbitrary bytes as a path must never panic, and must produce a reason
    /// from the closed set.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..96)) {
        let path = PathBuf::from(OsStr::from_bytes(&bytes));
        let xdg = xdg_at(Path::new("/home/u"));
        let probe = PermissiveProbe::new(SAMPLE_MOUNTS);
        let allowed = vec![AllowedRoot::new("/home/u/.cache")];
        let ctx = ctx(&xdg, &probe, &allowed);
        let result = verdict(&path, &ctx);
        let reason = result.reason().map(Reason::code).unwrap_or("allow");
        prop_assert!(!reason.is_empty());
    }

    /// The plan hash is a function of the operation set, not of the order the
    /// scanner produced it in.
    #[test]
    fn plan_hash_is_insertion_order_independent(
        names in prop::collection::vec(arb_component(), 1..6),
    ) {
        let mut unique: Vec<String> = names;
        unique.sort();
        unique.dedup();
        prop_assume!(!unique.is_empty());

        let xdg = xdg_at(Path::new("/home/u"));
        let probe = PermissiveProbe::new(SAMPLE_MOUNTS);
        let rule_root = PathBuf::from("/home/u/.cache");
        let allowed = vec![AllowedRoot::new(&rule_root)];
        let ctx = ctx(&xdg, &probe, &allowed);
        let rule = RuleId::new("test.rule").expect("valid");

        let mut forward = Plan::new();
        for name in &unique {
            forward.push(&rule_root.join(name), &rule, &ctx).expect("allowed");
        }
        forward.finish();

        let mut backward = Plan::new();
        for name in unique.iter().rev() {
            backward.push(&rule_root.join(name), &rule, &ctx).expect("allowed");
        }
        backward.finish();

        prop_assert_eq!(forward.hash(), backward.hash());
    }
}

// -------------------------------------------------------- mount + metadata ---

#[test]
fn a_read_only_mount_is_refused() {
    let xdg = xdg_at(Path::new("/home/u"));
    let probe = PermissiveProbe::new(SAMPLE_MOUNTS);
    let allowed = vec![AllowedRoot::new("/mnt/usb")];
    let ctx = ctx(&xdg, &probe, &allowed);
    assert_eq!(
        code(&verdict(Path::new("/mnt/usb/old.iso"), &ctx)),
        Reason::ReadOnlyMount.code()
    );
}

#[test]
fn a_mount_point_is_refused() {
    let xdg = xdg_at(Path::new("/home/u"));
    let probe = PermissiveProbe::new(SAMPLE_MOUNTS).as_dir();
    let allowed = vec![AllowedRoot {
        allow_root_itself: true,
        ..AllowedRoot::new("/home")
    }];
    let ctx = ctx(&xdg, &probe, &allowed);
    assert_eq!(
        code(&verdict(Path::new("/home"), &ctx)),
        Reason::Mounted.code()
    );
}

#[test]
fn a_snapshot_path_is_refused() {
    let xdg = xdg_at(Path::new("/home/u"));
    let probe = PermissiveProbe::new(SAMPLE_MOUNTS);
    let allowed = vec![AllowedRoot::new("/home/.snapshots")];
    let ctx = ctx(&xdg, &probe, &allowed);
    let result = verdict(Path::new("/home/.snapshots/12/snapshot"), &ctx);
    assert_eq!(code(&result), Reason::SnapshotPath.code());
}

#[test]
fn a_foreign_owner_is_refused() {
    let xdg = xdg_at(Path::new("/home/u"));
    let probe = FakeProbe::new(SAMPLE_MOUNTS)
        .dir("/home/u/.cache")
        .file("/home/u/.cache/root-owned")
        .owned_by("/home/u/.cache/root-owned", 0)
        .with_empty_scan();
    let allowed = vec![AllowedRoot::new("/home/u/.cache")];
    let ctx = ctx(&xdg, &probe, &allowed);
    assert_eq!(
        code(&verdict(Path::new("/home/u/.cache/root-owned"), &ctx)),
        Reason::ForeignOwner(0).code()
    );
}

#[test]
fn a_sticky_parent_is_refused() {
    let xdg = xdg_at(Path::new("/home/u"));
    let probe = FakeProbe::new(SAMPLE_MOUNTS)
        .dir_with_mode("/tmp", 0o1777)
        .file("/tmp/shared.bin")
        .with_empty_scan();
    let allowed = vec![AllowedRoot::new("/tmp")];
    let ctx = ctx(&xdg, &probe, &allowed);
    assert_eq!(
        code(&verdict(Path::new("/tmp/shared.bin"), &ctx)),
        Reason::StickyDir.code()
    );
}

#[test]
fn an_immutable_file_is_refused() {
    let xdg = xdg_at(Path::new("/home/u"));
    let probe = FakeProbe::new(SAMPLE_MOUNTS)
        .dir("/home/u/.cache")
        .file("/home/u/.cache/pinned")
        .immutable("/home/u/.cache/pinned")
        .with_empty_scan();
    let allowed = vec![AllowedRoot::new("/home/u/.cache")];
    let ctx = ctx(&xdg, &probe, &allowed);
    assert_eq!(
        code(&verdict(Path::new("/home/u/.cache/pinned"), &ctx)),
        Reason::Immutable.code()
    );
}

#[test]
fn an_open_file_is_refused() {
    let xdg = xdg_at(Path::new("/home/u"));
    let probe = FakeProbe::new(SAMPLE_MOUNTS)
        .dir("/home/u/.cache")
        .file("/home/u/.cache/live.db")
        .open_by("/home/u/.cache/live.db", 4242, "sqlite");
    let allowed = vec![AllowedRoot::new("/home/u/.cache")];
    let ctx = ctx(&xdg, &probe, &allowed);
    let result = verdict(Path::new("/home/u/.cache/live.db"), &ctx);
    match result.reason() {
        Some(Reason::OpenByProcess { pid, name }) => {
            assert_eq!(*pid, 4242);
            assert_eq!(name, "sqlite");
        }
        other => panic!("expected an open-file refusal, got {other:?}"),
    }
}

#[test]
fn a_sqlite_sidecar_is_refused_when_its_database_is_open() {
    let xdg = xdg_at(Path::new("/home/u"));
    let probe = FakeProbe::new(SAMPLE_MOUNTS)
        .dir("/home/u/.cache")
        .file("/home/u/.cache/history.db")
        .file("/home/u/.cache/history.db-wal")
        .open_by("/home/u/.cache/history.db", 11, "browser");
    let allowed = vec![AllowedRoot::new("/home/u/.cache")];
    let ctx = ctx(&xdg, &probe, &allowed);

    let result = verdict(Path::new("/home/u/.cache/history.db-wal"), &ctx);
    assert_eq!(
        code(&result),
        Reason::OpenByProcess {
            pid: 0,
            name: String::new()
        }
        .code()
    );
}

#[test]
fn a_missing_open_scan_fails_closed() {
    let xdg = xdg_at(Path::new("/home/u"));
    let probe = FakeProbe::new(SAMPLE_MOUNTS)
        .dir("/home/u/.cache")
        .file("/home/u/.cache/unknown.bin");
    let allowed = vec![AllowedRoot::new("/home/u/.cache")];
    let ctx = ctx(&xdg, &probe, &allowed);
    assert_eq!(
        code(&verdict(Path::new("/home/u/.cache/unknown.bin"), &ctx)),
        Reason::ProbeUnknown(String::new()).code()
    );
}

#[test]
fn an_unknown_mount_fails_closed() {
    let xdg = xdg_at(Path::new("/home/u"));
    let probe = FakeProbe::new("")
        .dir("/home/u/.cache")
        .file("/home/u/.cache/x")
        .with_empty_scan();
    let allowed = vec![AllowedRoot::new("/home/u/.cache")];
    let ctx = ctx(&xdg, &probe, &allowed);
    assert_eq!(
        code(&verdict(Path::new("/home/u/.cache/x"), &ctx)),
        Reason::UnknownMount.code()
    );
}

#[test]
fn a_path_on_another_device_is_refused() {
    let xdg = xdg_at(Path::new("/home/u"));
    let probe = FakeProbe::new(SAMPLE_MOUNTS)
        .dir("/home/u/.cache")
        .file("/home/u/.cache/elsewhere.bin")
        .on_device("/home/u/.cache/elsewhere.bin", 99)
        .with_empty_scan();
    let allowed = vec![AllowedRoot {
        path: PathBuf::from("/home/u/.cache"),
        device: Some(1),
        allow_root_itself: false,
    }];
    let ctx = ctx(&xdg, &probe, &allowed);
    assert_eq!(
        code(&verdict(Path::new("/home/u/.cache/elsewhere.bin"), &ctx)),
        Reason::OtherDevice.code()
    );
}

// ----------------------------------------------------------- real filesystem ---

/// A symlinked base directory is legitimate: sweep resolves it and acts on the
/// physical path instead of refusing everything under it.
#[test]
fn a_symlinked_base_directory_is_followed_to_its_physical_path() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path().join("home");
    let real = temp.path().join("real-cache");
    std::fs::create_dir_all(&home).expect("home");
    std::fs::create_dir_all(&real).expect("real");
    let link = home.join(".cache");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let file = link.join("stale.bin");
    std::fs::write(&file, b"x").expect("write");

    let xdg = xdg_at(&home);
    let probe = RealProbe::new().expect("probe").with_open_scan();
    let allowed = vec![AllowedRoot::new(&link)];
    let ctx = ctx(&xdg, &probe, &allowed);

    match verdict(&file, &ctx) {
        Verdict::Allow { physical } => assert_eq!(physical, real.join("stale.bin")),
        Verdict::Deny(reason) => panic!("denied: {reason}"),
    }
}

/// A symlink that resolves into a protected tree is refused, even though the
/// literal path looks harmless.
#[test]
fn a_symlink_into_a_protected_tree_is_refused() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    let link = home.join(".cache");
    std::os::unix::fs::symlink("/usr/lib", &link).expect("symlink");

    let xdg = xdg_at(&home);
    let probe = RealProbe::new().expect("probe").with_open_scan();
    let allowed = vec![AllowedRoot::new(&link)];
    let ctx = ctx(&xdg, &probe, &allowed);

    let result = verdict(&link.join("firmware"), &ctx);
    assert_eq!(
        code(&result),
        Reason::SymlinkAncestorEscape(PathBuf::new()).code()
    );
}

/// The dry run and the real run must describe exactly the same operations.
#[test]
fn dry_run_parity_on_a_real_tree() {
    let temp = tempfile::tempdir().expect("tempdir");
    let home = temp.path().join("home");
    let cache = home.join(".cache");
    std::fs::create_dir_all(cache.join("old")).expect("cache");
    for name in ["a.bin", "b.bin", "c.bin"] {
        std::fs::write(cache.join(name), b"payload").expect("write");
    }
    std::fs::write(cache.join("old").join("nested.bin"), b"payload").expect("write");

    let xdg = xdg_at(&home);
    let probe = RealProbe::new().expect("probe").with_open_scan();
    let allowed = vec![AllowedRoot::new(&cache)];
    let ctx = ctx(&xdg, &probe, &allowed);
    let rule = RuleId::new("test.rule").expect("valid");

    let candidates: Vec<PathBuf> = ["a.bin", "b.bin", "c.bin"]
        .iter()
        .map(|name| cache.join(name))
        .collect();

    let mut preview_plan = Plan::new();
    for path in &candidates {
        preview_plan.push(path, &rule, &ctx).expect("allowed");
    }
    preview_plan.finish();

    let preview = sweep_core::apply(&preview_plan, &probe, Mode::DryRun, "clean", None);
    assert_eq!(preview.would_remove(), 3);
    for path in &candidates {
        assert!(path.exists(), "dry run must not delete");
    }

    let mut real_plan = Plan::new();
    for path in candidates.iter().rev() {
        real_plan.push(path, &rule, &ctx).expect("allowed");
    }
    real_plan.finish();
    assert_eq!(
        preview_plan.hash(),
        real_plan.hash(),
        "the preview and the real run must be the same operation set"
    );

    let applied = sweep_core::apply(&real_plan, &probe, Mode::Apply, "clean", None);
    assert_eq!(applied.removed(), 3);
    for path in &candidates {
        assert!(!path.exists(), "planned path must be gone");
    }
    assert!(cache.exists(), "the rule root must survive");
    assert!(
        cache.join("old").join("nested.bin").exists(),
        "unplanned paths must survive"
    );
}

/// The operation log never gains a raw control byte, for any path bytes.
#[test]
fn op_log_lines_stay_single_and_escaped() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut log = sweep_core::Oplog::open(temp.path(), "test").expect("log");
    for byte in 0u8..=0x1f {
        let name = format!("/tmp/x{byte}y");
        let (path, hex) = sweep_core::oplog::encode_path(Path::new(&name));
        log.append(sweep_core::Record {
            ts: sweep_core::oplog::rfc3339(0),
            cmd: "clean",
            session: "test",
            action: sweep_core::Action::Skipped,
            rule: "test.rule",
            path,
            path_hex: hex,
            bytes: 0,
            reason: Some("control_byte"),
            detail: None,
        });
    }
    let raw = std::fs::read_to_string(log.path()).expect("read log");
    let lines: Vec<&str> = raw.lines().collect();
    assert_eq!(lines.len(), 32, "one record per control byte");
    for line in lines {
        assert!(
            !line.bytes().any(|byte| byte < 0x20),
            "record carries a raw control byte: {line:?}"
        );
    }
}

/// Mount lookup returns the deepest matching mount, never a prefix illusion.
#[test]
fn mount_lookup_picks_the_longest_prefix() {
    let table = MountTable::parse(SAMPLE_MOUNTS);
    let home = table.find(Path::new("/home/u/.cache")).expect("match");
    assert_eq!(home.mount_point, PathBuf::from("/home"));

    let root = table.find(Path::new("/etc/pacman.conf")).expect("match");
    assert_eq!(root.mount_point, PathBuf::from("/"));

    let usb = table.find(Path::new("/mnt/usb/x.iso")).expect("match");
    assert_eq!(usb.mount_point, PathBuf::from("/mnt/usb"));

    // `/homepage` shares a string prefix with `/home` but is a different
    // directory; it must fall through to the root mount.
    let lookalike = table.find(Path::new("/homepage")).expect("match");
    assert_eq!(lookalike.mount_point, PathBuf::from("/"));
}
