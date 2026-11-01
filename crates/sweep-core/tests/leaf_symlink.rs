//! What a symbolic link means to the plan and to the sink.
//!
//! A link is not a small file. `unlink` removes the link, `rm -rf` on the same
//! path is the same call, and neither touches the target — but a plan that
//! cannot tell "this entry is a link" from "this entry became a link" has no way
//! to notice a swap between the preview and the run. These tests pin both sides:
//! the policy that decides whether a link may be planned at all, and the sink
//! that refuses a link it was not told to expect.

use std::path::{Path, PathBuf};

use sweep_core::{AllowedRoot, FsProbe, Plan, Policy, Reason, RuleId, ValidateCtx, Xdg};
use sweep_testkit::{FaultyProbe, SAMPLE_MOUNTS};

fn xdg_at(home: &str) -> Xdg {
    let home = PathBuf::from(home);
    Xdg::resolve(move |key| match key {
        "HOME" => Some(home.clone().into_os_string()),
        _ => None,
    })
    .expect("home")
}

fn probe() -> FaultyProbe {
    FaultyProbe::new(SAMPLE_MOUNTS).with(|probe| {
        probe
            .dir("/home/u/work")
            .symlink("/home/u/work/link", "/home/u/.ssh/id_ed25519")
            .with_empty_scan()
    })
}

fn context<'a>(
    xdg: &'a Xdg,
    probe: &'a FaultyProbe,
    allowed: &'a [AllowedRoot],
    policy: Policy,
) -> ValidateCtx<'a> {
    ValidateCtx {
        xdg,
        probe,
        allowed,
        policy,
    }
}

#[test]
fn a_leaf_symlink_is_refused_under_the_default_policy() {
    // The default is the one every command but `purge` uses. A link inside a
    // cache root is often the user's own arrangement, and deleting it frees
    // nothing while breaking the setup.
    let xdg = xdg_at("/home/u");
    let probe = probe();
    let allowed = vec![AllowedRoot::new("/home/u/work")];
    let ctx = context(&xdg, &probe, &allowed, Policy::default());

    let verdict = sweep_core::validate(Path::new("/home/u/work/link"), &ctx);
    assert_eq!(
        verdict.reason().map(Reason::code),
        Some(Reason::LeafSymlink.code())
    );
}

#[test]
fn the_project_policy_plans_a_link_as_a_link() {
    // `node_modules/.bin` is a directory of links the package manager wrote, and
    // a sweep that leaves them behind leaves a tree that still looks installed.
    // The policy permits it; the metadata is what records it.
    let xdg = xdg_at("/home/u");
    let probe = probe();
    let allowed = vec![AllowedRoot::new("/home/u/work")];
    let ctx = context(
        &xdg,
        &probe,
        &allowed,
        Policy {
            allow_leaf_symlink: true,
            ..Policy::default()
        },
    );

    let path = Path::new("/home/u/work/link");
    let rule = RuleId::new("project.artifacts.sources").expect("rule id");
    let meta = probe.symlink_metadata(path).expect("the link exists");
    assert!(meta.is_symlink());

    let mut plan = Plan::new();
    plan.push(path, &rule, &ctx)
        .expect("the policy allows this link");
    assert_eq!(plan.len(), 1);
    assert!(
        plan.items()[0].is_symlink(),
        "the plan must remember that this item was a link"
    );
    assert!(!plan.items()[0].is_dir(), "a link is not a directory");
}

#[test]
fn a_link_needs_no_immutable_probe() {
    // The probe opens with `O_NOFOLLOW`, so asking a link for its inode flags
    // fails and would be classified as unknown — which is a refusal. That is not
    // a safety property, it is a question the sink never needs answered: the
    // target's flags are not this deletion's business.
    let xdg = xdg_at("/home/u");
    let probe = probe().immutable_error("/home/u/work/link");
    let allowed = vec![AllowedRoot::new("/home/u/work")];
    let ctx = context(
        &xdg,
        &probe,
        &allowed,
        Policy {
            allow_leaf_symlink: true,
            ..Policy::default()
        },
    );

    let mut plan = Plan::new();
    let rule = RuleId::new("project.artifacts.sources").expect("rule id");
    plan.push(Path::new("/home/u/work/link"), &rule, &ctx)
        .expect("a failing immutable probe on a link must not refuse it");
    assert_eq!(plan.len(), 1);
    assert!(plan.items()[0].is_symlink());
}
