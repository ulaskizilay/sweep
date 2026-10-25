//! Fuzz target: arbitrary bytes as a rule pack.
//!
//! The property is the same shape as `fuzz_validate`, one layer earlier:
//!
//! 1. no input panics — including invalid UTF-8, missing keys, huge numbers and
//!    nested tables;
//! 2. a pack that *does* compile produces rules that respect the invariants the
//!    compiler is supposed to enforce. If a future change lets a protected root
//!    through, this catches it without waiting for a reviewer to notice.
//!
//! Refusing is always an acceptable outcome; accepting something unsafe is not.

#![no_main]

use std::path::Component;

use libfuzzer_sys::fuzz_target;
use sweep_core::policy;
use sweep_core::rules::{RuleSet, Source};
use sweep_core::Xdg;

fuzz_target!(|data: &[u8]| {
    // A rule pack is text. Invalid UTF-8 is still a valid fuzz input: it must be
    // refused by the loader, not by an unwrap.
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // 64 KiB is far beyond any real pack and keeps a single run fast.
    if text.len() > 64 * 1024 {
        return;
    }

    let xdg = Xdg::resolve(|key| match key {
        "HOME" => Some("/home/u".into()),
        _ => None,
    })
    .expect("home");

    let sources = [Source::new("fuzz.toml", text)];
    let Ok(set) = RuleSet::from_sources(&sources, &xdg) else {
        return;
    };

    for rule in set.rules() {
        let root = rule.expanded_root(&xdg);
        assert!(root.is_absolute(), "{} -> {}", rule.id, root.display());
        assert!(
            !root
                .components()
                .any(|component| matches!(component, Component::ParentDir)),
            "{} -> {}",
            rule.id,
            root.display()
        );

        if rule.kind.deletes() {
            assert!(
                policy::match_root(&root).is_none(),
                "{} compiled into a protected root: {}",
                rule.id,
                root.display()
            );
            assert!(
                !rule.evidence.trim().is_empty(),
                "{} deletes without evidence",
                rule.id
            );
            assert!(
                !(rule.keep_days == 0 && !rule.recoverable),
                "{} would delete immediately without declaring the target regenerable",
                rule.id
            );
        }
    }
});
