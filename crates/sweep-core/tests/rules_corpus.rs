//! Catalog invariants — the properties a reviewer would otherwise re-check by
//! hand for every new rule.
//!
//! These are not unit tests of the compiler; those live next to the code. This
//! file asks the questions that only make sense across the whole shipped
//! catalog: is every deleting rule justified, is anything enabled that needs
//! privilege we do not have yet, did the catalog change without a reviewer
//! noticing?
//!
//! The digest at the bottom is deliberate friction. Adding, removing or
//! re-tuning a rule is a safety change, and the diff should show one line here
//! so a reviewer sees it next to the rule itself.

use std::path::Component;

use sweep_core::policy;
use sweep_core::rules::{builtin, Kind, Privilege, RuleSet, Section};
use sweep_core::Xdg;

fn xdg() -> Xdg {
    Xdg::resolve(|key| match key {
        "HOME" => Some("/home/u".into()),
        _ => None,
    })
    .expect("HOME must be resolvable in tests")
}

fn catalog() -> RuleSet {
    RuleSet::load_builtin(&xdg()).expect("built-in packs must compile")
}

#[test]
fn the_catalog_compiles() {
    let set = catalog();
    assert!(!set.is_empty());
    assert_eq!(builtin::BUILTIN_PACKS.len(), Section::ALL.len());
}

#[test]
fn every_deleting_rule_explains_why_it_is_safe() {
    for rule in catalog().rules() {
        if rule.kind.deletes() {
            assert!(
                !rule.evidence.trim().is_empty(),
                "{} deletes without an evidence line",
                rule.id
            );
            assert!(
                rule.evidence.len() >= 20,
                "{}: evidence is too short to be an explanation: {:?}",
                rule.id,
                rule.evidence
            );
        }
    }
}

#[test]
fn no_deleting_rule_resolves_into_a_protected_root() {
    let xdg = xdg();
    for rule in catalog().rules() {
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
                "{} resolves into a protected root: {}",
                rule.id,
                root.display()
            );
        }
    }
}

#[test]
fn every_enabled_root_rule_is_one_the_elevated_child_will_accept() {
    // A root rule is only reachable through `sweep __apply`, which re-derives
    // its allowlist from this same catalog. An enabled rule that is missing
    // from that list is worse than a disabled one: the parent plans items, the
    // child refuses every one of them, and the run reports a preview it can
    // never apply.
    let xdg = xdg();
    let ids = sweep_core::privilege::system_rule_ids();
    let roots: Vec<std::path::PathBuf> = sweep_core::privilege::system_roots()
        .into_iter()
        .map(|root| root.path)
        .collect();

    for rule in catalog().rules() {
        if rule.privilege != Privilege::Root || !rule.kind.deletes() {
            continue;
        }
        assert_eq!(
            rule.section,
            Section::System,
            "{}: only the system section may delete as root",
            rule.id
        );
        if !rule.enabled {
            continue;
        }
        assert!(
            ids.contains(rule.id.as_str()),
            "{} is enabled but the elevated child will refuse it",
            rule.id
        );
        let root = rule.expanded_root(&xdg);
        assert!(
            roots.contains(&root),
            "{} is enabled but {} is not on the child's allowlist",
            rule.id,
            root.display()
        );
    }
}

#[test]
fn every_section_has_at_least_one_rule() {
    let set = catalog();
    let covered: std::collections::BTreeSet<Section> =
        set.rules().iter().map(|rule| rule.section).collect();
    for section in Section::ALL {
        assert!(
            covered.contains(&section),
            "section {section} has no rule, so `clean` can never report it"
        );
    }
}

#[test]
fn ids_are_unique_and_namespaced() {
    let set = catalog();
    let mut ids: Vec<String> = set.rules().iter().map(|rule| rule.id.to_string()).collect();
    let before = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), before, "duplicate rule id");

    for rule in set.rules() {
        assert!(
            rule.id.as_str().contains('.'),
            "{} should be namespaced like <area>.<tool>.<target>",
            rule.id
        );
    }
}

#[test]
fn an_unbounded_retention_is_declared_recoverable() {
    for rule in catalog().rules() {
        if rule.kind.deletes() && rule.keep_days == 0 {
            assert!(
                rule.recoverable,
                "{} deletes immediately without saying the target is regenerable",
                rule.id
            );
        }
    }
}

#[test]
fn a_file_pattern_rule_never_matches_everything() {
    for rule in catalog().rules() {
        if rule.kind != Kind::FilePattern {
            continue;
        }
        for pattern in &rule.patterns {
            assert!(
                pattern.has_literal(),
                "{}: pattern {:?} is only wildcards",
                rule.id,
                pattern.source()
            );
        }
    }
}

#[test]
fn a_user_pack_can_add_rules_but_not_widen_a_builtin_one() {
    // The overlay is refused at load, together with the built-ins, because
    // "same id, different root" is how a config file would widen the policy.
    let temp = tempfile::tempdir().expect("tempdir");
    let xdg = Xdg::resolve(|key| match key {
        "HOME" => Some(temp.path().as_os_str().to_os_string()),
        _ => None,
    })
    .expect("home");
    let rules = xdg.config_dir().join("rules.d");
    std::fs::create_dir_all(&rules).expect("rules.d");
    std::fs::write(
        rules.join("99-replacement.toml"),
        r#"
[[rule]]
id = "user.cache.residual"
section = "user-essentials"
kind = "dir-sweep"
root = "{cache}/anything"
evidence = "a user tries to replace the residual sweep with a broader rule"
recoverable = true
keep_days = 0
privilege = "user"
"#,
    )
    .expect("write");

    let errors = RuleSet::load(&xdg).expect_err("must be refused");
    assert!(
        errors
            .iter()
            .any(|error| error.kind == sweep_core::RuleErrorKind::DuplicateId),
        "{errors:?}"
    );
}

#[test]
fn a_user_pack_can_add_a_new_rule() {
    let temp = tempfile::tempdir().expect("tempdir");
    let xdg = Xdg::resolve(|key| match key {
        "HOME" => Some(temp.path().as_os_str().to_os_string()),
        _ => None,
    })
    .expect("home");
    let rules = xdg.config_dir().join("rules.d");
    std::fs::create_dir_all(&rules).expect("rules.d");
    std::fs::write(
        rules.join("10-mine.toml"),
        r#"
[[rule]]
id = "user.my-cache"
section = "user-essentials"
kind = "dir-sweep"
root = "{cache}/my-cache"
evidence = "this directory is rebuilt by the tool that owns it"
recoverable = true
keep_days = 0
privilege = "user"
"#,
    )
    .expect("write");

    let set = RuleSet::load(&xdg).expect("overlay adds a rule");
    assert_eq!(set.len(), catalog().len() + 1);
    assert!(set
        .rules()
        .iter()
        .any(|rule| rule.id.as_str() == "user.my-cache"));
}

#[test]
fn the_catalog_digest_is_unchanged() {
    // FNV-1a over the safety-relevant shape of every rule, in id order. Tuning a
    // retention, moving a root, flipping a kind or adding a rule changes it.
    let set = catalog();
    let mut records: Vec<String> = set
        .rules()
        .iter()
        .map(|rule| {
            format!(
                "{}|{}|{}|{}|{}|{}",
                rule.id,
                rule.section,
                rule.kind,
                rule.root.raw(),
                rule.keep_days,
                rule.enabled
            )
        })
        .collect();
    records.sort();

    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for record in &records {
        for byte in record.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash ^= 0x1e;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }

    // Update this value in the same commit as the rule change, so the review
    // diff shows the catalog moved on purpose.
    const EXPECTED: u64 = 0x4838_30f4_4944_01b4;
    assert_eq!(
        format!("{hash:016x}"),
        format!("{EXPECTED:016x}"),
        "the rule catalog changed ({} rules). If that was intended, set EXPECTED \
         to {hash:#018x} in the same commit.",
        records.len()
    );
}
