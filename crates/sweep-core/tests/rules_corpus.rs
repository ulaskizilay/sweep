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
        let root = rule.root.literal_prefix(&xdg);
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
        // Emptying the trash is the one deletion whose target is user data by
        // definition: the file is there because the user already deleted it.
        // Calling that "regenerable" would be a lie in the JSON report.
        if rule.kind == Kind::TrashEmpty {
            continue;
        }
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
fn a_cache_root_that_holds_user_state_keeps_it() {
    // Each of these roots holds something a rebuild does not bring back beside
    // the cache the rule is for: a change history, an offline download, a login
    // token. The catalog's whole argument is "the target is regenerable", and
    // these are the places where a wider root quietly makes that false.
    let set = catalog();
    let rule = |id: &str| {
        set.rules()
            .iter()
            .find(|rule| rule.id.as_str() == id)
            .unwrap_or_else(|| panic!("{id} is missing from the catalog"))
    };
    let excludes = |id: &str| -> Vec<String> {
        rule(id)
            .exclude
            .iter()
            .map(|pattern| pattern.source().to_string())
            .collect()
    };

    // IntelliJ's LocalHistory is its own revision store for uncommitted work.
    assert!(
        excludes("dev.jetbrains.cache").contains(&"**/LocalHistory".to_string()),
        "the IDE's change history is not regenerable: {:?}",
        excludes("dev.jetbrains.cache")
    );

    // Spotify's audio chunks and per-user state are the two trees that are not
    // caches, and `Data/` is 1.7 GiB of offline downloads on a real machine.
    for pattern in ["Data/**", "Users/**"] {
        assert!(
            excludes("app.spotify.cache").contains(&pattern.to_string()),
            "{pattern} is user state, not cache: {:?}",
            excludes("app.spotify.cache")
        );
    }

    // Lutris protects its tokens by naming the child instead of the root: the
    // save-sync state sits at the root under names no glob can spell.
    assert_eq!(
        rule("app.lutris.cache").root.raw(),
        "{cache}/lutris/installer",
        "the root holds .gog.token, .egs.token and one <save>.json per game"
    );

    // Pub's cache root is several things in one directory. `hosted/pub.dev` is
    // the public index and comes back with `dart pub get`; `global_packages`
    // holds activated executables, `git` holds pinned checkouts, and `hosted`
    // may also name a private server that needs credentials. Only the public
    // host is a rule.
    assert_eq!(
        rule("dev.pub.cache").root.raw(),
        "{home}/.pub-cache/hosted/pub.dev",
        "the cache root also holds activated executables and git checkouts"
    );
}

#[test]
fn a_downloaded_artifact_is_reported_and_never_deleted() {
    // These three roots hold something a tool fetched, not something it can
    // rebuild: a browser revision from `npx puppeteer browsers install`, a
    // Cypress binary, a guest image from QEMU's functional test suite. A
    // `dir-sweep` with `keep_days = 0` would take them on every run, and their
    // mtime says nothing about use because the tree is read and never
    // rewritten. Deleting one costs a re-download, so the rule measures instead.
    let set = catalog();
    for id in [
        "dev.puppeteer.cache",
        "dev.cypress.cache",
        "virt.qemu.cache",
    ] {
        let rule = set
            .rules()
            .iter()
            .find(|rule| rule.id.as_str() == id)
            .unwrap_or_else(|| panic!("{id} is missing from the catalog"));
        assert_eq!(
            rule.kind,
            Kind::ReportOnly,
            "{id} holds a download, not a rebuild"
        );
    }
}

#[test]
fn a_versions_rule_names_the_launcher_that_must_survive() {
    // "Keep the newest" is a guess about which release is live. The launcher is
    // the statement, so every `versions` rule has to name one, and the named
    // path has to sit outside the directory being swept: a link inside it would
    // be skipped as a link and prove nothing about the entries.
    let xdg = xdg();
    let set = catalog();
    for rule in set.rules() {
        if rule.kind != Kind::Versions {
            continue;
        }
        assert!(
            rule.keep_versions.is_some_and(|count| count >= 1),
            "{}: a versions rule without a count would keep nothing",
            rule.id
        );
        let link = rule
            .keep_link
            .as_ref()
            .unwrap_or_else(|| panic!("{} has no keep_link", rule.id));
        assert!(
            !link.has_glob(),
            "{}: keep_link must name one launcher, not a pattern",
            rule.id
        );
        let root = rule.root.literal_prefix(&xdg);
        assert!(
            !link.literal_prefix(&xdg).starts_with(&root),
            "{}: the launcher is inside the swept directory",
            rule.id
        );
    }

    let rule = |id: &str| {
        set.rules()
            .iter()
            .find(|rule| rule.id.as_str() == id)
            .unwrap_or_else(|| panic!("{id} is missing from the catalog"))
    };
    for (id, link) in [
        ("dev.claude.versions", "{home}/.local/bin/claude"),
        (
            "dev.cursor-agent.versions",
            "{home}/.local/bin/cursor-agent",
        ),
    ] {
        assert_eq!(
            rule(id).keep_link.as_ref().map(|link| link.raw()),
            Some(link),
            "{id}: the launcher is the safety property of this rule"
        );
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
    //
    // The walk shape belongs here too: `max_depth` decides how far down a rule
    // looks, and `exclude` and `pattern` decide what it passes over. A rule whose
    // depth is raised without a note is exactly the kind of change this test
    // exists to put in front of a reviewer - `dev.uv.cache` needed 16 to reach
    // the unpacked wheels it had been promising to remove.
    let set = catalog();
    let mut records: Vec<String> = set
        .rules()
        .iter()
        .map(|rule| {
            let mut excludes: Vec<&str> = rule
                .exclude
                .iter()
                .map(|pattern| pattern.source())
                .collect();
            excludes.sort_unstable();
            let mut patterns: Vec<&str> = rule
                .patterns
                .iter()
                .map(|pattern| pattern.source())
                .collect();
            patterns.sort_unstable();
            format!(
                "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                rule.id,
                rule.section,
                rule.kind,
                rule.root.raw(),
                rule.keep_days,
                // A count and a launcher decide which entry survives just as
                // much as an age does, so they belong in the digest too.
                rule.keep_versions
                    .map(|n| n.to_string())
                    .unwrap_or_default(),
                rule.keep_link
                    .as_ref()
                    .map(|link| link.raw())
                    .unwrap_or_default(),
                rule.max_depth,
                excludes.join(","),
                patterns.join(","),
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
    const EXPECTED: u64 = 0x4c5a_5630_914d_9538;
    assert_eq!(
        format!("{hash:016x}"),
        format!("{EXPECTED:016x}"),
        "the rule catalog changed ({} rules). If that was intended, set EXPECTED \
         to {hash:#018x} in the same commit.",
        records.len()
    );
}
