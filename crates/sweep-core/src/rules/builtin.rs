//! The rule packs that ship inside the binary.
//!
//! `include_str!` rather than a runtime read: a rule catalog that depends on
//! files installed next to the binary is a rule catalog that can be half
//! installed, and "the deletion rules were not found" must never be a state the
//! program can reach. The files in `rules/` remain the source of truth and are
//! read by reviewers and by `sweep rules list`.
//!
//! One pack per section, in the order `clean` reports them.

use crate::rules::Source;

/// `(display name, body)`. The order is the section order.
pub const BUILTIN_PACKS: &[(&str, &str)] = &[
    (
        "rules/01-system.toml",
        include_str!("../../../../rules/01-system.toml"),
    ),
    (
        "rules/02-user-essentials.toml",
        include_str!("../../../../rules/02-user-essentials.toml"),
    ),
    (
        "rules/03-app-caches.toml",
        include_str!("../../../../rules/03-app-caches.toml"),
    ),
    (
        "rules/04-browsers.toml",
        include_str!("../../../../rules/04-browsers.toml"),
    ),
    (
        "rules/05-cloud-office.toml",
        include_str!("../../../../rules/05-cloud-office.toml"),
    ),
    (
        "rules/06-dev-tools.toml",
        include_str!("../../../../rules/06-dev-tools.toml"),
    ),
    (
        "rules/07-apps.toml",
        include_str!("../../../../rules/07-apps.toml"),
    ),
    (
        "rules/08-virtualization.toml",
        include_str!("../../../../rules/08-virtualization.toml"),
    ),
    (
        "rules/09-local-data.toml",
        include_str!("../../../../rules/09-local-data.toml"),
    ),
    (
        "rules/10-orphans.toml",
        include_str!("../../../../rules/10-orphans.toml"),
    ),
    (
        "rules/11-aur.toml",
        include_str!("../../../../rules/11-aur.toml"),
    ),
    (
        "rules/12-firmware.toml",
        include_str!("../../../../rules/12-firmware.toml"),
    ),
    (
        "rules/13-snapshots.toml",
        include_str!("../../../../rules/13-snapshots.toml"),
    ),
    (
        "rules/14-installers.toml",
        include_str!("../../../../rules/14-installers.toml"),
    ),
    (
        "rules/15-large-files.toml",
        include_str!("../../../../rules/15-large-files.toml"),
    ),
    (
        "rules/16-project-artifacts.toml",
        include_str!("../../../../rules/16-project-artifacts.toml"),
    ),
    (
        "rules/17-model-caches.toml",
        include_str!("../../../../rules/17-model-caches.toml"),
    ),
];

pub fn sources() -> Vec<Source> {
    BUILTIN_PACKS
        .iter()
        .map(|(name, body)| Source::new(*name, *body))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Section;

    #[test]
    fn one_pack_per_section_in_section_order() {
        assert_eq!(BUILTIN_PACKS.len(), Section::ALL.len());
        for (index, section) in Section::ALL.iter().enumerate() {
            let name = BUILTIN_PACKS[index].0;
            let expected = format!("rules/{:02}-{}.toml", index + 1, section.as_str());
            assert_eq!(name, expected);
        }
    }

    #[test]
    fn every_pack_is_non_empty_utf8() {
        for (name, body) in BUILTIN_PACKS {
            assert!(!body.trim().is_empty(), "{name} is empty");
            assert!(
                body.is_ascii() || body.is_char_boundary(body.len()),
                "{name}"
            );
        }
    }
}
