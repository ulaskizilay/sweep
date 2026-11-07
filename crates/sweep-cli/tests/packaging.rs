//! The packaging files name every command, and this is what says so.
//!
//! A man page is generated per command, and both the `PKGBUILD` and the release
//! workflow carry the list because neither can read the other. A new command
//! that is missing from one of them ships a package whose `sweep-<name>(1)` does
//! not exist, and the only place that shows up is the machine of whoever typed
//! `man sweep-<name>`. So the two lists are compared against the parser itself.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    // `CARGO_MANIFEST_DIR` is `crates/sweep-cli`.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root resolves")
}

/// Every command path the parser has, top level and one level down.
///
/// `rules` is the only command with subcommands today, and both of them need a
/// page, so the walk is not limited to the top level.
fn commands() -> Vec<String> {
    let mut all = subcommands(&[]);
    let top = all.clone();
    for command in top {
        for sub in subcommands(&[command.as_str()]) {
            all.push(format!("{command} {sub}"));
        }
    }
    all
}

/// The names a `--help` output lists under `Commands:`.
fn subcommands(path: &[&str]) -> Vec<String> {
    let mut args: Vec<&str> = path.to_vec();
    args.push("--help");
    let output = Command::new(env!("CARGO_BIN_EXE_sweep"))
        .args(&args)
        .output()
        .expect("spawn sweep --help");
    assert!(output.status.success(), "--help must succeed");
    let text = String::from_utf8(output.stdout).expect("utf-8 help");

    let mut seen = Vec::new();
    let mut in_commands = false;
    for line in text.lines() {
        if line.starts_with("Commands:") {
            in_commands = true;
            continue;
        }
        if !in_commands {
            continue;
        }
        if line.trim().is_empty() {
            break;
        }
        let Some(name) = line
            .strip_prefix("  ")
            .and_then(|rest| rest.split_whitespace().next())
        else {
            continue;
        };
        if name != "help" {
            seen.push(name.to_string());
        }
    }
    seen
}

/// `man_page sweep-clean clean` and `page sweep-clean clean` name a command path.
fn listed_commands(path: &Path, prefix: &str) -> Vec<String> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
    text.lines()
        .filter_map(|line| line.trim().strip_prefix(prefix))
        .map(|rest| {
            let mut words = rest.split_whitespace();
            // The page name is first, then the command path.
            words.next();
            words.collect::<Vec<_>>().join(" ")
        })
        .filter(|path| !path.is_empty())
        .collect()
}

#[test]
fn the_package_installs_a_man_page_for_every_command() {
    let root = repo_root();
    let commands = commands();

    let pkgbuild = listed_commands(&root.join("packaging/sweep-cli-git/PKGBUILD"), "man_page ");
    for command in &commands {
        assert!(
            pkgbuild.contains(command),
            "`{command}` has no man_page line in the PKGBUILD, so `man sweep-{command}` is a dead end"
        );
    }
    assert_eq!(
        pkgbuild.len(),
        commands.len(),
        "the PKGBUILD installs a page for a command that does not exist: {pkgbuild:?} vs {commands:?}"
    );
}

#[test]
fn the_release_archive_carries_the_same_pages_as_the_package() {
    let root = repo_root();
    let pkgbuild = listed_commands(&root.join("packaging/sweep-cli-git/PKGBUILD"), "man_page ");
    let release = listed_commands(&root.join(".github/workflows/release.yml"), "page ");
    assert_eq!(
        release, pkgbuild,
        "the release workflow and the PKGBUILD must install the same man pages"
    );
}
