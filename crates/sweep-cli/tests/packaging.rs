//! The packaging files name every command, and this is what says so.
//!
//! A man page is generated per command, and every `PKGBUILD` and the release
//! workflow carry the list because none of them can read the others. A new
//! command that is missing from one of them ships a package whose
//! `sweep-<name>(1)` does not exist, and the only place that shows up is the
//! machine of whoever typed `man sweep-<name>`. So every list is compared against
//! the parser itself, and every `PKGBUILD` in `packaging/` is found by walking
//! the directory rather than named here: a second package that nobody remembered
//! to add to this file would be exactly the one that drifts.

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

/// Every `packaging/<name>/PKGBUILD`, sorted, found by walking the directory.
///
/// Naming the files here would mean a new package is checked only after someone
/// remembers to add it, which is the failure this file exists to prevent.
fn pkgbuilds(root: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(root.join("packaging"))
        .expect("packaging/ is readable")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .map(|dir| dir.join("PKGBUILD"))
        .filter(|path| path.is_file())
        .collect();
    found.sort();
    assert!(
        !found.is_empty(),
        "packaging/ holds no PKGBUILD, so this test would pass without checking anything"
    );
    found
}

/// The body of a `name() {` shell function, up to the closing brace at column 0.
fn shell_function(text: &str, name: &str) -> String {
    let start = text
        .find(&format!("{name}() {{"))
        .unwrap_or_else(|| panic!("`{name}()` is defined"));
    let rest = &text[start..];
    let end = rest
        .find("\n}\n")
        .unwrap_or_else(|| panic!("`{name}()` is closed"));
    rest[..end].to_string()
}

#[test]
fn every_package_installs_a_man_page_for_every_command() {
    let root = repo_root();
    let commands = commands();

    for path in pkgbuilds(&root) {
        let pkgbuild = listed_commands(&path, "man_page ");
        for command in &commands {
            assert!(
                pkgbuild.contains(command),
                "`{command}` has no man_page line in {}, so `man sweep-{command}` is a dead end",
                path.display()
            );
        }
        assert_eq!(
            pkgbuild.len(),
            commands.len(),
            "{} installs a page for a command that does not exist: {pkgbuild:?} vs {commands:?}",
            path.display()
        );
    }
}

#[test]
fn the_release_archive_carries_the_same_pages_as_every_package() {
    let root = repo_root();
    let release = listed_commands(&root.join(".github/workflows/release.yml"), "page ");
    for path in pkgbuilds(&root) {
        let pkgbuild = listed_commands(&path, "man_page ");
        assert_eq!(
            release,
            pkgbuild,
            "the release workflow and {} must install the same man pages",
            path.display()
        );
    }
}

#[test]
fn the_package_never_runs_the_binary_under_fakeroot() {
    // `package()` runs inside fakeroot, where `geteuid()` answers 0, and sweep
    // refuses to run as root on purpose. Generating the completions and the man
    // pages there therefore fails the build with sweep's own refusal message
    // (`makepkg` did exactly that on 17 November 2026). The binary is built and
    // asked for its output in `build()`, which runs as the user; `package()` only
    // installs files.
    let root = repo_root();
    for path in pkgbuilds(&root) {
        let text = std::fs::read_to_string(&path).expect("PKGBUILD is readable");
        let package = shell_function(&text, "package");
        let mut installed = 0;
        for line in package.lines() {
            if !line.contains("target/release/sweep") {
                continue;
            }
            assert!(
                line.trim_start()
                    .starts_with("install -Dm755 target/release/sweep"),
                "{} calls the binary from package(), which runs as root under fakeroot: {line}",
                path.display()
            );
            installed += 1;
        }
        assert!(
            installed > 0,
            "{} never installs the binary, so this test would pass without checking anything",
            path.display()
        );

        let build = shell_function(&text, "build");
        assert!(
            build.contains("target/release/sweep completions"),
            "{} must generate the completions in build(), where it is not root",
            path.display()
        );
        assert!(
            build.contains("__manpage"),
            "{} must generate the man pages in build(), where it is not root",
            path.display()
        );
    }
}
