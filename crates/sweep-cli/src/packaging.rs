//! Completions and man pages, printed for the package build.
//!
//! A packaged command needs things that are not the command itself: a completion
//! script for each shell and a man page per command. Generating them from the
//! same `clap` definition the parser uses is the only version of this that cannot
//! drift: an option that exists in `--help` exists in the page and in the
//! completion, because all of them read one struct.
//!
//! Nothing is written to disk here. `sweep completions bash` prints a script and
//! `sweep __manpage [COMMAND]` prints a page; the `PKGBUILD` redirects them into
//! `/usr/share/...`. A command that writes into `$HOME` on request would be a
//! second install path with its own permissions and its own cleanup, for files a
//! package manager already knows how to own.

use std::io::Write;
use std::process::ExitCode;

use clap::{Command, CommandFactory};
use clap_complete::Shell;

use crate::Cli;

/// Turns off the `help` subcommand for a command and everything below it.
///
/// `clap` adds one when the definition is built, and the generators build their
/// clones, so a nested command would otherwise gain a `sweep-rules-help(1)`
/// reference that no page answers.
fn without_help(mut command: Command) -> Command {
    command = command.disable_help_subcommand(true);
    for sub in command.get_subcommands_mut() {
        let taken = std::mem::take(sub);
        *sub = without_help(taken);
    }
    command
}

/// The command definition without the hidden helpers.
///
/// `clap_complete` and `clap_mangen` walk every subcommand, hidden ones
/// included, so generating from `Cli::command()` would teach the shell to
/// complete `__apply` and print an internal helper in the man page. The
/// subcommand is reachable by name anyway; it should not be advertised.
fn public_command() -> Command {
    let full = Cli::command();
    let visible: Vec<Command> = full
        .get_subcommands()
        // `help` is the one clap adds for itself when the definition is built,
        // so it has no `sweep-help(1)` page and must not be named as if it did.
        .filter(|sub| !sub.is_hide_set() && sub.get_name() != "help")
        .cloned()
        .collect();

    // The name and version are the ones `clap` derives from the crate, so they
    // cannot disagree with `sweep --version`.
    let mut pruned = Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .disable_help_subcommand(true);
    if let Some(about) = full.get_about() {
        pruned = pruned.about(about.to_string());
    }
    // The one-line summary is what `--help` lists; the long text is what the man
    // page's DESCRIPTION section prints, and dropping it would leave the page
    // saying only that sweep is a cleanup tool.
    if let Some(long_about) = full.get_long_about() {
        pruned = pruned.long_about(long_about.to_string());
    }
    for arg in full.get_arguments() {
        pruned = pruned.arg(arg.clone());
    }
    for sub in visible {
        pruned = pruned.subcommand(without_help(sub));
    }
    pruned
}

/// Writes the completion script for `shell` to stdout.
pub fn completions(shell: Shell) -> ExitCode {
    let mut command = public_command();
    let name = command.get_name().to_string();
    clap_complete::generate(shell, &mut command, name, &mut std::io::stdout());
    ExitCode::SUCCESS
}

/// The command at `path` from the root, or `None` if some step is not a
/// command.
fn find<'a>(root: &'a Command, path: &[String]) -> Option<&'a Command> {
    let mut current = root;
    for name in path {
        current = current
            .get_subcommands()
            .find(|sub| sub.get_name() == name)?;
    }
    Some(current)
}

/// `sweep` for the root, `sweep-rules-list` for `rules list`.
///
/// The top page refers to its subcommands as `sweep-doctor(1)`, so the page for
/// `doctor` has to carry that name; a page titled `doctor` would leave the
/// reference dangling in every other page.
fn title_for(path: &[String]) -> String {
    if path.is_empty() {
        "sweep".to_string()
    } else {
        format!("sweep-{}", path.join("-"))
    }
}

/// Renders one page into memory, so a test can read it instead of a terminal.
///
/// The command is renamed before it is rendered: `clap_mangen` derives both the
/// NAME line and the cross-references from `get_display_name()`, so a page whose
/// title was overridden but whose name was not would announce itself as `list`
/// while every other page calls it `sweep-rules-list(1)`.
fn render(command: &Command, title: &str) -> std::io::Result<Vec<u8>> {
    let mut page = Vec::new();
    let renamed = command
        .clone()
        .name(title.to_string())
        .display_name(title.to_string());
    // The version is not set here: a page and the command it documents must
    // agree about which flags exist, and setting one would give `sweep rules
    // list` a `--version` it does not accept. The source field is metadata, and
    // it is set for every page.
    clap_mangen::Man::new(renamed)
        .title(title)
        .source(format!("{title} {}", env!("CARGO_PKG_VERSION")))
        .render(&mut page)?;
    Ok(page)
}

/// Writes the page for the command at `path`, `sweep.1` for an empty path.
///
/// Roff is generated rather than hand-written so a new flag cannot be
/// documented in one place and missing from the other.
pub fn manpage(path: &[String]) -> ExitCode {
    let root = public_command();
    let Some(command) = find(&root, path) else {
        eprintln!(
            "sweep __manpage: `{}` is not a command of sweep",
            path.join(" ")
        );
        return ExitCode::from(crate::EXIT_USAGE);
    };
    let page = match render(command, &title_for(path)) {
        Ok(page) => page,
        Err(error) => {
            eprintln!("sweep __manpage: cannot write the page: {error}");
            return ExitCode::FAILURE;
        }
    };
    match std::io::stdout().write_all(&page) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sweep __manpage: cannot write the page: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whatever the generator writes has to be a script the shell can source,
    /// and it has to be about `sweep` rather than about a placeholder.
    #[test]
    fn the_completion_script_is_about_sweep_and_names_its_commands() {
        // The generator writes to stdout, which a unit test cannot capture, so
        // this asserts on the same `clap` definition the generator is handed.
        let command = Cli::command();
        assert_eq!(command.get_name(), "sweep");
        let names: Vec<String> = command
            .get_subcommands()
            .map(|sub| sub.get_name().to_string())
            .collect();
        for expected in ["clean", "uninstall", "analyze", "history", "optimize"] {
            assert!(
                names.iter().any(|name| name == expected),
                "`{expected}` must reach the completions: {names:?}"
            );
        }
    }

    /// Every command in the tree has to produce a page, because the top page
    /// names its subcommands as `sweep-<name>(1)` and a nested command is named
    /// the same way by its parent.
    #[test]
    fn every_visible_command_renders_a_page_under_its_own_name() {
        /// The page text, and the path that names it.
        fn walk(command: &Command, path: &mut Vec<String>, seen: &mut Vec<(String, String)>) {
            let title = title_for(path);
            let page = render(command, &title).expect("render");
            let text = String::from_utf8(page).expect("roff is ascii in practice");
            assert!(
                text.contains(&format!(".TH {title} 1")),
                "`{title}` is not the page's title:\n{text}"
            );
            seen.push((title, text));
            for sub in command.get_subcommands().filter(|sub| !sub.is_hide_set()) {
                path.push(sub.get_name().to_string());
                walk(sub, path, seen);
                path.pop();
            }
        }

        let mut seen = Vec::new();
        walk(&public_command(), &mut Vec::new(), &mut seen);
        let titles: std::collections::BTreeSet<&str> =
            seen.iter().map(|(title, _)| title.as_str()).collect();
        for expected in [
            "sweep",
            "sweep-doctor",
            "sweep-rules",
            "sweep-rules-list",
            "sweep-uninstall",
            "sweep-completions",
        ] {
            assert!(titles.contains(expected), "{titles:?}");
        }
        assert!(
            !titles.iter().any(|title| title.starts_with("sweep-__")),
            "a hidden helper has no page: {titles:?}"
        );

        // Every `sweep-*(1)` a page points at has to exist, or the page sends
        // the reader to a command that is not on the system.
        for (title, text) in &seen {
            for reference in references(text) {
                assert!(
                    titles.contains(reference.as_str()),
                    "`{title}` refers to `{reference}(1)`, which has no page"
                );
            }
        }
    }

    /// Every `name(1)` cross-reference in a page, in the order it appears.
    ///
    /// `clap_mangen` writes the dash as the roff escape `\-`, so the text is
    /// unescaped first; scanning the source would read `sweep\-doctor` as
    /// `-doctor` and report a reference that is not there.
    fn references(page: &str) -> Vec<String> {
        let unescaped = page.replace("\\-", "-");
        let page = unescaped.as_str();
        let mut found = Vec::new();
        let marker = "(1)";
        let mut rest = page;
        while let Some(index) = rest.find(marker) {
            let head = &rest[..index];
            let name: String = head
                .chars()
                .rev()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect::<Vec<char>>()
                .into_iter()
                .rev()
                .collect();
            if !name.is_empty() {
                found.push(name);
            }
            rest = &rest[index + marker.len()..];
        }
        found
    }

    #[test]
    fn a_page_path_is_looked_up_from_the_root() {
        let root = public_command();
        for path in [
            vec!["clean".to_string()],
            vec!["analyze".to_string()],
            vec!["rules".to_string(), "list".to_string()],
        ] {
            assert!(find(&root, &path).is_some(), "{path:?} must exist");
        }
        assert!(find(&root, &["nosuchcommand".to_string()]).is_none());
        assert!(find(&root, &["clean".to_string(), "list".to_string()]).is_none());
        assert_eq!(title_for(&[]), "sweep");
        assert_eq!(
            title_for(&["rules".to_string(), "list".to_string()]),
            "sweep-rules-list"
        );
    }

    #[test]
    fn the_generated_definition_does_not_carry_the_hidden_helpers() {
        let command = public_command();
        let visible: Vec<&str> = command
            .get_subcommands()
            .filter(|sub| !sub.is_hide_set())
            .map(|sub| sub.get_name())
            .collect();
        assert!(
            !visible.contains(&"__apply"),
            "the elevated child is not a user command: {visible:?}"
        );
        assert!(
            !visible.contains(&"__manpage"),
            "the generator is not a user command: {visible:?}"
        );
        assert!(
            visible.contains(&"uninstall") && visible.contains(&"completions"),
            "{visible:?}"
        );
    }
}
