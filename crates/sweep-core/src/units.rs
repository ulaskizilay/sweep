//! Orphaned systemd user units.
//!
//! A unit that names a binary which is no longer on the machine cannot start.
//! systemd says so at login, into a log nobody reads, and the unit stays in the
//! way until someone notices. This module answers one question about each unit:
//! does the program its `ExecStart` names still exist?
//!
//! Nothing here deletes. A unit file is a few hundred bytes, not a cache, and
//! `systemctl --user disable` is not a cleanup operation - it is a decision about
//! what should start at login. The caller reports the answer and names the
//! command; the user decides.
//!
//! ## What counts as orphaned
//!
//! Only the program in `ExecStart`. `ExecStop`, `ExecReload` and the `*Pre` /
//! `*Post` variants are not checked: a unit whose stop command is gone still
//! starts, and a row that fires on it would be wrong about the thing the user
//! cares about.
//!
//! ## What is not evidence
//!
//! A command holding a systemd specifier (`%h`, `%t`) or a variable (`$HOME`) is
//! **unresolved**, never orphaned: this reader cannot expand it, and expanding it
//! wrongly would report a working unit as broken. The same goes for a unit that
//! cannot be read as UTF-8, and for a bare command name on a machine with no
//! `PATH`. Unknown is a separate count, and it is not a finding.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// One unit whose `ExecStart` program is missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Orphan {
    /// The file name, e.g. `backup.service`.
    pub unit: String,
    /// The `ExecStart` value that names the missing program, as written.
    pub command: String,
}

/// What a scan of one unit directory found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    /// `.service` files that were read.
    pub total: usize,
    /// Units with at least one `ExecStart` program that is gone.
    pub orphaned: Vec<Orphan>,
    /// Units whose command could not be resolved. Unknown, and therefore not a
    /// finding: a false alarm sends the user to a unit that is fine.
    pub unresolved: usize,
    /// The directory is not there. The normal case on a machine without units.
    pub missing: bool,
    /// The directory exists and could not be read.
    pub unreadable: bool,
}

/// Reads every `*.service` file directly in `root` and checks its programs.
///
/// Only the top level is read. `default.target.wants/` and the other `*.wants`
/// directories hold symbolic links to these same files, so walking into them
/// would report one unit twice and follow a link to do it.
pub fn scan(root: &Path, path_env: Option<&OsStr>) -> Report {
    let mut report = Report::default();

    let read = match std::fs::read_dir(root) {
        Ok(read) => read,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            report.missing = true;
            return report;
        }
        Err(_) => {
            report.unreadable = true;
            return report;
        }
    };

    let mut units: Vec<PathBuf> = read
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension() == Some(OsStr::new("service")))
        .collect();
    units.sort();

    for path in units {
        // `symlink_metadata` never follows, so a link inside the directory is
        // not read as if it were the unit it points at.
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let body = match std::fs::read_to_string(&path) {
            Ok(body) => body,
            Err(_) => {
                report.unresolved += 1;
                continue;
            }
        };
        report.total += 1;

        let unit = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();

        let mut missing: Option<String> = None;
        let mut unknown = false;
        for command in exec_starts(&body) {
            let Some(program) = program(&command) else {
                unknown = true;
                continue;
            };
            match resolve(&program, path_env) {
                Resolution::Present => {}
                Resolution::Missing => {
                    if missing.is_none() {
                        missing = Some(command);
                    }
                }
                Resolution::Unknown => unknown = true,
            }
        }

        match missing {
            Some(command) => report.orphaned.push(Orphan { unit, command }),
            None if unknown => report.unresolved += 1,
            None => {}
        }
    }

    report
}

/// Every `ExecStart=` command in `body`, after the last empty assignment.
///
/// An empty `ExecStart=` clears the list, which is how a drop-in removes the
/// commands an earlier file set. Reading the cleared ones as live would report a
/// unit as orphaned on the strength of a command systemd will never run.
fn exec_starts(body: &str) -> Vec<String> {
    let mut commands: Vec<String> = Vec::new();
    for line in body.lines() {
        let Some(value) = line.trim().strip_prefix("ExecStart=") else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            commands.clear();
        } else {
            commands.push(value.to_string());
        }
    }
    commands
}

/// The program a command line runs, with systemd's prefix modifiers removed.
///
/// `-` ignores a failure, `@` sets `argv[0]`, and `+`, `!` and `:` change the
/// privileges the command runs with. They may repeat and appear in any order,
/// and none of them changes which file is executed.
fn program(command: &str) -> Option<String> {
    let mut rest = command.trim_start();
    while let Some(first) = rest.chars().next() {
        if matches!(first, '-' | '@' | '+' | '!' | ':') {
            rest = &rest[first.len_utf8()..];
        } else {
            break;
        }
    }
    if rest.is_empty() {
        return None;
    }
    if let Some(quoted) = rest.strip_prefix('"') {
        let end = quoted.find('"')?;
        return Some(quoted[..end].to_string());
    }
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

enum Resolution {
    Present,
    Missing,
    /// A specifier, a variable, or a bare name with no `PATH` to search.
    Unknown,
}

fn resolve(program: &str, path_env: Option<&OsStr>) -> Resolution {
    if program.contains('%') || program.contains('$') {
        return Resolution::Unknown;
    }
    if program.starts_with('/') {
        // `exists` follows a symbolic link and is false for a broken one, which
        // is the question: can this path be executed right now?
        return if Path::new(program).exists() {
            Resolution::Present
        } else {
            Resolution::Missing
        };
    }
    let Some(path) = path_env else {
        return Resolution::Unknown;
    };
    for directory in std::env::split_paths(path) {
        if directory.join(program).exists() {
            return Resolution::Present;
        }
    }
    Resolution::Missing
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(root: &Path, name: &str, body: &str) {
        fs::create_dir_all(root).expect("mkdir");
        fs::write(root.join(name), body).expect("write");
    }

    fn unit(exec: &str) -> String {
        format!("[Unit]\nDescription=test\n\n[Service]\nExecStart={exec}\n")
    }

    #[test]
    fn a_unit_naming_a_missing_binary_is_orphaned() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("user");
        write(
            &root,
            "gone.service",
            &unit("/nonexistent/sweep-test-program"),
        );

        let report = scan(&root, None);
        assert_eq!(report.total, 1);
        assert_eq!(report.orphaned.len(), 1);
        assert_eq!(report.orphaned[0].unit, "gone.service");
        assert_eq!(
            report.orphaned[0].command,
            "/nonexistent/sweep-test-program"
        );
    }

    #[test]
    fn a_unit_naming_a_binary_that_exists_is_not() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("user");
        let binary = temp.path().join("bin/real");
        fs::create_dir_all(binary.parent().unwrap()).unwrap();
        fs::write(&binary, b"#!/bin/sh\n").unwrap();
        write(&root, "real.service", &unit(&binary.display().to_string()));

        let report = scan(&root, None);
        assert_eq!(report.total, 1);
        assert!(report.orphaned.is_empty(), "{:?}", report.orphaned);
    }

    #[test]
    fn the_prefix_modifiers_do_not_change_which_file_runs() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("user");
        for (name, exec) in [
            ("dash.service", "-/nonexistent/a"),
            ("at.service", "@/nonexistent/b arg"),
            ("colon.service", ":/nonexistent/c"),
            ("mixed.service", "-+!/nonexistent/d"),
        ] {
            write(&root, name, &unit(exec));
        }

        let report = scan(&root, None);
        let names: Vec<&str> = report
            .orphaned
            .iter()
            .map(|orphan| orphan.unit.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "at.service",
                "colon.service",
                "dash.service",
                "mixed.service"
            ]
        );
    }

    #[test]
    fn a_specifier_or_variable_is_unresolved_not_orphaned() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("user");
        write(&root, "home.service", &unit("%h/bin/thing"));
        write(&root, "var.service", &unit("$HOME/bin/thing"));

        let report = scan(&root, None);
        assert_eq!(report.total, 2);
        assert!(report.orphaned.is_empty(), "{:?}", report.orphaned);
        assert_eq!(report.unresolved, 2);
    }

    #[test]
    fn an_empty_assignment_clears_the_commands_before_it() {
        // A drop-in that sets `ExecStart=` to nothing removes the command the
        // main unit file set. The cleared one must not be checked.
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("user");
        write(
            &root,
            "cleared.service",
            "[Service]\nExecStart=/nonexistent/old\nExecStart=\n",
        );
        write(
            &root,
            "kept.service",
            "[Service]\nExecStart=\nExecStart=/nonexistent/new\n",
        );

        let report = scan(&root, None);
        assert_eq!(report.total, 2);
        assert_eq!(report.orphaned.len(), 1);
        assert_eq!(report.orphaned[0].unit, "kept.service");
    }

    #[test]
    fn a_bare_name_is_resolved_on_path() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("user");
        let bin = temp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        fs::write(bin.join("sh"), b"#!/bin/sh\n").unwrap();
        write(&root, "bare.service", &unit("sh -c true"));

        let report = scan(&root, Some(bin.as_os_str()));
        assert!(report.orphaned.is_empty(), "{:?}", report.orphaned);

        let elsewhere = temp.path().join("empty");
        fs::create_dir_all(&elsewhere).unwrap();
        let report = scan(&root, Some(elsewhere.as_os_str()));
        assert_eq!(report.orphaned.len(), 1, "not on PATH is gone");
    }

    #[test]
    fn only_service_files_are_read() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("user");
        write(&root, "notes.txt", "ExecStart=/nonexistent/x\n");
        write(&root, "a.timer", "[Timer]\n");

        let report = scan(&root, None);
        assert_eq!(report.total, 0);
        assert!(report.orphaned.is_empty());
    }

    #[test]
    fn a_wants_directory_is_not_walked() {
        // `default.target.wants/` holds links to the same unit files. Walking in
        // would report one unit twice and follow a link to do it.
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("user");
        write(&root, "gone.service", &unit("/nonexistent/a"));
        fs::create_dir_all(root.join("default.target.wants")).unwrap();
        std::os::unix::fs::symlink(
            root.join("gone.service"),
            root.join("default.target.wants/gone.service"),
        )
        .unwrap();

        let report = scan(&root, None);
        assert_eq!(report.total, 1);
        assert_eq!(report.orphaned.len(), 1);
    }

    #[test]
    fn a_missing_directory_is_reported_rather_than_guessed() {
        let temp = tempfile::tempdir().unwrap();
        let report = scan(&temp.path().join("absent"), None);
        assert!(report.missing);
        assert_eq!(report.total, 0);
        assert!(!report.unreadable);
    }
}
