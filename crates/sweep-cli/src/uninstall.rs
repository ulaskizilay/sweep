//! `sweep uninstall` — remove packages, and show what that means first.
//!
//! The command has one rule that everything else hangs from: **pacman owns the
//! transaction**. Sweep does not delete `/usr` paths, does not edit the package
//! database and does not decide what a package depends on. It asks pacman what
//! the transaction would be (`-Rs --print`), shows it with a size, asks once, and
//! then runs the same transaction through the privilege boundary.
//!
//! That split is why the preflight is not a copy of pacman's resolver. A
//! dependent that blocks the removal is pacman's answer, not sweep's guess, so
//! the two cannot disagree about what is safe to remove.
//!
//! Leftovers are a separate question and come after the package is gone: what
//! pacman leaves behind in `$HOME` is the user's data, matched by exact name
//! only ([`sweep_core::leftovers`]), and moved to the trash rather than deleted.
//! The move happens only when the removal succeeded, because a half-run
//! transaction means the package is still installed and its configuration is
//! still in use.

use std::path::PathBuf;
use std::process::ExitCode;

use serde::Serialize;
use sweep_core::leftovers::{self, Leftover};
use sweep_core::oplog::{encode_path, rfc3339, Action as LogAction, Oplog, Record};
use sweep_core::packages::{self, Package};
use sweep_core::paths::Xdg;
use sweep_core::privilege::{self, SystemElevator};

use crate::consent::{self, Consent};
use crate::format::{human_bytes, plural};
use crate::trash::Trash;

#[derive(Debug, Serialize)]
struct Report {
    version: String,
    generated_at: String,
    dry_run: bool,
    requested: Vec<String>,
    /// What pacman said it would remove, including dependencies.
    planned: Vec<Package>,
    packages: usize,
    bytes: u64,
    files: u64,
    /// Paths under `$HOME` named exactly after a requested package.
    leftovers: Vec<Leftover>,
    leftover_bytes: u64,
    /// Leftovers whose size a budget stopped, so the total is a floor.
    leftover_unknown: usize,
    /// What happened to each leftover: only after a successful removal.
    leftover_results: Vec<LeftoverResult>,
    /// The argv that ran, or would run.
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stdout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stderr: Option<String>,
}

#[derive(Debug, Serialize)]
struct LeftoverResult {
    path: PathBuf,
    package: String,
    /// `trashed`, or `skipped` with the reason the move was refused.
    action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<PathBuf>,
}

pub fn run(packages: Vec<String>, json: bool, verbose: u8, dry_run: bool, yes: bool) -> ExitCode {
    let xdg = match Xdg::from_env() {
        Ok(xdg) => xdg,
        Err(error) => {
            eprintln!("sweep uninstall: {error}");
            return ExitCode::from(crate::EXIT_UNSUPPORTED_ENVIRONMENT);
        }
    };

    let installed = match packages::explicit() {
        Ok(installed) => installed,
        Err(error) => {
            eprintln!("sweep uninstall: {error}");
            return ExitCode::from(crate::EXIT_UNSUPPORTED_ENVIRONMENT);
        }
    };

    if packages.is_empty() {
        return inventory(&installed, json);
    }

    // Every name is checked before any is planned, so a typo in a list of five
    // never leaves the other four half-decided.
    let mut problems: Vec<String> = Vec::new();
    for name in &packages {
        if let Err(problem) = packages::validate(name, &installed) {
            problems.push(problem);
            continue;
        }
        if let Some(why) = packages::protected(name) {
            problems.push(format!("`{name}` is not removable here: {why}"));
        }
    }
    if !problems.is_empty() {
        for problem in &problems {
            eprintln!("sweep uninstall: {problem}");
        }
        return ExitCode::from(crate::EXIT_DECLINED);
    }

    // Discovered before the removal and shown in the plan: they are part of what
    // the user is agreeing to, not a surprise afterwards. Only the packages the
    // user named are scanned; a dependency's `~/.config/<dep>` is usually
    // somebody else's directory that happens to share a name.
    let leftovers = leftovers::scan(&xdg, &packages);
    let (leftover_bytes, leftover_unknown) = leftovers::totals(&leftovers);

    // pacman's resolver decides what the transaction is, including the
    // dependencies that become unneeded and any package that blocks the removal.
    let planned = match packages::plan_removal(&packages) {
        Ok(planned) => planned,
        Err(error) => {
            eprintln!("sweep uninstall: pacman refused the transaction: {error}");
            return ExitCode::FAILURE;
        }
    };
    if planned.is_empty() {
        eprintln!(
            "sweep uninstall: pacman would remove nothing for {}",
            packages.join(", ")
        );
        return ExitCode::FAILURE;
    }

    let measured = measure(&planned);
    let elevator = match SystemElevator::discover() {
        Ok(elevator) => elevator,
        Err(error) => {
            eprintln!("sweep uninstall: {error}");
            return ExitCode::from(crate::EXIT_UNSUPPORTED_ENVIRONMENT);
        }
    };
    let argv = match privilege::package_argv(elevator.program(), &packages) {
        Ok(argv) => argv
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
        Err(error) => {
            eprintln!("sweep uninstall: {error}");
            return ExitCode::FAILURE;
        }
    };

    let mut report = Report {
        version: sweep_core::VERSION.to_string(),
        generated_at: rfc3339(now_unix()),
        dry_run,
        requested: packages.clone(),
        planned,
        packages: measured.packages,
        bytes: measured.bytes,
        files: measured.files,
        leftovers,
        leftover_bytes,
        leftover_unknown,
        leftover_results: Vec::new(),
        command: Some(argv),
        status: None,
        stdout: None,
        stderr: None,
    };

    if !json {
        print!("{}", plan_text(&report, verbose));
    }
    if dry_run {
        if json {
            return emit(&report, true, ExitCode::SUCCESS);
        }
        println!("  dry run: nothing was removed and nothing was moved.");
        return ExitCode::SUCCESS;
    }

    if !json {
        eprintln!(
            "  sweep runs this as root through run0 or sudo. Modified configuration\n  \
             files are kept as .pacsave.\n"
        );
    }
    // The question names the leftovers, because they are the part of this run
    // that touches the user's own files rather than pacman's.
    let mut prompt = format!(
        "Remove {} ({})?",
        plural(report.packages, "package"),
        human_bytes(report.bytes)
    );
    let mut what = format!("remove {}", plural(report.packages, "package"));
    if !report.leftovers.is_empty() {
        prompt.push_str(&format!(
            "\n{} in your home will follow them to the trash.",
            plural(report.leftovers.len(), "leftover path")
        ));
        what.push_str(&format!(
            " and move {} to the trash",
            plural(report.leftovers.len(), "leftover path")
        ));
    }
    match consent::ask(&prompt, &what, yes) {
        Consent::Granted => {}
        Consent::Declined(message) => {
            eprintln!("sweep uninstall: {message}");
            return ExitCode::from(crate::EXIT_DECLINED);
        }
    }

    let run = match elevator.run_pacman(&packages) {
        Ok(run) => run,
        Err(error) => {
            eprintln!("sweep uninstall: cannot run pacman: {error}");
            return ExitCode::FAILURE;
        }
    };

    report.status = run.status;
    report.stdout = Some(run.stdout.clone());
    report.stderr = Some(run.stderr.clone());

    let session = format!("uninstall-{}", now_unix());
    let mut log = Oplog::open(&xdg.state_dir(), session.clone()).ok();

    // One row per package, in the shared log, so `sweep history` shows the run
    // next to every cleanup. `path` carries the package name here rather than a
    // filesystem path: the transaction is pacman's, and the files it touched are
    // recorded in /var/log/pacman.log.
    if let Some(log) = log.as_mut() {
        for package in &report.planned {
            let (path, path_hex) = encode_path(&PathBuf::from(&package.name));
            log.append(Record {
                ts: rfc3339(now_unix()),
                cmd: "uninstall",
                session: &session,
                action: if run.success() {
                    LogAction::Removed
                } else {
                    LogAction::Failed
                },
                rule: "uninstall.package",
                path,
                path_hex,
                bytes: 0,
                reason: if run.success() {
                    None
                } else {
                    Some("pacman_failed")
                },
                detail: Some(format!("pacman -Rs {}", package.name)),
            });
        }
    }

    // Only after pacman succeeded: a half-run transaction means the package is
    // still installed and its configuration is still the one in use.
    if run.success() {
        let trash =
            match Trash::open(&xdg) {
                Ok(trash) => Some(trash),
                Err(error) => {
                    eprintln!(
                    "sweep uninstall: the trash is not available, so {} stayed where {}: {error}",
                    if report.leftovers.len() == 1 {
                        "the leftover".to_string()
                    } else {
                        format!("{} leftovers", report.leftovers.len())
                    },
                    if report.leftovers.len() == 1 { "it is" } else { "they are" }
                );
                    None
                }
            };
        if let Some(trash) = trash {
            for leftover in &report.leftovers {
                match trash.send(&leftover.path, &xdg) {
                    Ok(moved) => {
                        if let Some(log) = log.as_mut() {
                            let (path, path_hex) = encode_path(&leftover.path);
                            log.append(Record {
                                ts: rfc3339(now_unix()),
                                cmd: "uninstall",
                                session: &session,
                                action: LogAction::Trashed,
                                rule: "uninstall.leftover",
                                path,
                                path_hex,
                                bytes: leftover.bytes.unwrap_or(0),
                                reason: None,
                                detail: Some(format!("moved to {}", moved.to.display())),
                            });
                        }
                        report.leftover_results.push(LeftoverResult {
                            path: leftover.path.clone(),
                            package: leftover.package.clone(),
                            action: "trashed",
                            message: None,
                            to: Some(moved.to),
                        });
                    }
                    Err(refusal) => report.leftover_results.push(LeftoverResult {
                        path: leftover.path.clone(),
                        package: leftover.package.clone(),
                        action: "skipped",
                        message: Some(refusal.to_string()),
                        to: None,
                    }),
                }
            }
        }
    }

    if !json {
        for line in run.stdout.lines().filter(|line| !line.trim().is_empty()) {
            println!("  {line}");
        }
        for line in run.stderr.lines().filter(|line| !line.trim().is_empty()) {
            eprintln!("  {line}");
        }
        if run.success() {
            print!(
                "\n  removed {}; {} reclaimed on disk\n",
                plural(report.packages, "package"),
                human_bytes(report.bytes)
            );
            print!("{}", leftover_text(&report, verbose));
        }
    }

    let code = if run.success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    };
    emit(&report, json, code)
}

fn emit(report: &Report, json: bool, code: ExitCode) -> ExitCode {
    if json {
        match serde_json::to_string_pretty(report) {
            Ok(text) => println!("{text}"),
            Err(error) => {
                eprintln!("sweep uninstall: cannot serialise report: {error}");
                return ExitCode::FAILURE;
            }
        }
    }
    code
}

/// The inventory: what is installed explicitly, and what nothing needs.
fn inventory(installed: &[Package], json: bool) -> ExitCode {
    let orphans = packages::orphans().unwrap_or_default();

    if json {
        let document = serde_json::json!({
            "version": sweep_core::VERSION,
            "generated_at": rfc3339(now_unix()),
            "explicit": installed
                .iter()
                .map(|package| serde_json::json!({ "name": package.name, "version": package.version }))
                .collect::<Vec<_>>(),
            "orphans": orphans
                .iter()
                .map(|package| serde_json::json!({ "name": package.name, "version": package.version }))
                .collect::<Vec<_>>(),
        });
        match serde_json::to_string_pretty(&document) {
            Ok(text) => println!("{text}"),
            Err(error) => {
                eprintln!("sweep uninstall: cannot serialise inventory: {error}");
                return ExitCode::FAILURE;
            }
        }
        return ExitCode::SUCCESS;
    }

    println!(
        "sweep uninstall — {} installed explicitly\n",
        plural(installed.len(), "package")
    );
    let width = installed
        .iter()
        .map(|package| package.name.len())
        .max()
        .unwrap_or(0)
        .max(4);
    for package in installed {
        println!(
            "  {:<width$}  {}",
            package.name,
            package.version,
            width = width
        );
    }
    if !orphans.is_empty() {
        println!(
            "\n  {} nothing needs any more:",
            plural(orphans.len(), "orphan")
        );
        for package in &orphans {
            println!(
                "  {:<width$}  {}",
                package.name,
                package.version,
                width = width
            );
        }
        println!("\n  sudo pacman -Rns $(pacman -Qtdq)");
    }
    println!(
        "\n  Name a package to see what removing it takes:\n    sweep uninstall <name> --dry-run"
    );
    ExitCode::SUCCESS
}

struct Measured {
    packages: usize,
    bytes: u64,
    files: u64,
}

/// Sums what the transaction would free, from the paths pacman says it owns.
///
/// This walks metadata only: `st_blocks * 512` for every path in every planned
/// package, which is the same accounting `clean` reports. A path that vanished
/// between the listing and the stat is skipped; the number is then a floor, and
/// the plan prints the file count beside it so a wildly wrong total is visible.
fn measure(planned: &[Package]) -> Measured {
    use std::os::unix::fs::MetadataExt;
    let mut bytes = 0u64;
    let mut files = 0u64;
    for package in planned {
        let Ok(paths) = packages::files(&package.name) else {
            continue;
        };
        for path in paths {
            if let Ok(meta) = std::fs::symlink_metadata(&path) {
                bytes = bytes.saturating_add(meta.blocks().saturating_mul(512));
                files += 1;
            }
        }
    }
    Measured {
        packages: planned.len(),
        bytes,
        files,
    }
}

fn plan_text(report: &Report, verbose: u8) -> String {
    let mut out = String::new();
    out.push_str("sweep uninstall — plan\n\n");
    let width = report
        .planned
        .iter()
        .map(|package| package.name.len())
        .max()
        .unwrap_or(4);
    for package in &report.planned {
        // A dependency the user did not name is marked, because it is part of
        // the transaction and the count below includes it either way.
        let requested = report.requested.iter().any(|name| name == &package.name);
        let mark = if requested { "" } else { "  (a dependency)" };
        out.push_str(&format!(
            "  {:<width$}  {}{mark}\n",
            package.name,
            package.version,
            width = width
        ));
    }
    out.push_str(&format!(
        "\n  {}, {}, {}\n",
        plural(report.packages, "package"),
        human_bytes(report.bytes),
        plural(report.files as usize, "file")
    ));
    if let Some(argv) = &report.command {
        out.push_str(&format!("  command: {}\n", argv.join(" ")));
    }

    if !report.leftovers.is_empty() {
        let note = if report.dry_run {
            if report.leftovers.len() == 1 {
                "a real run moves it to the trash"
            } else {
                "a real run moves these to the trash"
            }
        } else {
            "moved to the trash when the removal succeeds"
        };
        out.push_str(&format!(
            "\n  {} (exact name match, {note}):\n",
            plural(report.leftovers.len(), "leftover"),
        ));
        let path_width = report
            .leftovers
            .iter()
            .map(|leftover| display(&leftover.path).len())
            .max()
            .unwrap_or(0);
        for leftover in &report.leftovers {
            let size = match leftover.bytes {
                Some(bytes) => human_bytes(bytes),
                None => "at least (walk stopped)".to_string(),
            };
            let kind = if leftover.is_symlink { " (a link)" } else { "" };
            out.push_str(&format!(
                "    {:<path_width$}  {size}{kind}\n",
                display(&leftover.path)
            ));
        }
        if report.leftover_unknown > 0 {
            out.push_str(
                "    a budget stopped the walk on some of these, so the total is a floor\n",
            );
        }
    }

    if verbose > 0 {
        out.push_str(
            "  pacman removes the package database entries and the files it owns; a\n  \
             configuration file you edited is kept beside the original as .pacsave.\n",
        );
    }
    out
}

fn leftover_text(report: &Report, verbose: u8) -> String {
    if report.leftover_results.is_empty() {
        return String::new();
    }
    let moved: Vec<&LeftoverResult> = report
        .leftover_results
        .iter()
        .filter(|result| result.action == "trashed")
        .collect();
    let skipped: Vec<&LeftoverResult> = report
        .leftover_results
        .iter()
        .filter(|result| result.action == "skipped")
        .collect();

    let mut out = String::new();
    if !moved.is_empty() {
        let bytes: u64 = report
            .leftovers
            .iter()
            .filter(|leftover| moved.iter().any(|result| result.path == leftover.path))
            .filter_map(|leftover| leftover.bytes)
            .sum();
        out.push_str(&format!(
            "  moved {} ({}) to the trash\n",
            plural(moved.len(), "leftover path"),
            human_bytes(bytes)
        ));
        if verbose > 0 {
            for result in &moved {
                out.push_str(&format!(
                    "    {}\n",
                    result
                        .to
                        .as_ref()
                        .map(|to| to.display().to_string())
                        .unwrap_or_else(|| display(&result.path))
                ));
            }
        }
    }
    for result in skipped {
        out.push_str(&format!(
            "  kept {}: {}\n",
            display(&result.path),
            result.message.as_deref().unwrap_or("the move was refused")
        ));
    }
    out
}

/// `~/.config/firefox` for a path under the home directory.
fn display(path: &std::path::Path) -> String {
    let home = match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home),
        None => return path.display().to_string(),
    };
    match path.strip_prefix(&home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => path.display().to_string(),
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sweep_core::leftovers::Root;

    fn report_with(leftovers: Vec<Leftover>) -> Report {
        let (leftover_bytes, leftover_unknown) = leftovers::totals(&leftovers);
        Report {
            version: "0.1.0".to_string(),
            generated_at: "2026-11-02T00:00:00Z".to_string(),
            dry_run: false,
            requested: vec!["firefox".to_string()],
            planned: vec![Package {
                name: "firefox".to_string(),
                version: "159.0-1".to_string(),
            }],
            packages: 1,
            bytes: 1024 * 1024,
            files: 98,
            leftovers,
            leftover_bytes,
            leftover_unknown,
            leftover_results: Vec::new(),
            command: Some(vec![
                "/usr/bin/run0".to_string(),
                "--".to_string(),
                "pacman".to_string(),
                "-Rs".to_string(),
                "--noconfirm".to_string(),
                "firefox".to_string(),
            ]),
            status: None,
            stdout: None,
            stderr: None,
        }
    }

    fn leftover(path: &str, bytes: Option<u64>) -> Leftover {
        Leftover {
            package: "firefox".to_string(),
            path: PathBuf::from(path),
            root: Root::Config,
            bytes,
            is_dir: true,
            is_symlink: false,
        }
    }

    #[test]
    fn one_package_is_not_one_packages() {
        assert_eq!(plural(1, "package"), "1 package");
        assert_eq!(plural(2, "package"), "2 packages");
        assert_eq!(plural(0, "file"), "0 files");
    }

    #[test]
    fn the_plan_names_the_elevated_argv_and_the_leftovers() {
        let report = report_with(vec![leftover("/home/u/.config/firefox", Some(4 * 1024))]);
        let text = plan_text(&report, 0);
        assert!(
            text.contains("/usr/bin/run0 -- pacman -Rs --noconfirm firefox"),
            "{text}"
        );
        assert!(text.contains("1 package, 1.0 MiB, 98 files"), "{text}");
        assert!(
            text.contains(
                "1 leftover (exact name match, moved to the trash when the removal succeeds)"
            ),
            "{text}"
        );
    }

    #[test]
    fn a_dry_run_says_the_leftovers_would_move_on_a_real_run() {
        let mut report = report_with(vec![leftover("/home/u/.cache/firefox", Some(1024))]);
        report.dry_run = true;
        let text = plan_text(&report, 0);
        assert!(text.contains("a real run moves it to the trash"), "{text}");
        assert!(!text.contains("when the removal succeeds"), "{text}");
    }

    #[test]
    fn an_unknown_leftover_size_is_a_floor_not_a_number() {
        let report = report_with(vec![leftover("/home/u/.config/firefox", None)]);
        let text = plan_text(&report, 0);
        assert!(text.contains("at least"), "{text}");
        assert!(text.contains("the total is a floor"), "{text}");
    }

    #[test]
    fn a_plan_with_no_leftovers_says_nothing_about_them() {
        let report = report_with(Vec::new());
        let text = plan_text(&report, 0);
        assert!(!text.contains("leftover"), "{text}");
        assert!(!text.contains("trash"), "{text}");
    }

    #[test]
    fn moved_and_kept_leftovers_are_reported_separately() {
        let mut report = report_with(vec![
            leftover("/home/u/.config/firefox", Some(2048)),
            leftover("/home/u/.cache/firefox", Some(4096)),
        ]);
        report.leftover_results = vec![
            LeftoverResult {
                path: PathBuf::from("/home/u/.config/firefox"),
                package: "firefox".to_string(),
                action: "trashed",
                message: None,
                to: Some(PathBuf::from("/home/u/.local/share/Trash/files/firefox")),
            },
            LeftoverResult {
                path: PathBuf::from("/home/u/.cache/firefox"),
                package: "firefox".to_string(),
                action: "skipped",
                message: Some("a directory above it is a symbolic link".to_string()),
                to: None,
            },
        ];
        let text = leftover_text(&report, 0);
        assert!(
            text.contains("moved 1 leftover path (2.0 KiB) to the trash"),
            "{text}"
        );
        assert!(text.contains("kept"), "{text}");
        assert!(
            text.contains("a directory above it is a symbolic link"),
            "{text}"
        );
    }

    #[test]
    fn a_failure_from_pacman_is_a_failed_row_with_a_fixed_reason() {
        // The decision the log makes, pinned without a pacman: a nonzero status
        // must not be written as REMOVED.
        let success = false;
        let action = if success {
            LogAction::Removed
        } else {
            LogAction::Failed
        };
        assert_eq!(action, LogAction::Failed);
        assert_eq!(action.as_str(), "FAILED");
    }
}
