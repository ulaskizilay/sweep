//! `sweep optimize` — the user-side indexes, rebuilt by their own tools.
//!
//! Everything here is deliberate and small. Each task is a program that ships
//! with the system, run with a fixed argv, on a directory sweep already knows
//! how to read. Sweep never writes into those directories itself: the tool that
//! owns an index is the only thing that should rewrite it, which is why this is
//! a list of commands rather than another deletion rule.
//!
//! Three boundaries:
//!
//! * **No elevation.** The system-wide half of this maintenance (`mandb`,
//!   `fstrim`, the system journal) needs root and is printed as the command to
//!   run, not executed through a privileged child. The privileged path in sweep
//!   exists for one known set of cache roots, and widening it to arbitrary
//!   maintenance programs would turn a validated plan into "run this as root".
//! * **Nothing runs because it exists.** A task whose program is not installed,
//!   or whose directory is not there, is skipped with the reason, and a plan of
//!   nothing is not a question worth asking.
//! * **Bounded.** Every command runs under `timeout`, so a hook that hangs on a
//!   broken file cannot hold the terminal; a timeout is reported as a failure
//!   with the command named.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::time::Instant;

use serde::Serialize;
use sweep_core::oplog::{encode_path, rfc3339, Action as LogAction, Oplog, Record};
use sweep_core::paths::Xdg;

use crate::consent::{self, Consent};
use crate::format::human_bytes;

/// Seconds one task may run. Long enough for a font index over a large family
/// collection, short enough that a wedged helper is a wait rather than a hang.
const TASK_SECONDS: u64 = 120;

/// One maintenance task, as the table describes it.
struct Task {
    id: &'static str,
    /// What it does, in a phrase a user can judge without reading the man page.
    title: &'static str,
    program: &'static str,
    /// Arguments; `{home}` is replaced by the home directory.
    args: &'static [&'static str],
    /// The directory the task rebuilds, as logged and measured.
    target: &'static str,
    /// Measure this directory before and after, to report what was reclaimed.
    measure: bool,
}

const TASKS: &[Task] = &[
    Task {
        id: "journal-vacuum",
        title: "vacuum your user journal older than 2 weeks",
        program: "journalctl",
        args: &["--user", "--vacuum-time=2weeks"],
        target: "/var/log/journal",
        measure: false,
    },
    Task {
        id: "font-cache",
        title: "rebuild the fontconfig index",
        program: "fc-cache",
        args: &["-f"],
        target: "{home}/.cache/fontconfig",
        measure: true,
    },
    Task {
        id: "desktop-database",
        title: "rebuild the application index",
        program: "update-desktop-database",
        args: &["{home}/.local/share/applications"],
        target: "{home}/.local/share/applications",
        measure: false,
    },
    Task {
        id: "mime-database",
        title: "rebuild the MIME index",
        program: "update-mime-database",
        args: &["{home}/.local/share/mime"],
        target: "{home}/.local/share/mime",
        measure: false,
    },
];

/// Maintenance that needs root, named rather than run.
const PRIVILEGED: &[(&str, &str)] = &[
    ("sudo mandb", "refresh the man page index"),
    ("sudo fstrim --all", "return unused blocks to the device"),
    (
        "sudo journalctl --vacuum-time=2weeks",
        "trim the system journal",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum State {
    /// A dry run: this task would have run.
    Planned,
    Ok,
    Failed,
    Skipped,
}

#[derive(Debug, Serialize)]
struct Outcome {
    id: &'static str,
    title: &'static str,
    state: State,
    /// Why it did not run, or why it failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    seconds: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    reclaimed: Option<u64>,
    /// The argv that would run, or did, so a reader can check it.
    #[serde(skip_serializing_if = "Option::is_none")]
    command: Option<String>,
}

#[derive(Debug, Serialize)]
struct Report {
    version: String,
    generated_at: String,
    dry_run: bool,
    outcomes: Vec<Outcome>,
}

/// A task that can run, with its arguments resolved against this home.
struct Scheduled {
    task: &'static Task,
    program: &'static str,
    argv: Vec<OsString>,
    target: PathBuf,
    /// `Err` holds the reason it was skipped.
    ready: Result<(), String>,
}

impl Scheduled {
    fn command_line(&self) -> String {
        let mut parts = Vec::with_capacity(self.argv.len() + 1);
        parts.push(self.program.to_string());
        for arg in &self.argv {
            let arg = arg.to_string_lossy();
            if arg.contains(' ') {
                parts.push(format!("\"{arg}\""));
            } else {
                parts.push(arg.into_owned());
            }
        }
        parts.join(" ")
    }
}

pub fn run(json: bool, verbose: u8, dry_run: bool, yes: bool) -> ExitCode {
    let xdg = match Xdg::from_env() {
        Ok(xdg) => xdg,
        Err(error) => {
            eprintln!("sweep optimize: {error}");
            return ExitCode::from(crate::EXIT_UNSUPPORTED_ENVIRONMENT);
        }
    };

    let scheduled = plan(&xdg);
    let runnable = scheduled.iter().filter(|task| task.ready.is_ok()).count();

    if dry_run {
        let report = Report {
            version: sweep_core::VERSION.to_string(),
            generated_at: rfc3339(now_unix()),
            dry_run: true,
            outcomes: scheduled.iter().map(planned).collect(),
        };
        return emit(json, &report, &scheduled, &xdg, verbose, ExitCode::SUCCESS);
    }

    if runnable == 0 {
        let report = Report {
            version: sweep_core::VERSION.to_string(),
            generated_at: rfc3339(now_unix()),
            dry_run: false,
            outcomes: scheduled.iter().map(skipped).collect(),
        };
        return emit(json, &report, &scheduled, &xdg, verbose, ExitCode::SUCCESS);
    }

    if !json {
        print!("{}", plan_text(&scheduled, &xdg));
        // The question belongs on the terminal, not in a redirected report.
        eprintln!("  sweep runs these as you, with a {TASK_SECONDS}s deadline each.\n");
    }
    match consent::ask(
        &format!("Run these {runnable} tasks?"),
        &format!("run {runnable} maintenance tasks"),
        yes,
    ) {
        Consent::Granted => {}
        Consent::Declined(message) => {
            eprintln!("sweep optimize: {message}");
            return ExitCode::from(crate::EXIT_DECLINED);
        }
    }

    let session = format!("optimize-{}", now_unix());
    let mut oplog = Oplog::open(&xdg.state_dir(), session.clone()).ok();
    let mut outcomes: Vec<Outcome> = Vec::with_capacity(scheduled.len());
    let mut failed = false;

    for task in &scheduled {
        let outcome = match &task.ready {
            Err(_) => skipped(task),
            Ok(()) => {
                let outcome = execute(task);
                if outcome.state == State::Failed {
                    failed = true;
                }
                outcome
            }
        };
        // Print each result as it lands, so a slow task does not look like a
        // stuck one.
        if !json {
            println!(
                "{}",
                result_line(report_width(&scheduled), &outcome, verbose)
            );
        }
        if let Some(log) = oplog.as_mut() {
            log_outcome(log, &outcome, task, &session);
        }
        outcomes.push(outcome);
    }

    let report = Report {
        version: sweep_core::VERSION.to_string(),
        generated_at: rfc3339(now_unix()),
        dry_run: false,
        outcomes,
    };
    let code = if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    };
    emit(json, &report, &scheduled, &xdg, verbose, code)
}

/// Prints the report in the shape the caller asked for.
fn emit(
    json: bool,
    report: &Report,
    scheduled: &[Scheduled],
    xdg: &Xdg,
    verbose: u8,
    code: ExitCode,
) -> ExitCode {
    if json {
        match serde_json::to_string_pretty(report) {
            Ok(text) => println!("{text}"),
            Err(error) => {
                eprintln!("sweep optimize: cannot serialise report: {error}");
                return ExitCode::FAILURE;
            }
        }
        return code;
    }
    if report.dry_run {
        print!("{}", plan_text(scheduled, xdg));
        println!("  dry run: nothing was run and nothing was logged.");
        return code;
    }
    if report
        .outcomes
        .iter()
        .all(|outcome| outcome.state == State::Skipped)
    {
        print!("{}", plan_text(scheduled, xdg));
        println!("  nothing to run on this machine.");
        return code;
    }
    println!();
    if verbose > 0 {
        println!("  the system-wide half is listed in the plan; run it yourself when it matters.");
    } else {
        println!("  system-wide maintenance is listed in the plan; sweep never runs it as root.");
    }
    code
}

/// The full plan: what will run, what cannot, and what sweep will not run.
fn plan_text(scheduled: &[Scheduled], xdg: &Xdg) -> String {
    let mut out = String::new();
    out.push_str("sweep optimize — user-side index maintenance\n\n");
    let width = scheduled
        .iter()
        .map(|task| task.task.id.len())
        .max()
        .unwrap_or(0);
    let title_width = scheduled
        .iter()
        .map(|task| task.task.title.len())
        .max()
        .unwrap_or(0);

    for task in scheduled {
        let target = display_path(&task.target, xdg);
        let size = match &task.ready {
            Err(_) => String::new(),
            Ok(()) => match directory_bytes(&task.target) {
                Some(bytes) => format!("  ({})", human_bytes(bytes)),
                None => String::new(),
            },
        };
        out.push_str(&format!(
            "  {:<width$}  {:<title_width$}  {target}{size}\n",
            task.task.id,
            task.task.title,
            width = width
        ));
        if let Err(reason) = &task.ready {
            out.push_str(&format!(
                "  {:<width$}  skipped: {reason}\n",
                "",
                width = width
            ));
        }
    }

    out.push_str(
        "\n  system-wide maintenance needs root, so sweep names it instead of running it:\n",
    );
    for (command, what) in PRIVILEGED {
        out.push_str(&format!("    {command:<38}  {what}\n"));
    }
    out.push('\n');
    out
}

fn report_width(scheduled: &[Scheduled]) -> usize {
    scheduled
        .iter()
        .map(|task| task.task.id.len())
        .max()
        .unwrap_or(0)
}

/// One line per task, printed as soon as it finishes.
fn result_line(width: usize, outcome: &Outcome, verbose: u8) -> String {
    // The message goes after the padded columns, so a short id does not shift
    // it. Two spaces, not a colon: the word already says what happened.
    let (word, detail) = match outcome.state {
        State::Ok => ("ok", String::new()),
        State::Failed => (
            "failed",
            format!(
                "  {}",
                outcome.message.as_deref().unwrap_or("unknown error")
            ),
        ),
        State::Skipped | State::Planned => (
            "skipped",
            format!(
                "  {}",
                outcome.message.as_deref().unwrap_or("nothing to do")
            ),
        ),
    };
    let time = if outcome.state == State::Ok {
        format!("  {:.1}s", outcome.seconds)
    } else {
        String::new()
    };
    let saved = match outcome.reclaimed {
        Some(bytes) if bytes > 0 => format!("  · {} reclaimed", human_bytes(bytes)),
        _ => String::new(),
    };
    let mut line = format!("  {word:<8}{:<width$}{time}{saved}{detail}", outcome.id);
    if verbose > 0 {
        if let Some(command) = &outcome.command {
            line.push_str(&format!("\n           ran: {command}"));
        }
    }
    line
}

fn planned(task: &Scheduled) -> Outcome {
    Outcome {
        id: task.task.id,
        title: task.task.title,
        state: match task.ready {
            Ok(()) => State::Planned,
            Err(_) => State::Skipped,
        },
        message: task.ready.as_ref().err().cloned(),
        seconds: 0.0,
        reclaimed: None,
        command: match task.ready {
            Ok(()) => Some(task.command_line()),
            Err(_) => None,
        },
    }
}

fn skipped(task: &Scheduled) -> Outcome {
    Outcome {
        id: task.task.id,
        title: task.task.title,
        state: State::Skipped,
        message: task.ready.as_ref().err().cloned(),
        seconds: 0.0,
        reclaimed: None,
        command: None,
    }
}

fn execute(task: &Scheduled) -> Outcome {
    let before = if task.task.measure {
        directory_bytes(&task.target)
    } else {
        None
    };
    let started = Instant::now();
    let result = std::process::Command::new("timeout")
        .arg(format!("{TASK_SECONDS}s"))
        .arg(task.program)
        .args(&task.argv)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output();
    let seconds = started.elapsed().as_secs_f64();

    match result {
        Ok(output) if output.status.success() => {
            let after = if task.task.measure {
                directory_bytes(&task.target)
            } else {
                None
            };
            Outcome {
                id: task.task.id,
                title: task.task.title,
                state: State::Ok,
                message: None,
                seconds,
                reclaimed: match (before, after) {
                    (Some(before), Some(after)) => Some(before.saturating_sub(after)),
                    _ => None,
                },
                command: Some(task.command_line()),
            }
        }
        Ok(output) => {
            // `timeout` exits 124 when the deadline passed, which is a failure
            // with a different fix from "the tool itself refused".
            let timed_out = output.status.code() == Some(124);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr = stderr.trim();
            let message = if timed_out {
                format!("timed out after {TASK_SECONDS}s")
            } else if stderr.is_empty() {
                match output.status.code() {
                    Some(code) => format!("exit status {code}"),
                    None => "killed by a signal".to_string(),
                }
            } else {
                format!(
                    "exit status {}: {}",
                    output
                        .status
                        .code()
                        .map(|code| code.to_string())
                        .unwrap_or_else(|| "signal".to_string()),
                    first_line(stderr)
                )
            };
            Outcome {
                id: task.task.id,
                title: task.task.title,
                state: State::Failed,
                message: Some(message),
                seconds,
                reclaimed: None,
                command: Some(task.command_line()),
            }
        }
        Err(error) => Outcome {
            id: task.task.id,
            title: task.task.title,
            state: State::Failed,
            message: Some(format!("cannot run {}: {error}", task.program)),
            seconds,
            reclaimed: None,
            command: Some(task.command_line()),
        },
    }
}

fn first_line(text: &str) -> String {
    let line = text.lines().next().unwrap_or("").trim();
    if line.chars().count() > 160 {
        format!("{}…", line.chars().take(159).collect::<String>())
    } else {
        line.to_string()
    }
}

fn log_outcome(log: &mut Oplog, outcome: &Outcome, task: &Scheduled, session: &str) {
    let (action, reason) = match outcome.state {
        State::Ok => (LogAction::Rebuilt, None),
        // One reason per row; a free-form message is the honest code when the
        // failure came from another program.
        State::Failed => (LogAction::Failed, outcome.message.as_deref()),
        State::Skipped | State::Planned => return,
    };
    let (path, path_hex) = encode_path(&task.target);
    log.append(Record {
        ts: rfc3339(now_unix()),
        cmd: "optimize",
        session,
        action,
        rule: task.task.id,
        path,
        path_hex,
        bytes: outcome.reclaimed.unwrap_or(0),
        reason,
        detail: Some(format!("ran {}", task.command_line())),
    });
}

/// Resolves the table against this machine and this home.
fn plan(xdg: &Xdg) -> Vec<Scheduled> {
    TASKS
        .iter()
        .map(|task| {
            let target = resolve(task.target, xdg);
            let argv: Vec<OsString> = task
                .args
                .iter()
                .map(|arg| OsString::from(arg.replace("{home}", &xdg.home.to_string_lossy())))
                .collect();
            let ready = if program_exists(task.program) {
                if target.exists() {
                    Ok(())
                } else {
                    Err(format!(
                        "{} does not exist, so there is no index to rebuild",
                        target.display()
                    ))
                }
            } else {
                Err(format!("{} is not installed", task.program))
            };
            Scheduled {
                task,
                program: task.program,
                argv,
                target,
                ready,
            }
        })
        .collect()
}

fn resolve(template: &str, xdg: &Xdg) -> PathBuf {
    let expanded = template.replace("{home}", &xdg.home.to_string_lossy());
    PathBuf::from(expanded)
}

fn display_path(path: &Path, xdg: &Xdg) -> String {
    match path.strip_prefix(&xdg.home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => path.display().to_string(),
    }
}

/// Looks a program up in `PATH` without spawning a shell.
fn program_exists(program: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let candidate = dir.join(program);
        std::fs::metadata(&candidate)
            .map(|meta| meta.is_file() && is_executable(&meta))
            .unwrap_or(false)
    })
}

fn is_executable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

/// Accounted size of a directory, or `None` when it cannot be read.
fn directory_bytes(path: &Path) -> Option<u64> {
    let probe = sweep_core::probe::RealProbe::new().ok()?;
    let limits = sweep_core::scan::Limits::default();
    let mut spec = sweep_core::scan::Spec::new(usize::MAX, &limits);
    spec.select = sweep_core::scan::Select::Everything;
    let collected = sweep_core::scan::collect(path, path, 0, &spec, &probe);
    if collected.missing_root || collected.root_unreadable {
        return None;
    }
    Some(collected.bytes)
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

    fn xdg_at(home: &Path) -> Xdg {
        Xdg::resolve(|key| match key {
            "HOME" => Some(home.as_os_str().to_os_string()),
            _ => None,
        })
        .expect("home")
    }

    #[test]
    fn every_task_in_the_table_is_unique_and_names_a_target() {
        let mut ids: Vec<&str> = TASKS.iter().map(|task| task.id).collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), count, "two tasks share an id");
        for task in TASKS {
            assert!(!task.target.is_empty(), "{} has no target", task.id);
            assert!(!task.program.is_empty(), "{} has no program", task.id);
        }
    }

    #[test]
    fn a_task_whose_directory_is_missing_is_skipped_with_a_reason() {
        let temp = tempfile::tempdir().expect("tempdir");
        let xdg = xdg_at(temp.path());
        let planned = plan(&xdg);
        let font = planned
            .iter()
            .find(|task| task.task.id == "font-cache")
            .expect("font-cache is in the table");
        match &font.ready {
            Err(reason) => assert!(reason.contains("does not exist"), "{reason}"),
            Ok(()) => panic!("the fixture home has no font cache"),
        }
    }

    #[test]
    fn a_present_directory_and_program_makes_a_task_runnable() {
        let temp = tempfile::tempdir().expect("tempdir");
        let xdg = xdg_at(temp.path());
        std::fs::create_dir_all(xdg.home.join(".cache/fontconfig")).expect("mkdir");
        let planned = plan(&xdg);
        let font = planned
            .iter()
            .find(|task| task.task.id == "font-cache")
            .expect("font-cache");
        assert_eq!(font.target, xdg.home.join(".cache/fontconfig"));
        assert_eq!(font.command_line(), "fc-cache -f");
        if program_exists("fc-cache") {
            assert!(font.ready.is_ok(), "{:?}", font.ready);
        }
    }

    #[test]
    fn an_argument_template_resolves_to_the_home_it_was_planned_for() {
        let temp = tempfile::tempdir().expect("tempdir");
        let xdg = xdg_at(temp.path());
        std::fs::create_dir_all(xdg.home.join(".local/share/applications")).expect("mkdir");
        let planned = plan(&xdg);
        let desktop = planned
            .iter()
            .find(|task| task.task.id == "desktop-database")
            .expect("desktop-database");
        let expected = format!("{}/.local/share/applications", xdg.home.display());
        assert_eq!(
            desktop
                .argv
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            [expected]
        );
    }

    #[test]
    fn the_plan_says_what_needs_root_instead_of_running_it() {
        let temp = tempfile::tempdir().expect("tempdir");
        let xdg = xdg_at(temp.path());
        let text = plan_text(&plan(&xdg), &xdg);
        assert!(text.contains("sudo fstrim --all"), "{text}");
        assert!(text.contains("sudo mandb"), "{text}");
        assert!(text.contains("sweep optimize"), "{text}");
        for task in TASKS {
            assert!(text.contains(task.id), "{} missing from the plan", task.id);
        }
    }

    #[test]
    fn a_result_line_says_ok_failed_or_skipped_and_why() {
        let ok = Outcome {
            id: "font-cache",
            title: "rebuild the fontconfig index",
            state: State::Ok,
            message: None,
            seconds: 1.25,
            reclaimed: Some(1024 * 1024),
            command: Some("fc-cache -f".to_string()),
        };
        let text = result_line(14, &ok, 1);
        assert!(text.contains("ok"), "{text}");
        assert!(text.contains("1.0 MiB reclaimed"), "{text}");
        assert!(text.contains("1.2s") || text.contains("1.3s"), "{text}");
        assert!(text.contains("ran: fc-cache -f"), "{text}");

        let failed = Outcome {
            id: "mime-database",
            title: "rebuild the MIME index",
            state: State::Failed,
            message: Some("exit status 1: bad magic".to_string()),
            seconds: 0.1,
            reclaimed: None,
            command: Some("update-mime-database /home/u/.local/share/mime".to_string()),
        };
        let text = result_line(14, &failed, 0);
        assert!(text.contains("failed"), "{text}");
        assert!(text.contains("exit status 1: bad magic"), "{text}");
        assert!(!text.contains("ran:"), "a quiet line names no command");

        let skipped = Outcome {
            id: "journal-vacuum",
            title: "vacuum your user journal older than 2 weeks",
            state: State::Skipped,
            message: Some("journalctl is not installed".to_string()),
            seconds: 0.0,
            reclaimed: None,
            command: None,
        };
        let text = result_line(14, &skipped, 0);
        assert!(text.contains("skipped"), "{text}");
        assert!(text.contains("journalctl is not installed"), "{text}");
    }

    #[test]
    fn a_path_under_home_is_displayed_with_a_tilde() {
        let temp = tempfile::tempdir().expect("tempdir");
        let xdg = xdg_at(temp.path());
        assert_eq!(
            display_path(&xdg.home.join(".cache/fontconfig"), &xdg),
            "~/.cache/fontconfig"
        );
        assert_eq!(
            display_path(Path::new("/var/log/journal"), &xdg),
            "/var/log/journal"
        );
    }

    #[test]
    fn a_missing_program_is_a_skip_not_a_failure() {
        let temp = tempfile::tempdir().expect("tempdir");
        let xdg = xdg_at(temp.path());
        std::fs::create_dir_all(xdg.home.join(".cache/fontconfig")).expect("mkdir");
        static TASK: Task = Task {
            id: "not-a-program",
            title: "nothing",
            program: "sweep-no-such-program-anywhere",
            args: &[],
            target: "{home}/.cache/fontconfig",
            measure: false,
        };
        let scheduled = Scheduled {
            task: &TASK,
            program: TASK.program,
            argv: Vec::new(),
            target: xdg.home.join(".cache/fontconfig"),
            ready: Err(format!("{} is not installed", TASK.program)),
        };
        let outcome = skipped(&scheduled);
        assert_eq!(outcome.state, State::Skipped);
        assert!(outcome
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("is not installed"));
        assert!(
            outcome.command.is_none(),
            "nothing ran, so nothing is named"
        );
    }

    #[test]
    fn a_dry_run_plan_never_claims_a_task_ran() {
        let temp = tempfile::tempdir().expect("tempdir");
        let xdg = xdg_at(temp.path());
        let scheduled = plan(&xdg);
        let outcome = planned(&scheduled[0]);
        assert!(
            matches!(outcome.state, State::Planned | State::Skipped),
            "{outcome:?}"
        );
    }
}
