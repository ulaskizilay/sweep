//! `sweep` — terminal cleanup for Arch Linux.
//!
//! The binary is a thin shell around `sweep-core`: argument parsing, output
//! formatting, and exit codes. No policy lives here.

#![deny(unsafe_code)]

mod analyze;
mod consent;
mod doctor;
mod format;
mod history;
mod optimize;
mod orphan_cache;
mod packaging;
mod pipeline;
mod rules;
mod status;
mod trash;
mod uninstall;

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sweep_core::privilege;
use sweep_core::probe::RealProbe;
use sweep_core::rules::Section;

#[derive(Debug, Parser)]
#[command(
    name = "sweep",
    version,
    about = "Terminal cleanup and maintenance for Arch Linux",
    long_about = "sweep reclaims cache, log and build space on Arch Linux through a single \
                  validated deletion path. Every action is previewable, logged, and refuses to \
                  touch package-owned, read-only, or symlinked-out paths.",
    disable_help_subcommand = true
)]
pub(crate) struct Cli {
    /// Machine-readable JSON output.
    #[arg(long, global = true)]
    json: bool,

    /// Increase log verbosity (-v, -vv).
    #[arg(long, short, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Report what sweep can see: mounts, base directories, capabilities.
    Doctor,

    /// Inspect the rule catalog: `list` shows it, `verify` compiles it.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },

    /// Reclaim cache, log and build space through the validated plan.
    Clean {
        /// Show the plan and stop: no deletion, no operation-log entry.
        #[arg(long, conflicts_with = "yes")]
        dry_run: bool,

        /// Apply the plan without asking. Required when stdin is not a terminal.
        #[arg(long)]
        yes: bool,

        /// Also sweep root-owned system caches, through run0 or sudo.
        ///
        /// Without this flag, an interactive run asks once before elevating and
        /// a non-interactive run leaves the system section in place.
        #[arg(long)]
        privileged: bool,

        /// Restrict the run to one or more sections (`--only dev-tools`).
        #[arg(long, value_name = "SECTION")]
        only: Vec<Section>,
    },

    /// A compact, read-only health summary: disk, memory, caches, last run.
    Status,

    /// Remove build artifacts from the projects in your home directory.
    ///
    /// A directory is only a target when the manifest beside it says the build
    /// produced it: `node_modules` next to a `package.json`, `target` next to a
    /// `Cargo.toml`. The manifest is also the recipe, so the artifact comes back
    /// with one install command.
    Purge {
        /// Show the plan and stop: no deletion, no operation-log entry.
        #[arg(long, conflicts_with = "yes")]
        dry_run: bool,

        /// Apply the plan without asking. Required when stdin is not a terminal.
        #[arg(long)]
        yes: bool,
    },

    /// Remove installer files that have already been installed or can be fetched again.
    ///
    /// The target is the archive, never the installed program: package files and
    /// images under `~/Downloads` that nobody has touched for a month.
    Installer {
        /// Show the plan and stop: no deletion, no operation-log entry.
        #[arg(long, conflicts_with = "yes")]
        dry_run: bool,

        /// Apply the plan without asking. Required when stdin is not a terminal.
        #[arg(long)]
        yes: bool,
    },

    /// Remove packages, and show what pacman would remove first.
    ///
    /// With no name, this lists what is installed explicitly and what is an
    /// orphan. With names, it asks pacman what the transaction would be, prints
    /// it with a size, and only then runs `pacman -Rs` as root. Sweep never
    /// deletes a `/usr` path itself.
    Uninstall {
        /// Packages to remove. Nothing is removed without at least one.
        #[arg(value_name = "PACKAGE")]
        packages: Vec<String>,

        /// Show the transaction and stop: no removal, no operation-log entry.
        #[arg(long, conflicts_with = "yes")]
        dry_run: bool,

        /// Remove without asking. Required when stdin is not a terminal.
        #[arg(long)]
        yes: bool,
    },

    /// Rebuild the user-side indexes through the tools that own them.
    Optimize {
        /// Show the tasks and the commands, run nothing.
        #[arg(long, conflicts_with = "yes")]
        dry_run: bool,
        /// Run without asking.
        #[arg(long)]
        yes: bool,
    },

    /// What sweep did: the operation log, grouped by run.
    History {
        /// How many runs to print, newest first (default 20).
        #[arg(
            long,
            value_name = "N",
            default_value_t = history::DEFAULT_SESSIONS,
            value_parser = clap::value_parser!(u16).range(1..=1_000)
        )]
        limit: u16,
    },

    /// Explore disk usage, and move a chosen entry to the trash.
    ///
    /// Without `--largest` this opens a full-screen explorer over the given
    /// directory, or over $HOME. `--largest` prints the biggest files and exits,
    /// which is the mode that works in a pipe.
    Analyze {
        /// Directory to explore. Defaults to $HOME.
        #[arg(value_name = "PATH")]
        path: Option<std::path::PathBuf>,

        /// Print the N largest files below the root and exit (default 20).
        #[arg(
            long,
            value_name = "N",
            num_args = 0..=1,
            default_missing_value = "20",
            value_parser = clap::value_parser!(u16).range(1..=10_000)
        )]
        largest: Option<u16>,
    },

    /// Remove built package archives from AUR helper caches.
    ///
    /// The clone, the sources and the PKGBUILD stay: an edited recipe exists
    /// nowhere else. Only the archive makepkg can build again is removed.
    Aur {
        /// Show the plan and stop: no deletion, no operation-log entry.
        #[arg(long, conflicts_with = "yes")]
        dry_run: bool,

        /// Apply the plan without asking. Required when stdin is not a terminal.
        #[arg(long)]
        yes: bool,
    },

    /// Print a completion script for one shell.
    ///
    /// Written to stdout so the package build can redirect it; sweep never
    /// writes into your home directory on request.
    Completions {
        #[arg(value_name = "SHELL")]
        shell: clap_complete::Shell,
    },

    /// Internal: print one man page, for the package build.
    ///
    /// No argument is `sweep.1`; `rules list` is `sweep-rules-list.1`.
    #[command(name = "__manpage", hide = true)]
    Manpage {
        #[arg(value_name = "COMMAND", num_args = 0..)]
        command: Vec<String>,
    },

    /// Internal: remove root-owned items on behalf of `clean`.
    ///
    /// Hidden, undocumented and never called by a user. It exists so the
    /// elevated process is this same binary: the parent starts it through
    /// `run0` or `sudo` with a fixed argv and the plan on stdin, and the child
    /// re-derives the allowlist from the compiled catalog instead of trusting
    /// the parent. It takes no arguments, because an argv is something the
    /// caller of a privileged program can influence and a pipe is not.
    #[command(name = "__apply", hide = true)]
    Apply,
}

#[derive(Debug, Subcommand)]
enum RulesCommand {
    /// Every rule, its section, its retention and the root it resolves to.
    List,
    /// Compile the built-in packs and the user overlay, and report every error.
    Verify,
}

/// Exit code for a command that exists but is not implemented in this build.
///
/// Held for the commands the later milestones wire up; nothing returns it today.
#[allow(dead_code)]
pub(crate) const EXIT_NOT_IMPLEMENTED: u8 = 4;

/// Exit code for a rule catalog that failed to load.
pub(crate) const EXIT_INVALID_RULES: u8 = 3;

/// Exit code for a command line that cannot be acted on.
///
/// `clap` already uses it for a mistyped flag; `__manpage` uses it for a page
/// path that is not a command, which is the same mistake made by a build script
/// instead of a person.
pub(crate) const EXIT_USAGE: u8 = 2;

/// Exit code for a run the user did not confirm.
///
/// Separate from 1 on purpose: "you said no" and "the syscall failed" are
/// different outcomes, and only the second one means the machine is in a state
/// worth investigating.
pub(crate) const EXIT_DECLINED: u8 = 5;

/// Exit code for a refusal that is about the environment, not the command line.
///
/// Distinct from 2 (usage error) on purpose: a script can tell "you typed the
/// flag wrong" from "this machine or this account cannot run sweep".
pub(crate) const EXIT_UNSUPPORTED_ENVIRONMENT: u8 = 78;

fn main() -> ExitCode {
    // Before anything can print: a pipeline that closed its reader should end
    // this process the way it ends `ls` and `grep`, not with a panic message.
    sweep_core::sys::die_on_broken_pipe();

    let cli = Cli::parse();
    init_tracing(cli.verbose);

    let command = cli.command;

    // The elevated child is the one process that must be root, and it is
    // checked here rather than in `refuse_root`: every other command keeps the
    // blanket refusal, so a new subcommand cannot inherit a privileged habit by
    // being added after this match.
    if matches!(command, Command::Apply) {
        return apply_child();
    }

    // Checked before dispatch, so no other command can acquire a privileged
    // habit: the whole program becomes unreachable as root rather than each new
    // subcommand remembering to refuse.
    if let Err(message) = refuse_root(current_uid()) {
        eprintln!("sweep: {message}");
        return ExitCode::from(EXIT_UNSUPPORTED_ENVIRONMENT);
    }

    match command {
        Command::Doctor => doctor::run(cli.json),
        Command::Rules { command } => match command {
            RulesCommand::List => rules::list(cli.json, cli.verbose),
            RulesCommand::Verify => rules::verify(cli.json, cli.verbose),
        },
        Command::Clean {
            dry_run,
            yes,
            privileged,
            only,
        } => pipeline::run(
            pipeline::Scope::CLEAN,
            cli.json,
            cli.verbose,
            &only,
            dry_run,
            yes,
            privileged,
        ),
        Command::Status => status::run(cli.json, cli.verbose),
        Command::Uninstall {
            packages,
            dry_run,
            yes,
        } => uninstall::run(packages, cli.json, cli.verbose, dry_run, yes),
        Command::History { limit } => history::run(limit as usize, cli.json, cli.verbose),
        Command::Optimize { dry_run, yes } => optimize::run(cli.json, cli.verbose, dry_run, yes),
        Command::Analyze { path, largest } => {
            analyze::run(path, largest.map(usize::from), cli.json, cli.verbose)
        }
        Command::Aur { dry_run, yes } => pipeline::run(
            pipeline::Scope::AUR,
            cli.json,
            cli.verbose,
            &[],
            dry_run,
            yes,
            false,
        ),
        Command::Installer { dry_run, yes } => pipeline::run(
            pipeline::Scope::INSTALLER,
            cli.json,
            cli.verbose,
            &[],
            dry_run,
            yes,
            false,
        ),
        Command::Purge { dry_run, yes } => pipeline::run(
            pipeline::Scope::PURGE,
            cli.json,
            cli.verbose,
            &[],
            dry_run,
            yes,
            false,
        ),
        Command::Completions { shell } => packaging::completions(shell),
        Command::Manpage { command } => packaging::manpage(&command),
        Command::Apply => unreachable!("handled before the root refusal"),
    }
}

/// The body of `sweep __apply`: the elevated half of `clean`.
///
/// It refuses to run as anyone but root, so a user who types the hidden name
/// learns what it is instead of watching it fail on the first `EACCES`. The
/// refusal is not `refuse_root`'s: that message is aimed at a user who ran the
/// whole program as root, and this process is supposed to be root.
fn apply_child() -> ExitCode {
    if current_uid() != 0 {
        eprintln!(
            "sweep __apply: this is clean's internal elevation helper and runs only as root; \
             run `sweep clean` as your normal user instead"
        );
        return ExitCode::from(EXIT_UNSUPPORTED_ENVIRONMENT);
    }

    let probe = match RealProbe::new() {
        Ok(probe) => probe.with_open_scan(),
        Err(error) => {
            eprintln!("sweep __apply: cannot probe this filesystem: {error}");
            return ExitCode::from(EXIT_UNSUPPORTED_ENVIRONMENT);
        }
    };

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    match privilege::run_child(stdin.lock(), &mut stdout, &probe) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // The parent treats a nonzero status as "the elevated half did not
            // run" and leaves the items in place, so this must not pretend the
            // request succeeded.
            eprintln!("sweep __apply: {error}");
            ExitCode::FAILURE
        }
    }
}

fn current_uid() -> u32 {
    // `sweep-cli` denies `unsafe_code` and the syscall lives in `sweep-core::sys`
    // with the rest of them, so the privilege boundary is one crate wide.
    sweep_core::sys::euid()
}

/// A user-scoped tool must not run as root.
///
/// Every base directory, rule file and log path it reads belongs to a user. As
/// root those paths resolve to `/root`'s tree, and a cleanup that decides "this
/// is not mine, skip it" under one identity deletes it under another. The system
/// sections that genuinely need privilege are meant to ask for it one narrow
/// operation at a time, not inherit it from the shell.
fn refuse_root(uid: u32) -> Result<(), String> {
    if uid != 0 {
        return Ok(());
    }
    Err(
        "refusing to run as root; run sweep as your normal user and let it \
         request privilege for the specific operations that need it"
            .to_string(),
    )
}

fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(format!("sweep={level}")));
    // Diagnostics go to stderr so `--json` stays a single document on stdout.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_refused_with_a_reason_and_a_next_step() {
        let message = refuse_root(0).expect_err("uid 0 must be refused");
        assert!(message.contains("root"), "{message}");
        // A refusal that does not say what to do instead is not actionable.
        assert!(message.contains("normal user"), "{message}");
        assert_eq!(EXIT_UNSUPPORTED_ENVIRONMENT, 78);
    }

    #[test]
    fn an_ordinary_user_is_allowed() {
        for uid in [1, 500, 1000, 65534] {
            assert!(refuse_root(uid).is_ok(), "uid {uid} must be allowed");
        }
    }

    #[test]
    fn the_uid_comes_from_the_process_not_from_the_environment() {
        // Reading `$UID` or `$USER` would let `SUDO_UID`-style variables decide
        // whether the refusal fires. The effective uid cannot be spoofed.
        let uid = current_uid();
        assert_eq!(uid, sweep_core::sys::euid());
        if uid != 0 {
            assert!(refuse_root(uid).is_ok());
        }
    }
}
