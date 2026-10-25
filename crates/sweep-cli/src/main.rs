//! `sweep` — terminal cleanup for Arch Linux.
//!
//! The binary is a thin shell around `sweep-core`: argument parsing, output
//! formatting, and exit codes. No policy lives here.

#![deny(unsafe_code)]

mod doctor;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

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
struct Cli {
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
}

/// Exit code for a refusal that is about the environment, not the command line.
///
/// Distinct from 2 (usage error) on purpose: a script can tell "you typed the
/// flag wrong" from "this machine or this account cannot run sweep".
pub(crate) const EXIT_UNSUPPORTED_ENVIRONMENT: u8 = 78;

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    // Checked before dispatch, so no command can acquire a privileged habit:
    // the whole program becomes unreachable as root rather than each new
    // subcommand remembering to refuse.
    if let Err(message) = refuse_root(current_uid()) {
        eprintln!("sweep: {message}");
        return ExitCode::from(EXIT_UNSUPPORTED_ENVIRONMENT);
    }

    match cli.command {
        Command::Doctor => doctor::run(cli.json),
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
