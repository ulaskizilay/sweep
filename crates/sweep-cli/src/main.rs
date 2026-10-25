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

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match cli.command {
        Command::Doctor => doctor::run(cli.json),
    }
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
