//! `sweep analyze` — the disk explorer, and the report that does not need one.
//!
//! Two modes, one command, because they answer the same question at different
//! depths. `--largest` prints the biggest files below a root and exits; the bare
//! command opens an explorer over the same root. Neither mode deletes anything
//! on its own: the explorer's only destructive key moves one entry to the
//! freedesktop trash, after a confirmation, and logs the move.
//!
//! The explorer is not a second deletion path. It refuses the same protected
//! roots and identity paths the planner refuses, it never follows a symbolic
//! link, and it moves rather than removes: `analyze` is the one place in sweep
//! where a mistaken keystroke is recoverable, because the user is choosing
//! files by hand rather than approving a rule.

mod app;
mod largest;
mod measure;
mod ui;
mod view;

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use sweep_core::paths::Xdg;

use crate::EXIT_UNSUPPORTED_ENVIRONMENT;

pub fn run(root: Option<PathBuf>, largest: Option<usize>, json: bool, verbose: u8) -> ExitCode {
    let xdg = match Xdg::from_env() {
        Ok(xdg) => xdg,
        Err(error) => {
            eprintln!("sweep analyze: {error}");
            return ExitCode::from(EXIT_UNSUPPORTED_ENVIRONMENT);
        }
    };
    let root = match root {
        Some(root) => absolute(&root),
        None => xdg.home.clone(),
    };

    if let Some(count) = largest {
        return largest::run(&root, count, json, verbose);
    }

    // The explorer needs a terminal on both ends: it reads keys and draws a
    // full-screen frame. Saying which mode works instead is more useful than a
    // rendering error from halfway through the first frame.
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        eprintln!(
            "sweep analyze: the explorer needs a terminal.\n\
             Run `sweep analyze --largest` for the text report, or `sweep analyze --largest N` for more rows."
        );
        return ExitCode::from(EXIT_UNSUPPORTED_ENVIRONMENT);
    }

    ui::run(&root, &xdg, verbose)
}

/// The same path, anchored at the current directory when it is relative.
fn absolute(path: &std::path::Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    match std::env::current_dir() {
        Ok(cwd) => cwd.join(path),
        Err(_) => path.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn a_relative_root_is_anchored_at_the_working_directory() {
        let cwd = std::env::current_dir().expect("cwd");
        assert_eq!(absolute(Path::new("sub/dir")), cwd.join("sub/dir"));
        assert_eq!(absolute(Path::new("/var")), Path::new("/var"));
    }
}
