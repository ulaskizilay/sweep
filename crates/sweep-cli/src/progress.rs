//! A liveness line for scans long enough to look hung.
//!
//! `sweep clean` walks every rule root before it can print a plan. On a real
//! cache that is a minute or more with nothing on screen, which is
//! indistinguishable from a wedged process. On a terminal the scan therefore
//! keeps one line on **stderr** that says which rule it is on and how long the
//! scan has been running; the line is overwritten in place and cleared before
//! the report starts.
//!
//! stderr, not stdout, because stdout carries the plan, the JSON document or a
//! prompt, and a pipe must receive exactly that. JSON output gets no line at
//! all: a document with `\r` in it is not a document.
//!
//! The first update is delayed by one tick, so a fast scan - a small home, a
//! narrow `--only` - prints nothing and does not flash a line on the way out.

use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How often the line is refreshed. Fast enough to look alive, slow enough that
/// a million-entry scan spends no measurable time formatting it.
const TICK: Duration = Duration::from_millis(200);

/// Whether this run gets a live line: only a terminal, and never with `--json`.
fn enabled(json: bool, stderr_is_terminal: bool) -> bool {
    !json && stderr_is_terminal
}

/// One line, as it appears on the terminal.
fn line(label: &str, seconds: u64) -> String {
    format!("  scanning {label}  {seconds}s")
}

/// A live progress line, dropped or finished to clear it.
pub struct Progress {
    inner: Option<Inner>,
}

struct Inner {
    /// What the scan is doing now; written by the scan, read by the ticker.
    label: Arc<Mutex<String>>,
    stop: Arc<AtomicBool>,
    /// Widest line printed, so the clear covers every character.
    width: Arc<AtomicUsize>,
    handle: JoinHandle<()>,
}

impl Progress {
    /// A live line when this run may have one, otherwise an inert value.
    ///
    /// Every method is a no-op on the inert value, so callers do not branch.
    pub fn new(json: bool) -> Self {
        if !enabled(json, io::stderr().is_terminal()) {
            return Self { inner: None };
        }

        let label = Arc::new(Mutex::new("the catalog".to_string()));
        let stop = Arc::new(AtomicBool::new(false));
        let width = Arc::new(AtomicUsize::new(0));
        let thread_label = Arc::clone(&label);
        let thread_stop = Arc::clone(&stop);
        let thread_width = Arc::clone(&width);

        let handle = std::thread::Builder::new()
            .name("sweep-progress".to_string())
            .spawn(move || {
                let started = Instant::now();
                let mut widest = 0;
                let mut stderr = io::stderr();
                loop {
                    // Sleep first: a scan that finishes inside one tick never
                    // prints, so a fast run stays quiet.
                    std::thread::sleep(TICK);
                    if thread_stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let label = thread_label
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone();
                    let text = line(&label, started.elapsed().as_secs());
                    widest = widest.max(text.chars().count());
                    let _ = write!(stderr, "\r{text:<widest$}");
                    let _ = stderr.flush();
                    thread_width.store(widest, Ordering::Relaxed);
                }
            })
            .ok();

        match handle {
            Some(handle) => Self {
                inner: Some(Inner {
                    label,
                    stop,
                    width,
                    handle,
                }),
            },
            // A thread that cannot start is not a reason to fail a cleanup.
            None => Self { inner: None },
        }
    }

    /// Says what the scan is doing now. The ticker picks it up on its next pass.
    pub fn step(&self, label: impl Into<String>) {
        if let Some(inner) = &self.inner {
            *inner
                .label
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = label.into();
        }
    }

    /// Stops the line and clears it. Dropping does the same.
    pub fn finish(self) {}
}

impl Drop for Progress {
    fn drop(&mut self) {
        let Some(inner) = self.inner.take() else {
            return;
        };
        inner.stop.store(true, Ordering::Relaxed);
        let _ = inner.handle.join();
        let width = inner.width.load(Ordering::Relaxed);
        if width > 0 {
            let mut stderr = io::stderr();
            let _ = write!(stderr, "\r{}\r", " ".repeat(width));
            let _ = stderr.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pipe_and_a_json_document_get_no_line() {
        assert!(enabled(false, true), "a terminal gets the line");
        assert!(!enabled(false, false), "a pipe gets nothing");
        assert!(!enabled(true, true), "json stays a document");
        assert!(!enabled(true, false));
    }

    #[test]
    fn the_line_names_the_rule_and_the_elapsed_time() {
        assert_eq!(
            line("dev.uv.cache (12/122)", 7),
            "  scanning dev.uv.cache (12/122)  7s"
        );
    }

    #[test]
    fn an_inert_value_is_a_no_op() {
        let progress = Progress::new(true);
        progress.step("nothing");
        progress.finish();
    }
}
