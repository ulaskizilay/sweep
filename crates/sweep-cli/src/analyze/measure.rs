//! Measuring the subtrees the explorer shows.
//!
//! A directory's size is the size of everything below it, and there is no cheap
//! way to ask for that on Linux: the walk has to visit every entry. Doing it on
//! the UI thread would freeze the frame for seconds on a home directory, so one
//! worker thread walks the visible directories one at a time and sends each
//! result back. The UI keeps drawing, fills rows in as they arrive, and stays
//! responsive — which is what makes a long measurement tolerable instead of a
//! hang.
//!
//! Each directory gets its own budget. A single shared budget would let one huge
//! tree starve every row after it; a per-row budget means the worst case is one
//! row marked `≥` instead of a screen of blanks.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::Arc;
use std::time::Duration;

use sweep_core::probe::RealProbe;
use sweep_core::scan::{self, Limits, Select, Spec};

use super::view::Measured;

/// Entries one directory may contribute before its size is a lower bound.
///
/// Large enough for a package cache or a kernel source tree, small enough that a
/// mis-aimed root cannot hold the whole explorer hostage.
const ENTRIES_PER_DIRECTORY: usize = 100_000;

/// Wall clock one directory may take. The scan itself also checks a deadline;
/// this is the same number, kept here because the worker owns the decision.
const SECONDS_PER_DIRECTORY: u64 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Update {
    Measured { index: usize, measured: Measured },
    Finished,
}

/// A running measurement, dropped to stop it.
pub struct Sizes {
    receiver: Receiver<Update>,
    cancel: Arc<AtomicBool>,
    pub total: usize,
    pub done: usize,
}

impl Sizes {
    /// Starts one worker for `directories`, which are `(row index, path)` pairs.
    ///
    /// Returns `None` when there is nothing to measure, so the caller does not
    /// have to special-case an empty directory.
    pub fn spawn(directories: Vec<(usize, PathBuf)>) -> Option<Self> {
        if directories.is_empty() {
            return None;
        }
        let total = directories.len();
        let (sender, receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        std::thread::Builder::new()
            .name("sweep-analyze-sizes".to_string())
            .spawn(move || {
                let probe = match RealProbe::new() {
                    Ok(probe) => probe.with_open_scan(),
                    Err(_) => return,
                };
                for (index, path) in directories {
                    if worker_cancel.load(Ordering::Relaxed) {
                        return;
                    }
                    let measured = measure_one(&path, &probe);
                    if sender.send(Update::Measured { index, measured }).is_err() {
                        return;
                    }
                }
                let _ = sender.send(Update::Finished);
            })
            .ok()?;
        Some(Self {
            receiver,
            cancel,
            total,
            done: 0,
        })
    }

    /// One pending update, if any without waiting.
    pub fn poll(&mut self) -> Option<Update> {
        match self.receiver.try_recv() {
            Ok(update) => {
                if matches!(update, Update::Measured { .. }) {
                    self.done += 1;
                }
                Some(update)
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => None,
        }
    }

    pub fn is_finished(&self) -> bool {
        self.done >= self.total
    }
}

impl Drop for Sizes {
    fn drop(&mut self) {
        // The worker checks between directories, so it stops after at most one.
        self.cancel.store(true, Ordering::Relaxed);
    }
}

fn measure_one(path: &std::path::Path, probe: &dyn sweep_core::FsProbe) -> Measured {
    let limits = Limits {
        max_entries: ENTRIES_PER_DIRECTORY,
        time_budget: Duration::from_secs(SECONDS_PER_DIRECTORY),
    };
    let mut spec = Spec::new(usize::MAX, &limits);
    spec.select = Select::Everything;
    let collected = scan::collect(path, path, 0, &spec, probe);
    // A budget, an unreadable child or an unknown mount all mean "there is more
    // here than this number". The row keeps the number and marks it a floor.
    let partial = !collected.stop.is_complete()
        || collected.root_unreadable
        || collected.missing_root
        || collected.not_a_directory
        || collected.stats.unreadable > 0
        || collected.stats.unknown_mount > 0
        || !collected.blocked.is_empty();
    Measured {
        bytes: collected.bytes,
        items: collected.entries.len() as u64,
        partial,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(sizes: Sizes) -> Vec<Update> {
        let mut seen = Vec::new();
        let mut sizes = sizes;
        for _ in 0..10_000 {
            match sizes.poll() {
                Some(update) => {
                    let finished = update == Update::Finished;
                    seen.push(update);
                    if finished {
                        return seen;
                    }
                }
                None => {
                    if sizes.is_finished() {
                        return seen;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
        panic!("the worker did not finish: {seen:?}");
    }

    #[test]
    fn each_directory_gets_its_own_size_and_item_count() {
        let temp = tempfile::tempdir().expect("tempdir");
        let one = temp.path().join("one");
        let two = temp.path().join("two");
        std::fs::create_dir_all(&one).expect("mkdir");
        std::fs::create_dir_all(&two).expect("mkdir");
        for index in 0..4 {
            std::fs::write(one.join(format!("file{index}")), vec![b'x'; 1024]).expect("write");
        }
        std::fs::write(two.join("only"), b"one").expect("write");

        let sizes = Sizes::spawn(vec![(0, one), (1, two)]).expect("worker");
        let updates = drain(sizes);
        let measured: Vec<(usize, Measured)> = updates
            .iter()
            .filter_map(|update| match update {
                Update::Measured { index, measured } => Some((*index, *measured)),
                Update::Finished => None,
            })
            .collect();
        assert_eq!(measured.len(), 2, "one update per directory");
        assert_eq!(measured[0].0, 0);
        assert!(measured[0].1.bytes >= 4096, "{:?}", measured[0].1);
        assert_eq!(measured[0].1.items, 4);
        assert!(!measured[0].1.partial, "a small tree is complete");
        assert_eq!(measured[1].0, 1);
        assert_eq!(measured[1].1.items, 1);
    }

    #[test]
    fn nothing_to_measure_is_not_a_worker() {
        assert!(Sizes::spawn(Vec::new()).is_none());
    }

    #[test]
    fn a_missing_directory_is_reported_partial_not_zero() {
        let probe = RealProbe::new().expect("probe").with_open_scan();
        let measured = measure_one(std::path::Path::new("/definitely/not/here"), &probe);
        assert_eq!(measured.bytes, 0);
        assert!(measured.partial, "an unreadable path is not an empty one");
    }
}
