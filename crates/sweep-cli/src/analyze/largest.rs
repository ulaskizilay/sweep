//! The non-interactive half of `analyze`: the biggest files below a root.
//!
//! Size is not evidence of anything. A file over a gigabyte may be a disk image
//! the user forgot, a video export mid-render, a virtual machine, or the only
//! copy of something irreplaceable — which is exactly why this mode only reads.
//! The report exists so a user can see what occupies the disk without running a
//! sweep first, and the explorer exists so a chosen file can be moved to Trash
//! rather than deleted.
//!
//! The walk is [`sweep_core::scan::collect`], the same walker every rule uses, so
//! mount crossings, symbolic links and the entry/time budget behave here exactly
//! as they do in a cleanup. A walk that ran out of budget is reported as
//! incomplete instead of printing a smaller list as if it were the whole answer.

use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use serde::Serialize;
use sweep_core::probe::RealProbe;
use sweep_core::scan::{self, Limits, Select, Spec};
use sweep_core::FsProbe;

use crate::format::{human_bytes, human_count};

/// Entries this report may hold before it stops walking.
///
/// Five times the budget a cleanup rule gets, because nothing here deletes: the
/// only costs of a deeper walk are time and the memory the entry list occupies.
/// It is still a number, because a root pointed at `/` would otherwise collect
/// the whole filesystem into one `Vec`.
const REPORT_ENTRIES: usize = 500_000;

/// Wall clock the report may take. Long enough for a home directory, short
/// enough that a mistyped root is a wait rather than a hang.
const REPORT_SECONDS: u64 = 30;

/// One row of the report.
#[derive(Debug, Clone, Serialize)]
struct File {
    path: String,
    bytes: u64,
    /// Days since the file was last modified, so the report can say "old" with a
    /// number instead of an adjective.
    modified_days: u64,
}

#[derive(Debug, Serialize)]
struct Report {
    root: String,
    generated_at: String,
    largest: Vec<File>,
    scanned: Scanned,
}

#[derive(Debug, Serialize)]
struct Scanned {
    files: u64,
    entries: u64,
    bytes: u64,
    seconds: f64,
    complete: bool,
    /// The budget that stopped the walk, when one did.
    #[serde(skip_serializing_if = "Option::is_none")]
    stopped: Option<&'static str>,
}

pub fn run(root: &Path, count: usize, json: bool, verbose: u8) -> ExitCode {
    let probe = match RealProbe::new() {
        Ok(probe) => probe.with_open_scan(),
        Err(error) => {
            eprintln!("sweep analyze: cannot probe: {error}");
            return ExitCode::from(crate::EXIT_UNSUPPORTED_ENVIRONMENT);
        }
    };
    match collect(root, count, &probe) {
        Ok(report) => {
            if json {
                match serde_json::to_string_pretty(&report) {
                    Ok(text) => println!("{text}"),
                    Err(error) => {
                        eprintln!("sweep analyze: cannot serialise report: {error}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                print!("{}", render(&report, verbose));
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("sweep analyze: {message}");
            ExitCode::from(crate::EXIT_UNSUPPORTED_ENVIRONMENT)
        }
    }
}

fn collect(root: &Path, count: usize, probe: &dyn FsProbe) -> Result<Report, String> {
    let started = Instant::now();
    let root = match std::fs::canonicalize(root) {
        Ok(path) => path,
        Err(error) => return Err(format!("cannot read {}: {error}", root.display())),
    };
    let metadata = match std::fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) => return Err(format!("cannot read {}: {error}", root.display())),
    };
    if !metadata.is_dir() {
        return Err(format!("{} is not a directory", root.display()));
    }

    let limits = Limits {
        max_entries: REPORT_ENTRIES,
        time_budget: std::time::Duration::from_secs(REPORT_SECONDS),
    };
    let mut spec = Spec::new(usize::MAX, &limits);
    spec.select = Select::Everything;
    let collected = scan::collect(&root, &root, 0, &spec, probe);
    if collected.missing_root {
        return Err(format!("{} does not exist", root.display()));
    }
    if collected.not_a_directory {
        return Err(format!("{} is not a directory", root.display()));
    }
    if collected.root_unreadable {
        return Err(format!("{} cannot be read", root.display()));
    }

    let now = now_unix();
    let mut files: Vec<&scan::Entry> = collected
        .entries
        .iter()
        .filter(|entry| !entry.is_dir)
        .collect();
    // Largest first, then by path so two files of the same size have a stable
    // order: a report that reshuffles between runs cannot be diffed.
    files.sort_by(|left, right| {
        right
            .bytes
            .cmp(&left.bytes)
            .then_with(|| left.path.cmp(&right.path))
    });
    let files: Vec<File> = files
        .into_iter()
        .take(count)
        .map(|entry| File {
            path: entry.path.display().to_string(),
            bytes: entry.bytes,
            modified_days: (now.saturating_sub(entry.mtime) / 86_400) as u64,
        })
        .collect();

    let stopped = match collected.stop {
        scan::Stop::Complete => None,
        scan::Stop::EntryBudget => Some("entry budget"),
        scan::Stop::TimeBudget => Some("time budget"),
    };
    Ok(Report {
        root: root.display().to_string(),
        generated_at: sweep_core::oplog::rfc3339(now),
        largest: files,
        scanned: Scanned {
            files: collected
                .entries
                .iter()
                .filter(|entry| !entry.is_dir)
                .count() as u64,
            entries: collected.entries.len() as u64,
            bytes: collected.bytes,
            seconds: started.elapsed().as_secs_f64(),
            complete: stopped.is_none(),
            stopped,
        },
    })
}

fn render(report: &Report, verbose: u8) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "sweep analyze — the {} largest files below {}\n\n",
        report.largest.len(),
        report.root
    ));

    if report.largest.is_empty() {
        out.push_str("  every file here is zero bytes\n");
    } else {
        out.push_str(&format!(
            "  {:>10}  {:>9}  {}\n",
            "size", "modified", "path"
        ));
        for file in &report.largest {
            out.push_str(&format!(
                "  {:>10}  {:>9}  {}\n",
                human_bytes(file.bytes),
                super::view::age_text(file.modified_days),
                file.path
            ));
        }
    }

    out.push('\n');
    out.push_str(&format!(
        "  scanned {} files ({} entries, {}) in {:.1}s",
        human_count(report.scanned.files),
        human_count(report.scanned.entries),
        human_bytes(report.scanned.bytes),
        report.scanned.seconds
    ));
    match report.scanned.stopped {
        Some(budget) => out.push_str(&format!(
            " — the {budget} stopped the walk, so larger files may exist\n"
        )),
        None => out.push_str(" — complete\n"),
    }
    out.push_str(
        "  Nothing was deleted. `sweep analyze` opens the explorer, where a chosen\n  \
         entry is moved to the trash and can be restored.\n",
    );
    if verbose > 0 {
        out.push_str(&format!(
            "  budget: {} entries, {REPORT_SECONDS}s\n",
            human_count(REPORT_ENTRIES as u64)
        ));
    }
    out
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
    use std::fs::FileTimes;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};

    fn fixture() -> (tempfile::TempDir, RealProbe) {
        let temp = tempfile::tempdir().expect("tempdir");
        let probe = RealProbe::new().expect("probe").with_open_scan();
        (temp, probe)
    }

    fn write(root: &Path, relative: &str, bytes: usize) -> PathBuf {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, vec![b'x'; bytes]).expect("write");
        path
    }

    fn age(path: &Path, days: u64) {
        let when = SystemTime::now() - Duration::from_secs(days * 86_400);
        let file = std::fs::File::options()
            .read(true)
            .open(path)
            .expect("open");
        file.set_times(FileTimes::new().set_modified(when))
            .expect("set mtime");
    }

    #[test]
    fn the_report_is_ordered_by_size_and_takes_only_n() {
        let (temp, probe) = fixture();
        let root = temp.path().join("root");
        write(&root, "small.txt", 16);
        let big = write(&root, "nested/big.bin", 128 * 1024);
        let middle = write(&root, "middle.bin", 64 * 1024);
        age(&big, 40);

        let report = collect(&root, 2, &probe).expect("report");
        assert_eq!(report.largest.len(), 2);
        assert!(report.largest[0].path.ends_with("big.bin"));
        assert_eq!(report.largest[0].bytes, 128 * 1024);
        assert!(report.largest[0].modified_days >= 39);
        assert!(report.largest[1].path.ends_with("middle.bin"));
        assert_eq!(report.scanned.files, 3);
        assert!(report.scanned.complete, "a small tree is walked whole");
        let _ = middle;
    }

    #[test]
    fn ties_are_broken_by_path_so_two_runs_agree() {
        let (temp, probe) = fixture();
        let root = temp.path().join("root");
        write(&root, "b.bin", 4096);
        write(&root, "a.bin", 4096);

        let report = collect(&root, 5, &probe).expect("report");
        let names: Vec<&str> = report
            .largest
            .iter()
            .map(|file| file.path.rsplit('/').next().expect("name"))
            .collect();
        assert_eq!(names, ["a.bin", "b.bin"]);
    }

    #[test]
    fn a_symlink_is_not_a_big_file() {
        let (temp, probe) = fixture();
        let root = temp.path().join("root");
        let target = write(&root, "target.bin", 8192);
        std::os::unix::fs::symlink(&target, root.join("link.bin")).expect("link");

        let report = collect(&root, 10, &probe).expect("report");
        assert!(
            report
                .largest
                .iter()
                .all(|file| !file.path.ends_with("link.bin")),
            "a link is not the file it points at: {:?}",
            report.largest
        );
    }

    #[test]
    fn a_missing_root_is_an_error_not_an_empty_report() {
        let (temp, probe) = fixture();
        let error = collect(&temp.path().join("nope"), 5, &probe).expect_err("missing root");
        assert!(error.contains("cannot read"), "{error}");
    }

    #[test]
    fn the_text_report_says_nothing_was_deleted() {
        let report = Report {
            root: "/home/u".to_string(),
            generated_at: "2026-11-01T00:00:00Z".to_string(),
            largest: vec![File {
                path: "/home/u/disk.img".to_string(),
                bytes: 5 * 1024 * 1024 * 1024,
                modified_days: 66,
            }],
            scanned: Scanned {
                files: 1200,
                entries: 1300,
                bytes: 6 * 1024 * 1024 * 1024,
                seconds: 1.25,
                complete: true,
                stopped: None,
            },
        };
        let text = render(&report, 0);
        assert!(text.contains("5.0 GiB"), "{text}");
        assert!(text.contains("1,200 files"), "{text}");
        assert!(text.contains("Nothing was deleted."), "{text}");
        assert!(text.contains("complete"), "{text}");
    }
}
