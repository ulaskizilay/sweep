//! `sweep history` — what sweep did, read back from its own log.
//!
//! Every command that changes the machine appends one row per decision to
//! `operations.jsonl`. This module is the only reader that shows the whole file
//! rather than the newest session, and it is read-only: it opens the log, it
//! never creates it, and a missing log is an empty history rather than an error.
//!
//! A session is one invocation. It is the unit a user remembers ("the clean I
//! ran last night"), and it is the unit the log already groups rows by, so the
//! summary can say "41 removed, 12 skipped, 1 failed" without inventing a
//! second bookkeeping layer.
//!
//! Two numbers are deliberately not fused:
//!
//! * bytes removed by `clean` and bytes moved to the trash by `analyze` are
//!   different promises — one is reclaimed space, the other is recoverable
//!   space — so the totals line keeps them apart.
//! * a session that was cut out of the read window is never presented as
//!   complete: the header says how many sessions were read out of how much of
//!   the file, and a session whose first rows fall outside the window is marked.

use std::collections::HashMap;
use std::process::ExitCode;

use serde::Serialize;
use sweep_core::oplog::{self, Action, LogRow};
use sweep_core::paths::Xdg;

use crate::format::{human_bytes, human_count};

/// Sessions printed when the caller names no limit.
pub const DEFAULT_SESSIONS: u16 = 20;

/// Bytes of log this command will read.
///
/// Eight mebibytes is on the order of a hundred thousand rows: a year of daily
/// sweeps, read in one pass without a scan over a log that has grown without
/// bound. `--all` does not exist on purpose; a user who needs more can read the
/// file, and a command that silently scans a gigabyte is a command that hangs.
const WINDOW: u64 = 8 * 1024 * 1024;

#[derive(Debug, Default, Serialize)]
struct Counts {
    removed: u64,
    trashed: u64,
    rebuilt: u64,
    skipped: u64,
    failed: u64,
    previewed: u64,
}

impl Counts {
    fn add(&mut self, action: Action) {
        match action {
            Action::Removed => self.removed += 1,
            Action::Trashed => self.trashed += 1,
            Action::Rebuilt => self.rebuilt += 1,
            Action::Skipped => self.skipped += 1,
            Action::Failed => self.failed += 1,
            Action::WouldRemove => self.previewed += 1,
        }
    }
}

#[derive(Debug, Serialize)]
struct Session {
    id: String,
    command: String,
    /// First and last row of the session, so a long sweep has an extent rather
    /// than one timestamp that may be hours before it finished.
    started: String,
    ended: String,
    counts: Counts,
    /// Bytes the session removed, and bytes it moved to the trash.
    removed_bytes: u64,
    trashed_bytes: u64,
    /// Skip codes with their counts, most frequent first.
    reasons: Vec<Reason>,
    /// The first rows of this session are older than the read window.
    truncated: bool,
}

#[derive(Debug, Serialize)]
struct Reason {
    code: String,
    count: u64,
}

#[derive(Debug, Serialize)]
struct Report {
    generated_at: String,
    /// Sessions in the report, newest first.
    sessions: Vec<Session>,
    /// Every session found in the window, including the ones not printed.
    sessions_found: usize,
    totals: Counts,
    totals_removed_bytes: u64,
    totals_trashed_bytes: u64,
    log: LogInfo,
}

#[derive(Debug, Serialize)]
struct LogInfo {
    path: String,
    /// Size of the whole file.
    bytes: u64,
    /// Bytes actually read, from the end.
    window: u64,
    rows: u64,
    /// Lines that were not a complete record.
    malformed: u64,
    /// Older rows exist outside the window.
    truncated: bool,
}

pub fn run(limit: usize, json: bool, verbose: u8) -> ExitCode {
    let xdg = match Xdg::from_env() {
        Ok(xdg) => xdg,
        Err(error) => {
            eprintln!("sweep history: {error}");
            return ExitCode::from(crate::EXIT_UNSUPPORTED_ENVIRONMENT);
        }
    };
    let report = match gather(&xdg, limit) {
        Ok(report) => report,
        Err(message) => {
            eprintln!("sweep history: {message}");
            return ExitCode::from(crate::EXIT_UNSUPPORTED_ENVIRONMENT);
        }
    };

    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(text) => println!("{text}"),
            Err(error) => {
                eprintln!("sweep history: cannot serialise report: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        print!("{}", render(&report, verbose));
    }
    ExitCode::SUCCESS
}

fn gather(xdg: &Xdg, limit: usize) -> Result<Report, String> {
    let path = xdg.state_dir().join("operations.jsonl");
    let (rows, log) = match oplog::read_tail(&path, WINDOW) {
        Ok(tail) => (
            tail.rows,
            LogInfo {
                path: path.display().to_string(),
                bytes: tail.size,
                window: tail.size.min(WINDOW),
                rows: 0,
                malformed: tail.malformed as u64,
                truncated: tail.truncated,
            },
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (
            Vec::<LogRow>::new(),
            LogInfo {
                path: path.display().to_string(),
                bytes: 0,
                window: 0,
                rows: 0,
                malformed: 0,
                truncated: false,
            },
        ),
        Err(error) => return Err(format!("cannot read {}: {error}", path.display())),
    };

    let mut log = log;
    log.rows = rows.len() as u64;

    let mut sessions: Vec<Session> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut totals = Counts::default();
    let mut totals_removed_bytes = 0u64;
    let mut totals_trashed_bytes = 0u64;

    for row in &rows {
        totals.add(row.action);
        match row.action {
            Action::Removed | Action::Rebuilt => totals_removed_bytes += row.bytes,
            Action::Trashed => totals_trashed_bytes += row.bytes,
            _ => {}
        }

        let position = match index.get(&row.session) {
            Some(position) => *position,
            None => {
                // The window began inside the oldest session it contains, so
                // that session's first rows are gone. Its counts are a floor.
                let oldest = sessions.is_empty() && log.truncated;
                index.insert(row.session.clone(), sessions.len());
                sessions.push(Session {
                    id: row.session.clone(),
                    command: row.cmd.clone(),
                    started: row.ts.clone(),
                    ended: row.ts.clone(),
                    counts: Counts::default(),
                    removed_bytes: 0,
                    trashed_bytes: 0,
                    reasons: Vec::new(),
                    truncated: oldest,
                });
                sessions.len() - 1
            }
        };

        let session = &mut sessions[position];
        session.ended = row.ts.clone();
        session.counts.add(row.action);
        match row.action {
            Action::Removed | Action::Rebuilt => session.removed_bytes += row.bytes,
            Action::Trashed => session.trashed_bytes += row.bytes,
            Action::Skipped => {
                let code = row
                    .reason
                    .clone()
                    .unwrap_or_else(|| "unspecified".to_string());
                match session.reasons.iter_mut().find(|seen| seen.code == code) {
                    Some(seen) => seen.count += 1,
                    None => session.reasons.push(Reason { code, count: 1 }),
                }
            }
            _ => {}
        }
    }

    for session in &mut sessions {
        session.reasons.sort_by(|left, right| {
            right
                .count
                .cmp(&left.count)
                .then(left.code.cmp(&right.code))
        });
    }

    // Newest first: the timestamp is RFC 3339 in UTC, so the newest session has
    // the greatest string, and sorting by `ended` keeps one sweep together.
    sessions.sort_by(|left, right| right.ended.cmp(&left.ended));

    let sessions_found = sessions.len();
    sessions.truncate(limit);

    Ok(Report {
        generated_at: oplog::rfc3339(now_unix()),
        sessions,
        sessions_found,
        totals,
        totals_removed_bytes,
        totals_trashed_bytes,
        log,
    })
}

fn render(report: &Report, verbose: u8) -> String {
    let mut out = String::new();

    if report.sessions.is_empty() {
        out.push_str("sweep history — nothing recorded yet\n\n");
        out.push_str(&format!(
            "  A command that changes the machine appends one row per decision to\n  {}\n",
            report.log.path
        ));
        return out;
    }

    out.push_str(&format!(
        "sweep history — {} of {} sessions, newest first\n\n",
        report.sessions.len(),
        human_count(report.sessions_found as u64)
    ));

    let width = report
        .sessions
        .iter()
        .map(|session| session.command.len())
        .max()
        .unwrap_or(7)
        .max(7);

    for session in &report.sessions {
        out.push_str(&format!(
            "  {}  {:<width$}  {}{}\n",
            short_stamp(&session.ended),
            session.command,
            describe(
                &session.counts,
                session.removed_bytes,
                session.trashed_bytes
            ),
            if session.truncated {
                "  (partial: the window began inside this session)"
            } else {
                ""
            },
            width = width
        ));
        if verbose > 0 && !session.reasons.is_empty() {
            out.push_str(&format!(
                "  {}  {:<width$}  skipped: {}\n",
                " ".repeat(16),
                "",
                session
                    .reasons
                    .iter()
                    .map(|reason| format!("{} {}", reason.code, reason.count))
                    .collect::<Vec<_>>()
                    .join(", "),
                width = width
            ));
        }
    }

    out.push('\n');
    out.push_str(&format!(
        "  {} sessions read: {}{}\n",
        human_count(report.sessions_found as u64),
        describe(
            &report.totals,
            report.totals_removed_bytes,
            report.totals_trashed_bytes
        ),
        if report.log.truncated {
            "  (older rows are outside the window)"
        } else {
            ""
        }
    ));
    out.push_str(&format!(
        "  log: {} — {} rows in the last {}{}\n",
        report.log.path,
        human_count(report.log.rows),
        human_bytes(report.log.window),
        if report.log.malformed > 0 {
            format!(", {} unreadable", human_count(report.log.malformed))
        } else {
            String::new()
        }
    ));
    if report.log.truncated {
        out.push_str(&format!(
            "  the whole log is {}; only its tail was read, so older sessions are not shown\n",
            human_bytes(report.log.bytes)
        ));
    }
    out
}

/// One session in a few words, in the order a user cares about.
fn describe(counts: &Counts, removed_bytes: u64, trashed_bytes: u64) -> String {
    let mut parts: Vec<String> = Vec::new();
    if counts.removed > 0 {
        parts.push(format!(
            "{} removed · {}",
            human_count(counts.removed),
            human_bytes(removed_bytes)
        ));
    }
    if counts.trashed > 0 {
        parts.push(format!(
            "{} trashed · {}",
            human_count(counts.trashed),
            human_bytes(trashed_bytes)
        ));
    }
    if counts.rebuilt > 0 {
        parts.push(format!("{} rebuilt", human_count(counts.rebuilt)));
    }
    if counts.skipped > 0 {
        parts.push(format!("{} skipped", human_count(counts.skipped)));
    }
    if counts.failed > 0 {
        parts.push(format!("{} failed", human_count(counts.failed)));
    }
    if counts.previewed > 0 {
        parts.push(format!("{} previewed", human_count(counts.previewed)));
    }
    if parts.is_empty() {
        parts.push("no decisions".to_string());
    }
    parts.join(" · ")
}

/// `2026-11-02 11:37` from an RFC 3339 stamp, or the stamp itself.
fn short_stamp(ts: &str) -> String {
    if ts.len() >= 16 && ts.is_char_boundary(16) {
        format!("{} {}", &ts[0..10], &ts[11..16])
    } else {
        ts.to_string()
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
    use sweep_core::oplog::{Oplog, Record};

    fn xdg_at(home: &std::path::Path) -> Xdg {
        Xdg::resolve(|key| match key {
            "HOME" => Some(home.as_os_str().to_os_string()),
            _ => None,
        })
        .expect("home")
    }

    fn write_log(xdg: &Xdg, rows: &[(&str, &str, Action, u64, Option<&str>)]) {
        let mut log = Oplog::open(&xdg.state_dir(), "seed").expect("log");
        for (session, cmd, action, bytes, reason) in rows {
            log.append(Record {
                ts: oplog::rfc3339(1_000_000_000),
                cmd,
                session,
                action: *action,
                rule: "test.rule",
                path: format!("/tmp/{session}"),
                path_hex: None,
                bytes: *bytes,
                reason: *reason,
                detail: None,
            });
        }
    }

    #[test]
    fn a_missing_log_is_an_empty_history_not_an_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let xdg = xdg_at(temp.path());
        let report = gather(&xdg, 20).expect("report");
        assert!(report.sessions.is_empty());
        assert_eq!(report.log.rows, 0);
        let text = render(&report, 0);
        assert!(text.contains("nothing recorded yet"), "{text}");
        assert!(text.contains("operations.jsonl"), "{text}");
    }

    #[test]
    fn rows_group_into_sessions_newest_first() {
        let temp = tempfile::tempdir().expect("tempdir");
        let xdg = xdg_at(temp.path());
        write_log(
            &xdg,
            &[
                ("clean-1", "clean", Action::Removed, 2048, None),
                ("clean-1", "clean", Action::Removed, 1024, None),
                ("clean-1", "clean", Action::Skipped, 0, Some("race_changed")),
                ("aur-2", "aur", Action::Removed, 4096, None),
            ],
        );
        let report = gather(&xdg, 20).expect("report");
        assert_eq!(report.sessions.len(), 2);
        assert_eq!(report.sessions[0].command, "clean");
        assert_eq!(report.sessions[0].counts.removed, 2);
        assert_eq!(report.sessions[0].removed_bytes, 3072);
        assert_eq!(report.sessions[0].counts.skipped, 1);
        assert_eq!(report.sessions[0].reasons[0].code, "race_changed");
        assert_eq!(report.totals.removed, 3);
        assert_eq!(report.totals_removed_bytes, 7168);
    }

    #[test]
    fn the_limit_cuts_the_printed_list_but_not_the_totals() {
        let temp = tempfile::tempdir().expect("tempdir");
        let xdg = xdg_at(temp.path());
        let rows: Vec<(&str, &str, Action, u64, Option<&str>)> = (0..5)
            .map(|index| {
                let session: &'static str = Box::leak(format!("s-{index}").into_boxed_str());
                (session, "clean", Action::Removed, 1, None)
            })
            .collect();
        write_log(&xdg, &rows);
        let report = gather(&xdg, 2).expect("report");
        assert_eq!(report.sessions.len(), 2, "two sessions are printed");
        assert_eq!(report.sessions_found, 5, "five were read");
        assert_eq!(report.totals.removed, 5, "the totals cover the window");
    }

    #[test]
    fn the_text_says_what_happened_and_keeps_reclaimed_apart_from_trashed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let xdg = xdg_at(temp.path());
        write_log(
            &xdg,
            &[
                (
                    "clean-1",
                    "clean",
                    Action::Removed,
                    1024 * 1024 * 1024,
                    None,
                ),
                ("clean-1", "clean", Action::Failed, 0, None),
                ("analyze-2", "analyze", Action::Trashed, 4096, None),
            ],
        );
        let report = gather(&xdg, 20).expect("report");
        let text = render(&report, 1);
        assert!(text.contains("1 removed · 1.0 GiB"), "{text}");
        assert!(text.contains("1 failed"), "{text}");
        assert!(text.contains("1 trashed · 4.0 KiB"), "{text}");
        assert!(
            text.contains("2 sessions read: 1 removed · 1.0 GiB · 1 trashed · 4.0 KiB · 1 failed"),
            "the totals line must keep removal and trash apart: {text}"
        );
        assert!(text.contains("log:"), "{text}");
    }

    #[test]
    fn a_stamp_is_shortened_without_inventing_a_timezone() {
        assert_eq!(short_stamp("2026-11-02T11:37:13Z"), "2026-11-02 11:37");
        assert_eq!(short_stamp("nonsense"), "nonsense");
    }
}
