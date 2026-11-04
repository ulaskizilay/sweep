//! `sweep status` — a compact, read-only health summary.
//!
//! Status answers one question: "is there anything here worth acting on, and
//! what command acts on it?" It is not a dashboard and not a monitor. There are
//! no alerts, no history graphs, no refresh loop, and nothing it prints changes
//! the machine.
//!
//! Every row is a fact plus, when the fact is actionable, the command that acts
//! on it. The JSON form is the same facts with stable field names so a script
//! can read them without parsing prose.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde::Serialize;
use sweep_core::fs_facts::MountTable;
use sweep_core::oplog::rfc3339;
use sweep_core::paths::Xdg;
use sweep_core::probe::RealProbe;
use sweep_core::scan::{self, Limits, Select, Spec};
use sweep_core::{sys, FsProbe};

use crate::format::{human_bytes, human_count, percent};

/// How a row should be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum State {
    /// Nothing to do; the number is there for context.
    Ok,
    /// Worth knowing, but no command acts on it.
    Info,
    /// A command can plausibly reclaim or fix this.
    Attention,
}

#[derive(Debug, Serialize)]
struct Finding {
    id: &'static str,
    label: &'static str,
    state: State,
    /// The number or sentence the row is about, already formatted.
    value: String,
    /// The command that acts on it, when one does.
    #[serde(skip_serializing_if = "Option::is_none")]
    next: Option<String>,
    /// Why the row could not be measured, when that is the case.
    #[serde(skip_serializing_if = "Option::is_none")]
    unavailable: Option<String>,
}

#[derive(Debug, Serialize)]
struct Report {
    version: String,
    generated_at: String,
    health: &'static str,
    host: Host,
    findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
struct Host {
    kernel: String,
    uptime_seconds: u64,
    cpus: usize,
    load: [f64; 3],
}

pub fn run(json: bool, verbose: u8) -> ExitCode {
    let report = match gather() {
        Ok(report) => report,
        Err(message) => {
            eprintln!("sweep status: {message}");
            return ExitCode::from(crate::EXIT_UNSUPPORTED_ENVIRONMENT);
        }
    };

    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(text) => println!("{text}"),
            Err(error) => {
                eprintln!("sweep status: cannot serialise report: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        print!("{}", render(&report, verbose));
    }
    ExitCode::SUCCESS
}

fn gather() -> Result<Report, String> {
    let xdg = Xdg::from_env().map_err(|error| error.to_string())?;
    let probe = RealProbe::new().map_err(|error| format!("cannot probe: {error}"))?;
    let limits = Limits::default();

    let mut findings: Vec<Finding> = Vec::new();
    let host = host();
    findings.extend(disk_findings(&xdg));
    findings.push(memory_finding());
    findings.push(load_finding());
    findings.extend(package_findings(&limits, &probe));
    findings.push(trash_finding(&xdg, &limits, &probe));
    findings.push(last_run_finding(&xdg));

    Ok(Report {
        version: sweep_core::VERSION.to_string(),
        generated_at: rfc3339(now_unix()),
        health: if findings.iter().any(|f| f.state == State::Attention) {
            "attention"
        } else {
            "ok"
        },
        host,
        findings,
    })
}

// ------------------------------------------------------------------ rows ---

fn disk_findings(xdg: &Xdg) -> Vec<Finding> {
    let mount = MountTable::load()
        .ok()
        .and_then(|table| table.find(&xdg.home).map(|mount| mount.mount_point.clone()))
        .unwrap_or_else(|| PathBuf::from("/"));
    let Ok(space) = sys::statvfs_space(&mount) else {
        return vec![Finding {
            id: "disk",
            label: "disk",
            state: State::Info,
            value: String::new(),
            next: None,
            unavailable: Some("cannot read filesystem statistics".to_string()),
        }];
    };

    let used = space.total.saturating_sub(space.free);
    let used_percent = percent(used, space.total);
    let disk = Finding {
        id: "disk",
        label: "disk",
        state: if used_percent >= 90.0 {
            State::Attention
        } else {
            State::Ok
        },
        value: format!(
            "{} used of {}, {:.0}% used, {} available",
            human_bytes(used),
            human_bytes(space.total),
            used_percent,
            human_bytes(space.avail)
        ),
        next: Some("sweep clean".to_string()),
        unavailable: None,
    };

    // Inodes are a second capacity that a cleanup tool is expected to know
    // about, and a full inode table looks exactly like a full disk from user
    // space. A filesystem that does not track them reports zero.
    let inodes = if space.files > 0 {
        let used = space.files.saturating_sub(space.files_free);
        let used_percent = percent(used, space.files);
        Finding {
            id: "inodes",
            label: "inodes",
            state: if used_percent >= 90.0 {
                State::Attention
            } else {
                State::Ok
            },
            value: format!(
                "{} used of {}, {:.1}% used",
                human_count(used),
                human_count(space.files),
                used_percent
            ),
            next: None,
            unavailable: None,
        }
    } else {
        Finding {
            id: "inodes",
            label: "inodes",
            state: State::Info,
            value: String::new(),
            next: None,
            unavailable: Some(format!("{} does not track inodes", mount.display())),
        }
    };

    vec![disk, inodes]
}

fn memory_finding() -> Finding {
    let (total, available) = match read_meminfo() {
        Some(values) => values,
        None => {
            return Finding {
                id: "memory",
                label: "memory",
                state: State::Info,
                value: String::new(),
                next: None,
                unavailable: Some("cannot read /proc/meminfo".to_string()),
            }
        }
    };
    let used = total.saturating_sub(available);
    let used_percent = percent(used, total);
    Finding {
        id: "memory",
        label: "memory",
        state: State::Ok,
        value: format!(
            "{} used of {}, {:.0}% used",
            human_bytes(used),
            human_bytes(total),
            used_percent
        ),
        next: None,
        unavailable: None,
    }
}

fn load_finding() -> Finding {
    let load = read_load()
        .unwrap_or([0.0, 0.0, 0.0])
        .map(|value| (value * 100.0).round() / 100.0);
    Finding {
        id: "load",
        label: "load",
        state: State::Info,
        value: format!(
            "{:.2} {:.2} {:.2} over {} cpus",
            load[0],
            load[1],
            load[2],
            cpus()
        ),
        next: None,
        unavailable: None,
    }
}

/// The two package-manager facts a cleanup tool can act on.
///
/// Both are read-only: `pacman -Qtdq` prints orphaned package names and
/// `statvfs`/a walk measure the cache. Nothing here removes a package; the row
/// names the command a user would run if they decided to.
fn package_findings(limits: &Limits, probe: &dyn FsProbe) -> Vec<Finding> {
    let mut findings = Vec::new();
    let cache = Path::new("/var/cache/pacman/pkg");
    if let Some((bytes, files)) = measure(cache, limits, probe) {
        findings.push(Finding {
            id: "pacman.cache",
            label: "package cache",
            state: if bytes >= 2 * 1024 * 1024 * 1024 {
                State::Attention
            } else {
                State::Ok
            },
            value: format!("{} in {} packages", human_bytes(bytes), human_count(files)),
            next: Some("sweep clean --only system".to_string()),
            unavailable: None,
        });
    } else {
        findings.push(Finding {
            id: "pacman.cache",
            label: "package cache",
            state: State::Info,
            value: String::new(),
            next: None,
            unavailable: Some(format!(
                "{} is not present or not readable",
                cache.display()
            )),
        });
    }

    match orphans() {
        Some(0) => findings.push(Finding {
            id: "pacman.orphans",
            label: "orphan packages",
            state: State::Ok,
            value: "none".to_string(),
            next: None,
            unavailable: None,
        }),
        Some(count) => findings.push(Finding {
            id: "pacman.orphans",
            label: "orphan packages",
            state: State::Attention,
            value: format!("{} installed, nothing depends on them", human_count(count)),
            next: Some("sudo pacman -Rns $(pacman -Qtdq)".to_string()),
            unavailable: None,
        }),
        None => findings.push(Finding {
            id: "pacman.orphans",
            label: "orphan packages",
            state: State::Info,
            value: String::new(),
            next: None,
            unavailable: Some("pacman is not available".to_string()),
        }),
    }
    findings
}

fn trash_finding(xdg: &Xdg, limits: &Limits, probe: &dyn FsProbe) -> Finding {
    let root = xdg.data.join("Trash/files");
    match measure(&root, limits, probe) {
        Some((0, _)) => Finding {
            id: "trash",
            label: "trash",
            state: State::Ok,
            value: "empty".to_string(),
            next: None,
            unavailable: None,
        },
        Some((bytes, files)) => Finding {
            id: "trash",
            label: "trash",
            state: State::Info,
            value: format!("{} in {} items", human_bytes(bytes), human_count(files)),
            // Emptying the trash is part of `clean`, which removes each payload
            // together with the `.trashinfo` record that names it.
            next: Some("sweep clean --only user-essentials".to_string()),
            unavailable: None,
        },
        None => Finding {
            id: "trash",
            label: "trash",
            state: State::Ok,
            value: "empty".to_string(),
            next: None,
            unavailable: None,
        },
    }
}

/// The last applied run, read from the operation log.
///
/// A session is contiguous in the file, so walking backwards while the session
/// id matches gives the run's own totals without scanning the whole history.
fn last_run_finding(xdg: &Xdg) -> Finding {
    let path = xdg.state_dir().join("operations.jsonl");
    // 64 KiB is a few hundred rows, far more than a session normally holds, and
    // it keeps `status` off a multi-megabyte log. When a session is larger than
    // that the row says `at least`, because a partial sum printed as a total is
    // exactly the kind of quiet lie this program is supposed to avoid.
    let Some(tail) = tail_rows(&path, 64 * 1024) else {
        return Finding {
            id: "last.run",
            label: "last sweep",
            state: State::Info,
            value: "never run".to_string(),
            next: None,
            unavailable: None,
        };
    };
    let rows = &tail.rows;
    let Some(last) = rows.last() else {
        return Finding {
            id: "last.run",
            label: "last sweep",
            state: State::Info,
            value: "never run".to_string(),
            next: None,
            unavailable: None,
        };
    };
    let Some(session) = last.get("session").and_then(|value| value.as_str()) else {
        return Finding {
            id: "last.run",
            label: "last sweep",
            state: State::Info,
            value: "never run".to_string(),
            next: None,
            unavailable: None,
        };
    };
    let mut bytes = 0u64;
    let mut removed = 0u64;
    for row in rows.iter().rev() {
        if row.get("session").and_then(|value| value.as_str()) != Some(session) {
            break;
        }
        if row.get("action").and_then(|value| value.as_str()) == Some("REMOVED") {
            removed += 1;
            bytes += row
                .get("bytes")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
        }
    }
    let command = last
        .get("cmd")
        .and_then(|value| value.as_str())
        .unwrap_or("sweep");
    let when = last
        .get("ts")
        .and_then(|value| value.as_str())
        .map(|ts| format!(", {}", age_of(ts)))
        .unwrap_or_default();
    // The window ends inside the session it is describing, so the sum counts
    // only the rows that fit. Say so rather than printing a short total.
    let partial = tail.truncated
        && rows
            .first()
            .and_then(|row| row.get("session"))
            .and_then(|value| value.as_str())
            == Some(session);
    let counted = if partial {
        format!("at least {}", plural(removed, "item", "items"))
    } else {
        plural(removed, "item", "items")
    };
    Finding {
        id: "last.run",
        label: "last sweep",
        state: State::Info,
        value: format!(
            "{command}{when}, {counted} removed, {} accounted",
            human_bytes(bytes)
        ),
        next: None,
        unavailable: None,
    }
}

// ---------------------------------------------------------------- inputs ---

fn host() -> Host {
    Host {
        kernel: kernel(),
        uptime_seconds: read_uptime().unwrap_or(0),
        cpus: cpus(),
        load: read_load().unwrap_or([0.0, 0.0, 0.0]),
    }
}

fn kernel() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|text| text.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn cpus() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
}

fn read_uptime() -> Option<u64> {
    let raw = std::fs::read_to_string("/proc/uptime").ok()?;
    let first = raw.split_whitespace().next()?;
    first.parse::<f64>().ok().map(|seconds| seconds as u64)
}

fn read_load() -> Option<[f64; 3]> {
    let raw = std::fs::read_to_string("/proc/loadavg").ok()?;
    let mut parts = raw.split_whitespace();
    Some([
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ])
}

fn read_meminfo() -> Option<(u64, u64)> {
    let raw = std::fs::read_to_string("/proc/meminfo").ok()?;
    let mut total = None;
    let mut available = None;
    for line in raw.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let Some(kib) = value
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<u64>().ok())
        else {
            continue;
        };
        match key {
            "MemTotal" => total = Some(kib * 1024),
            "MemAvailable" => available = Some(kib * 1024),
            _ => {}
        }
    }
    Some((total?, available?))
}

/// Bytes and file count below `root`, or `None` when the walk could not finish.
///
/// A partial measurement is reported as unavailable rather than as a smaller
/// number: "1.2 GiB" for a tree sweep could not enumerate is worse than "could
/// not measure".
fn measure(root: &Path, limits: &Limits, probe: &dyn FsProbe) -> Option<(u64, u64)> {
    if !root.is_dir() {
        return None;
    }
    let mut spec = Spec::new(usize::MAX, limits);
    spec.select = Select::Everything;
    let collected = scan::collect(root, root, 0, &spec, probe);
    if collected.stop != scan::Stop::Complete
        || collected.root_unreadable
        || collected.missing_root
        || collected.not_a_directory
    {
        return None;
    }
    let files = collected
        .entries
        .iter()
        .filter(|entry| !entry.is_dir)
        .count() as u64;
    Some((collected.bytes, files))
}

fn orphans() -> Option<u64> {
    let output = Command::new("pacman").arg("-Qtdq").output().ok()?;
    // `pacman -Qtdq` exits 1 with no output when nothing is orphaned. A real
    // failure exits with something else and is not a count of zero.
    match output.status.code() {
        Some(0) | Some(1) => Some(
            output
                .stdout
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .count() as u64,
        ),
        _ => None,
    }
}

struct Tail {
    rows: Vec<serde_json::Value>,
    /// The window did not start at the beginning of the file.
    truncated: bool,
}

/// The last `limit` bytes of a file, parsed as JSON lines.
///
/// A partial first line is dropped: half a JSON object is not a record.
fn tail_rows(path: &Path, limit: u64) -> Option<Tail> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    let start = len.saturating_sub(limit);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut raw = String::new();
    file.read_to_string(&mut raw).ok()?;
    let mut lines: Vec<&str> = raw.lines().collect();
    if start > 0 && !lines.is_empty() {
        lines.remove(0);
    }
    Some(Tail {
        rows: lines
            .iter()
            .filter_map(|line| serde_json::from_str(line).ok())
            .filter(|value: &serde_json::Value| value.is_object())
            .collect(),
        truncated: start > 0,
    })
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

/// `2 days ago` from an RFC 3339 stamp, or the stamp itself if unparseable.
fn age_of(ts: &str) -> String {
    let Some(seconds) = parse_rfc3339(ts) else {
        return ts.to_string();
    };
    let delta = now_unix().saturating_sub(seconds);
    match delta {
        d if d < 60 => "just now".to_string(),
        d if d < 3_600 => format!("{} ago", plural((d / 60) as u64, "minute", "minutes")),
        d if d < 86_400 => format!("{} ago", plural((d / 3_600) as u64, "hour", "hours")),
        d => format!("{} ago", plural((d / 86_400) as u64, "day", "days")),
    }
}

/// Days since the Unix epoch for a civil date, without a date library.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn parse_rfc3339(ts: &str) -> Option<i64> {
    // `YYYY-MM-DDTHH:MM:SSZ`, the only shape `rfc3339` writes.
    if ts.len() != 20 || !ts.ends_with('Z') {
        return None;
    }
    let year = ts.get(0..4)?.parse::<i64>().ok()?;
    let month = ts.get(5..7)?.parse::<i64>().ok()?;
    let day = ts.get(8..10)?.parse::<i64>().ok()?;
    let hour = ts.get(11..13)?.parse::<i64>().ok()?;
    let minute = ts.get(14..16)?.parse::<i64>().ok()?;
    let second = ts.get(17..19)?.parse::<i64>().ok()?;
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// `3d 4h`, `4h 12m`, `12m`: the shortest form that still tells the time.
fn duration(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

fn plural(count: u64, one: &str, many: &str) -> String {
    if count == 1 {
        format!("1 {one}")
    } else {
        format!("{count} {many}")
    }
}

// ---------------------------------------------------------------- output ---

fn render(report: &Report, verbose: u8) -> String {
    let mut out = String::new();
    out.push_str(&format!("sweep status — {}\n\n", report.generated_at));
    out.push_str(&format!(
        "  {:<16} Linux {}, up {}, {} cpus\n",
        "host",
        report.host.kernel,
        duration(report.host.uptime_seconds),
        report.host.cpus
    ));

    let mut attention: Vec<&Finding> = Vec::new();
    for finding in &report.findings {
        let value = match &finding.unavailable {
            Some(reason) if verbose > 0 => format!("— {reason}"),
            Some(_) => "— not available".to_string(),
            None => finding.value.clone(),
        };
        out.push_str(&format!("  {:<16} {}\n", finding.label, value));
        if finding.state == State::Attention {
            attention.push(finding);
        }
    }

    if attention.is_empty() {
        out.push_str("\n  nothing needs attention\n");
    } else {
        out.push_str("\n  wants attention\n");
        for finding in attention {
            let next = finding
                .next
                .as_ref()
                .map(|next| format!("   → {next}"))
                .unwrap_or_default();
            out.push_str(&format!(
                "    {:<18} {}{next}\n",
                finding.label, finding.value
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_round_trips_through_the_age_parser() {
        let seconds = parse_rfc3339("1970-01-02T00:00:00Z").expect("parsed");
        assert_eq!(seconds, 86_400);
        assert_eq!(
            parse_rfc3339("2026-11-01T10:00:00Z").map(|s| s % 86_400),
            Some(36_000)
        );
        assert_eq!(parse_rfc3339("not a timestamp"), None);
        assert_eq!(parse_rfc3339("2026-11-01 10:00:00"), None);
    }

    #[test]
    fn a_short_session_is_summed_from_the_tail() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("operations.jsonl");
        let rows = [
            r#"{"ts":"2026-11-01T09:00:00Z","cmd":"clean","session":"clean-1","action":"REMOVED","bytes":100}"#,
            r#"{"ts":"2026-11-01T09:00:01Z","cmd":"clean","session":"clean-1","action":"REMOVED","bytes":200}"#,
            r#"{"ts":"2026-11-01T09:00:02Z","cmd":"purge","session":"purge-2","action":"REMOVED","bytes":7}"#,
        ];
        std::fs::write(&path, rows.join("\n") + "\n").expect("write");
        let parsed = tail_rows(&path, 4096).expect("tail");
        assert_eq!(parsed.rows.len(), 3);
        assert_eq!(parsed.rows[2]["session"], "purge-2");
        assert!(!parsed.truncated, "the whole file fit in the window");
    }

    fn xdg_at(home: &Path) -> Xdg {
        Xdg::resolve(|key| match key {
            "HOME" => Some(home.as_os_str().to_os_string()),
            _ => None,
        })
        .expect("home")
    }

    #[test]
    fn a_session_longer_than_the_window_is_counted_as_at_least() {
        // A partial sum printed as a total is the quiet lie this program exists
        // to avoid, so the row has to admit the window cut the session.
        let temp = tempfile::tempdir().expect("tempdir");
        let state = temp.path().join(".local/state/sweep");
        std::fs::create_dir_all(&state).expect("mkdir");
        let mut body = String::new();
        for index in 0..2_000 {
            body.push_str(&format!(
                r#"{{"ts":"2026-11-01T09:00:00Z","cmd":"clean","session":"clean-9","action":"REMOVED","rule":"x.y","path":"/home/u/f{index}","bytes":1024}}"#
            ));
            body.push('\n');
        }
        std::fs::write(state.join("operations.jsonl"), &body).expect("write");

        let finding = last_run_finding(&xdg_at(temp.path()));
        assert!(
            finding.value.starts_with("clean"),
            "the row names the command: {}",
            finding.value
        );
        assert!(
            finding.value.contains("at least"),
            "a cut session must not look complete: {}",
            finding.value
        );
    }

    #[test]
    fn a_measure_of_a_missing_directory_is_unknown_not_zero() {
        let probe = RealProbe::new().expect("probe");
        assert_eq!(
            measure(
                Path::new("/definitely/not/here"),
                &Limits::default(),
                &probe
            ),
            None
        );
    }

    #[test]
    fn plural_says_one_item_for_one() {
        assert_eq!(plural(1, "item", "items"), "1 item");
        assert_eq!(plural(0, "item", "items"), "0 items");
        assert_eq!(plural(2, "item", "items"), "2 items");
    }
}
