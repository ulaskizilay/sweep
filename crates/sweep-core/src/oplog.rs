//! Append-only operation log.
//!
//! One JSON object per line, written with a single `write_all` on an `O_APPEND`
//! handle. JSON gives exact fidelity for path bytes: a name containing a newline
//! is encoded as `\n` (two bytes, backslash + `n`) and round-trips unchanged, so
//! a path can never forge a second record.
//!
//! A path that is not valid UTF-8 is written twice: `path` for humans (lossy)
//! and `path_hex` for exactness. Losing a path in the audit trail would be worse
//! than a small extra field.
//!
//! Log failure never aborts a cleanup. It warns once, then continues: stopping
//! mid-sweep because a disk is full leaves the tree in a half-cleaned state with
//! no record of which half.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// What happened to one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Action {
    Removed,
    WouldRemove,
    /// Moved to the freedesktop trash, where it can be restored.
    Trashed,
    /// Rewritten in place by the tool that owns it, as `optimize` does.
    Rebuilt,
    Skipped,
    Failed,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Removed => "REMOVED",
            Action::WouldRemove => "WOULD_REMOVE",
            Action::Trashed => "TRASHED",
            Action::Rebuilt => "REBUILT",
            Action::Skipped => "SKIPPED",
            Action::Failed => "FAILED",
        }
    }
}

/// One stored line, read back.
///
/// Separate from [`Record`] because a reader must tolerate what a writer may
/// never produce: a row from an older build, or a line a disk filled up in the
/// middle of. A required field that is missing makes the line malformed rather
/// than fatal, and the caller reports how many it could not read.
#[derive(Debug, Clone, Deserialize)]
pub struct LogRow {
    pub ts: String,
    pub cmd: String,
    pub session: String,
    pub action: Action,
    pub rule: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub path_hex: Option<String>,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub detail: Option<String>,
}

impl LogRow {
    /// The path as it is on disk, exact when the log carried hex bytes.
    pub fn path(&self) -> Option<PathBuf> {
        match &self.path_hex {
            Some(hex) => decode_hex(hex),
            None if self.path.is_empty() => None,
            None => Some(PathBuf::from(&self.path)),
        }
    }
}

/// What a tail read found.
#[derive(Debug)]
pub struct LogTail {
    pub rows: Vec<LogRow>,
    /// Lines that were not a complete record, skipped rather than fatal.
    pub malformed: usize,
    /// The window began after the start of the file, so older rows exist.
    pub truncated: bool,
    /// Total size of the log, so a caller can say what it read out of how much.
    pub size: u64,
}

/// Reads the last `limit` bytes of an operation log.
///
/// A partial first line is dropped: half a JSON object is not a record. The
/// read is deliberately bounded, because the log grows with every sweep and a
/// history command must stay fast on a log that has been accumulating for a
/// year.
pub fn read_tail(path: &Path, limit: u64) -> io::Result<LogTail> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    let start = size.saturating_sub(limit);
    if start > 0 {
        file.seek(SeekFrom::Start(start))?;
    }
    let mut raw = Vec::new();
    file.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw);
    let mut lines: Vec<&str> = text.lines().collect();
    if start > 0 && !lines.is_empty() {
        lines.remove(0);
    }
    let mut rows = Vec::with_capacity(lines.len());
    let mut malformed = 0;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<LogRow>(line) {
            Ok(row) => rows.push(row),
            Err(_) => malformed += 1,
        }
    }
    Ok(LogTail {
        rows,
        malformed,
        truncated: start > 0,
        size,
    })
}

/// Decodes the lowercase hex [`encode_path`] writes, back into a path.
pub fn decode_hex(hex: &str) -> Option<PathBuf> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.as_bytes().chunks_exact(2);
    for pair in &mut chars {
        let high = value(pair[0])?;
        let low = value(pair[1])?;
        bytes.push(high << 4 | low);
    }
    Some(PathBuf::from(OsString::from_vec(bytes)))
}

fn value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// One log line.
#[derive(Debug, Serialize)]
pub struct Record<'a> {
    pub ts: String,
    pub cmd: &'a str,
    pub session: &'a str,
    pub action: Action,
    pub rule: &'a str,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_hex: Option<String>,
    pub bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The operation log handle.
#[derive(Debug)]
pub struct Oplog {
    file: File,
    path: PathBuf,
    session: String,
    failures: u32,
}

impl Oplog {
    /// Opens (creating if needed) `<state_dir>/operations.jsonl`.
    pub fn open(state_dir: &Path, session: impl Into<String>) -> io::Result<Self> {
        std::fs::create_dir_all(state_dir)?;
        let path = state_dir.join("operations.jsonl");
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            file,
            path,
            session: session.into(),
            failures: 0,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn session(&self) -> &str {
        &self.session
    }

    /// Appends one record. A write error warns once and is otherwise swallowed.
    pub fn append(&mut self, record: Record<'_>) {
        match self.write_record(record) {
            Ok(()) => {}
            Err(error) => {
                self.failures += 1;
                if self.failures == 1 {
                    tracing::warn!(
                        path = %self.path.display(),
                        %error,
                        "operation log is not writable; continuing without records"
                    );
                }
            }
        }
    }

    fn write_record(&mut self, record: Record<'_>) -> io::Result<()> {
        let line = serialize(&record)?;
        self.file.write_all(&line)
    }

    /// Number of failed appends, exposed for `sweep doctor`.
    pub fn failures(&self) -> u32 {
        self.failures
    }
}

/// Serializes one record into a single newline-terminated line.
///
/// Pure, so the "no raw control byte" property can be tested without a file.
pub fn serialize(record: &Record<'_>) -> io::Result<Vec<u8>> {
    let line = serde_json::to_vec(record)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    debug_assert!(
        !line.iter().any(|byte| *byte < 0x20),
        "serialized record must not contain raw control bytes"
    );
    // `serde_json` escapes the C0 range because JSON requires it, but DEL
    // (0x7f) is legal raw inside a JSON string and would reach the log as a
    // control byte. Replace it with its escape: 0x7f can only occur inside a
    // string here, so this cannot corrupt the document.
    let line = if line.contains(&0x7f) {
        let mut escaped = Vec::with_capacity(line.len() + 6);
        for byte in line {
            if byte == 0x7f {
                escaped.extend_from_slice(b"\\u007f");
            } else {
                escaped.push(byte);
            }
        }
        escaped
    } else {
        line
    };
    let mut line = line;
    line.push(b'\n');
    Ok(line)
}

/// Splits a path into a lossy display string and, when needed, exact hex bytes.
pub fn encode_path(path: &Path) -> (String, Option<String>) {
    let bytes = path.as_os_str().as_bytes();
    match std::str::from_utf8(bytes) {
        Ok(text) => (text.to_string(), None),
        Err(_) => (
            String::from_utf8_lossy(bytes).into_owned(),
            Some(hex(bytes)),
        ),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(nibble(byte >> 4));
        out.push(nibble(byte & 0x0f));
    }
    out
}

fn nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + value - 10) as char,
    }
}

/// Formats Unix seconds as RFC 3339 UTC (`2026-10-25T11:52:03Z`).
///
/// Hand-rolled to keep the dependency surface small; pinned by tests against
/// known dates, including a leap day.
pub fn rfc3339(unix_seconds: i64) -> String {
    const SECS_PER_DAY: i64 = 86_400;
    let days = unix_seconds.div_euclid(SECS_PER_DAY);
    let secs_of_day = unix_seconds.rem_euclid(SECS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 to a calendar date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn rfc3339_matches_known_instants() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_000_000_000), "2001-09-09T01:46:40Z");
        // 2024-02-29 is a leap day.
        assert_eq!(rfc3339(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(rfc3339(1792929123), "2026-10-25T11:52:03Z");
    }

    #[test]
    fn control_bytes_are_escaped_not_raw() {
        let temp = tempfile::tempdir().unwrap();
        let mut log = Oplog::open(temp.path(), "test").unwrap();
        let (path, hex) = encode_path(Path::new("/tmp/a\nb\tc\u{1b}"));
        log.append(Record {
            ts: rfc3339(0),
            cmd: "clean",
            session: "test",
            action: Action::Removed,
            rule: "test.rule",
            path,
            path_hex: hex,
            bytes: 1,
            reason: None,
            detail: None,
        });
        let raw = std::fs::read_to_string(log.path()).unwrap();
        assert_eq!(
            raw.lines().count(),
            1,
            "a newline in a path must not split records"
        );
        assert!(!raw[..raw.len() - 1].bytes().any(|byte| byte < 0x20));
        assert!(raw.contains("\\n"));
    }

    #[test]
    fn a_written_record_reads_back_whole_including_a_non_utf8_path() {
        let temp = tempfile::tempdir().unwrap();
        let mut log = Oplog::open(temp.path(), "history-test").unwrap();
        let raw = std::ffi::OsStr::from_bytes(b"/tmp/bad-\xff-name");
        let (path, hex) = encode_path(Path::new(raw));
        log.append(Record {
            ts: rfc3339(1_000_000_000),
            cmd: "clean",
            session: "history-test",
            action: Action::Removed,
            rule: "test.rule",
            path,
            path_hex: hex,
            bytes: 4096,
            reason: None,
            detail: None,
        });
        let tail = read_tail(log.path(), 64 * 1024).unwrap();
        assert_eq!(tail.rows.len(), 1);
        assert_eq!(tail.malformed, 0);
        assert!(!tail.truncated);
        assert_eq!(tail.rows[0].action, Action::Removed);
        assert_eq!(tail.rows[0].bytes, 4096);
        assert_eq!(
            tail.rows[0].path().as_deref(),
            Some(Path::new(raw)),
            "hex round-trips the exact bytes"
        );
    }

    #[test]
    fn a_half_written_line_is_counted_not_fatal() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("operations.jsonl");
        let mut body = serialize(&Record {
            ts: rfc3339(0),
            cmd: "clean",
            session: "s",
            action: Action::Skipped,
            rule: "r",
            path: "/tmp/x".to_string(),
            path_hex: None,
            bytes: 0,
            reason: Some("race_changed"),
            detail: None,
        })
        .unwrap();
        body.extend_from_slice(b"{\"ts\":\"2026-");
        std::fs::write(&path, body).unwrap();

        let tail = read_tail(&path, 64 * 1024).unwrap();
        assert_eq!(tail.rows.len(), 1, "the complete row is kept");
        assert_eq!(tail.malformed, 1, "the torn one is counted, not invented");
    }

    #[test]
    fn a_tail_read_keeps_whole_records_and_says_it_was_truncated() {
        let temp = tempfile::tempdir().unwrap();
        let mut log = Oplog::open(temp.path(), "s").unwrap();
        for index in 0..50 {
            log.append(Record {
                ts: rfc3339(index),
                cmd: "clean",
                session: "s",
                action: Action::Removed,
                rule: "r",
                path: format!("/tmp/{index}"),
                path_hex: None,
                bytes: index as u64,
                reason: None,
                detail: None,
            });
        }
        let tail = read_tail(log.path(), 512).unwrap();
        assert!(tail.truncated);
        assert!(tail.rows.len() < 50);
        assert!(
            tail.rows.iter().all(|row| !row.path.is_empty()),
            "no partial line became a row"
        );
        assert_eq!(
            tail.rows.last().map(|row| row.path.as_str()),
            Some("/tmp/49")
        );
    }

    #[test]
    fn a_missing_log_is_an_empty_history_not_an_error_to_report_as_history() {
        let temp = tempfile::tempdir().unwrap();
        let error = read_tail(&temp.path().join("nope.jsonl"), 1024).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn backslash_names_stay_distinguishable_from_escapes() {
        let a = serde_json::to_string(&"a\\nb").unwrap();
        let b = serde_json::to_string(&"a\nb").unwrap();
        assert_ne!(a, b, "JSON keeps a literal backslash apart from a newline");
    }

    #[test]
    fn invalid_utf8_paths_keep_exact_bytes() {
        let raw = OsStr::from_bytes(&[b'/', b't', b'm', b'p', b'/', 0xff, 0xfe]);
        let path = Path::new(raw);
        let (text, hex) = encode_path(path);
        assert!(text.starts_with("/tmp/"));
        assert_eq!(hex.as_deref(), Some("2f746d702ffffe"));
    }

    #[test]
    fn a_failing_write_warns_once_and_never_panics() {
        let temp = tempfile::tempdir().unwrap();
        let mut log = Oplog::open(temp.path(), "test").unwrap();
        // A read-only handle makes `write_all` fail with EBADF.
        log.file = File::open(log.path()).unwrap();
        let record = || Record {
            ts: rfc3339(0),
            cmd: "clean",
            session: "test",
            action: Action::Removed,
            rule: "test.rule",
            path: "/tmp/x".into(),
            path_hex: None,
            bytes: 0,
            reason: None,
            detail: None,
        };
        log.append(record());
        log.append(record());
        log.append(record());
        assert_eq!(log.failures(), 3);
    }

    #[test]
    fn serialize_never_emits_a_raw_control_byte() {
        let record = Record {
            ts: rfc3339(0),
            cmd: "clean",
            session: "test",
            action: Action::Skipped,
            rule: "test.rule",
            path: "/tmp/\u{0}\u{1}\u{1b}\u{7f}".into(),
            path_hex: None,
            bytes: 0,
            reason: Some("probe_unknown"),
            detail: Some("detail\u{0}with\u{1b}bytes".into()),
        };
        let line = serialize(&record).unwrap();
        let body = &line[..line.len() - 1];
        assert!(!body.iter().any(|byte| *byte < 0x20 || *byte == 0x7f));
    }
}
