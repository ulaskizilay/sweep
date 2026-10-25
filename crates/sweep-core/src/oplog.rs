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

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// What happened to one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Action {
    Removed,
    WouldRemove,
    Skipped,
    Failed,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Removed => "REMOVED",
            Action::WouldRemove => "WOULD_REMOVE",
            Action::Skipped => "SKIPPED",
            Action::Failed => "FAILED",
        }
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
