//! Report-only detection of cache directories with no visible owner.
//!
//! `status` is read-only, so this module only measures. It answers one
//! question per direct child of the XDG cache base: does anything on this
//! machine still name it?
//!
//! Evidence is deliberately conservative. A dedicated catalog rule, a command
//! with the directory's name on `PATH`, or a desktop entry whose `Exec` binary
//! exists all leave the directory alone. Only a directory with none of them is
//! reported, and it is never deleted: the row is a hint that the owner may be
//! gone, not a verdict. `docs/ORPHAN_DATA.md` records why each source is
//! weaker than it looks.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sweep_core::rules::RuleSet;
use sweep_core::scan::{self, Limits, Select, Spec, Stop};
use sweep_core::{FsProbe, Xdg};

/// Below this the row is noise. One MiB is also the floor the design note
/// names, so the report and a future deletion rule agree on what matters.
const MIN_BYTES: u64 = 1 << 20;

/// Per-candidate walk budget. A cache that cannot be measured inside this
/// window is treated as unknown, never as a smaller number.
const CANDIDATE_ENTRIES: usize = 50_000;
const CANDIDATE_TIME: Duration = Duration::from_secs(2);

/// Desktop files are a few hundred bytes. A user's own applications directory
/// can hold anything, so a file above this is skipped rather than read into
/// memory.
const DESKTOP_MAX_BYTES: u64 = 64 * 1024;

/// The whole row has to fit in a health summary. When this runs out the row
/// says "at least", because a short list printed as the whole answer is the
/// quiet lie this program exists to avoid.
const TOTAL_TIME: Duration = Duration::from_secs(4);

/// A directory the evidence does not account for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub name: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Report {
    /// The cache base does not exist; there is nothing to report.
    Absent,
    /// The base exists but cannot be read, or the catalog did not compile.
    Unavailable(&'static str),
    /// Largest first. `complete` is false when a budget cut the scan.
    Found {
        candidates: Vec<Candidate>,
        complete: bool,
    },
}

/// Session-wide caches. They are shared by many applications, so "no single
/// application owns this" is not evidence that one left it behind.
const SHARED_NAMES: &[&str] = &[
    "appstream",
    "dconf",
    "fontconfig",
    "gstreamer-1.0",
    "gtk-2.0",
    "gtk-3.0",
    "gtk-4.0",
    "ibus",
    "kactivitymanagerd",
    "kdeconnect.app",
    "kglobalaccel",
    "kio",
    "kpackage-knshandler",
    "kscreen",
    "ksycoca5",
    "ksycoca6",
    "kwin",
    "logs",
    "pipewire",
    "plasmashell",
    "pulse",
    "qmlcache",
    "sessions",
    "systemd",
    "tracker3",
    "wireplumber",
];

/// Shared caches that carry a version or a driver name.
const SHARED_PREFIXES: &[&str] = &["kde", "mesa_shader_cache", "nvidia", "plasma"];

pub(crate) fn scan(xdg: &Xdg, probe: &dyn FsProbe) -> Report {
    match std::fs::metadata(&xdg.cache) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Report::Unavailable("the cache base is not a directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Report::Absent,
        Err(_) => return Report::Unavailable("the cache base is not readable"),
    }

    let Ok(set) = RuleSet::load(xdg) else {
        // "No dedicated rule" cannot be proven without the catalog, so the
        // row refuses to guess rather than report every child as an orphan.
        return Report::Unavailable("the rule catalog did not compile");
    };
    let roots = dedicated_roots(&set, xdg);
    let residual = set
        .rules()
        .iter()
        .find(|rule| rule.id.as_str() == "user.cache.residual");

    let read = match std::fs::read_dir(&xdg.cache) {
        Ok(read) => read,
        Err(_) => return Report::Unavailable("the cache base is not readable"),
    };

    let mut pending: Vec<(String, PathBuf)> = Vec::new();
    let mut desktops: Option<Vec<DesktopEntry>> = None;
    for entry in read.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let path = entry.path();
        if roots.iter().any(|root| covers(root, &path)) {
            continue;
        }
        if let Some(rule) = residual {
            if rule.excludes(Path::new(&name)) {
                continue;
            }
        }
        if shared(&name) || bin_evidence(&name) {
            continue;
        }
        let entries = desktops.get_or_insert_with(|| desktop_entries(xdg));
        if desktop_evidence(&name, entries) {
            continue;
        }
        pending.push((name, path));
    }

    let started = Instant::now();
    let mut candidates = Vec::new();
    let mut complete = true;
    for (name, path) in pending {
        let remaining = TOTAL_TIME.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            complete = false;
            break;
        }
        let limits = Limits {
            max_entries: CANDIDATE_ENTRIES,
            time_budget: remaining.min(CANDIDATE_TIME),
        };
        let mut spec = Spec::new(usize::MAX, &limits);
        spec.select = Select::Everything;
        let collected = scan::collect(&path, &path, 0, &spec, probe);
        if collected.stop != Stop::Complete
            || collected.root_unreadable
            || collected.missing_root
            || collected.not_a_directory
            || collected.stats.unreadable > 0
        {
            complete = false;
            continue;
        }
        if collected.bytes < MIN_BYTES {
            continue;
        }
        candidates.push(Candidate {
            name,
            bytes: collected.bytes,
        });
    }
    candidates.sort_by(|left, right| {
        right
            .bytes
            .cmp(&left.bytes)
            .then_with(|| left.name.cmp(&right.name))
    });

    Report::Found {
        candidates,
        complete,
    }
}

/// Every root the catalog names, with glob roots expanded.
///
/// Disabled rules count too: a disabled rule still documents that the path is
/// known, and the row is about ownership rather than about what `clean` would
/// take today. A glob that cannot be expanded contributes nothing, which
/// leaves its subtree eligible for the report instead of hiding it.
fn dedicated_roots(set: &RuleSet, xdg: &Xdg) -> Vec<PathBuf> {
    set.rules()
        .iter()
        .flat_map(|rule| rule.expanded_roots(xdg).unwrap_or_default())
        .collect()
}

/// True when a rule names this directory or something inside it.
///
/// A rule rooted above the candidate (`user.cache.residual` at `{cache}`) is
/// not evidence: it is the blanket scan this report is trying to see past.
fn covers(root: &Path, candidate: &Path) -> bool {
    root == candidate || root.starts_with(candidate)
}

fn shared(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SHARED_NAMES.iter().any(|shared| lower == *shared)
        || SHARED_PREFIXES
            .iter()
            .any(|prefix| lower.starts_with(prefix))
}

/// A command with the directory's name, for tools that ship no desktop file.
fn bin_evidence(name: &str) -> bool {
    bin_evidence_in(name, std::env::var_os("PATH").as_deref())
}

fn bin_evidence_in(name: &str, path: Option<&OsStr>) -> bool {
    let base = name.to_ascii_lowercase().replace(' ', "-");
    ["", "-bin", "-launcher", "-cli"]
        .iter()
        .any(|suffix| binary_available_in(&format!("{base}{suffix}"), path))
}

fn binary_available(binary: &str) -> bool {
    binary_available_in(binary, std::env::var_os("PATH").as_deref())
}

fn binary_available_in(binary: &str, path: Option<&OsStr>) -> bool {
    if binary.is_empty() {
        return false;
    }
    if binary.contains('/') {
        let path = Path::new(binary);
        return path.is_absolute() && is_executable(path);
    }
    let Some(path) = path else {
        return false;
    };
    std::env::split_paths(path)
        .filter(|directory| !directory.as_os_str().is_empty())
        .any(|directory| is_executable(&directory.join(binary)))
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

struct DesktopEntry {
    /// Normalized file stem, `Name`, `StartupWMClass` and `X-Flatpak`.
    tokens: Vec<String>,
    /// `Exec` and `TryExec` binaries, before the PATH lookup.
    binaries: Vec<String>,
}

/// Parse the desktop entries that can name an application.
///
/// Only `[Desktop Entry]` is read: a `[Desktop Action ...]` group has its own
/// `Exec`, and treating that as the application's binary would be wrong.
fn desktop_entries(xdg: &Xdg) -> Vec<DesktopEntry> {
    let mut directories: Vec<PathBuf> = vec![xdg.data.join("applications")];
    match std::env::var_os("XDG_DATA_DIRS") {
        Some(value) => directories.extend(
            std::env::split_paths(&value)
                .filter(|directory| !directory.as_os_str().is_empty())
                .map(|directory| directory.join("applications")),
        ),
        None => {
            directories.push(PathBuf::from("/usr/local/share/applications"));
            directories.push(PathBuf::from("/usr/share/applications"));
        }
    }
    directories.push(PathBuf::from("/var/lib/flatpak/exports/share/applications"));
    directories.push(xdg.data.join("flatpak/exports/share/applications"));
    directories.sort();
    directories.dedup();

    let mut entries = Vec::new();
    for directory in directories {
        let Ok(read) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in read.flatten() {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("desktop") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|value| value.to_str()) else {
                continue;
            };
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if !meta.is_file() || meta.len() > DESKTOP_MAX_BYTES {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let mut parsed = DesktopEntry {
                tokens: vec![normalize(stem)],
                binaries: Vec::new(),
            };
            let mut in_entry = false;
            for line in text.lines() {
                let line = line.trim();
                if line.starts_with('[') && line.ends_with(']') {
                    in_entry = line[1..line.len() - 1].trim() == "Desktop Entry";
                    continue;
                }
                if !in_entry {
                    continue;
                }
                let Some((key, value)) = line.split_once('=') else {
                    continue;
                };
                let value = value.trim();
                match key.trim() {
                    "Name" | "StartupWMClass" | "X-Flatpak" => {
                        parsed.tokens.push(normalize(value));
                    }
                    "Exec" => {
                        if let Some(binary) = exec_binary(value) {
                            parsed.tokens.push(normalize(
                                Path::new(&binary)
                                    .file_name()
                                    .and_then(|name| name.to_str())
                                    .unwrap_or(&binary),
                            ));
                            parsed.binaries.push(binary);
                        }
                    }
                    "TryExec" => {
                        if let Some(binary) = exec_binary(value) {
                            parsed.tokens.push(normalize(
                                Path::new(&binary)
                                    .file_name()
                                    .and_then(|name| name.to_str())
                                    .unwrap_or(&binary),
                            ));
                            parsed.binaries.push(binary);
                        }
                    }
                    _ => {}
                }
            }
            parsed.tokens.retain(|token| !token.is_empty());
            if !parsed.tokens.is_empty() {
                entries.push(parsed);
            }
        }
    }
    entries
}

/// The binary an `Exec=` line would start.
///
/// `Exec` is not a shell command line. It is a quoted argument list, and it may
/// start with `env` and its assignments (`Exec=env FOO=bar app`). Field codes
/// (`%u`, `%F`) are arguments, not part of the binary.
fn exec_binary(value: &str) -> Option<String> {
    let words = split_exec(value);
    let mut words = words.iter();
    let mut first = words.next()?;
    if first == "env" {
        let mut found = None;
        for word in words {
            if word.starts_with('-') || word.contains('=') {
                continue;
            }
            found = Some(word);
            break;
        }
        first = found?;
    }
    let first = first.trim_matches(|character| character == '"' || character == '\'');
    if first.is_empty() {
        None
    } else {
        Some(first.to_string())
    }
}

fn split_exec(value: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for character in value.chars() {
        match quote {
            Some(open) if character == open => quote = None,
            Some(_) => current.push(character),
            None if character == '"' || character == '\'' => quote = Some(character),
            None if character.is_whitespace() => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            None => current.push(character),
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn desktop_evidence(name: &str, entries: &[DesktopEntry]) -> bool {
    let token = normalize(name);
    if token.is_empty() {
        return false;
    }
    entries.iter().any(|entry| {
        entry
            .tokens
            .iter()
            .any(|candidate| similarity(&token, candidate) >= 5)
            && entry.binaries.iter().any(|binary| binary_available(binary))
    })
}

/// A deliberately small fuzzy score.
///
/// A data directory rarely shares its exact name with a desktop file (`Code`
/// vs `code.desktop`, `BraveSoftware` vs `brave-browser.desktop`), so a shared
/// prefix or a long substring counts. Five is the floor: shorter overlaps are
/// how `cursor-agent` matched an entry named `Age of History 3`.
fn similarity(left: &str, right: &str) -> usize {
    if left == right {
        return usize::MAX;
    }
    let prefix = left
        .bytes()
        .zip(right.bytes())
        .take_while(|(left, right)| left == right)
        .count();
    let mut score = prefix;
    if left.len() >= 6 && right.contains(left) {
        score = score.max(left.len());
    }
    if right.len() >= 6 && left.contains(right) {
        score = score.max(right.len());
    }
    score
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sweep_core::probe::RealProbe;

    fn xdg_at(home: &Path) -> Xdg {
        Xdg::resolve(|key| match key {
            "HOME" => Some(home.as_os_str().to_os_string()),
            _ => None,
        })
        .expect("home")
    }

    #[test]
    fn a_rule_root_above_the_candidate_is_not_evidence() {
        let candidate = Path::new("/home/u/.cache/SomeApp");
        assert!(!covers(Path::new("/home/u/.cache"), candidate));
        assert!(covers(candidate, candidate));
        assert!(covers(
            Path::new("/home/u/.cache/SomeApp/nested"),
            candidate
        ));
        assert!(!covers(Path::new("/home/u/.cache/Other"), candidate));
    }

    #[test]
    fn shared_session_caches_are_never_candidates() {
        for name in ["KDE", "gtk-4.0", "fontconfig", "mesa_shader_cache_db"] {
            assert!(shared(name), "{name} is a shared cache");
        }
        assert!(!shared("SomeApp"));
    }

    #[test]
    fn a_directory_name_can_evidence_a_command_on_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let binary = temp.path().join("sweep-test-tool");
        std::fs::write(&binary, b"#!/bin/sh\n").expect("write");
        let mut permissions = std::fs::metadata(&binary).expect("metadata").permissions();
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o755);
        std::fs::set_permissions(&binary, permissions).expect("chmod");

        let path = temp.path().as_os_str();
        assert!(
            bin_evidence_in("sweep-test-tool", Some(path)),
            "a command with the directory's name is evidence"
        );
        assert!(
            !bin_evidence_in("sweep-test-missing", Some(path)),
            "a name with no command is not evidence"
        );
    }

    #[test]
    fn exec_binary_skips_env_assignments_and_field_codes() {
        assert_eq!(
            exec_binary(r#""/home/u/.local/bin/claude" --handle-uri %u"#).as_deref(),
            Some("/home/u/.local/bin/claude")
        );
        assert_eq!(
            exec_binary("env FOO=bar app --flag %F").as_deref(),
            Some("app")
        );
        assert_eq!(exec_binary(""), None);
    }

    #[test]
    fn similarity_does_not_match_two_short_unrelated_names() {
        assert!(similarity("cursoragent", "ageofhistory3") < 5);
        assert!(similarity("bravesoftware", "brave") >= 5);
        assert!(similarity("shelly", "comshellyorgshelly") >= 5);
    }

    #[test]
    fn a_missing_cache_base_is_absent_not_empty() {
        let temp = tempfile::tempdir().expect("tempdir");
        let probe = RealProbe::new().expect("probe");
        assert_eq!(scan(&xdg_at(temp.path()), &probe), Report::Absent);
    }

    #[test]
    fn an_unowned_cache_directory_is_reported_with_its_size() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        let cache = home.join(".cache/GoneApp");
        std::fs::create_dir_all(&cache).expect("mkdir");
        std::fs::write(cache.join("blob"), vec![0u8; 2 * 1024 * 1024]).expect("write");

        let probe = RealProbe::new().expect("probe");
        let report = scan(&xdg_at(home), &probe);
        let Report::Found {
            candidates,
            complete,
        } = report
        else {
            panic!("expected a report: {report:?}");
        };
        assert!(complete, "a tiny tree must fit the budget");
        let found = candidates
            .iter()
            .find(|candidate| candidate.name == "GoneApp")
            .expect("the unowned directory is a candidate");
        assert!(found.bytes >= MIN_BYTES, "{}", found.bytes);
    }

    #[test]
    fn a_catalogued_cache_directory_is_not_reported() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path();
        // `dev.uv.cache` owns `{cache}/uv`, so the row must leave it alone even
        // when it is empty and nothing else on the machine names it.
        let cache = home.join(".cache/uv");
        std::fs::create_dir_all(&cache).expect("mkdir");
        std::fs::write(cache.join("blob"), vec![0u8; 2 * 1024 * 1024]).expect("write");

        let probe = RealProbe::new().expect("probe");
        let report = scan(&xdg_at(home), &probe);
        let Report::Found { candidates, .. } = report else {
            panic!("expected a report: {report:?}");
        };
        assert!(
            !candidates.iter().any(|candidate| candidate.name == "uv"),
            "a rule names this path: {candidates:?}"
        );
    }
}
