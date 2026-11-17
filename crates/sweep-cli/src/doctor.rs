//! `sweep doctor` — what the tool can actually see on this machine.
//!
//! Doctor is read-only and it is the honest answer to "why did sweep skip
//! everything?". It prints the resolved base directories, every mount with its
//! filesystem type and copy-on-write status, the number of protected roots, and
//! whether `openat2` is available. A user reporting a bug can paste its output
//! whole.

use std::process::ExitCode;

use serde::Serialize;
use sweep_core::fs_facts::MountTable;
use sweep_core::paths::{is_within, Xdg};
use sweep_core::policy::PROTECTED_ROOTS;
use sweep_core::probe::{OpenInodes, RealProbe};
use sweep_core::{sys, FsProbe};

#[derive(Debug, Serialize)]
pub(crate) struct Report {
    version: String,
    uid: u32,
    running_as_root: bool,
    openat2: bool,
    xdg: XdgReport,
    mounts: Vec<MountReport>,
    protected_roots: usize,
    open_handles: usize,
    state_writable: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct XdgReport {
    home: String,
    cache: String,
    config: String,
    data: String,
    state: String,
    runtime: String,
    /// From `user-dirs.dirs`: the locale-dependent directory `installer` reads.
    download: String,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct MountReport {
    mount_point: String,
    fstype: String,
    read_only: bool,
    cow: bool,
    snapshots: Vec<String>,
}

pub fn run(json: bool) -> ExitCode {
    let report = match gather() {
        Ok(report) => report,
        Err(message) => {
            eprintln!("sweep doctor: {message}");
            return ExitCode::from(crate::EXIT_UNSUPPORTED_ENVIRONMENT);
        }
    };

    match render(&report, json) {
        Ok(text) => print!("{text}"),
        Err(message) => {
            eprintln!("sweep doctor: {message}");
            return ExitCode::FAILURE;
        }
    }

    if report.running_as_root {
        eprintln!(
            "sweep doctor: refusing to run as root; run as your user and let sweep \
             request privilege for system sections only"
        );
        return ExitCode::from(crate::EXIT_UNSUPPORTED_ENVIRONMENT);
    }
    ExitCode::SUCCESS
}

fn gather() -> Result<Report, String> {
    let xdg = Xdg::from_env().map_err(|error| error.to_string())?;
    let mounts = MountTable::load().map_err(|error| format!("cannot read mounts: {error}"))?;
    let probe = RealProbe::new().map_err(|error| format!("cannot probe: {error}"))?;
    let uid = probe.euid();
    let open_inodes = OpenInodes::scan();
    let state_writable = state_dir_writable(&xdg);

    Ok(Report {
        version: sweep_core::VERSION.to_string(),
        uid,
        running_as_root: uid == 0,
        openat2: sys::openat2_supported(),
        xdg: XdgReport {
            home: xdg.home.display().to_string(),
            cache: xdg.cache.display().to_string(),
            config: xdg.config.display().to_string(),
            data: xdg.data.display().to_string(),
            state: xdg.state.display().to_string(),
            runtime: xdg.runtime.display().to_string(),
            download: xdg.download.display().to_string(),
            warnings: xdg.warnings.clone(),
        },
        mounts: mounts
            .mounts()
            .iter()
            .filter(|mount| {
                !mount.mount_point.starts_with("/proc") && !mount.mount_point.starts_with("/sys")
            })
            .map(|mount| {
                let facts = mounts.facts(&mount.mount_point);
                MountReport {
                    mount_point: mount.mount_point.display().to_string(),
                    fstype: mount.fstype.name().to_string(),
                    read_only: mount.options.read_only,
                    cow: facts.as_ref().map(|f| f.is_cow).unwrap_or(false),
                    snapshots: snapshots_on(&mount.mount_point, facts.as_ref()),
                }
            })
            .collect(),
        protected_roots: PROTECTED_ROOTS.len(),
        open_handles: open_inodes.len(),
        state_writable,
    })
}

/// Snapshot directories that actually exist *on this mount*.
///
/// The candidate list is global on purpose — a path under `/.snapshots` must be
/// refused no matter which mount it is reported on — but attributing it to every
/// mount would make the `[snapshots]` flag meaningless: one existing
/// `/.snapshots` would decorate all thirty mounts. Narrowing to the mount point
/// keeps the column honest.
fn snapshots_on(mount_point: &std::path::Path, facts: Option<&sweep_core::FsFacts>) -> Vec<String> {
    facts
        .map(|facts| {
            facts
                .snapshot_candidates
                .iter()
                .filter(|candidate| is_within(mount_point, candidate))
                .filter(|candidate| candidate.exists())
                .map(|candidate| candidate.display().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn state_dir_writable(xdg: &Xdg) -> bool {
    let dir = xdg.state_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return false;
    }
    // Create and remove a probe file rather than trusting the mode bits: a
    // read-only mount, a full disk and an ACL all look the same from `stat`.
    let probe = dir.join(".doctor-probe");
    match std::fs::write(&probe, b"ok") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Renders the report. Returning a `String` keeps the formatting testable:
/// asserting on stdout from inside the process is fragile and cannot see the
/// exact bytes.
pub(crate) fn render(report: &Report, json: bool) -> Result<String, String> {
    if json {
        let mut text = serde_json::to_string_pretty(report)
            .map_err(|error| format!("cannot serialize report: {error}"))?;
        text.push('\n');
        return Ok(text);
    }
    Ok(render_human(report))
}

fn render_human(report: &Report) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();

    let _ = writeln!(out, "sweep {}", report.version);
    let _ = writeln!(
        out,
        "user            uid {}{}",
        report.uid,
        if report.running_as_root {
            "  (root — unsupported)"
        } else {
            ""
        }
    );
    let _ = writeln!(
        out,
        "openat2         {}",
        if report.openat2 {
            "available"
        } else {
            "unavailable (using the component-walk fallback)"
        }
    );
    let _ = writeln!(out, "home            {}", report.xdg.home);
    let _ = writeln!(out, "cache           {}", report.xdg.cache);
    let _ = writeln!(out, "config          {}", report.xdg.config);
    let _ = writeln!(out, "data            {}", report.xdg.data);
    let _ = writeln!(out, "state           {}", report.xdg.state);
    let _ = writeln!(out, "download        {}", report.xdg.download);
    let _ = writeln!(
        out,
        "state writable  {}",
        if report.state_writable { "yes" } else { "no" }
    );
    let _ = writeln!(out, "protected roots {}", report.protected_roots);
    let _ = writeln!(out, "open handles    {}", report.open_handles);
    let _ = writeln!(out, "mounts          {}", report.mounts.len());
    // Column widths come from the data: a fixed width silently misaligns as soon
    // as a real mount point is longer than the guess, and
    // `/run/credentials/systemd-journald.service` is longer than any guess.
    // Only a minimum is imposed; capping the maximum would re-break alignment on
    // exactly the long paths that motivated measuring.
    let path_width = report
        .mounts
        .iter()
        .map(|mount| mount.mount_point.chars().count())
        .max()
        .unwrap_or(0)
        .max(12);
    let type_width = report
        .mounts
        .iter()
        .map(|mount| mount.fstype.chars().count())
        .max()
        .unwrap_or(0)
        .max(6);
    for mount in &report.mounts {
        let mut flags = Vec::new();
        if mount.read_only {
            flags.push("ro");
        }
        if mount.cow {
            flags.push("cow");
        }
        if !mount.snapshots.is_empty() {
            flags.push("snapshots");
        }
        let suffix = if flags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", flags.join(","))
        };
        // Trim the padding when there is no suffix, so a piped report has no
        // trailing whitespace to trip up `awk` or a diff.
        let line = format!(
            "  {:<path_width$} {:<type_width$}{}",
            mount.mount_point, mount.fstype, suffix
        );
        let _ = writeln!(out, "{}", line.trim_end());
    }
    if !report.xdg.warnings.is_empty() {
        let _ = writeln!(out, "warnings");
        for warning in &report.xdg.warnings {
            let _ = writeln!(out, "  - {warning}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn gather_reports_the_real_machine() {
        // Runs everywhere: a probe that cannot see the local mounts is a hard
        // failure, not a skipped test.
        let report = gather().expect("doctor must gather on Linux");
        assert!(!report.mounts.is_empty());
        assert!(report.protected_roots > 10);
        assert!(!report.running_as_root, "tests must not run as root");
    }

    #[test]
    fn json_round_trips() {
        let report = gather().expect("gather");
        let text = serde_json::to_string(&report).expect("serialize");
        let value: serde_json::Value = serde_json::from_str(&text).expect("parse");
        assert!(value.get("mounts").is_some());
        assert!(value.get("xdg").is_some());
    }

    #[test]
    fn a_global_snapshot_root_is_attributed_to_one_mount_only() {
        let raw = "30 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n\
                   31 30 8:3 / /home rw,relatime - ext4 /dev/sda3 rw\n\
                   32 30 8:4 / /srv rw,relatime - ext4 /dev/sda4 rw\n";
        let table = MountTable::parse(raw);

        // Refusal keeps using the global list: a path under `/.snapshots` is
        // refused whichever mount reports it.
        let home = table.facts(Path::new("/home")).expect("facts");
        assert!(
            home.is_snapshot_path(Path::new("/.snapshots/1/snapshot")),
            "a global snapshot root must still refuse a path beneath it"
        );

        // Display must not: one existing `/.snapshots` would otherwise decorate
        // every mount in the table.
        let shown = snapshots_on(Path::new("/home"), Some(&home));
        assert!(
            shown.is_empty(),
            "a mount must not claim a snapshot directory outside itself: {shown:?}"
        );
        let shown = snapshots_on(Path::new("/srv"), Some(&home));
        assert!(
            shown.is_empty(),
            "/srv must not claim /home's or the root's snapshots: {shown:?}"
        );
    }
}

#[cfg(test)]
mod render_tests {
    use super::*;

    fn sample() -> Report {
        Report {
            version: "0.1.0".into(),
            uid: 1000,
            running_as_root: false,
            openat2: true,
            xdg: XdgReport {
                home: "/home/u".into(),
                cache: "/home/u/.cache".into(),
                config: "/home/u/.config".into(),
                data: "/home/u/.local/share".into(),
                state: "/home/u/.local/state".into(),
                runtime: "/run/user/1000".into(),
                download: "/home/u/Downloads".into(),
                warnings: vec![],
            },
            mounts: vec![
                MountReport {
                    mount_point: "/".into(),
                    fstype: "btrfs".into(),
                    read_only: false,
                    cow: true,
                    snapshots: vec!["/.snapshots".into()],
                },
                MountReport {
                    mount_point: "/mnt/usb".into(),
                    fstype: "vfat".into(),
                    read_only: true,
                    cow: false,
                    snapshots: vec![],
                },
            ],
            protected_roots: 22,
            open_handles: 12,
            state_writable: true,
        }
    }

    #[test]
    fn human_output_names_the_facts_a_report_needs() {
        let text = render_human(&sample());
        for expected in [
            "sweep 0.1.0",
            "uid 1000",
            "openat2         available",
            "protected roots 22",
            "/home/u/.cache",
            "[cow,snapshots]",
            "[ro]",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
    }

    #[test]
    fn human_output_has_no_trailing_whitespace() {
        // A report someone pastes into a bug tracker must not carry invisible
        // padding, and `diff` noise makes support threads harder to read.
        let text = render_human(&sample());
        for line in text.lines() {
            assert_eq!(line.trim_end(), line, "trailing whitespace: {line:?}");
        }
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn columns_align_even_when_a_mount_point_is_long() {
        let text = render_human(&sample());
        let type_starts: Vec<usize> = text
            .lines()
            .filter(|line| line.starts_with("  /"))
            .map(|line| {
                line.find("btrfs")
                    .or_else(|| line.find("vfat"))
                    .expect("fstype present")
            })
            .collect();
        assert_eq!(type_starts.len(), 2);
        assert_eq!(
            type_starts[0], type_starts[1],
            "filesystem column drifts:\n{text}"
        );
    }

    #[test]
    fn root_mount_is_marked_unsupported() {
        let mut report = sample();
        report.running_as_root = true;
        report.uid = 0;
        let text = render_human(&report);
        assert!(text.contains("root — unsupported"), "{text}");
    }

    #[test]
    fn warnings_are_listed_when_present() {
        let mut report = sample();
        report.xdg.warnings = vec!["XDG_CACHE_HOME ignored (not absolute)".into()];
        let text = render_human(&report);
        assert!(text.contains("warnings"));
        assert!(text.contains("XDG_CACHE_HOME ignored"));
    }

    #[test]
    fn json_output_parses_as_one_document() {
        let text = render(&sample(), true).expect("render");
        assert!(text.ends_with('\n'));
        // One document: `from_str` rejects trailing content, so a second
        // concatenated document would fail here.
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        assert_eq!(value["mounts"][0]["fstype"], "btrfs");
        assert_eq!(value["mounts"].as_array().expect("array").len(), 2);
        // A JSON consumer must never receive a raw control byte.
        assert!(
            !text.bytes().any(|byte| byte < 0x20 && byte != b'\n'),
            "control byte in JSON output"
        );
    }

    #[test]
    fn a_missing_openat2_is_reported_as_the_fallback() {
        let mut report = sample();
        report.openat2 = false;
        let text = render_human(&report);
        assert!(
            text.contains("component-walk fallback"),
            "an unavailable openat2 must say what is used instead:\n{text}"
        );
    }
}
