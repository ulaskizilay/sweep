//! End-to-end tests against the built binary.
//!
//! These are the only tests that exercise argument parsing, the tracing setup and
//! the exit codes, because they run `sweep` as a separate process. Everything
//! else calls library functions, which is where the interesting logic lives; this
//! file exists so that "the binary starts and says the right thing" is covered by
//! a machine rather than by whoever happened to run it last.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn sweep() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sweep"))
}

/// A binary invocation with every XDG variable pointed at a temporary home.
///
/// `clean` and `rules` resolve their roots from the environment, so a test that
/// inherited the developer's real `$HOME` would scan it: slow, machine-dependent
/// and, for the write-nothing assertion, meaningless.
fn sweep_in(home: &Path) -> Command {
    let mut command = sweep();
    command.env("HOME", home);
    for key in [
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_RUNTIME_DIR",
    ] {
        command.env_remove(key);
    }
    command
}

struct Output {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Output {
    collect(sweep().args(args).output().expect("spawn sweep"))
}

fn run_in(home: &Path, args: &[&str]) -> Output {
    collect(sweep_in(home).args(args).output().expect("spawn sweep"))
}

fn collect(output: std::process::Output) -> Output {
    Output {
        code: output.status.code(),
        stdout: String::from_utf8(output.stdout).expect("utf-8 stdout"),
        stderr: String::from_utf8(output.stderr).expect("utf-8 stderr"),
    }
}

#[test]
fn version_goes_to_stdout_and_exits_zero() {
    let output = run(&["--version"]);
    assert_eq!(output.code, Some(0));
    assert!(
        output.stdout.contains("sweep"),
        "stdout: {:?}",
        output.stdout
    );
    assert!(output.stderr.is_empty(), "stderr: {:?}", output.stderr);
}

#[test]
fn help_lists_the_command_surface() {
    let output = run(&["--help"]);
    assert_eq!(output.code, Some(0));
    for command in ["doctor", "rules", "clean"] {
        assert!(
            output.stdout.contains(command),
            "`{command}` is missing from the command list:\n{}",
            output.stdout
        );
    }
    assert!(
        output.stdout.contains("Arch Linux"),
        "the help text must say what this is for:\n{}",
        output.stdout
    );
}

#[test]
fn an_unknown_command_is_a_usage_error() {
    let output = run(&["definitely-not-a-command"]);
    assert_eq!(
        output.code,
        Some(2),
        "clap reports usage errors with 2, not 1"
    );
    assert!(
        !output.stderr.is_empty(),
        "a usage error must explain itself"
    );
}

#[test]
fn doctor_human_output_is_stable_and_parseable() {
    let output = run(&["doctor"]);
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    assert!(output.stdout.starts_with("sweep "), "{}", output.stdout);
    assert!(output.stdout.contains("protected roots"));
    // `--json` must stay a pure document on stdout, so human output must not be
    // mixed into it either.
    assert!(
        !output.stdout.lines().any(|line| line.trim().is_empty()),
        "doctor must not emit blank lines:\n{}",
        output.stdout
    );
}

#[test]
fn doctor_json_is_a_single_parseable_document() {
    let output = run(&["doctor", "--json"]);
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    let value: serde_json::Value =
        serde_json::from_str(&output.stdout).expect("stdout must be one JSON document");

    for key in [
        "version",
        "uid",
        "running_as_root",
        "openat2",
        "xdg",
        "mounts",
        "protected_roots",
        "open_handles",
        "state_writable",
    ] {
        assert!(value.get(key).is_some(), "missing {key} in {value:#}");
    }
    assert!(
        !value["mounts"].as_array().expect("array").is_empty(),
        "a machine with no visible mounts is not a working machine"
    );
}

#[test]
fn doctor_writes_nothing_to_stdout_on_stderr_warnings() {
    // Verbose logging goes to stderr, so `--json | jq` never breaks.
    let output = run(&["-vv", "doctor", "--json"]);
    assert_eq!(output.code, Some(0));
    serde_json::from_str::<serde_json::Value>(&output.stdout)
        .expect("verbose logging must not pollute stdout");
}

#[test]
fn doctor_reports_the_real_effective_uid() {
    // No `libc` in a test crate: ask the system the same way a user would.
    let uid = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|text| text.trim().to_string())
        .expect("`id -u` must work on Linux");

    let output = run(&["doctor", "--json"]);
    let value: serde_json::Value = serde_json::from_str(&output.stdout).expect("json");
    assert_eq!(
        value["uid"].as_u64().map(|uid| uid.to_string()),
        Some(uid),
        "the report must name the uid it actually used"
    );
    assert_eq!(
        value["running_as_root"],
        value["uid"] == 0,
        "the root flag must be derived from the uid, not hard-coded"
    );
}

#[test]
fn root_invocation_is_refused_with_exit_78() {
    // CI runs unprivileged, so the only way to exercise the refusal end to end
    // is to actually be uid 0. When the suite runs as root this asserts the
    // refusal; otherwise it asserts the ordinary path. The refusal *logic* is
    // unit-tested in `main.rs` against a literal uid 0, which is the part that
    // can otherwise rot unnoticed.
    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|text| text.trim() == "0")
        .unwrap_or(false);

    if is_root {
        let refused = run(&["doctor", "--json"]);
        assert_eq!(refused.code, Some(78), "root must be refused with 78");
        assert!(
            refused.stderr.contains("refusing to run as root"),
            "the refusal must say why: {:?}",
            refused.stderr
        );
        assert!(
            refused.stdout.is_empty(),
            "a refused run must not emit a report: {:?}",
            refused.stdout
        );
        return;
    }

    let json = run(&["doctor", "--json"]);
    assert_eq!(json.code, Some(0), "stderr: {}", json.stderr);
    let value: serde_json::Value = serde_json::from_str(&json.stdout).expect("json");
    assert_eq!(
        value["running_as_root"], false,
        "an ordinary user must not be reported as root"
    );
}

#[test]
fn a_real_uid_zero_process_is_refused() {
    // `unshare -r` maps the caller to uid 0 inside a new user namespace, which is
    // the only way an unprivileged test suite can present a genuine `geteuid()
    // == 0` to the binary. Skipped where unprivileged user namespaces are
    // disabled, because that is an environment limitation and not a defect.
    let probe = Command::new("unshare")
        .args(["-r", "id", "-u"])
        .output()
        .ok();
    let uid_zero = probe
        .as_ref()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim() == "0")
        .unwrap_or(false);
    if !uid_zero {
        eprintln!("skipping: unprivileged user namespaces unavailable");
        return;
    }

    let output = Command::new("unshare")
        .arg("-r")
        .arg(env!("CARGO_BIN_EXE_sweep"))
        .args(["doctor", "--json"])
        .output()
        .expect("spawn under unshare");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.code(),
        Some(78),
        "a uid-0 process must be refused with 78; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stderr.contains("refusing to run as root"),
        "stderr must name the cause: {stderr:?}"
    );
    assert!(
        stdout.trim().is_empty(),
        "a refused run must produce no report: {stdout:?}"
    );
}

// ----------------------------------------------------------------- rules ---

fn home() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn write(root: &Path, relative: &str, body: &str) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    std::fs::write(&path, body).expect("write");
}

/// Every path below `root`, sorted.
///
/// Used as a before/after fingerprint: a dry run may not create, remove or
/// rewrite anything, and a set comparison catches all three without needing to
/// know which file the implementation might have touched.
fn snapshot(root: &Path) -> BTreeSet<PathBuf> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let Ok(read) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in read.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path.clone());
            }
            seen.insert(path);
        }
    }
    seen
}

const BROKEN_OVERLAY: &str = r#"
[[rule]]
id = "user.bad"
section = "user-essentials"
kind = "dir-sweep"
root = "/usr/share"
evidence = "a rule cannot opt out of the compile-time protected list"
recoverable = true
keep_days = 0
privilege = "user"
"#;

#[test]
fn rules_list_names_every_section_and_keeps_disabled_rules_visible() {
    let home = home();
    let output = run_in(home.path(), &["rules", "list"]);
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    assert!(
        output.stdout.contains("sweep rules —"),
        "the header must say what this is:\n{}",
        output.stdout
    );
    for section in [
        "system",
        "user-essentials",
        "dev-tools",
        "project-artifacts",
    ] {
        assert!(
            output
                .stdout
                .lines()
                .any(|line| line.trim_start().starts_with(section)),
            "section {section} is missing from the summary:\n{}",
            output.stdout
        );
    }

    // A disabled rule stays on the list, marked as such: `list` is the review
    // surface and hiding a rule is how a stale one goes unnoticed.
    let line = output
        .stdout
        .lines()
        .find(|line| line.contains("system.pacman.package-cache"))
        .expect("a known rule must be listed");
    assert!(
        line.contains(" off "),
        "disabled rule is not marked: {line:?}"
    );
}

#[test]
fn rules_list_json_is_one_document_that_agrees_with_itself() {
    let home = home();
    let output = run_in(home.path(), &["rules", "list", "--json"]);
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    let value: serde_json::Value = serde_json::from_str(&output.stdout)
        .expect("`--json` must stay a single document on stdout");

    let rules = value["rule"].as_array().expect("rule array");
    assert!(!rules.is_empty());
    assert_eq!(
        value["rules"].as_u64(),
        Some(rules.len() as u64),
        "the count and the array must describe the same catalog"
    );
    assert!(value["packs"].as_u64().unwrap_or(0) >= 1);
    let enabled = rules
        .iter()
        .filter(|rule| rule["enabled"] == serde_json::Value::Bool(true))
        .count();
    assert_eq!(value["enabled"].as_u64(), Some(enabled as u64));

    for rule in rules {
        let root = rule["resolved_root"].as_str().expect("resolved_root");
        assert!(root.starts_with('/'), "{root} is not absolute");
        assert!(
            rule["id"].as_str().unwrap_or_default().contains('.'),
            "ids are namespaced"
        );
    }
    assert!(
        rules
            .iter()
            .any(|rule| rule["enabled"] == serde_json::Value::Bool(false)),
        "root rules must stay visible while their privilege boundary is missing"
    );
}

#[test]
fn rules_verify_compiles_the_catalog() {
    let home = home();
    let output = run_in(home.path(), &["rules", "verify"]);
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    assert!(
        output
            .stdout
            .contains("compile and are internally consistent"),
        "verify must say what it proved:\n{}",
        output.stdout
    );

    let json = run_in(home.path(), &["rules", "verify", "--json"]);
    assert_eq!(json.code, Some(0), "stderr: {}", json.stderr);
    let value: serde_json::Value = serde_json::from_str(&json.stdout).expect("json");
    assert_eq!(value["ok"], serde_json::Value::Bool(true));
    assert!(value["errors"].as_array().expect("errors").is_empty());
}

#[test]
fn a_broken_user_overlay_is_refused_by_rules_and_by_clean() {
    let home = home();
    write(
        home.path(),
        ".config/sweep/rules.d/10-bad.toml",
        BROKEN_OVERLAY,
    );

    let verify = run_in(home.path(), &["rules", "verify"]);
    assert_eq!(
        verify.code,
        Some(3),
        "an invalid catalog is exit 3; stderr: {}",
        verify.stderr
    );
    assert!(
        verify.stderr.contains("protected_root"),
        "the refusal must name the reason code: {:?}",
        verify.stderr
    );
    assert!(
        verify.stderr.contains("user.bad"),
        "the refusal must name the rule: {:?}",
        verify.stderr
    );
    assert!(
        verify.stderr.contains("rules.d"),
        "the refusal must say where the editable files live: {:?}",
        verify.stderr
    );

    // A script reading `--json` gets the diagnosis on stdout and the exit code,
    // not prose on stderr it would have to parse.
    let json = run_in(home.path(), &["rules", "verify", "--json"]);
    assert_eq!(json.code, Some(3));
    let value: serde_json::Value = serde_json::from_str(&json.stdout).expect("one document");
    assert_eq!(value["ok"], serde_json::Value::Bool(false));
    assert_eq!(value["errors"][0]["code"], "protected_root");
    assert_eq!(value["errors"][0]["rule"], "user.bad");

    let clean = run_in(home.path(), &["clean", "--dry-run"]);
    assert_eq!(clean.code, Some(3), "clean shares the catalog gate");
    assert!(
        clean.stderr.contains("rules verify"),
        "the refusal must name what to run next: {:?}",
        clean.stderr
    );
    assert!(
        clean.stdout.is_empty(),
        "a refused clean must not print a plan: {:?}",
        clean.stdout
    );
}

// ----------------------------------------------------------------- clean ---

/// One row per line from the operation log, parsed.
fn log_rows(home: &Path) -> Vec<serde_json::Value> {
    let path = home.join(".local/state/sweep/operations.jsonl");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    raw.lines()
        .map(|line| serde_json::from_str(line).expect("one JSON record per line"))
        .collect()
}

fn firefox_cache(home: &Path) -> PathBuf {
    home.join(".cache/mozilla/firefox/profile/cache2/entries/blob")
}

#[test]
fn clean_without_yes_on_a_pipe_declines_and_writes_nothing() {
    let home = home();
    let blob = firefox_cache(home.path());
    write(
        home.path(),
        ".cache/mozilla/firefox/profile/cache2/entries/blob",
        "cache body",
    );
    let before = snapshot(home.path());

    // `Command::output` gives the child a null stdin, which is the case a cron
    // job hits: there is nobody to answer the prompt.
    let output = run_in(home.path(), &["clean"]);
    assert_eq!(
        output.code,
        Some(5),
        "a declined run is exit 5, not a silent preview; stderr: {}",
        output.stderr
    );
    assert!(
        output.stderr.contains("--yes"),
        "the refusal must name the flag that turns the question off: {:?}",
        output.stderr
    );
    assert!(
        output.stderr.contains("nothing was removed"),
        "the refusal must say what did not happen: {:?}",
        output.stderr
    );
    assert!(
        output.stdout.is_empty(),
        "a declined run must not print a report: {:?}",
        output.stdout
    );

    assert_eq!(
        before,
        snapshot(home.path()),
        "a declined run must not create, remove or move anything below HOME"
    );
    assert!(blob.exists(), "the planned file is still there");
    assert!(
        !home.path().join(".local/state/sweep").exists(),
        "a declined run must not create the state directory"
    );
}

#[test]
fn clean_yes_removes_only_planned_paths_and_logs_them() {
    let home = home();
    let blob = firefox_cache(home.path());
    write(
        home.path(),
        ".cache/mozilla/firefox/profile/cache2/entries/blob",
        "cache body",
    );
    // Profile data sits outside the cache root; a cache sweep must not see it.
    write(
        home.path(),
        ".mozilla/firefox/profile/bookmarks.sqlite",
        "precious",
    );

    let before = snapshot(home.path());
    let output = run_in(home.path(), &["clean", "--yes"]);
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    assert!(
        output.stdout.contains("applying the plan"),
        "the header must state the mode:\n{}",
        output.stdout
    );
    assert!(
        output.stdout.contains("operations.jsonl"),
        "the report must name the log it wrote:\n{}",
        output.stdout
    );

    assert!(!blob.exists(), "the planned file must be gone");
    assert!(
        home.path()
            .join(".mozilla/firefox/profile/bookmarks.sqlite")
            .exists(),
        "profile data is not a cache"
    );
    assert!(
        home.path().join(".cache/mozilla/firefox").exists(),
        "a dir-sweep root stays; only its entries go"
    );

    let after = snapshot(home.path());
    let gone: BTreeSet<PathBuf> = before.difference(&after).cloned().collect();
    assert!(!gone.is_empty(), "the run must have removed something");

    let rows = log_rows(home.path());
    assert!(!rows.is_empty(), "an applied run must log every decision");
    let mut removed = BTreeSet::new();
    for row in &rows {
        assert_eq!(row["cmd"], "clean");
        assert_eq!(
            row["session"].as_str().map(|s| s.starts_with("clean-")),
            Some(true),
            "the session is named after the command: {row}"
        );
        assert!(
            matches!(
                row["action"].as_str(),
                Some("REMOVED") | Some("SKIPPED") | Some("FAILED")
            ),
            "an applied run never writes WOULD_REMOVE: {row}"
        );
        if row["action"] == "REMOVED" {
            removed.insert(PathBuf::from(row["path"].as_str().expect("path")));
        }
    }
    assert_eq!(
        gone, removed,
        "every path that vanished must have one REMOVED row, and nothing else"
    );
    assert!(
        removed.contains(&blob),
        "the cache blob must be in the ledger: {removed:?}"
    );
}

#[test]
fn clean_dry_run_and_apply_describe_the_same_plan() {
    let home = home();
    write(
        home.path(),
        ".cache/mozilla/firefox/profile/cache2/entries/blob",
        "cache body",
    );

    let preview = run_in(home.path(), &["clean", "--dry-run", "--json"]);
    assert_eq!(preview.code, Some(0), "stderr: {}", preview.stderr);
    let preview: serde_json::Value = serde_json::from_str(&preview.stdout).expect("one document");
    assert_eq!(preview["mode"], "dry-run");
    assert_eq!(preview["log"], serde_json::Value::Null);
    assert_eq!(
        preview["funnel"]["removed"], 0,
        "a dry run removes nothing: {preview}"
    );
    let would = preview["funnel"]["would_remove"].as_u64().unwrap_or(0);
    assert!(would > 0, "the fixture must plan something: {preview}");

    let applied = run_in(home.path(), &["clean", "--yes", "--json"]);
    assert_eq!(applied.code, Some(0), "stderr: {}", applied.stderr);
    let applied: serde_json::Value = serde_json::from_str(&applied.stdout).expect("one document");
    assert_eq!(applied["mode"], "apply");
    assert_eq!(
        applied["plan_hash"], preview["plan_hash"],
        "the prompt must describe exactly the plan that gets applied"
    );
    assert_eq!(
        applied["funnel"]["would_remove"], 0,
        "an applied run reports removals, not intentions: {applied}"
    );
    assert_eq!(
        applied["funnel"]["removed"].as_u64(),
        Some(would),
        "every previewed item must be removed or accounted for"
    );
    assert_eq!(
        applied["log"]["session"]
            .as_str()
            .map(|session| session.starts_with("clean-")),
        Some(true),
        "the applied run names its session: {applied}"
    );
    assert!(
        applied["log"]["path"]
            .as_str()
            .unwrap_or_default()
            .ends_with("operations.jsonl"),
        "the report names the log file: {applied}"
    );
}

const TOOL_CACHE_OVERLAY: &str = r#"
[[rule]]
id = "test.tool-cache"
section = "dev-tools"
kind = "tool-cache"
root = "{home}/.cache/sweep-tool-test"
evidence = "a fixture directory that exists only in this test"
recoverable = true
keep_days = 0
privilege = "user"
"#;

#[test]
fn a_tool_cache_rule_removes_its_root_and_nothing_beside_it() {
    let home = home();
    write(
        home.path(),
        ".config/sweep/rules.d/50-tool-cache.toml",
        TOOL_CACHE_OVERLAY,
    );
    write(
        home.path(),
        ".cache/sweep-tool-test/v1/objects/blob",
        "built artifact",
    );
    write(home.path(), ".cache/keep-me.txt", "someone else's file");

    let root = home.path().join(".cache/sweep-tool-test");
    let output = run_in(home.path(), &["clean", "--yes", "--only", "dev-tools"]);
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    assert!(
        !root.exists(),
        "a tool cache owns its directory and removes it: {}",
        output.stdout
    );
    assert!(
        home.path().join(".cache/keep-me.txt").exists(),
        "a tool-cache rule must not widen to its parent"
    );
}

#[test]
fn clean_yes_with_nothing_to_plan_exits_zero_and_writes_no_log() {
    let home = home();
    let output = run_in(home.path(), &["clean", "--yes"]);
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    assert!(
        output.stdout.contains("Nothing to remove"),
        "an empty plan needs no confirmation:\n{}",
        output.stdout
    );
    assert!(
        !home.path().join(".local/state/sweep").exists(),
        "a run that removed nothing must not create a log for it"
    );
}

#[test]
fn yes_with_dry_run_is_a_usage_error() {
    let home = home();
    let output = run_in(home.path(), &["clean", "--dry-run", "--yes"]);
    assert_eq!(
        output.code,
        Some(2),
        "two contradictory modes are a usage error; stderr: {}",
        output.stderr
    );
    assert!(
        output.stderr.contains("--dry-run") || output.stderr.contains("--yes"),
        "the error must name the conflicting flags: {:?}",
        output.stderr
    );
}

#[test]
fn clean_dry_run_plans_a_real_target_and_writes_nothing() {
    let home = home();
    let blob = home
        .path()
        .join(".cache/mozilla/firefox/profile/cache2/entries/blob");
    write(
        home.path(),
        ".cache/mozilla/firefox/profile/cache2/entries/blob",
        "cache body",
    );
    let before = snapshot(home.path());

    let output = run_in(home.path(), &["clean", "--dry-run"]);
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    assert!(
        output.stdout.contains("dry run, nothing is deleted"),
        "the header must state the mode:\n{}",
        output.stdout
    );
    // The plan must not be empty, or "writes nothing" below would prove nothing:
    // the firefox rule deletes immediately and its root exists.
    assert!(
        output.stdout.contains("would be removed permanently"),
        "the fixture should be plannable:\n{}",
        output.stdout
    );

    let after = snapshot(home.path());
    assert_eq!(
        before, after,
        "a dry run must not create, remove or move anything below HOME"
    );
    assert!(blob.exists(), "the planned file is still there");
    assert!(
        !home.path().join(".local/state/sweep").exists(),
        "a dry run must not create the state directory"
    );
}

#[test]
fn clean_dry_run_json_is_one_document_with_a_repeatable_plan_hash() {
    let home = home();
    write(
        home.path(),
        ".cache/mozilla/firefox/profile/cache2/entries/blob",
        "cache body",
    );

    let first = run_in(home.path(), &["clean", "--dry-run", "--json"]);
    let second = run_in(home.path(), &["clean", "--dry-run", "--json"]);
    assert_eq!(first.code, Some(0), "stderr: {}", first.stderr);
    assert_eq!(second.code, Some(0), "stderr: {}", second.stderr);

    let first: serde_json::Value = serde_json::from_str(&first.stdout).expect("one document");
    let second: serde_json::Value = serde_json::from_str(&second.stdout).expect("one document");
    assert_eq!(first["mode"], "dry-run");
    let hash = first["plan_hash"].as_str().expect("plan_hash");
    assert_eq!(hash.len(), 16, "the hash is 64 bits, hex encoded: {hash}");
    assert_eq!(
        first["plan_hash"], second["plan_hash"],
        "the same tree must produce the same plan identity"
    );
    assert!(
        first["totals"]["items"].as_u64().unwrap_or(0) > 0,
        "the fixture must plan something: {first}"
    );
    assert!(
        !first["rules"].as_array().expect("rules").is_empty(),
        "the per-rule section is the point of the report"
    );
}

#[test]
fn only_restricts_the_run_to_the_named_sections() {
    let home = home();
    write(
        home.path(),
        ".cache/mozilla/firefox/profile/cache2/entries/blob",
        "cache body",
    );

    let output = run_in(home.path(), &["clean", "--dry-run", "--only", "dev-tools"]);
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    assert!(
        output.stdout.contains("dev-tools"),
        "the selected section must still be reported:\n{}",
        output.stdout
    );
    assert!(
        !output.stdout.contains("browsers"),
        "`--only` must not scan or report another section:\n{}",
        output.stdout
    );
    assert!(
        !output.stdout.contains("would be removed permanently"),
        "the fixture target belongs to browsers, so dev-tools plans nothing:\n{}",
        output.stdout
    );
}

#[test]
fn an_unknown_section_is_a_usage_error() {
    let home = home();
    let output = run_in(home.path(), &["clean", "--dry-run", "--only", "nope"]);
    assert_eq!(output.code, Some(2), "stderr: {}", output.stderr);
    assert!(
        output.stderr.contains("unknown section"),
        "the error must list the sections a user could type: {:?}",
        output.stderr
    );
}
