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

#[test]
fn the_hidden_apply_command_is_not_in_the_help_and_refuses_a_normal_user() {
    // `clean` starts this command through run0/sudo with the plan on stdin. It
    // must stay out of the command list, and a user who types it must be told
    // what it is instead of seeing a stack of `EACCES` failures.
    let help = run(&["--help"]);
    assert!(
        !help.stdout.contains("__apply"),
        "the elevation helper is not a user command:\n{}",
        help.stdout
    );

    let output = run(&["__apply"]);
    assert_eq!(
        output.code,
        Some(78),
        "the helper must refuse a normal user the way any unsupported environment is refused; \
         stderr: {}",
        output.stderr
    );
    assert!(
        output.stderr.contains("elevation helper"),
        "the refusal must say what this command is: {:?}",
        output.stderr
    );
    assert!(
        output.stderr.contains("sweep clean"),
        "the refusal must name the command the user meant: {:?}",
        output.stderr
    );
    assert!(
        output.stdout.trim().is_empty(),
        "a refusal must not emit a reply the parent could read as a result: {:?}",
        output.stdout
    );
}

#[test]
fn clean_help_lists_the_privileged_flag() {
    let output = run(&["clean", "--help"]);
    assert_eq!(output.code, Some(0));
    assert!(
        output.stdout.contains("--privileged"),
        "the flag that sweeps the system section must be discoverable:\n{}",
        output.stdout
    );
    assert!(
        output.stdout.contains("root-owned"),
        "the flag must say what it unlocks:\n{}",
        output.stdout
    );
}

#[test]
fn the_apply_helper_is_reachable_only_when_the_process_really_is_root() {
    // The one exception to "sweep never runs as root". Inside a user namespace
    // the binary is uid 0, so the helper must get past the guard and read a
    // request - and with stdin at EOF there is no request, which is an error
    // rather than a refusal. That is what proves the guard is about the uid and
    // not a stub that always says no.
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
        .arg("__apply")
        .output()
        .expect("spawn under unshare");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "an empty request is a failure, not a refusal; stderr={stderr:?}"
    );
    assert!(
        stderr.contains("sweep __apply:"),
        "the error must name the command: {stderr:?}"
    );
    assert!(
        !stderr.contains("elevation helper"),
        "uid 0 is the one caller this command accepts: {stderr:?}"
    );
    assert!(
        output.stdout.is_empty(),
        "nothing was asked for, so nothing is reported"
    );
}

/// Hex, the way the child expects a path: bytes, not a lossy string.
fn hex_path(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn the_child_reports_a_path_outside_the_allowlist_instead_of_removing_it() {
    // The interesting half of the boundary is what the child does with a
    // request the parent should never have sent: it answers per item rather
    // than trusting the caller, and the answer is a refusal. Run under
    // `unshare -r` because the child only starts as root; the namespace keeps
    // that from being a real privilege escalation.
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

    use std::io::Write;
    use std::os::unix::fs::MetadataExt;

    let home = home();
    let victim = home.path().join("not-a-system-cache");
    std::fs::write(&victim, "payload").expect("write");
    let meta = std::fs::symlink_metadata(&victim).expect("stat");

    let request = serde_json::json!({
        "cmd": "clean",
        "session": "clean-test",
        "items": [{
            "rule": "system.man.cache",
            "path_hex": hex_path(&victim),
            "dev": meta.dev(),
            "ino": meta.ino(),
            "is_dir": false,
            "bytes": 7,
        }],
    })
    .to_string();

    let mut child = Command::new("unshare")
        .arg("-r")
        .arg(env!("CARGO_BIN_EXE_sweep"))
        .arg("__apply")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn under unshare");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(request.as_bytes())
        .expect("write the request");
    let output = child.wait_with_output().expect("wait");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "a request the child can judge is not an error; stdout={stdout:?} stderr={stderr:?}"
    );

    let reply: serde_json::Value = stdout
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("one JSON object per item"))
        .expect("one result for the one item");
    assert_eq!(reply["rule"], "system.man.cache");
    assert_eq!(reply["action"], "SKIPPED");
    assert_eq!(
        reply["code"], "not_in_allowed_root",
        "the child decides against its own allowlist, not the parent's: {reply}"
    );
    assert!(victim.exists(), "a refused path is still there");
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
        .find(|line| line.contains("system.coredump.report"))
        .expect("a known rule must be listed");
    assert!(
        line.contains(" off "),
        "disabled rule is not marked: {line:?}"
    );

    // A package cache has two retentions, and the column shows both: printing
    // only the version count would hide the recency floor, and printing only the
    // days would hide how many versions stay.
    let pkg = output
        .stdout
        .lines()
        .find(|line| line.contains("system.pacman.package-cache"))
        .expect("the package cache rule is part of the catalog");
    assert!(
        pkg.contains("2v/7d"),
        "a pkg-cache rule must show both retentions: {pkg:?}"
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
    //
    // Scoped to the section the fixture lives in. A bare run also plans the
    // root-owned system caches on the host, which would make this test depend on
    // the machine it runs on and ask a second question it is not about.
    let output = run_in(home.path(), &["clean", "--only", "browsers"]);
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
    let output = run_in(home.path(), &["clean", "--yes", "--only", "browsers"]);
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

    let preview = run_in(
        home.path(),
        &["clean", "--dry-run", "--json", "--only", "browsers"],
    );
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

    let applied = run_in(
        home.path(),
        &["clean", "--yes", "--json", "--only", "browsers"],
    );
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
    // Scoped to a section the fixture leaves empty. A bare run on a machine with
    // system caches does have something to plan, so "nothing to remove" is a
    // property of the chosen section, not of the host.
    let output = run_in(
        home.path(),
        &["clean", "--yes", "--only", "user-essentials"],
    );
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

// ------------------------------------------------------------ model caches ---

/// A hub repository laid out the way `huggingface_hub` writes one, every file
/// old enough to be a candidate: one blob a snapshot links to, one orphan and
/// one abandoned download.
///
/// Returns `(root, used, orphan, incomplete)`.
fn hub_cache(home: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let root = home.join(".cache/huggingface/hub/models--org--name");
    write(
        home,
        ".cache/huggingface/hub/models--org--name/blobs/used",
        "used weights",
    );
    write(
        home,
        ".cache/huggingface/hub/models--org--name/blobs/orphan",
        "orphan weights",
    );
    write(
        home,
        ".cache/huggingface/hub/models--org--name/blobs/abc.incomplete",
        "half a download",
    );
    write(
        home,
        ".cache/huggingface/hub/models--org--name/refs/main",
        "deadbee",
    );
    std::fs::create_dir_all(root.join("snapshots/deadbee")).expect("mkdir");
    std::os::unix::fs::symlink(
        "../../blobs/used",
        root.join("snapshots/deadbee/config.json"),
    )
    .expect("symlink");

    for relative in [
        "blobs/used",
        "blobs/orphan",
        "blobs/abc.incomplete",
        "snapshots/deadbee/config.json",
        "snapshots/deadbee",
        "snapshots",
    ] {
        age(&root.join(relative), 200);
    }

    (
        root.clone(),
        root.join("blobs/used"),
        root.join("blobs/orphan"),
        root.join("blobs/abc.incomplete"),
    )
}

/// Backdates a path's mtime. `touch -d` is not portable enough for a test that
/// must also stamp symlinks and directories, so this uses the same syscall.
fn age(path: &Path, days: u64) {
    let when = std::time::SystemTime::now() - std::time::Duration::from_secs(days * 86_400);
    let file = std::fs::File::open(path).expect("open for mtime");
    file.set_times(std::fs::FileTimes::new().set_modified(when))
        .expect("set mtime");
}

#[test]
fn a_bare_run_leaves_model_caches_alone_and_says_how_to_review_them() {
    let home = home();
    let (_, used, orphan, incomplete) = hub_cache(home.path());

    let output = run_in(home.path(), &["clean", "--dry-run", "--json"]);
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    let report: serde_json::Value = serde_json::from_str(&output.stdout).expect("one document");

    let section = report["sections"]
        .as_array()
        .expect("sections")
        .iter()
        .find(|section| section["section"] == "model-caches")
        .expect("model-caches is listed even when it is skipped");
    assert_eq!(
        section["items"], 0,
        "an opt-in section must not be scanned in a bare run: {section}"
    );

    let rules = report["rules"].as_array().expect("rules");
    let hub = rules
        .iter()
        .find(|run| run["id"] == "model.huggingface.hub")
        .expect("the hub rule is listed");
    assert_eq!(hub["status"], "opt_in", "{hub}");
    assert!(
        hub["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("--only model-caches"),
        "the skip must say how to review the section: {hub}"
    );

    let notes = report["notes"]
        .as_array()
        .expect("notes")
        .iter()
        .filter_map(|note| note.as_str())
        .collect::<Vec<_>>();
    assert!(
        notes.iter().any(|note| note.contains("model-caches")
            && note.contains("not scanned")
            && !note.contains("0 B")),
        "the note must say the section was not scanned, never that it is empty: {notes:?}"
    );

    for path in [&used, &orphan, &incomplete] {
        assert!(path.exists(), "a bare run must not touch the hub: {path:?}");
    }
}

#[test]
fn only_model_caches_plans_the_orphans_and_keeps_everything_a_snapshot_links() {
    let home = home();
    let (root, used, orphan, incomplete) = hub_cache(home.path());

    let preview = run_in(
        home.path(),
        &["clean", "--only", "model-caches", "--dry-run", "--json"],
    );
    assert_eq!(preview.code, Some(0), "stderr: {}", preview.stderr);
    let preview: serde_json::Value = serde_json::from_str(&preview.stdout).expect("one document");
    assert_eq!(
        preview["totals"]["items"], 2,
        "only the orphan and the abandoned download are planned: {preview}"
    );

    let rules = preview["rules"].as_array().expect("rules");
    assert_eq!(
        rules.len(),
        3,
        "naming the section must not widen the run to other sections: {preview}"
    );

    let applied = run_in(home.path(), &["clean", "--yes", "--only", "model-caches"]);
    assert_eq!(applied.code, Some(0), "stderr: {}", applied.stderr);

    assert!(!orphan.exists(), "the unreferenced blob is a leftover");
    assert!(!incomplete.exists(), "an abandoned download is a leftover");
    assert!(used.exists(), "a blob a snapshot links to is the model");
    assert!(
        root.join("snapshots/deadbee/config.json").exists(),
        "the snapshot entry is never deleted"
    );
    assert!(
        !std::fs::read(root.join("snapshots/deadbee/config.json"))
            .expect("the surviving link must resolve")
            .is_empty(),
        "the snapshot must still read after the sweep"
    );
    assert!(
        root.join("refs/main").exists(),
        "refs are the record of what is installed"
    );

    let removed: BTreeSet<PathBuf> = log_rows(home.path())
        .iter()
        .filter(|row| row["action"] == "REMOVED")
        .map(|row| PathBuf::from(row["path"].as_str().expect("path")))
        .collect();
    assert_eq!(
        removed,
        BTreeSet::from([orphan, incomplete]),
        "the ledger must name exactly the two leftovers"
    );
}

#[test]
fn a_repository_whose_snapshots_cannot_be_read_is_preserved_whole() {
    let home = home();
    let (_, _, orphan, incomplete) = hub_cache(home.path());
    let snapshots = home
        .path()
        .join(".cache/huggingface/hub/models--org--name/snapshots");
    std::fs::remove_dir_all(&snapshots).expect("remove");
    // A file where the snapshot directory belongs: reading it fails, and a
    // failed read must never be taken as "nothing is referenced".
    write(
        home.path(),
        ".cache/huggingface/hub/models--org--name/snapshots",
        "not a directory",
    );

    let output = run_in(
        home.path(),
        &["clean", "--only", "model-caches", "--dry-run", "--json"],
    );
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    let report: serde_json::Value = serde_json::from_str(&output.stdout).expect("one document");
    assert_eq!(
        report["totals"]["items"], 0,
        "an unreadable snapshot tree must preserve the repository: {report}"
    );

    let hub = report["rules"]
        .as_array()
        .expect("rules")
        .iter()
        .find(|run| run["id"] == "model.huggingface.hub")
        .expect("the hub rule is listed")
        .clone();
    assert!(
        hub["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("preserved"),
        "the report must say the repository was kept and why: {hub}"
    );
    let notes = report["notes"]
        .as_array()
        .expect("notes")
        .iter()
        .filter_map(|note| note.as_str())
        .collect::<Vec<_>>();
    assert!(
        notes
            .iter()
            .any(|note| note.contains("preserved") && note.contains("models--org--name")),
        "preserving a repository is a summary fact, not a `-v` detail: {notes:?}"
    );
    assert!(
        orphan.exists() && incomplete.exists(),
        "nothing was removed"
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

    let output = run_in(home.path(), &["clean", "--dry-run", "--only", "browsers"]);
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

    let first = run_in(
        home.path(),
        &["clean", "--dry-run", "--json", "--only", "browsers"],
    );
    let second = run_in(
        home.path(),
        &["clean", "--dry-run", "--json", "--only", "browsers"],
    );
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

// ------------------------------------------------------------ installer ---

#[test]
fn installer_takes_archives_from_downloads_and_leaves_the_rest() {
    let home = home();
    for relative in [
        "Downloads/pkg.pkg.tar.zst",
        "Downloads/arch/linux.iso",
        "Downloads/fresh.deb",
        "Downloads/source.zip",
        "Downloads/tool.exe",
        "Downloads/sub/deep/too-deep.rpm",
        "Documents/vm.iso",
    ] {
        write(home.path(), relative, "payload");
    }
    // Everything is old except the package fetched two days ago: it may be the
    // copy the user is about to install.
    for relative in [
        "Downloads/pkg.pkg.tar.zst",
        "Downloads/arch/linux.iso",
        "Downloads/source.zip",
        "Downloads/tool.exe",
        "Downloads/sub/deep/too-deep.rpm",
        "Documents/vm.iso",
    ] {
        let path = home.path().join(relative);
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(60 * 86_400);
        std::fs::File::options()
            .read(true)
            .open(&path)
            .expect("open")
            .set_times(std::fs::FileTimes::new().set_modified(when))
            .expect("set mtime");
    }
    let before = snapshot(home.path());

    let dry = run_in(home.path(), &["installer", "--dry-run"]);
    assert_eq!(dry.code, Some(0), "stderr: {}", dry.stderr);
    assert!(
        dry.stdout
            .contains("sweep installer — dry run, nothing is deleted"),
        "the header must name the command:\n{}",
        dry.stdout
    );
    assert_eq!(before, snapshot(home.path()), "a dry run writes nothing");

    let applied = run_in(home.path(), &["installer", "--yes"]);
    assert_eq!(applied.code, Some(0), "stderr: {}", applied.stderr);

    for gone in ["Downloads/pkg.pkg.tar.zst", "Downloads/arch/linux.iso"] {
        assert!(
            !home.path().join(gone).exists(),
            "the installer archive must be gone: {gone}"
        );
    }
    for kept in [
        "Downloads/fresh.deb",
        "Downloads/source.zip",
        "Downloads/tool.exe",
        "Downloads/sub/deep/too-deep.rpm",
        "Documents/vm.iso",
    ] {
        assert!(
            home.path().join(kept).exists(),
            "neither a recent download, an archive, nor a file outside Downloads is an installer: {kept}"
        );
    }

    let rows = log_rows(home.path());
    assert!(!rows.is_empty(), "an applied installer run must be logged");
    for row in &rows {
        assert_eq!(
            row["cmd"], "installer",
            "the log must name the command: {row}"
        );
        assert!(
            row["session"]
                .as_str()
                .unwrap_or_default()
                .starts_with("installer-"),
            "the session separates installer rows from clean rows: {row}"
        );
    }
}

#[test]
fn a_bare_clean_names_installer_instead_of_sweeping_downloads() {
    let home = home();
    write(home.path(), "Downloads/pkg.pkg.tar.zst", "payload");

    let output = run_in(home.path(), &["clean", "--dry-run", "--json"]);
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    let report: serde_json::Value = serde_json::from_str(&output.stdout).expect("one document");
    let rule = report["rules"]
        .as_array()
        .expect("rules")
        .iter()
        .find(|run| run["id"] == "installer.downloads")
        .expect("the rule is listed even when another command owns it");
    assert_eq!(rule["status"], "command_scoped", "{rule}");
    assert!(
        rule["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("sweep installer"),
        "the skip must name the command to run: {rule}"
    );
    assert!(
        home.path().join("Downloads/pkg.pkg.tar.zst").exists(),
        "a bare clean must not touch Downloads"
    );
}

// ---------------------------------------------------------------- purge ---

/// A home with three projects, one artifact-shaped directory with no manifest,
/// and a link inside an artifact.
fn project_home() -> tempfile::TempDir {
    let home = home();
    write(home.path(), "web/package.json", "{}");
    write(home.path(), "web/src/index.js", "console.log(1);");
    write(
        home.path(),
        "web/node_modules/left-pad/index.js",
        "module.exports = 1;",
    );
    write(
        home.path(),
        "rustproj/Cargo.toml",
        "[package]\nname = \"x\"\n",
    );
    write(home.path(), "rustproj/src/main.rs", "fn main() {}");
    write(home.path(), "rustproj/target/debug/app", "binary");
    write(home.path(), "pyproj/pyproject.toml", "[project]\n");
    write(home.path(), "pyproj/pkg/mod.py", "x = 1");
    write(home.path(), "pyproj/.venv/bin/activate", "# venv");
    // No manifest: artifact-shaped, but nothing says a build produced it.
    write(home.path(), "stray/node_modules/x/index.js", "x");
    write(home.path(), "notes/todo.md", "keep me");

    std::fs::create_dir_all(home.path().join("web/node_modules/.bin")).expect("mkdir");
    std::os::unix::fs::symlink(
        "../left-pad/index.js",
        home.path().join("web/node_modules/.bin/left-pad"),
    )
    .expect("link inside the artifact");
    std::os::unix::fs::symlink(
        "/usr/bin/python3",
        home.path().join("pyproj/.venv/bin/python3"),
    )
    .expect("venv interpreter link");

    // A month of not building is the whole premise of `keep_days = 30`.
    for relative in [
        "web",
        "web/package.json",
        "web/src",
        "web/node_modules",
        "web/node_modules/left-pad",
        "rustproj",
        "rustproj/Cargo.toml",
        "rustproj/target",
        "pyproj",
        "pyproj/pyproject.toml",
        "pyproj/.venv",
        "stray",
        "stray/node_modules",
        "notes",
    ] {
        let path = home.path().join(relative);
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(60 * 86_400);
        // `-h` semantics: the link's own mtime, not its target's.
        let meta = std::fs::symlink_metadata(&path).expect("metadata");
        let _ = meta;
        std::fs::File::options()
            .read(true)
            .open(&path)
            .expect("open")
            .set_times(std::fs::FileTimes::new().set_modified(when))
            .expect("set mtime");
    }
    home
}

#[test]
fn purge_requires_the_manifests_it_removes_around() {
    let home = project_home();
    let before = snapshot(home.path());

    let dry = run_in(home.path(), &["purge", "--dry-run"]);
    assert_eq!(dry.code, Some(0), "stderr: {}", dry.stderr);
    assert!(
        dry.stdout
            .contains("sweep purge — dry run, nothing is deleted"),
        "the header must name the command: \n{}",
        dry.stdout
    );
    assert!(
        dry.stdout.contains("would be removed permanently"),
        "the fixture must plan something:\n{}",
        dry.stdout
    );
    assert_eq!(
        before,
        snapshot(home.path()),
        "a dry run must not create, remove or move anything below HOME"
    );

    let applied = run_in(home.path(), &["purge", "--yes"]);
    assert_eq!(applied.code, Some(0), "stderr: {}", applied.stderr);
    assert!(
        applied.stdout.contains("Removed"),
        "the report must say what happened:\n{}",
        applied.stdout
    );

    for gone in ["web/node_modules", "rustproj/target", "pyproj/.venv"] {
        assert!(
            !home.path().join(gone).exists(),
            "the build directory must be gone: {gone}"
        );
    }
    for kept in [
        "web/package.json",
        "web/src/index.js",
        "rustproj/Cargo.toml",
        "rustproj/src/main.rs",
        "pyproj/pyproject.toml",
        "pyproj/pkg/mod.py",
        "stray/node_modules/x/index.js",
        "notes/todo.md",
    ] {
        assert!(
            home.path().join(kept).exists(),
            "a purge removes artifacts, never the project: {kept}"
        );
    }
    assert!(
        std::fs::symlink_metadata(home.path().join("web/node_modules/.bin/left-pad")).is_err(),
        "a link inside a removed artifact goes with it"
    );
    assert!(
        std::path::Path::new("/usr/bin/python3").exists(),
        "unlinking the venv interpreter never touches its target"
    );

    let rows = log_rows(home.path());
    assert!(!rows.is_empty(), "an applied purge must be logged");
    for row in &rows {
        assert_eq!(row["cmd"], "purge", "the log must name the command: {row}");
        assert!(
            row["session"]
                .as_str()
                .unwrap_or_default()
                .starts_with("purge-"),
            "the session separates purge rows from clean rows: {row}"
        );
    }
}

#[test]
fn purge_without_yes_on_a_pipe_declines_and_writes_nothing() {
    let home = project_home();
    let before = snapshot(home.path());

    let output = run_in(home.path(), &["purge"]);
    assert_eq!(output.code, Some(5), "stderr: {}", output.stderr);
    assert!(
        output.stderr.contains("--yes"),
        "the refusal must name the flag that turns the question off: {:?}",
        output.stderr
    );
    assert_eq!(
        before,
        snapshot(home.path()),
        "a declined purge writes nothing"
    );
    assert!(home.path().join("web/node_modules").exists());
}

#[test]
fn a_bare_clean_names_purge_instead_of_walking_projects() {
    let home = project_home();

    let output = run_in(home.path(), &["clean", "--dry-run", "--json"]);
    assert_eq!(output.code, Some(0), "stderr: {}", output.stderr);
    let report: serde_json::Value = serde_json::from_str(&output.stdout).expect("one document");

    let rule = report["rules"]
        .as_array()
        .expect("rules")
        .iter()
        .find(|run| run["id"] == "project.artifacts.sources")
        .expect("the rule is listed even when another command owns it");
    assert_eq!(
        rule["status"], "command_scoped",
        "a bare clean must say whose section this is: {rule}"
    );
    assert!(
        rule["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("sweep purge"),
        "the skip must name the command to run: {rule}"
    );
    assert!(
        home.path()
            .join("web/node_modules/left-pad/index.js")
            .exists(),
        "a bare clean must not walk project directories"
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
