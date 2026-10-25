//! End-to-end tests against the built binary.
//!
//! These are the only tests that exercise argument parsing, the tracing setup and
//! the exit codes, because they run `sweep` as a separate process. Everything
//! else calls library functions, which is where the interesting logic lives; this
//! file exists so that "the binary starts and says the right thing" is covered by
//! a machine rather than by whoever happened to run it last.

use std::process::Command;

fn sweep() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sweep"))
}

struct Output {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Output {
    let output = sweep().args(args).output().expect("spawn sweep");
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
    assert!(output.stdout.contains("doctor"), "{}", output.stdout);
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
    // The kernel refuses root by design. CI runs unprivileged, so this checks the
    // refusal only when the suite is actually run as root; either way it asserts
    // that the non-root path is the one that succeeded.
    let json = run(&["doctor", "--json"]);
    let value: serde_json::Value = serde_json::from_str(&json.stdout).expect("json");
    if value["running_as_root"] == false {
        assert_eq!(json.code, Some(0), "stderr: {}", json.stderr);
        return;
    }
    let output = run(&["doctor"]);
    assert_eq!(output.code, Some(78), "root must be refused with 78");
    assert!(
        output.stderr.contains("root"),
        "the refusal must say why: {:?}",
        output.stderr
    );
}
