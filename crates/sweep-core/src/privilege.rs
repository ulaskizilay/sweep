//! The privilege boundary: how a user-scoped plan reaches root-owned paths.
//!
//! `sweep` refuses to run as root, and it should stay that way: the catalog, the
//! overlay and the state directory all resolve through `$HOME`, which belongs to
//! the invoking user. So system cleanup is two processes.
//!
//! 1. The user process plans normally. Reading `/var/cache/man` needs no
//!    privilege, and validation decides every item against a root pinned to
//!    uid 0 (`AllowedRoot::owned_by_root`).
//! 2. Only after consent, the same binary is re-executed through `run0` or
//!    `sudo` with one fixed argv — [`CHILD_COMMAND`] — and the plan arrives on
//!    **stdin**, never as shell text. No shell is involved, so no path can be
//!    word-split or expanded.
//!
//! The child does not trust the parent. It re-derives the allowlist from the
//! compiled-in catalog, refuses a rule id it does not know, and refuses a path
//! outside those roots. A user overlay cannot widen root deletion, because the
//! child never reads the overlay.
//!
//! The child also does not write the operation log. It reports outcomes on
//! stdout and the user process appends them, so root never opens a file inside
//! the user's state directory and the audit trail keeps one writer.

use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

use crate::funnel::{self, Mode, Outcome};
use crate::oplog::Action;
use crate::plan::{Plan, RuleId};
use crate::probe::FsProbe;
use crate::rules::{builtin, Kind, Privilege, RuleSet, Section, Source};
use crate::validate::{AllowedRoot, Policy, Reason, ValidateCtx};
use crate::Xdg;

/// The argv the elevated child is started with. One argument, and nothing from
/// the command line can add another.
pub const CHILD_COMMAND: &str = "__apply";

/// One item the parent asks the child to remove.
///
/// The path travels as hex because a path is bytes, not text: a lossy string
/// would silently address a different file. `dev`/`ino` travel with it so the
/// child can refuse a plan that went stale while the password prompt was open.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub rule: String,
    pub path_hex: String,
    pub dev: u64,
    pub ino: u64,
    pub is_dir: bool,
    pub bytes: u64,
}

/// The whole request: what to remove, and which session it belongs to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub cmd: String,
    pub session: String,
    pub items: Vec<Item>,
}

/// What the child did with one item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemResult {
    pub rule: String,
    pub path: String,
    pub path_hex: String,
    pub action: Action,
    pub bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The child's answer, one result per item it was given.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Reply {
    pub results: Vec<ItemResult>,
}

impl Reply {
    pub fn removed(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.action == Action::Removed)
            .count()
    }

    pub fn failed(&self) -> usize {
        self.results
            .iter()
            .filter(|result| result.action == Action::Failed)
            .count()
    }

    pub fn bytes(&self) -> u64 {
        self.results
            .iter()
            .filter(|result| result.action == Action::Removed)
            .map(|result| result.bytes)
            .sum()
    }
}

/// The root-owned parts of the catalog, as an allowlist.
///
/// Derived from the compiled-in packs, never from the overlay and never from
/// the parent's request. A system rule is included only when it deletes, is
/// declared `privilege = "root"`, lives in the `system` section, and names a
/// literal absolute root: a template would expand against whichever `$HOME` the
/// elevated child happens to inherit, and that is not a path the parent and the
/// child can agree on.
pub fn system_roots() -> Vec<AllowedRoot> {
    let Some(set) = system_pack() else {
        return Vec::new();
    };
    let Some(xdg) = synthetic_xdg() else {
        return Vec::new();
    };
    let mut roots: Vec<AllowedRoot> = Vec::new();
    for rule in set.rules() {
        if rule.section != Section::System || rule.privilege != Privilege::Root {
            continue;
        }
        // A disabled rule is not permission. The child must be able to explain
        // why a path is on its list, and "the catalog switched this off" is the
        // opposite of that.
        if !rule.enabled || !rule.kind.deletes() || !is_literal_root(rule.root.raw()) {
            continue;
        }
        let path = rule.expanded_root(&xdg);
        if roots.iter().any(|root| root.path == path) {
            continue;
        }
        roots.push(AllowedRoot::new(path).owned_by_root());
    }
    roots
}

/// The system pack alone, compiled.
///
/// Only one pack is read on purpose. The other packs describe `$HOME`, and
/// compiling them under the elevated child's environment would either fail
/// (a `{home}` root is a bare root) or mean something different than it did for
/// the parent. Neither is a decision the child should be making.
fn system_pack() -> Option<RuleSet> {
    let (name, body) = builtin::BUILTIN_PACKS
        .iter()
        .find(|(name, _)| *name == "rules/01-system.toml")?;
    let xdg = synthetic_xdg()?;
    RuleSet::from_sources(&[Source::new(*name, *body)], &xdg).ok()
}

/// The rule ids the child accepts. A request naming anything else is refused
/// whole rather than partly applied.
pub fn system_rule_ids() -> BTreeSet<String> {
    let Some(set) = system_pack() else {
        return BTreeSet::new();
    };
    set.rules()
        .iter()
        .filter(|rule| {
            rule.enabled
                && rule.section == Section::System
                && rule.privilege == Privilege::Root
                && rule.kind.deletes()
                && matches!(rule.kind, Kind::DirSweep | Kind::DirAge | Kind::FilePattern)
                && is_literal_root(rule.root.raw())
        })
        .map(|rule| rule.id.to_string())
        .collect()
}

fn is_literal_root(raw: &str) -> bool {
    raw.starts_with('/') && !raw.contains('{')
}

/// An `Xdg` whose only meaningful job is to satisfy the constructor.
///
/// Literal absolute roots never consult it, and a rule that does mention a base
/// is filtered out by [`is_literal_root`] before expansion, so this placeholder
/// cannot decide a path. It is deliberately not read from the environment: the
/// question "which home does the elevated child think it has" must not have an
/// answer that changes the allowlist.
fn synthetic_xdg() -> Option<Xdg> {
    Xdg::resolve(|key| match key {
        "HOME" => Some("/root".into()),
        _ => None,
    })
    .ok()
}

/// Runs one request as the elevated child.
///
/// The caller is the `__apply` subcommand, which has already refused to run
/// without uid 0. Every refusal is per item and reported, except an unknown rule
/// id or a malformed path, which refuse the request: a parent that invents
/// either is not one to take instructions from.
pub fn apply(request: &Request, probe: &dyn FsProbe) -> io::Result<Reply> {
    let roots = system_roots();
    if roots.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no literal system roots in the compiled catalog",
        ));
    }
    apply_with(request, probe, &roots, &system_rule_ids())
}

/// The part with no catalog in it, so a fixture root can exercise the boundary.
///
/// `apply` is the only caller in the shipped binary and it always passes the
/// compiled allowlist; this split exists so the tests can prove what happens to
/// a path that is not on it.
pub fn apply_with(
    request: &Request,
    probe: &dyn FsProbe,
    roots: &[AllowedRoot],
    known: &BTreeSet<String>,
) -> io::Result<Reply> {
    let xdg = synthetic_xdg().ok_or_else(|| {
        io::Error::new(io::ErrorKind::Unsupported, "no usable HOME for validation")
    })?;

    let mut plan = Plan::new();
    let mut reply = Reply::default();
    let ctx = ValidateCtx {
        xdg: &xdg,
        probe,
        allowed: roots,
        policy: Policy::default(),
    };

    for item in &request.items {
        if !known.contains(&item.rule) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("rule {} is not a compiled system rule", item.rule),
            ));
        }
        let path = match decode_path(&item.path_hex) {
            Some(path) => path,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "a planned path is not valid hex",
                ))
            }
        };
        let rule = RuleId::new(item.rule.clone())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;

        // The parent planned one inode; anything else at this path now is a
        // different file, and the plan no longer describes it.
        match probe.symlink_metadata(&path) {
            Ok(meta) if meta.dev == item.dev && meta.ino == item.ino => {}
            Ok(_) => {
                reply.results.push(refusal(
                    item,
                    &path,
                    Action::Skipped,
                    Reason::RaceChanged,
                    None,
                ));
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                reply.results.push(refusal(
                    item,
                    &path,
                    Action::Skipped,
                    Reason::AlreadyGone,
                    None,
                ));
                continue;
            }
            Err(error) => {
                reply.results.push(ItemResult {
                    rule: item.rule.clone(),
                    path: display(&path),
                    path_hex: hex(path.as_os_str().as_encoded_bytes()),
                    action: Action::Skipped,
                    bytes: 0,
                    code: Some("probe_unknown".to_string()),
                    detail: Some(error.to_string()),
                });
                continue;
            }
        }

        match plan.push(&path, &rule, &ctx) {
            Ok(_) => {}
            Err(reason) => {
                reply
                    .results
                    .push(refusal(item, &path, Action::Skipped, reason, None));
            }
        }
    }

    plan.finish();
    let applied = funnel::apply(&plan, probe, Mode::Apply, &request.cmd, None);
    for result in applied.results {
        let (path, path_hex) = encode_path(&result.path);
        reply.results.push(ItemResult {
            rule: result.rule.to_string(),
            path,
            path_hex,
            action: match &result.outcome {
                Outcome::Removed { .. } => Action::Removed,
                Outcome::WouldRemove { .. } => Action::WouldRemove,
                Outcome::Skipped(_) => Action::Skipped,
                Outcome::Failed { .. } => Action::Failed,
            },
            bytes: match &result.outcome {
                Outcome::Removed { bytes } | Outcome::WouldRemove { bytes } => *bytes,
                _ => 0,
            },
            code: match &result.outcome {
                Outcome::Skipped(reason) => Some(reason.code().to_string()),
                Outcome::Failed { .. } => Some("syscall".to_string()),
                _ => None,
            },
            detail: match &result.outcome {
                Outcome::Failed { message, .. } => Some(message.clone()),
                Outcome::Skipped(reason) => Some(reason.to_string()),
                _ => None,
            },
        });
    }

    Ok(reply)
}

fn refusal(
    item: &Item,
    path: &Path,
    action: Action,
    reason: Reason,
    detail: Option<String>,
) -> ItemResult {
    ItemResult {
        rule: item.rule.clone(),
        path: display(path),
        path_hex: hex(path.as_os_str().as_encoded_bytes()),
        action,
        bytes: 0,
        code: Some(reason.code().to_string()),
        detail: detail.or_else(|| Some(reason.to_string())),
    }
}

/// How the parent reaches root.
pub trait Elevator {
    /// Runs the child with `request` on its stdin and returns what it reported.
    fn run(&self, request: &Request) -> io::Result<Reply>;
}

/// The real one: `run0` when systemd provides it, `sudo` otherwise.
///
/// Both are invoked with `--` before a fixed argv, so no option and no shell
/// metacharacter can be introduced by a path. The plan goes on stdin; the
/// password prompt does not, because both tools read the controlling terminal
/// directly.
#[derive(Debug, Clone)]
pub struct SystemElevator {
    program: PathBuf,
}

impl SystemElevator {
    /// Finds an elevater, or says which two were missing.
    pub fn discover() -> io::Result<Self> {
        for candidate in ["run0", "sudo"] {
            if let Some(path) = which(candidate) {
                return Ok(Self { program: path });
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "neither run0 nor sudo is installed; system caches need one of them",
        ))
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    /// The exact argv, exposed so a test can assert there is no shell in it.
    pub fn argv(&self) -> io::Result<Vec<std::ffi::OsString>> {
        let exe = std::env::current_exe()?;
        Ok(vec![
            self.program.clone().into_os_string(),
            "--".into(),
            exe.into_os_string(),
            CHILD_COMMAND.into(),
        ])
    }
}

impl Elevator for SystemElevator {
    fn run(&self, request: &Request) -> io::Result<Reply> {
        let mut argv = self.argv()?;
        let program = argv.remove(0);
        let mut child = Command::new(program)
            .args(argv)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        let body = serde_json::to_vec(request)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| io::Error::other("the elevated child has no stdin"))?;
            stdin.write_all(&body)?;
            // Dropping the handle closes the pipe, which is what tells the child
            // the request is complete.
        }

        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "the elevated child exited with {}",
                output.status
            )));
        }
        parse_reply(&output.stdout)
    }
}

fn parse_reply(stdout: &[u8]) -> io::Result<Reply> {
    let text = std::str::from_utf8(stdout)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut reply = Reply::default();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let result: ItemResult = serde_json::from_str(line)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        reply.results.push(result);
    }
    Ok(reply)
}

/// Reads a request from a reader, runs it, and writes one JSON line per item.
///
/// This is the body of `sweep __apply`; it is separate so the subcommand itself
/// stays a three-line refusal plus a call.
pub fn run_child<R: Read, W: Write>(
    input: R,
    output: &mut W,
    probe: &dyn FsProbe,
) -> io::Result<()> {
    let request: Request = serde_json::from_reader(input)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let reply = apply(&request, probe)?;
    for result in &reply.results {
        let line = serde_json::to_vec(result)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        output.write_all(&line)?;
        output.write_all(b"\n")?;
    }
    output.flush()
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
}

fn display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn encode_path(path: &Path) -> (String, String) {
    let bytes = path.as_os_str().as_encoded_bytes();
    (display(path), hex(bytes))
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(nibble(byte >> 4));
        out.push(nibble(byte & 0x0f));
    }
    out
}

fn nibble(value: u8) -> char {
    char::from(if value < 10 {
        b'0' + value
    } else {
        b'a' + value - 10
    })
}

pub fn decode_path(hex: &str) -> Option<PathBuf> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let raw = hex.as_bytes();
    for pair in raw.chunks_exact(2) {
        let high = high_nibble(pair[0])?;
        let low = high_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Some(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

fn high_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The `Request` for a set of plan items, or `None` when none needs root.
pub fn request_from(
    plan: &Plan,
    privileged: impl Fn(&str) -> bool,
    cmd: &str,
    session: &str,
) -> Option<Request> {
    let items: Vec<Item> = plan
        .items()
        .iter()
        .filter(|item| privileged(item.rule().as_str()))
        .map(|item| Item {
            rule: item.rule().to_string(),
            path_hex: hex(item.path().as_os_str().as_encoded_bytes()),
            dev: item.dev(),
            ino: item.ino(),
            is_dir: item.is_dir(),
            bytes: item.bytes(),
        })
        .collect();
    if items.is_empty() {
        return None;
    }
    Some(Request {
        cmd: cmd.to_string(),
        session: session.to_string(),
        items,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::RealProbe;
    use crate::validate::Owner;
    use std::os::unix::fs::MetadataExt;

    fn fixture(files: &[&str]) -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("tempdir");
        for relative in files {
            let path = temp.path().join(relative);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(&path, "body").expect("write");
        }
        temp
    }

    fn item(rule: &str, path: &Path) -> Item {
        let meta = std::fs::symlink_metadata(path).expect("stat");
        Item {
            rule: rule.to_string(),
            path_hex: hex(path.as_os_str().as_encoded_bytes()),
            dev: meta.dev(),
            ino: meta.ino(),
            is_dir: meta.is_dir(),
            bytes: meta.blocks() * 512,
        }
    }

    fn request(items: Vec<Item>) -> Request {
        Request {
            cmd: "clean".to_string(),
            session: "clean-test".to_string(),
            items,
        }
    }

    fn known(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|id| id.to_string()).collect()
    }

    fn run(request: &Request, roots: &[AllowedRoot], ids: &[&str]) -> Reply {
        let probe = RealProbe::new().expect("probe").with_open_scan();
        apply_with(request, &probe, roots, &known(ids)).expect("the request itself is valid")
    }

    #[test]
    fn the_allowlist_is_literal_and_expects_root_ownership() {
        let roots = system_roots();
        assert!(!roots.is_empty(), "the system pack has deleting rules");
        for root in &roots {
            assert_eq!(root.owner, Owner::Root, "{:?}", root.path);
            assert!(
                root.path.is_absolute() && !root.path.to_string_lossy().contains('{'),
                "a literal absolute root only: {:?}",
                root.path
            );
        }
        let ids = system_rule_ids();
        assert!(
            ids.iter().all(|id| id.starts_with("system.")),
            "the child accepts system rules only: {ids:?}"
        );
    }

    #[test]
    fn a_path_outside_the_allowlist_is_refused_by_the_child() {
        let temp = fixture(&["root/keep", "elsewhere/complained"]);
        let root = temp.path().join("root");
        let outside = temp.path().join("elsewhere/complained");
        let reply = run(
            &request(vec![item("system.test", &outside)]),
            &[AllowedRoot::new(&root).owned_by_root()],
            &["system.test"],
        );
        assert_eq!(reply.results.len(), 1);
        assert_eq!(reply.results[0].action, Action::Skipped);
        assert_eq!(
            reply.results[0].code.as_deref(),
            Some("not_in_allowed_root")
        );
        assert!(outside.exists(), "a refused item is still there");
    }

    #[test]
    fn a_rule_the_child_does_not_know_refuses_the_whole_request() {
        let temp = fixture(&["root/victim"]);
        let root = temp.path().join("root");
        let probe = RealProbe::new().expect("probe").with_open_scan();
        let error = apply_with(
            &request(vec![item("user.made.up", &temp.path().join("root/victim"))]),
            &probe,
            &[AllowedRoot::new(&root).owned_by_root()],
            &known(&["system.test"]),
        )
        .expect_err("an invented rule id is not a request to honour");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn a_plan_that_went_stale_is_skipped_instead_of_removed() {
        let temp = fixture(&["root/victim"]);
        let root = temp.path().join("root");
        let victim = temp.path().join("root/victim");
        let mut stale = item("system.test", &victim);
        stale.ino += 1;

        let reply = run(
            &request(vec![stale]),
            &[AllowedRoot::new(&root).owned_by_root()],
            &["system.test"],
        );
        assert_eq!(reply.results[0].code.as_deref(), Some("race_changed"));
        assert!(victim.exists(), "the replacement is not what was planned");
    }

    #[test]
    fn a_leaf_symlink_is_never_removed_by_the_child() {
        let temp = fixture(&["root/real"]);
        let root = temp.path().join("root");
        let link = temp.path().join("root/link");
        std::os::unix::fs::symlink(temp.path().join("root/real"), &link).expect("symlink");

        let reply = run(
            &request(vec![item("system.test", &link)]),
            &[AllowedRoot::new(&root).owned_by_root()],
            &["system.test"],
        );
        assert_eq!(reply.results[0].code.as_deref(), Some("leaf_symlink"));
        assert!(link.symlink_metadata().is_ok());
    }

    #[test]
    fn a_root_root_refuses_a_file_owned_by_the_calling_user() {
        // Every file this test can create belongs to the test's uid, and a
        // system root demands uid 0. The refusal is the ownership pin doing its
        // job: "the parent said root owns this" is re-decided here.
        let temp = fixture(&["root/victim"]);
        let root = temp.path().join("root");
        let victim = temp.path().join("root/victim");
        let reply = run(
            &request(vec![item("system.test", &victim)]),
            &[AllowedRoot::new(&root).owned_by_root()],
            &["system.test"],
        );
        assert_eq!(reply.results[0].code.as_deref(), Some("foreign_owner"));
        assert!(victim.exists());
    }

    #[test]
    fn hex_round_trips_a_path_that_is_not_text() {
        use std::ffi::OsString;
        let raw = b"/var/cache/\xff\xfe";
        let encoded = hex(raw);
        let decoded = decode_path(&encoded).expect("decodes");
        assert_eq!(decoded, PathBuf::from(OsString::from_vec(raw.to_vec())));
        assert!(decode_path("abc").is_none(), "odd length");
        assert!(decode_path("zz").is_none(), "not hex");
    }

    #[test]
    fn the_child_argv_contains_no_shell() {
        let elevator = SystemElevator {
            program: PathBuf::from("/usr/bin/run0"),
        };
        let argv = elevator.argv().expect("current_exe");
        assert_eq!(argv.len(), 4, "{argv:?}");
        assert_eq!(argv[0], "/usr/bin/run0");
        assert_eq!(argv[1], "--");
        assert_eq!(argv[3], CHILD_COMMAND);
        assert!(
            argv.iter()
                .all(|arg| !arg.to_string_lossy().contains("sh -c")),
            "nothing is handed to a shell: {argv:?}"
        );
    }

    #[test]
    fn a_request_is_built_only_from_items_that_need_root() {
        let temp = fixture(&["root/one", "home/two"]);
        let root = temp.path().join("root");
        let xdg = Xdg::resolve(|key| match key {
            "HOME" => Some(temp.path().join("home").into_os_string()),
            _ => None,
        })
        .expect("home");
        let probe = RealProbe::new().expect("probe").with_open_scan();
        let mounts = crate::fs_facts::MountTable::load().expect("mounts");
        let allowed = [
            AllowedRoot::new(&root),
            AllowedRoot::new(temp.path().join("home")),
        ];
        let ctx = ValidateCtx {
            xdg: &xdg,
            probe: &probe,
            allowed: &allowed,
            policy: Policy::default(),
        };
        let mut plan = Plan::new();
        let privileged = RuleId::new("system.test").expect("id");
        let ordinary = RuleId::new("dev.test").expect("id");
        plan.push(&temp.path().join("root/one"), &privileged, &ctx)
            .expect("root rule plans");
        plan.push(&temp.path().join("home/two"), &ordinary, &ctx)
            .expect("user rule plans");
        plan.finish();

        let request = request_from(
            &plan,
            |rule| rule == privileged.as_str(),
            "clean",
            "clean-1",
        )
        .expect("one item needs root");
        assert_eq!(request.items.len(), 1);
        assert_eq!(request.items[0].rule, "system.test");
        assert_eq!(request.session, "clean-1");
        assert!(
            request_from(&plan, |_| false, "clean", "clean-1").is_none(),
            "nothing to elevate means no request"
        );
        let _ = mounts;
    }

    /// A stand-in for run0/sudo: reads the request from stdin into a file and
    /// writes a canned reply, so the transport can be tested without a password.
    ///
    /// Written to a temporary name and renamed into place: exec'ing a file that
    /// the same process has just written can fail with `ETXTBSY`, and the rename
    /// makes the executable inode one nobody has open for writing.
    fn shim(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let staged = dir.join("shim.tmp");
        let path = dir.join("shim");
        std::fs::write(&staged, body).expect("write the shim");
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))
            .expect("make it executable");
        std::fs::rename(&staged, &path).expect("install the shim");
        path
    }

    #[test]
    fn the_elevator_sends_the_request_on_stdin_and_parses_one_line_per_item() {
        let temp = fixture(&[]);
        let captured = temp.path().join("request.json");
        let program = shim(
            temp.path(),
            &format!(
                "#!/bin/sh\ncat > '{}'\nprintf '%s\\n' '{}'\n",
                captured.display(),
                r#"{"rule":"system.man.cache","path":"/var/cache/man/x","path_hex":"2f78","action":"REMOVED","bytes":4096}"#
            ),
        );
        let elevator = SystemElevator { program };

        let request = request(vec![Item {
            rule: "system.man.cache".to_string(),
            path_hex: hex(b"/var/cache/man/x"),
            dev: 1,
            ino: 2,
            is_dir: false,
            bytes: 4096,
        }]);
        let reply = elevator.run(&request).expect("the shim answers");

        assert_eq!(reply.results.len(), 1);
        assert_eq!(reply.results[0].action, Action::Removed);
        assert_eq!(reply.removed(), 1);
        assert_eq!(reply.bytes(), 4096);

        // The request must arrive as the serialised `Request`, not as shell
        // text: the shim receives it on stdin, and every argument after the
        // program name is fixed by `argv()`.
        let sent: Request =
            serde_json::from_str(&std::fs::read_to_string(&captured).expect("captured request"))
                .expect("the shim receives one JSON document");
        assert_eq!(sent.session, "clean-test");
        assert_eq!(sent.items.len(), 1);
        assert_eq!(sent.items[0].path_hex, hex(b"/var/cache/man/x"));
    }

    #[test]
    fn a_child_that_exits_nonzero_is_an_error_not_a_partial_success() {
        let temp = fixture(&[]);
        let program = shim(temp.path(), "#!/bin/sh\ncat >/dev/null\nexit 3\n");
        let elevator = SystemElevator { program };
        let error = elevator
            .run(&request(Vec::new()))
            .expect_err("a nonzero status means nothing was applied");
        assert!(
            error.to_string().contains("exited"),
            "the error must say the child did not finish: {error}"
        );
    }

    #[test]
    fn a_reply_that_is_not_one_json_object_per_line_is_refused() {
        let temp = fixture(&[]);
        let program = shim(
            temp.path(),
            "#!/bin/sh\ncat >/dev/null\nprintf 'not json\\n'\n",
        );
        let elevator = SystemElevator { program };
        assert!(
            elevator.run(&request(Vec::new())).is_err(),
            "a reply the parent cannot parse must not be read as \"nothing happened\""
        );
    }
}
