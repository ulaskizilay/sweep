//! The only place in the program that deletes anything.
//!
//! Properties that hold by construction:
//!
//! * **It cannot recurse.** One `unlinkat` per plan item; a directory with
//!   children fails with `ENOTEMPTY` and stays intact. The scanner is
//!   responsible for emitting children before parents.
//! * **It re-checks identity.** `dev`/`ino` are compared with the plan before
//!   the syscall, so a path replaced between planning and deletion is skipped
//!   instead of removed.
//! * **It deletes through a pinned parent handle.** `open_dir_nofollow` opens
//!   the parent with `RESOLVE_NO_SYMLINKS`, so the entry name cannot be
//!   redirected by a symlink swap.
//! * **Dry run and apply share the plan.** `Mode::DryRun` performs no syscall
//!   that mutates, and the report carries the same `plan_hash`.

use std::io;
use std::path::PathBuf;

use crate::oplog::{encode_path, rfc3339, Action, Oplog, Record};
use crate::plan::{Plan, PlanItem, RuleId};
use crate::probe::FsProbe;
use crate::sys::open_dir_nofollow;
use crate::validate::Reason;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    DryRun,
    Apply,
}

impl Mode {
    pub fn is_dry_run(self) -> bool {
        matches!(self, Mode::DryRun)
    }

    /// Session suffix used in the operation log.
    pub fn session_suffix(self) -> &'static str {
        match self {
            Mode::DryRun => "-dry-run",
            Mode::Apply => "",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Removed { bytes: u64 },
    WouldRemove { bytes: u64 },
    Skipped(Reason),
    Failed { errno: Option<i32>, message: String },
}

impl Outcome {
    pub fn is_removed(&self) -> bool {
        matches!(self, Outcome::Removed { .. })
    }

    pub fn is_would_remove(&self) -> bool {
        matches!(self, Outcome::WouldRemove { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemResult {
    pub rule: RuleId,
    pub literal: PathBuf,
    pub path: PathBuf,
    pub outcome: Outcome,
}

#[derive(Debug, Clone, Default)]
pub struct Report {
    pub results: Vec<ItemResult>,
    /// Bytes accounted for by items this run removed (or would remove).
    pub removed_bytes: u64,
    /// Removals that failed at the syscall, not refusals.
    pub failed: usize,
    pub skipped: usize,
}

impl Report {
    pub fn removed(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.outcome.is_removed())
            .count()
    }

    pub fn would_remove(&self) -> usize {
        self.results
            .iter()
            .filter(|r| r.outcome.is_would_remove())
            .count()
    }

    /// Refusal counts by reason code, sorted by code: `[("open_by_process", 12), ...]`.
    pub fn skip_codes(&self) -> Vec<(&'static str, usize)> {
        let mut counts: std::collections::BTreeMap<&'static str, usize> =
            std::collections::BTreeMap::new();
        for result in &self.results {
            if let Outcome::Skipped(reason) = &result.outcome {
                *counts.entry(reason.code()).or_insert(0) += 1;
            }
        }
        counts.into_iter().collect()
    }
}

/// Applies (or previews) a finished plan.
///
/// `cmd` is the command name recorded in the operation log (`clean`, `purge`,
/// `aur`, …), so history can be filtered per command.
pub fn apply(
    plan: &Plan,
    probe: &dyn FsProbe,
    mode: Mode,
    cmd: &str,
    mut oplog: Option<&mut Oplog>,
) -> Report {
    let mut report = Report::default();

    for item in plan.items() {
        let outcome = apply_one(item, probe, mode);
        match &outcome {
            Outcome::Removed { bytes } | Outcome::WouldRemove { bytes } => {
                report.removed_bytes = report.removed_bytes.saturating_add(*bytes);
            }
            Outcome::Skipped(_) => report.skipped += 1,
            Outcome::Failed { .. } => report.failed += 1,
        }

        if let Some(log) = oplog.as_deref_mut() {
            append_record(log, cmd, item, &outcome);
        }

        report.results.push(ItemResult {
            rule: item.rule().clone(),
            literal: item.literal().to_path_buf(),
            path: item.path().to_path_buf(),
            outcome,
        });
    }

    report
}

fn append_record(log: &mut Oplog, cmd: &str, item: &PlanItem, outcome: &Outcome) {
    let (path, path_hex) = encode_path(item.literal());
    let ts = rfc3339(now_unix());
    let session = log.session().to_string();

    let (action, bytes, reason, detail) = match outcome {
        Outcome::Removed { bytes } => (Action::Removed, *bytes, None, None),
        Outcome::WouldRemove { bytes } => (Action::WouldRemove, *bytes, None, None),
        Outcome::Skipped(reason) => (
            Action::Skipped,
            0,
            Some(reason.code()),
            Some(reason.to_string()),
        ),
        Outcome::Failed { errno, message } => (
            Action::Failed,
            0,
            Some("io_error"),
            Some(match errno {
                Some(code) => format!("{message} (errno {code})"),
                None => message.clone(),
            }),
        ),
    };

    log.append(Record {
        ts,
        cmd,
        session: &session,
        action,
        rule: item.rule().as_str(),
        path,
        path_hex,
        bytes,
        reason,
        detail,
    });
}

fn apply_one(item: &PlanItem, probe: &dyn FsProbe, mode: Mode) -> Outcome {
    let meta = match probe.symlink_metadata(item.path()) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Outcome::Skipped(Reason::AlreadyGone)
        }
        Err(error) => {
            return Outcome::Failed {
                errno: error.raw_os_error(),
                message: error.to_string(),
            }
        }
    };

    if meta.dev != item.dev() || meta.ino != item.ino() {
        return Outcome::Skipped(Reason::RaceChanged);
    }
    if meta.is_symlink() {
        return Outcome::Skipped(Reason::LeafSymlink);
    }

    if mode.is_dry_run() {
        return Outcome::WouldRemove {
            bytes: item.bytes(),
        };
    }

    let Some(parent) = item.path().parent() else {
        return Outcome::Skipped(Reason::RootItself);
    };
    let Some(name) = item.path().file_name() else {
        return Outcome::Skipped(Reason::RootItself);
    };

    let dirfd = match open_dir_nofollow(parent) {
        Ok(fd) => fd,
        Err(crate::sys::OpenDirError::SymlinkRefused) => {
            return Outcome::Skipped(Reason::SymlinkAncestorEscape(parent.to_path_buf()))
        }
        Err(crate::sys::OpenDirError::Io(error)) => {
            return Outcome::Failed {
                errno: error.raw_os_error(),
                message: error.to_string(),
            }
        }
    };

    match crate::sys::unlink_beneath(&dirfd, name, meta.is_dir()) {
        Ok(()) => Outcome::Removed {
            bytes: item.bytes(),
        },
        Err(error) => match error.raw_os_error() {
            Some(libc::ENOENT) => Outcome::Skipped(Reason::AlreadyGone),
            Some(libc::ENOTEMPTY) | Some(libc::EEXIST) => {
                Outcome::Skipped(Reason::DirectoryNotEmpty)
            }
            Some(libc::EBUSY) => Outcome::Skipped(Reason::Mounted),
            Some(libc::ELOOP) => Outcome::Skipped(Reason::LeafSymlink),
            _ => Outcome::Failed {
                errno: error.raw_os_error(),
                message: error.to_string(),
            },
        },
    }
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::RuleId;
    use crate::probe::RealProbe;
    use crate::validate::{AllowedRoot, Policy, ValidateCtx, Verdict};
    use crate::Xdg;
    use std::path::Path;

    fn fixture() -> (tempfile::TempDir, Xdg, RealProbe) {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().to_path_buf();
        let xdg = Xdg::resolve(|key| match key {
            "HOME" => Some(home.clone().into_os_string()),
            _ => None,
        })
        .unwrap();
        let probe = RealProbe::new().unwrap().with_open_scan();
        (temp, xdg, probe)
    }

    fn plan_for(xdg: &Xdg, probe: &RealProbe, root: &Path, paths: &[PathBuf]) -> Plan {
        let allowed = vec![AllowedRoot::new(root)];
        let ctx = ValidateCtx {
            xdg,
            probe,
            allowed: &allowed,
            policy: Policy::default(),
        };
        let rule = RuleId::new("test.rule").unwrap();
        let mut plan = Plan::new();
        for path in paths {
            let _ = plan.push(path, &rule, &ctx);
        }
        plan.finish();
        plan
    }

    #[test]
    fn dry_run_removes_nothing() {
        let (temp, xdg, probe) = fixture();
        let cache = xdg.cache.clone();
        std::fs::create_dir_all(&cache).unwrap();
        let file = cache.join("stale.bin");
        std::fs::write(&file, b"data").unwrap();

        let plan = plan_for(&xdg, &probe, &cache, std::slice::from_ref(&file));
        assert_eq!(plan.len(), 1, "denied: {:?}", plan.denied());

        let report = apply(&plan, &probe, Mode::DryRun, "clean", None);
        assert_eq!(report.would_remove(), 1);
        assert!(file.exists(), "dry run must not delete");
        drop(temp);
    }

    #[test]
    fn apply_removes_a_file_and_logs_it() {
        let (temp, xdg, probe) = fixture();
        let cache = xdg.cache.clone();
        std::fs::create_dir_all(&cache).unwrap();
        let file = cache.join("stale.bin");
        std::fs::write(&file, b"data").unwrap();

        let plan = plan_for(&xdg, &probe, &cache, std::slice::from_ref(&file));
        assert_eq!(plan.len(), 1, "denied: {:?}", plan.denied());

        let mut log = Oplog::open(
            &xdg.state_dir(),
            format!("test{}", Mode::Apply.session_suffix()),
        )
        .unwrap();
        let report = apply(&plan, &probe, Mode::Apply, "clean", Some(&mut log));
        assert_eq!(report.removed(), 1);
        assert!(!file.exists());
        assert!(cache.exists(), "the rule root itself must survive");

        let raw = std::fs::read_to_string(log.path()).unwrap();
        assert!(raw.contains("\"action\":\"REMOVED\""));
        drop(temp);
    }

    #[test]
    fn a_non_empty_directory_is_refused_not_recursed() {
        let (temp, xdg, probe) = fixture();
        let cache = xdg.cache.clone();
        let nested = cache.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        let child = nested.join("keep.txt");
        std::fs::write(&child, b"keep").unwrap();

        // Plan the directory itself, as a scanner that lost its post-order would.
        let plan = plan_for(&xdg, &probe, &cache, std::slice::from_ref(&nested));
        assert_eq!(plan.len(), 1, "denied: {:?}", plan.denied());

        let report = apply(&plan, &probe, Mode::Apply, "clean", None);
        assert_eq!(report.removed(), 0);
        assert_eq!(report.skipped, 1);
        assert!(nested.exists(), "the directory must survive");
        assert!(child.exists(), "the child must survive");
        drop(temp);
    }

    #[test]
    fn a_symlinked_leaf_is_never_removed() {
        let (temp, xdg, probe) = fixture();
        let cache = xdg.cache.clone();
        std::fs::create_dir_all(&cache).unwrap();
        let target = xdg.home.join("precious.txt");
        std::fs::write(&target, b"precious").unwrap();
        let link = cache.join("link-out");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let plan = plan_for(&xdg, &probe, &cache, std::slice::from_ref(&link));
        assert_eq!(plan.len(), 0, "a symlink must be refused at plan time");
        assert_eq!(plan.denied()[0].reason.code(), Reason::LeafSymlink.code());
        assert!(target.exists());
        drop(temp);
    }

    #[test]
    fn identity_paths_are_denied_even_inside_an_allowed_root() {
        let (temp, xdg, probe) = fixture();
        let ssh = xdg.home.join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::write(ssh.join("id_ed25519"), b"key").unwrap();

        // Pretend the rule root is the whole home directory.
        let plan = plan_for(&xdg, &probe, &xdg.home, &[ssh.join("id_ed25519")]);
        assert_eq!(plan.len(), 0);
        assert_eq!(
            plan.denied()[0].reason.code(),
            Reason::ProtectedIdentity(String::new()).code()
        );
        drop(temp);
    }

    #[test]
    fn a_plan_root_itself_is_denied() {
        let (temp, xdg, probe) = fixture();
        let root = xdg.cache.join("rule-root");
        std::fs::create_dir_all(&root).unwrap();
        let plan = plan_for(&xdg, &probe, &root, std::slice::from_ref(&root));
        assert_eq!(plan.len(), 0);
        assert_eq!(
            plan.denied()[0].reason.code(),
            Reason::AllowedRootItself.code()
        );
        drop(temp);
    }

    #[test]
    fn reason_for_a_missing_path_is_not_found() {
        let (temp, xdg, probe) = fixture();
        let cache = xdg.cache.clone();
        std::fs::create_dir_all(&cache).unwrap();
        let missing = cache.join("gone.bin");
        let plan = plan_for(&xdg, &probe, &cache, &[missing]);
        assert_eq!(plan.denied()[0].reason.code(), Reason::NotFound.code());
        drop(temp);
    }

    #[test]
    fn paths_outside_the_rule_root_are_denied() {
        let (temp, xdg, probe) = fixture();
        let cache = xdg.cache.clone();
        let other = xdg.data.clone();
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let file = other.join("file.bin");
        std::fs::write(&file, b"x").unwrap();

        let plan = plan_for(&xdg, &probe, &cache, &[file]);
        assert_eq!(
            plan.denied()[0].reason.code(),
            Reason::NotInAllowedRoot.code()
        );
        drop(temp);
    }

    #[test]
    fn verdict_carries_the_physical_path_through_a_symlinked_parent() {
        let (temp, xdg, probe) = fixture();
        let real = xdg.home.join("real-cache");
        std::fs::create_dir_all(&real).unwrap();
        let link = xdg.home.join("linked-cache");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let file = link.join("stale.bin");
        std::fs::write(&file, b"x").unwrap();

        let allowed = vec![AllowedRoot::new(&link)];
        let ctx = ValidateCtx {
            xdg: &xdg,
            probe: &probe,
            allowed: &allowed,
            policy: Policy::default(),
        };
        match crate::validate::validate(&file, &ctx) {
            Verdict::Allow { physical } => {
                assert_eq!(physical, real.join("stale.bin"));
            }
            Verdict::Deny(reason) => panic!("denied: {reason}"),
        }
        drop(temp);
    }
}
