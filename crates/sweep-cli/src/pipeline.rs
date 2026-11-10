//! `sweep clean`, `purge`, `installer`, `aur` — plan, confirm, apply.
//!
//! Every one of them is the same pipeline with a different [`Scope`]: which
//! sections it owns when the user names none, and the command name that appears
//! in messages, in the plan hash's session and in the operation log. Keeping one
//! implementation is the point - a second copy of the consent gate is a second
//! place for it to be wrong.
//!
//! The command is two-phase on purpose. [`build`] decides what could go: it
//! loads the catalog, decides which rules apply to this machine, walks their
//! roots and validates every candidate through [`sweep_core::Plan::push`]. It
//! never writes. Only after that plan exists, and only with consent, does
//! [`sweep_core::funnel::apply`] touch the filesystem — in [`Mode::Apply`] for a
//! real run, in [`Mode::DryRun`] when the user asked for a preview.
//!
//! Consent is explicit: `--yes` for scripts, an interactive prompt otherwise,
//! and a refusal when stdin is not a terminal. A refusal deletes nothing and
//! writes nothing, not even the operation log, for the same reason a dry run
//! does: "there is no record of this run" is better than "the plan directory now
//! exists because someone asked a question".
//!
//! The shape of the run matters more than the output. A rule is skipped for a
//! reason the user can act on (declared disabled, needs privilege, its tool is
//! not installed, its root is absent), and a rule whose scan did not complete is
//! skipped **entirely** rather than partially planned: a half-seen directory
//! tree is exactly the case where "the newest file is old" is a lie.
//!
//! `dir-age` keeps a whole subtree only when every entry in it - including
//! nested files, and including anything the walker deliberately left alone - is
//! older than the cutoff. A single fresh file, a symlink or an excluded child
//! keeps the subtree.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::format::human_bytes;
use serde::Serialize;
use sweep_core::fs_facts::MountTable;
use sweep_core::model_cache::{self, Leftover};
use sweep_core::oplog::{encode_path, rfc3339, Action, Oplog, Record};
use sweep_core::paths::{first_component, is_within};
use sweep_core::pkg_cache;
use sweep_core::privilege::{self, Elevator, SystemElevator};
use sweep_core::probe::{FsProbe, RealProbe};
use sweep_core::project;
use sweep_core::rules::{Kind, Privilege, Rule, RuleSet, Section};
use sweep_core::scan::{self, BlockKind, Collect, Entry, Limits, Select, Spec, Stop};
use sweep_core::trash;
use sweep_core::validate::{AllowedRoot, Policy, ValidateCtx};
use sweep_core::versions;
use sweep_core::{funnel, Mode, Plan, Xdg};

/// Which sections a command owns when the user does not name any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sections {
    /// Everything `clean` owns: the catalog minus the sections that belong to a
    /// command of their own, and minus the opt-in ones.
    ///
    /// A bare `sweep clean` must not walk the user's project directories. Those
    /// belong to `purge`, which asks about them and explains what a manifest is
    /// doing there.
    Clean,
    /// Exactly one section: `purge` owns `project-artifacts`, and so on.
    Assigned(Section),
}

/// One command's view of the pipeline.
#[derive(Debug, Clone, Copy)]
pub struct Scope {
    /// `clean`, `purge`, … Also the operation-log `cmd` field and the session
    /// prefix, so `sweep history` can separate them later.
    pub command: &'static str,
    sections: Sections,
}

impl Scope {
    pub const CLEAN: Scope = Scope {
        command: "clean",
        sections: Sections::Clean,
    };

    pub const PURGE: Scope = Scope {
        command: "purge",
        sections: Sections::Assigned(Section::ProjectArtifacts),
    };

    pub const AUR: Scope = Scope {
        command: "aur",
        sections: Sections::Assigned(Section::Aur),
    };

    pub const INSTALLER: Scope = Scope {
        command: "installer",
        sections: Sections::Assigned(Section::Installers),
    };

    /// The sections this run may touch.
    ///
    /// An explicit `--only` wins over the command's own list: `clean --only
    /// project-artifacts` is a user asking for the sweep by name, and
    /// `purge --only` does not exist because `purge` owns one section.
    fn sections(self, only: &[Section]) -> Vec<Section> {
        if !only.is_empty() {
            return only.to_vec();
        }
        match self.sections {
            Sections::Assigned(section) => vec![section],
            Sections::Clean => Section::ALL
                .iter()
                .copied()
                .filter(|section| !section.is_opt_in() && section.command().is_none())
                .collect(),
        }
    }
}

/// Why a rule contributed nothing. Machine-readable for `--json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Planned,
    ReportOnly,
    DeclaredDisabled,
    /// A section that is only swept when the user names it (`--only`).
    OptIn,
    /// A section owned by another command (`project-artifacts` by `purge`).
    CommandScoped,
    MissingRequirement,
    NotPresent,
    NotADirectory,
    SymlinkedRoot,
    Unreadable,
    ScanIncomplete,
    /// A `versions` rule could not tell which entry the launcher uses.
    KeepLinkUnknown,
    Empty,
}

impl Status {
    fn is_skip(self) -> bool {
        !matches!(self, Status::Planned | Status::ReportOnly)
    }

    fn label(self) -> &'static str {
        match self {
            Status::Planned => "planned",
            Status::ReportOnly => "report-only",
            Status::DeclaredDisabled => "disabled by the catalog",
            Status::OptIn => "opt-in section, not selected",
            Status::CommandScoped => "belongs to another command",
            Status::MissingRequirement => "tool not installed",
            Status::NotPresent => "path not present",
            Status::NotADirectory => "not a directory",
            Status::SymlinkedRoot => "rule root is a symlink",
            Status::Unreadable => "permission denied",
            Status::ScanIncomplete => "scan incomplete; nothing planned",
            Status::KeepLinkUnknown => "launcher unknown; nothing planned",
            Status::Empty => "nothing to remove",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct RuleRun {
    id: String,
    section: &'static str,
    kind: &'static str,
    status: Status,
    /// Candidates handed to the plan (after validation).
    items: usize,
    /// Candidates the policy refused.
    refused: usize,
    /// Bytes the plan would reclaim.
    bytes: u64,
    /// Bytes visited, including entries that were not planned.
    scanned_bytes: u64,
    /// Paths the user's ignore file protected, so the report can confirm the
    /// line took effect instead of leaving the user to guess.
    ignored: usize,
    /// Repositories a scanner refused to judge because part of the tree was
    /// unreadable. Empty for every kind but `hf-cache`.
    preserved: Vec<String>,
    detail: Option<String>,
}

#[derive(Debug, Serialize)]
struct SectionRun {
    section: &'static str,
    rules: usize,
    items: usize,
    refused: usize,
    bytes: u64,
}

#[derive(Debug, Serialize, Default)]
struct FunnelReport {
    /// Items removed (or that would be removed) at the final sink.
    removed: usize,
    would_remove: usize,
    skipped: usize,
    failed: usize,
    bytes: u64,
    skip_codes: Vec<SkipCode>,
}

impl FunnelReport {
    /// `removed` and `would_remove` are disjoint: exactly one of them is
    /// non-zero, and which one is decided by the mode, not by the data.
    fn of(report: &funnel::Report, mode: Mode) -> Self {
        Self {
            removed: if mode.is_dry_run() {
                0
            } else {
                report.removed()
            },
            would_remove: if mode.is_dry_run() {
                report.would_remove()
            } else {
                0
            },
            skipped: report.skipped,
            failed: report.failed,
            bytes: report.removed_bytes,
            skip_codes: report
                .skip_codes()
                .into_iter()
                .map(|(code, count)| SkipCode {
                    code: code.to_string(),
                    count,
                })
                .collect(),
        }
    }
}

impl FunnelReport {
    /// Adds the elevated half to the user half, so the summary counts one run.
    fn merge(&mut self, other: &FunnelReport) {
        self.removed += other.removed;
        self.would_remove += other.would_remove;
        self.skipped += other.skipped;
        self.failed += other.failed;
        self.bytes = self.bytes.saturating_add(other.bytes);
        for code in &other.skip_codes {
            match self
                .skip_codes
                .iter_mut()
                .find(|seen| seen.code == code.code)
            {
                Some(seen) => seen.count += code.count,
                None => self.skip_codes.push(SkipCode {
                    code: code.code.clone(),
                    count: code.count,
                }),
            }
        }
        self.skip_codes
            .sort_by(|left, right| left.code.cmp(&right.code));
    }

    /// Records `count` items that were never attempted, under one reason.
    ///
    /// "Not elevated" is a decision, not a syscall failure, so it belongs with
    /// the other skips: the ledger says what happened to every planned item
    /// without pretending the attempt was made.
    fn count_skips(&mut self, code: &'static str, count: usize) {
        self.skipped += count;
        match self.skip_codes.iter_mut().find(|seen| seen.code == code) {
            Some(seen) => seen.count += count,
            None => self.skip_codes.push(SkipCode {
                code: code.to_string(),
                count,
            }),
        }
        self.skip_codes
            .sort_by(|left, right| left.code.cmp(&right.code));
    }

    /// The same shape, built from what the elevated child reported.
    fn of_reply(reply: &privilege::Reply) -> Self {
        let mut out = Self::default();
        for result in &reply.results {
            match result.action {
                Action::Removed => {
                    out.removed += 1;
                    out.bytes = out.bytes.saturating_add(result.bytes);
                }
                Action::WouldRemove => out.would_remove += 1,
                // The elevation reply never carries this: only `analyze` moves
                // an entry to the trash, and it does so in this process. The arm
                // exists because the enum is shared, and counting a move as a
                // removal is true about the space and false about nothing.
                Action::Trashed => {
                    out.removed += 1;
                    out.bytes = out.bytes.saturating_add(result.bytes);
                }
                // Only `optimize` rebuilds an index, and it does so in this
                // process; the arm keeps the shared enum exhaustive.
                Action::Rebuilt => out.removed += 1,
                Action::Failed => out.failed += 1,
                Action::Skipped => {
                    out.skipped += 1;
                    let code = result.code.clone().unwrap_or_else(|| "unknown".to_string());
                    match out.skip_codes.iter_mut().find(|seen| seen.code == code) {
                        Some(seen) => seen.count += 1,
                        None => out.skip_codes.push(SkipCode { code, count: 1 }),
                    }
                }
            }
        }
        out.skip_codes
            .sort_by(|left, right| left.code.cmp(&right.code));
        out
    }
}

#[derive(Debug, Serialize)]
struct SkipCode {
    /// Owned because the elevated child reports codes this process never
    /// contains as a literal.
    code: String,
    count: usize,
}

/// What happened to the root-owned half of the plan.
#[derive(Debug, Serialize)]
struct ElevationReport {
    /// `applied`, `declined`, `unavailable` or `failed`.
    status: &'static str,
    requested: usize,
    bytes: u64,
    detail: Option<String>,
}

/// Where this run's rows went. Absent from a dry run, which logs nothing.
#[derive(Debug, Serialize)]
struct LogRef {
    session: String,
    path: String,
}

/// Why the policy refused candidates, grouped by rule and reason.
#[derive(Debug, Serialize)]
struct Refusal {
    rule: String,
    code: &'static str,
    count: usize,
}

#[derive(Debug, Serialize)]
struct PipelineReport {
    command: &'static str,
    mode: &'static str,
    plan_hash: String,
    sections: Vec<SectionRun>,
    rules: Vec<RuleRun>,
    refusals: Vec<Refusal>,
    funnel: FunnelReport,
    /// Present only when the plan contained root-owned items.
    elevation: Option<ElevationReport>,
    log: Option<LogRef>,
    totals: Totals,
    /// Things a user must know before trusting the numbers above.
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Totals {
    rules: usize,
    planned: usize,
    skipped: usize,
    items: usize,
    refused: usize,
    bytes: u64,
}

pub fn run(
    scope: Scope,
    json: bool,
    verbose: u8,
    only: &[Section],
    dry_run: bool,
    yes: bool,
    privileged: bool,
) -> ExitCode {
    let command = scope.command;
    let xdg = match Xdg::from_env() {
        Ok(xdg) => xdg,
        Err(error) => {
            eprintln!("sweep {command}: {error}");
            return ExitCode::from(crate::EXIT_UNSUPPORTED_ENVIRONMENT);
        }
    };

    let set = match RuleSet::load(&xdg) {
        Ok(set) => set,
        Err(errors) => {
            eprintln!(
                "sweep {command}: {} load {} refused; run `sweep rules verify` for details",
                errors.len(),
                if errors.len() == 1 { "error" } else { "errors" }
            );
            for error in &errors {
                eprintln!("  {error}");
            }
            return ExitCode::from(crate::EXIT_INVALID_RULES);
        }
    };

    // A malformed ignore file refuses the run instead of being skipped: the user
    // wrote it to protect something, and sweeping past a typo is the one outcome
    // they would not expect.
    let ignore = match sweep_core::ignore::Ignore::load(&xdg) {
        Ok(ignore) => ignore,
        Err(error) => {
            eprintln!("sweep {command}: {error}");
            eprintln!(
                "  fix {} and run again; nothing was planned",
                if error.line == 0 {
                    "the file"
                } else {
                    "that line, or delete it"
                }
            );
            return ExitCode::from(crate::EXIT_INVALID_RULES);
        }
    };

    let mounts = match MountTable::load() {
        Ok(mounts) => mounts,
        Err(error) => {
            eprintln!("sweep {command}: cannot read the mount table: {error}");
            return ExitCode::from(crate::EXIT_UNSUPPORTED_ENVIRONMENT);
        }
    };

    let probe = match RealProbe::new() {
        Ok(probe) => probe.with_open_scan(),
        Err(error) => {
            eprintln!("sweep {command}: cannot probe this filesystem: {error}");
            return ExitCode::from(crate::EXIT_UNSUPPORTED_ENVIRONMENT);
        }
    };

    let mode = if dry_run { Mode::DryRun } else { Mode::Apply };
    let Built {
        mut plan,
        mut report,
    } = build(
        scope,
        &set,
        &xdg,
        &probe,
        &mounts,
        only,
        &Limits::default(),
        mode,
        &ignore,
    );

    // Which rules the elevated child may act on. Derived from the loaded
    // catalog rather than from the plan, so an overlay rule can never be sent
    // to a process that would refuse it anyway.
    let privileged_rules = privileged_rule_ids(&set);

    if mode.is_dry_run() {
        // The preview covers the whole plan, including the root-owned half: a
        // dry run that hid half the items because they need a password would
        // report a total that is not the plan.
        let preview = funnel::apply(&plan, &probe, Mode::DryRun, command, None);
        report.funnel = FunnelReport::of(&preview, mode);
        let (root_plan, _) = plan.split(|item| privileged_rules.contains(item.rule().as_str()));
        if !root_plan.is_empty() {
            let requested = root_plan.len();
            let bytes = root_plan.total_bytes();
            report.elevation = Some(ElevationReport {
                status: "not_attempted",
                requested,
                bytes,
                detail: Some("a dry run never elevates".to_string()),
            });
            report.notes.push(format!(
                "{requested} of the planned items ({}) are root-owned; applying them needs \
                 `--privileged` or a yes at the prompt",
                human_bytes(bytes)
            ));
        }
        return finish(json, verbose, &report, 0);
    }

    // An empty plan is not a question worth asking, and it must not create the
    // state directory: nothing happened, so nothing is recorded.
    if plan.is_empty() {
        return finish(json, verbose, &report, 0);
    }

    match confirm(command, plan.len(), plan.total_bytes(), yes) {
        Consent::Granted => {}
        Consent::Declined(message) => {
            eprintln!("sweep {command}: {message}");
            return ExitCode::from(crate::EXIT_DECLINED);
        }
    }

    // The prompt is a window, and a version launcher is a symlink an update
    // moves. Read it once more now that the answer is in: a re-pointed link
    // changes no inode, so the funnel's `st_dev`/`st_ino` re-check cannot catch
    // it. Whatever it names now leaves the plan.
    withdraw_live_versions(&mut plan, &mut report, &set, &xdg, &probe);
    if plan.is_empty() {
        // Everything the user confirmed was withdrawn, so nothing happened and
        // nothing is recorded. Same rule as a plan that was empty to begin with.
        return finish(json, verbose, &report, 0);
    }

    let session = format!("{command}-{}", now_unix());
    let log_path = xdg.state_dir().join("operations.jsonl");
    let mut oplog = match Oplog::open(&xdg.state_dir(), session.clone()) {
        Ok(log) => {
            report.log = Some(LogRef {
                session: session.clone(),
                path: log.path().display().to_string(),
            });
            Some(log)
        }
        Err(error) => {
            // Bounded cleanup does not stop because the audit trail is missing;
            // the report says so instead of pretending the run was recorded.
            report.notes.push(format!(
                "the operation log at {} could not be opened ({error}); this run is not recorded",
                log_path.display()
            ));
            None
        }
    };

    // The two halves are applied differently. User items go through the funnel
    // in this process; root items go through the privilege boundary. A root item
    // is never attempted as the user, because `EACCES` would then be reported as
    // a syscall failure when it is a permission boundary doing its job.
    let (root_plan, user_plan) = plan.split(|item| privileged_rules.contains(item.rule().as_str()));

    let applied = funnel::apply(&user_plan, &probe, Mode::Apply, command, oplog.as_mut());
    let mut funnel_report = FunnelReport::of(&applied, mode);
    let mut code = if applied.failed > 0 {
        eprintln!(
            "sweep {command}: {} items could not be removed and were left in place; \
             the operation log has the reason for each",
            applied.failed
        );
        1
    } else {
        0
    };

    if !root_plan.is_empty() {
        let requested = root_plan.len();
        let bytes = root_plan.total_bytes();
        match elevate_consent(command, requested, bytes, privileged) {
            Elevation::Granted => match SystemElevator::discover() {
                Ok(elevator) => {
                    let outcome = apply_root(
                        command,
                        &root_plan,
                        &privileged_rules,
                        &session,
                        &elevator,
                        oplog.as_mut(),
                    );
                    match outcome {
                        Ok(elevated) => {
                            if elevated.failed > 0 {
                                eprintln!(
                                    "sweep {command}: {} root-owned items could not be removed; \
                                     the operation log has the reason for each",
                                    elevated.failed
                                );
                                code = 1;
                            }
                            if elevated.removed > 0 {
                                report.notes.push(format!(
                                    "{} of {requested} root-owned items ({}) were removed as root",
                                    elevated.removed,
                                    human_bytes(elevated.bytes)
                                ));
                            }
                            let status = if elevated.failed > 0 {
                                "failed"
                            } else if elevated.removed == 0 {
                                // Nothing failed and nothing was removed: the
                                // child re-validated and refused. That is the
                                // boundary working, not a syscall error.
                                "refused"
                            } else {
                                "applied"
                            };
                            funnel_report.merge(&elevated);
                            report.elevation = Some(ElevationReport {
                                status,
                                requested,
                                bytes,
                                detail: None,
                            });
                        }
                        Err(error) => {
                            eprintln!(
                                "sweep {command}: {requested} root-owned items were left in place: \
                                 elevation did not run ({error})"
                            );
                            skip_unattempted(
                                oplog.as_mut(),
                                command,
                                &root_plan,
                                "elevation_failed",
                            );
                            funnel_report.count_skips("elevation_failed", requested);
                            report.notes.push(format!(
                                "{requested} root-owned items ({}) were left in place because \
                                 elevation did not run: {error}",
                                human_bytes(bytes)
                            ));
                            report.elevation = Some(ElevationReport {
                                status: "failed",
                                requested,
                                bytes,
                                detail: Some(error.to_string()),
                            });
                            code = 1;
                        }
                    }
                }
                Err(error) => {
                    eprintln!("sweep {command}: {error}");
                    skip_unattempted(oplog.as_mut(), command, &root_plan, "elevation_unavailable");
                    funnel_report.count_skips("elevation_unavailable", requested);
                    report.notes.push(format!(
                        "{requested} root-owned items ({}) were left in place: {error}",
                        human_bytes(bytes)
                    ));
                    report.elevation = Some(ElevationReport {
                        status: "unavailable",
                        requested,
                        bytes,
                        detail: Some(error.to_string()),
                    });
                    if privileged {
                        // The user asked for the system half explicitly; not
                        // delivering it is a failure, not a quiet partial run.
                        code = 1;
                    }
                }
            },
            Elevation::Declined(message) => {
                skip_unattempted(oplog.as_mut(), command, &root_plan, "not_elevated");
                funnel_report.count_skips("not_elevated", requested);
                report.notes.push(format!(
                    "{requested} root-owned items ({}) were left in place: {message}",
                    human_bytes(bytes)
                ));
                report.elevation = Some(ElevationReport {
                    status: "declined",
                    requested,
                    bytes,
                    detail: Some(message),
                });
            }
        }
    }
    report.funnel = funnel_report;

    // Drop the handle before reporting so a buffered record cannot outlive the
    // summary that says the log was written.
    drop(oplog);
    finish(json, verbose, &report, code)
}

/// The rule ids whose items belong to the elevated child.
fn privileged_rule_ids(set: &RuleSet) -> BTreeSet<String> {
    set.rules()
        .iter()
        .filter(|rule| rule.privilege == Privilege::Root)
        .map(|rule| rule.id.to_string())
        .collect()
}

/// Withdraws the version entries the launcher names *now*, after consent.
///
/// The plan is built before the confirmation prompt, and the launcher is a
/// symlink an update moves. The funnel re-checks `st_dev`/`st_ino`, which
/// catches a swapped path but not a re-pointed link: every version entry keeps
/// its inode while the entry in use changes. So the launcher is read once more
/// between the answer and the first unlink, and whatever it names leaves the
/// plan. A rule whose launcher can no longer be read withdraws everything it
/// planned, because the answer the plan was built from is gone.
fn withdraw_live_versions(
    plan: &mut Plan,
    report: &mut PipelineReport,
    set: &RuleSet,
    xdg: &Xdg,
    probe: &dyn FsProbe,
) {
    let mut touched: BTreeSet<String> = BTreeSet::new();
    let mut unknown: BTreeSet<String> = BTreeSet::new();
    let mut withdrawn = 0usize;
    let mut bytes = 0u64;

    for rule in set.rules() {
        if rule.kind != Kind::Versions {
            continue;
        }
        let Some(keep_link) = rule.keep_link.as_ref().map(|link| link.expand(xdg)) else {
            continue;
        };
        let planned: Vec<(PathBuf, u64)> = plan
            .items()
            .iter()
            .filter(|item| item.rule() == &rule.id)
            .map(|item| (item.path().to_path_buf(), item.bytes()))
            .collect();
        if planned.is_empty() {
            continue;
        }

        // A path can be named twice when a glob root resolves to nested
        // directories, so the withdrawal is collected before it is applied.
        let mut drop: BTreeMap<PathBuf, u64> = BTreeMap::new();
        match rule.expanded_roots(xdg) {
            Ok(roots) => {
                for root in &roots {
                    match versions::live_entry(root, &keep_link, probe) {
                        Ok(live) => {
                            for (path, size) in &planned {
                                if path == &live || path.starts_with(&live) {
                                    drop.insert(path.clone(), *size);
                                }
                            }
                        }
                        Err(_) => {
                            // This root's answer is gone; keep everything it
                            // contributed rather than guess which entry is live.
                            unknown.insert(rule.id.to_string());
                            for (path, size) in &planned {
                                if path.starts_with(root) {
                                    drop.insert(path.clone(), *size);
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => {
                // The pattern resolved when the plan was built and does not
                // now. Unknown never deletes.
                unknown.insert(rule.id.to_string());
                drop.extend(planned.iter().cloned());
            }
        }
        if drop.is_empty() {
            continue;
        }

        let rule_withdrawn = drop.len();
        let rule_bytes: u64 = drop.values().sum();
        for path in drop.keys() {
            plan.forget(path);
        }
        withdrawn += rule_withdrawn;
        bytes += rule_bytes;
        touched.insert(rule.id.to_string());

        if let Some(run) = report
            .rules
            .iter_mut()
            .find(|run| run.id == rule.id.as_str())
        {
            let remaining: Vec<u64> = plan
                .items()
                .iter()
                .filter(|item| item.rule().as_str() == run.id)
                .map(|item| item.bytes())
                .collect();
            run.items = remaining.len();
            run.bytes = remaining.iter().sum();
            let note = if unknown.contains(&rule.id.to_string()) {
                "the launcher could not be read after you answered, so nothing this rule \
                 planned is removed"
                    .to_string()
            } else if run.items == 0 {
                "the launcher now names the entry this rule planned, so it stays in place"
                    .to_string()
            } else {
                format!(
                    "{rule_withdrawn} {} withdrawn because the launcher moved while the prompt \
                     was open",
                    if rule_withdrawn == 1 {
                        "entry was"
                    } else {
                        "entries were"
                    }
                )
            };
            if run.items == 0 {
                run.status = if unknown.contains(&rule.id.to_string()) {
                    Status::KeepLinkUnknown
                } else {
                    Status::Empty
                };
            }
            run.detail = Some(match run.detail.take() {
                Some(detail) => format!("{detail}; {note}"),
                None => note,
            });
        }
    }

    if withdrawn == 0 {
        return;
    }

    plan.finish();
    report.plan_hash = plan.hash().to_string();
    report.sections = summarise_sections(&report.rules);
    report.totals.planned = report
        .rules
        .iter()
        .filter(|run| run.status == Status::Planned)
        .count();
    report.totals.skipped = report
        .rules
        .iter()
        .filter(|run| run.status.is_skip())
        .count();
    report.totals.items = plan.len();
    report.totals.bytes = plan.total_bytes();
    report.notes.push(format!(
        "{withdrawn} planned {} ({}) left in place: the launcher changed while the prompt was open",
        if withdrawn == 1 {
            "item was"
        } else {
            "items were"
        },
        human_bytes(bytes)
    ));
    if !unknown.is_empty() {
        report.notes.push(format!(
            "the launcher for {} could not be read after you answered, so nothing it planned is \
             removed",
            unknown.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
}

/// Hands the root-owned half to the elevated child and folds its answer in.
///
/// Separate from `run` so a test can drive the boundary with a fake elevator:
/// the real one would ask for a password, and the interesting assertion — that
/// the request names only root items and that the reply reaches the log — does
/// not need one.
fn apply_root(
    cmd: &str,
    root_plan: &Plan,
    privileged_rules: &BTreeSet<String>,
    session: &str,
    elevator: &dyn Elevator,
    oplog: Option<&mut Oplog>,
) -> io::Result<FunnelReport> {
    let request = privilege::request_from(
        root_plan,
        |rule| privileged_rules.contains(rule),
        cmd,
        session,
    )
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no privileged items"))?;
    let reply = elevator.run(&request)?;
    log_reply(oplog, cmd, &reply);
    Ok(FunnelReport::of_reply(&reply))
}

/// Prints the report and returns the exit code the command settled on.
fn finish(json: bool, verbose: u8, report: &PipelineReport, code: u8) -> ExitCode {
    if json {
        match serde_json::to_string_pretty(report) {
            Ok(text) => println!("{text}"),
            Err(error) => {
                eprintln!("sweep {}: cannot serialise report: {error}", report.command);
                return ExitCode::FAILURE;
            }
        }
    } else {
        print!("{}", render(report, verbose));
    }
    ExitCode::from(code)
}

use crate::consent::Consent;

/// What the user said about using root for the root-owned part of the plan.
enum Elevation {
    Granted,
    Declined(String),
}

/// Asks for elevation, and declines when there is nobody to ask.
///
/// This is a second question on purpose: `--yes` answers "delete this plan", not
/// "become root". A script that wants the system half says `--privileged`, and a
/// run whose stdin is not a terminal declines rather than reaching for sudo on
/// its own.
fn elevate_consent(command: &str, items: usize, bytes: u64, allowed: bool) -> Elevation {
    if allowed {
        return Elevation::Granted;
    }
    if !io::stdin().is_terminal() {
        // The count is added by the caller, which is the only place that knows
        // both halves; repeating it here produced a sentence that said the same
        // thing twice.
        return Elevation::Declined(
            "stdin is not a terminal, so nobody could be asked; re-run with --privileged to \
             sweep the system section (nothing outside $HOME was touched)"
                .to_string(),
        );
    }

    eprint!(
        "sweep {command}: {items} of these items ({}) are root-owned.\n\
         Elevate with run0/sudo to remove them? [y/N] ",
        human_bytes(bytes)
    );
    let _ = io::stderr().flush();

    let mut answer = String::new();
    match io::stdin().read_line(&mut answer) {
        Ok(0) => {
            Elevation::Declined("no answer on stdin; the system section was left alone".into())
        }
        Ok(_) => {
            let answer = answer.trim().to_ascii_lowercase();
            if answer == "y" || answer == "yes" {
                Elevation::Granted
            } else {
                Elevation::Declined(
                    "the system section was left alone; run with --privileged to include it"
                        .to_string(),
                )
            }
        }
        Err(error) => Elevation::Declined(format!(
            "cannot read the confirmation ({error}); the system section was left alone"
        )),
    }
}

/// Writes one `SKIPPED` row per item that was never attempted.
fn skip_unattempted(oplog: Option<&mut Oplog>, cmd: &str, plan: &Plan, code: &str) {
    let Some(log) = oplog else {
        return;
    };
    let ts = rfc3339(now_unix());
    let session = log.session().to_string();
    for item in plan.items() {
        let (path, path_hex) = encode_path(item.literal());
        log.append(Record {
            ts: ts.clone(),
            cmd,
            session: &session,
            action: Action::Skipped,
            rule: item.rule().as_str(),
            path,
            path_hex,
            bytes: 0,
            reason: Some(code),
            detail: Some(
                "root-owned and not elevated; nothing was attempted as the user".to_string(),
            ),
        });
    }
}

/// Appends the elevated child's report to the user's log.
///
/// The child never writes the log itself: root opening a file inside the user's
/// state directory is a worse arrangement than trusting this binary's own output
/// on a pipe, which is what it is.
fn log_reply(oplog: Option<&mut Oplog>, cmd: &str, reply: &privilege::Reply) {
    let Some(log) = oplog else {
        return;
    };
    let ts = rfc3339(now_unix());
    let session = log.session().to_string();
    for result in &reply.results {
        let (path, path_hex) = match privilege::decode_path(&result.path_hex) {
            Some(exact) => encode_path(&exact),
            // A reply we cannot decode is not silently mis-filed: the display
            // path and the hex both come from the same child, so this only
            // happens if the child is not this binary.
            None => (result.path.clone(), Some(result.path_hex.clone())),
        };
        log.append(Record {
            ts: ts.clone(),
            cmd,
            session: &session,
            action: result.action,
            rule: &result.rule,
            path,
            path_hex,
            bytes: result.bytes,
            reason: result.code.as_deref(),
            detail: result.detail.clone(),
        });
    }
}

/// Asks before deleting, in the shape every command's question has.
///
/// The decision itself is [`crate::consent::ask`]; this is only the sentence,
/// which names the command, the count and the space so the question can be
/// answered without scrolling back to the plan.
fn confirm(command: &str, items: usize, bytes: u64, yes: bool) -> Consent {
    crate::consent::ask(
        &format!(
            "sweep {command} will permanently remove {items} items ({}).\nContinue?",
            human_bytes(bytes)
        ),
        &format!("remove {items} items ({})", human_bytes(bytes)),
        yes,
    )
}

struct Built {
    plan: Plan,
    report: PipelineReport,
}

#[allow(clippy::too_many_arguments)]
fn build(
    scope: Scope,
    set: &RuleSet,
    xdg: &Xdg,
    probe: &RealProbe,
    mounts: &MountTable,
    only: &[Section],
    limits: &Limits,
    mode: Mode,
    ignore: &sweep_core::ignore::Ignore,
) -> Built {
    let command = scope.command;
    let sections = scope.sections(only);
    // The report lists every rule the user asked to see; `sections` decides
    // which of them may run. Those differ for a bare `clean`, which lists the
    // sections another command owns (status `belongs to another command`)
    // instead of hiding them, but scans none of them. A command that owns its
    // section reports only that section, because seventeen rows of "not
    // selected" is not a preview.
    let report_sections: Vec<Section> = match (only.is_empty(), scope.sections) {
        (false, _) => only.to_vec(),
        (true, Sections::Assigned(section)) => vec![section],
        (true, Sections::Clean) => Section::ALL.to_vec(),
    };
    let selected = set.select(&report_sections, xdg);
    let now = now_unix();

    // Every deletable root becomes an allowed root, because validation works on
    // "is this path inside something a rule declared?" and one plan mixes items
    // from several rules. Overlapping roots are fine: the deepest rule is the
    // one that records the item, thanks to the selection order.
    let deleting: Vec<&Rule> = selected
        .iter()
        .copied()
        .filter(|rule| rule.enabled && rule.kind.deletes())
        .collect();
    // A glob root becomes as many concrete directories as it matches. An
    // expansion error means "unknown", so that rule contributes no allowed root
    // and is reported as an incomplete scan below instead of being planned.
    let allowed: Vec<AllowedRoot> = deleting
        .iter()
        .flat_map(|rule| {
            rule.expanded_roots(xdg)
                .unwrap_or_default()
                .into_iter()
                .map(|path| {
                    let mut root = AllowedRoot::new(path).pinned_to_current_device(mounts);
                    // A tool cache owns its directory: the sweep removes the root too.
                    root.allow_root_itself = rule.kind == Kind::ToolCache;
                    // A system rule only ever removes files owned by root, whoever is
                    // asking. The elevated child re-applies the same expectation.
                    if rule.privilege == Privilege::Root {
                        root = root.owned_by_root();
                    }
                    root
                })
        })
        .collect();
    let roots: Vec<PathBuf> = deleting
        .iter()
        .flat_map(|rule| rule.expanded_roots(xdg).unwrap_or_default())
        .collect();
    // The claim set is the whole catalog, not this run's selection. A root
    // another rule names is off limits to the blanket sweep whatever the user
    // asked for, and whether that rule is enabled, disabled or report-only: the
    // catalog saying "I look at this path" is the reason, and none of those
    // three answers makes the blanket sweep a better owner. Taking the claim
    // set from `deleting` made it depend on `--only`: a bare `clean` left
    // `{cache}/lutris` alone because `app.lutris.cache` claimed a child of it,
    // while `clean --only user-essentials` planned the parent and would have
    // removed the GOG and Epic tokens stored at its root.
    //
    // A glob root claims every directory it currently matches. Those are the
    // concrete targets the rule would take, so the blanket sweep must leave
    // each one alone for the same reason it leaves a literal root alone.
    let claims: Vec<PathBuf> = set
        .rules()
        .iter()
        .flat_map(|rule| rule.expanded_roots(xdg).unwrap_or_default())
        .collect();

    let ctx = ValidateCtx {
        xdg,
        probe,
        allowed: &allowed,
        // The pipeline deletes what it plans, so the policy is the strict one.
        // Dry run is a *mode of the funnel*, not a weaker policy: the preview
        // must exercise exactly the checks the real run will.
        //
        // One exception, and it is narrower than it looks: a run that may touch
        // `project-artifacts` may unlink a symbolic link. `node_modules/.bin`
        // and a virtualenv's `bin/python3` are links the package manager wrote,
        // and a sweep that leaves them behind leaves a tree that still looks
        // installed. The flag alone cannot put a link in a plan - only the
        // artifact walk emits one - and the sink unlinks the link, never its
        // target. A `versions` entry sets the same flag for its own walk, per
        // rule, because a release tree holds its own links; every other command
        // keeps the refusal.
        policy: Policy {
            allow_leaf_symlink: sections.contains(&Section::ProjectArtifacts),
            ..Policy::default()
        },
    };

    let mut plan = Plan::new();
    if !ignore.is_empty() {
        plan.set_ignore(ignore.clone());
    }
    let mut runs: Vec<RuleRun> = Vec::with_capacity(selected.len());
    let mut notes: Vec<String> = Vec::new();

    for rule in &selected {
        if let Some(status) = skip_reason(rule, xdg, &sections) {
            runs.push(base_run(
                rule,
                status,
                skip_detail(command, rule, xdg, status),
            ));
            continue;
        }
        let roots = match rule.expanded_roots(xdg) {
            Ok(roots) => roots,
            Err(error) => {
                // A pattern that cannot be resolved completely is an unknown,
                // and unknown never deletes. The detail names the pattern
                // rather than pretending the target is absent.
                runs.push(base_run(
                    rule,
                    Status::ScanIncomplete,
                    Some(error.to_string()),
                ));
                continue;
            }
        };
        if roots.is_empty() {
            runs.push(base_run(rule, Status::NotPresent, None));
            continue;
        }
        let per_root: Vec<RuleRun> = roots
            .iter()
            .map(|root| execute(rule, root, probe, &ctx, limits, &mut plan, &claims, now))
            .collect();
        runs.push(merge_roots(rule, per_root));
    }

    plan.finish();

    let declared_off = runs
        .iter()
        .filter(|run| run.status == Status::DeclaredDisabled)
        .count();
    if declared_off > 0 {
        notes.push(format!(
            "{declared_off} rules are declared disabled by the catalog and are listed but \
             never planned"
        ));
    }
    let absent = runs
        .iter()
        .filter(|run| run.status == Status::NotPresent)
        .count();
    if absent > 0 {
        notes.push(format!(
            "{absent} rule roots are not present on this machine and were skipped"
        ));
    }
    let opt_in: Vec<&str> = Section::ALL
        .into_iter()
        .filter(|section| section.is_opt_in())
        .filter(|section| {
            runs.iter()
                .any(|run| run.status == Status::OptIn && run.section == section.as_str())
        })
        .map(|section| section.as_str())
        .collect();
    if !opt_in.is_empty() {
        // Nothing in these sections is scanned, so the note must not imply a
        // size: the number only exists once the user asks for that section.
        notes.push(format!(
            "{} {} opt-in and was not scanned; `sweep {command} --only {}` reviews it",
            opt_in.join(", "),
            if opt_in.len() == 1 { "is" } else { "are" },
            opt_in.join(" --only ")
        ));
    }
    let incomplete: Vec<&str> = runs
        .iter()
        .filter(|run| run.status == Status::ScanIncomplete)
        .map(|run| run.id.as_str())
        .collect();
    if !incomplete.is_empty() {
        notes.push(format!(
            "{} rules were skipped because their scan did not complete; nothing from a \
             partial scan is planned: {}",
            incomplete.len(),
            incomplete.join(", ")
        ));
    }
    let root_ids = privileged_rule_ids(set);
    let unreadable: Vec<&str> = runs
        .iter()
        .filter(|run| run.status == Status::Unreadable && root_ids.contains(&run.id))
        .map(|run| run.id.as_str())
        .collect();
    if !unreadable.is_empty() {
        // This is not a broken path; it is a root cache the user cannot see.
        // Saying so once is the difference between "sweep found nothing" and
        // "sweep could not look".
        notes.push(format!(
            "{} {} could not be read as your user and {} not planned: {}. A plan you cannot \
             see is not one you can confirm",
            unreadable.len(),
            if unreadable.len() == 1 {
                "root cache"
            } else {
                "root caches"
            },
            if unreadable.len() == 1 { "was" } else { "were" },
            unreadable.join(", ")
        ));
    }
    for run in &runs {
        if run.preserved.is_empty() {
            continue;
        }
        // "Kept because it could not be read" is the opposite of a skip the user
        // can ignore, so it is stated once in the summary and not only in the
        // per-rule detail.
        let mut names = run.preserved.iter().take(3).cloned().collect::<Vec<_>>();
        if run.preserved.len() > names.len() {
            names.push(format!("and {} more", run.preserved.len() - names.len()));
        }
        notes.push(format!(
            "{} {} preserved because {} snapshots could not be read completely: {}",
            run.preserved.len(),
            if run.preserved.len() == 1 {
                "repository"
            } else {
                "repositories"
            },
            if run.preserved.len() == 1 {
                "its"
            } else {
                "their"
            },
            names.join(", ")
        ));
    }

    let sections = summarise_sections(&runs);
    let totals = Totals {
        rules: runs.len(),
        planned: runs
            .iter()
            .filter(|run| run.status == Status::Planned)
            .count(),
        skipped: runs.iter().filter(|run| run.status.is_skip()).count(),
        items: plan.len(),
        refused: plan.denied().len(),
        bytes: plan.total_bytes(),
    };
    if totals.bytes > 0 && touches_copy_on_write(&roots, mounts) {
        // The number is what the inodes account for, not what `statvfs` will
        // gain back. On btrfs those differ, and a maintenance tool that silently
        // equates them is how "freed 40 GB" gets into a bug report about a full
        // disk.
        notes.push(
            "sizes are the sum of st_blocks; on a copy-on-write filesystem, extents shared \
             with a snapshot or a reflink may free less than that"
                .to_string(),
        );
    }

    let refusals = summarise_refusals(&plan);
    // Two routes reach the same outcome: a walk blocks an ignored entry before it
    // is ever a candidate, and a kind whose candidates come from somewhere else
    // (a blob store, a package cache) has the plan refuse it. The user cares
    // about one number, so both are summed here.
    let ignored = runs.iter().map(|run| run.ignored).sum::<usize>()
        + refusals
            .iter()
            .filter(|refusal| refusal.code == "ignored")
            .map(|refusal| refusal.count)
            .sum::<usize>();
    if ignored > 0 {
        // The user wrote a line to protect something. Confirming it took effect
        // is the difference between "my ignore file works" and "did I put it in
        // the right place", and only the tool knows which paths it skipped.
        notes.push(format!(
            "{ignored} {} left alone by your ignore file (~/.config/sweep/ignore)",
            if ignored == 1 {
                "path was"
            } else {
                "paths were"
            }
        ));
    }
    Built {
        report: PipelineReport {
            command,
            mode: if mode.is_dry_run() {
                "dry-run"
            } else {
                "apply"
            },
            plan_hash: plan.hash().to_string(),
            sections,
            rules: runs,
            refusals,
            funnel: FunnelReport::default(),
            elevation: None,
            log: None,
            totals,
            notes,
        },
        plan,
    }
}

fn touches_copy_on_write(roots: &[PathBuf], mounts: &MountTable) -> bool {
    roots.iter().any(|root| {
        mounts
            .find(root)
            .map(|mount| mount.fstype.is_cow())
            .unwrap_or(false)
    })
}

/// Why a rule contributed nothing before it was scanned.
fn skip_reason(rule: &Rule, xdg: &Xdg, sections: &[Section]) -> Option<Status> {
    if !rule.enabled {
        return Some(Status::DeclaredDisabled);
    }
    // A section another command owns is not missing and not empty; it is out of
    // this command's scope. Saying so is what makes `sweep clean` explain
    // `purge` rather than silently under-report.
    if rule.section.command().is_some() && !sections.contains(&rule.section) {
        return Some(Status::CommandScoped);
    }
    // Model weights are the one target that may not be re-downloadable, so the
    // section is skipped unless the user named it. The rules stay enabled: the
    // section name *is* the consent, and there is no second switch to keep in
    // sync with it.
    if rule.section.is_opt_in() && !sections.contains(&rule.section) {
        return Some(Status::OptIn);
    }
    if rule.missing_requirement(xdg).is_some() {
        return Some(Status::MissingRequirement);
    }
    None
}

fn skip_detail(command: &str, rule: &Rule, xdg: &Xdg, status: Status) -> Option<String> {
    match status {
        Status::MissingRequirement => rule
            .missing_requirement(xdg)
            .map(|requirement| format!("requires {}", requirement.label())),
        Status::OptIn => Some(format!(
            "run `sweep {command} --only {}` to review it",
            rule.section.as_str()
        )),
        Status::CommandScoped => Some(format!(
            "this section belongs to `sweep {}`",
            rule.section.command().unwrap_or("clean")
        )),
        _ => None,
    }
}

/// Names the one unreadable case a user can act on.
///
/// A root cache with 0700 permissions exists but is invisible to the user
/// process, and planning happens before any password is typed. The alternative
/// would be to let the child choose the items for the plan the user confirms;
/// until that lands, the honest answer is one line saying what could not be
/// looked at.
fn unreadable_detail(rule: &Rule) -> Option<String> {
    if rule.privilege != Privilege::Root {
        return None;
    }
    Some(
        "not readable as your user (root-only directory), so it was not planned; \
         a cache you cannot see is not a plan you can confirm"
            .to_string(),
    )
}

fn base_run(rule: &Rule, status: Status, detail: Option<String>) -> RuleRun {
    RuleRun {
        id: rule.id.to_string(),
        section: rule.section.as_str(),
        kind: rule.kind.as_str(),
        status,
        items: 0,
        refused: 0,
        bytes: 0,
        scanned_bytes: 0,
        ignored: 0,
        preserved: Vec::new(),
        detail,
    }
}

/// Combines the per-directory runs of one glob root into the single row the
/// report prints.
///
/// A rule that matched three version directories is still one rule, so the
/// counters add up and the status is the strongest answer any directory gave. A
/// directory whose scan did not complete never turns the whole rule into a
/// clean "planned": the detail says how many were skipped, and nothing from
/// those directories is in the plan.
fn merge_roots(rule: &Rule, runs: Vec<RuleRun>) -> RuleRun {
    let total = runs.len();
    let mut merged = base_run(rule, Status::Planned, None);
    let first_status = runs
        .first()
        .map(|run| run.status)
        .unwrap_or(Status::Planned);
    let mut planned = 0;
    let mut report_only = 0;
    let mut incomplete = 0;
    let mut unreadable = 0;
    let mut empty = 0;

    for run in runs {
        merged.items += run.items;
        merged.refused += run.refused;
        merged.bytes = merged.bytes.saturating_add(run.bytes);
        merged.scanned_bytes = merged.scanned_bytes.saturating_add(run.scanned_bytes);
        merged.ignored += run.ignored;
        merged.preserved.extend(run.preserved);
        match run.status {
            Status::Planned => planned += 1,
            Status::ReportOnly => report_only += 1,
            Status::ScanIncomplete => incomplete += 1,
            Status::Unreadable => unreadable += 1,
            Status::Empty => empty += 1,
            _ => {}
        }
        if merged.detail.is_none() {
            merged.detail = run.detail;
        }
    }

    merged.status = if planned > 0 {
        Status::Planned
    } else if report_only > 0 {
        Status::ReportOnly
    } else if incomplete > 0 {
        Status::ScanIncomplete
    } else if unreadable > 0 {
        Status::Unreadable
    } else if empty > 0 {
        Status::Empty
    } else {
        first_status
    };
    if incomplete > 0 {
        merged.detail = Some(format!(
            "{incomplete} of {total} matched directories could not be scanned completely; \
             nothing from those directories is planned"
        ));
    }
    merged
}

#[allow(clippy::too_many_arguments)]
fn execute(
    rule: &Rule,
    root: &Path,
    probe: &RealProbe,
    ctx: &ValidateCtx<'_>,
    limits: &Limits,
    plan: &mut Plan,
    all_roots: &[PathBuf],
    now: i64,
) -> RuleRun {
    if rule.kind == Kind::HfCache {
        return execute_hf(rule, root, probe, ctx, limits, plan, now);
    }
    if rule.kind == Kind::PkgCache {
        return execute_pkg(rule, root, probe, ctx, limits, plan, now);
    }
    if rule.kind == Kind::Versions {
        return execute_versions(rule, root, probe, ctx, limits, plan, now);
    }
    if rule.kind == Kind::ProjectArtifacts {
        return execute_project(rule, root, probe, ctx, limits, plan, now);
    }
    if rule.kind == Kind::TrashEmpty {
        return execute_trash(rule, root, probe, ctx, limits, plan);
    }

    // Roots the catalog has an opinion about: the residual cache sweep must not
    // take a target that has a retention policy of its own.
    let claimed: Vec<PathBuf> = all_roots
        .iter()
        .filter(|other| other.as_path() != root && is_within(root, other))
        .cloned()
        .collect();

    let mut spec = Spec::new(rule.max_depth, limits);
    spec.exclude = &rule.exclude;
    spec.skip_roots = &claimed;
    spec.ignore = plan.ignore();
    if rule.kind == Kind::FilePattern {
        spec.select = Select::Files(&rule.patterns);
    }

    let collected = scan::collect(root, root, 0, &spec, probe);

    let mut run = base_run(rule, Status::Planned, None);
    run.scanned_bytes = collected.bytes;
    run.ignored = collected.stats.ignored;

    if collected.missing_root {
        run.status = Status::NotPresent;
        return run;
    }
    if collected.not_a_directory {
        run.status = Status::NotADirectory;
        return run;
    }
    if collected.root_unreadable {
        run.status = Status::Unreadable;
        run.detail = unreadable_detail(rule);
        return run;
    }
    if collected.stop != Stop::Complete {
        // Same rule as the scan contracts in the safety kernel: a budget that ran
        // out means "unknown", and unknown never deletes.
        run.status = Status::ScanIncomplete;
        run.detail = Some(match collected.stop {
            Stop::EntryBudget => "entry budget exhausted".to_string(),
            Stop::TimeBudget => "time budget exhausted".to_string(),
            Stop::Complete => unreachable!("checked above"),
        });
        return run;
    }

    if rule.kind == Kind::ReportOnly {
        run.status = Status::ReportOnly;
        // The numbers stay in `detail` rather than `run.items`/`run.bytes`:
        // those columns count what the plan will remove, and a reported entry is
        // never planned. Putting them in the table would make the section totals
        // promise a reclaim that `--dry-run` then refuses to perform.
        run.detail = Some(format!(
            "{} entries, {} measured, never deleted",
            collected.entries.len(),
            human_bytes(collected.bytes)
        ));
        return run;
    }

    let mut candidates: Vec<&Path> = match rule.kind {
        Kind::ReportOnly => unreachable!("handled above"),
        Kind::FilePattern => {
            // The catalog declares a real retention for these rules (`.crate`
            // after 30 days, rotated logs after 7), so it is applied here rather
            // than printed and ignored: a fresh match stays.
            let cutoff = rule.cutoff(now);
            collected
                .entries
                .iter()
                .filter(|entry| !entry.is_dir && entry.mtime < cutoff)
                .map(|entry| entry.path.as_path())
                .collect()
        }
        Kind::DirSweep => sweep_candidates(&collected, root),
        Kind::ToolCache => {
            let mut paths = sweep_candidates(&collected, root);
            // The root itself is scheduled only when the walk left nothing behind
            // that sweep chose not to touch; otherwise it cannot be removed.
            if collected.blocked.is_empty() {
                paths.push(root);
            }
            paths
        }
        Kind::DirAge => age_candidates(rule, &collected, root, now, &mut run),
        Kind::HfCache
        | Kind::PkgCache
        | Kind::Versions
        | Kind::ProjectArtifacts
        | Kind::TrashEmpty => {
            unreachable!("handled before the walk")
        }
    };
    // Children first is the plan's job (`Plan::finish` sorts deepest-first); the
    // walk already emits post-order, so this stays readable even before sorting.
    candidates.sort();

    plan_candidates(plan, ctx, rule, &mut run, candidates);

    if run.items == 0 && run.refused == 0 {
        run.status = Status::Empty;
        if run.detail.is_none() {
            run.detail = blocked_detail(&collected);
        }
    }
    run
}

/// Build artifacts inside project directories.
///
/// The discovery is [`sweep_core::project`]: a manifest names the project, the
/// manifest that produces a directory names the artifact. This function is the
/// second half - for each artifact it walks the tree completely, refuses the
/// whole artifact if the walk saw anything it could not take, and plans every
/// entry plus the artifact directory itself.
///
/// Two decisions are worth stating:
///
/// * **All or nothing per artifact.** `node_modules` with one unreadable
///   directory would be left as a half-installed tree, which is worse than
///   either state. A partial walk therefore plans nothing and the artifact is
///   counted, with its reason, in the detail line.
/// * **Links are included.** `node_modules/.bin` and a virtualenv's
///   `bin/python3` are links the package manager wrote. Leaving them behind is
///   what makes a "purged" directory still look installed. The plan records each
///   one as a link, and the sink unlinks the link, never its target.
fn execute_project(
    rule: &Rule,
    root: &Path,
    probe: &RealProbe,
    ctx: &ValidateCtx<'_>,
    limits: &Limits,
    plan: &mut Plan,
    now: i64,
) -> RuleRun {
    let found = project::discover(root, rule.max_depth, rule.keep_days, now, limits, probe);
    let mut run = base_run(rule, Status::Planned, None);
    run.scanned_bytes = found.bytes_visited;

    if found.missing_root {
        run.status = Status::NotPresent;
        return run;
    }
    if found.root_is_symlink {
        run.status = Status::SymlinkedRoot;
        run.detail = Some(
            "a symlinked project root is not followed; point the rule at the real directory".into(),
        );
        return run;
    }
    if found.not_a_directory {
        run.status = Status::NotADirectory;
        return run;
    }
    if found.root_unreadable {
        run.status = Status::Unreadable;
        run.detail = unreadable_detail(rule);
        return run;
    }
    if found.stop != Stop::Complete {
        run.status = Status::ScanIncomplete;
        run.detail = Some(match found.stop {
            Stop::EntryBudget => "entry budget exhausted".to_string(),
            Stop::TimeBudget => "time budget exhausted".to_string(),
            Stop::Complete => unreachable!("checked above"),
        });
        return run;
    }

    // Artifacts the discovery already left alone are in `found.skipped`; this
    // counts only the ones that passed discovery and then could not be
    // enumerated completely.
    let mut walk_skipped = 0usize;
    let mut ignored_artifacts = 0usize;
    for artifact in &found.artifacts {
        let mut spec = Spec::new(usize::MAX, limits);
        spec.include_links = true;
        spec.ignore = plan.ignore();
        let collected = scan::collect(&artifact.path, &artifact.path, 0, &spec, probe);
        if collected
            .blocked
            .iter()
            .any(|block| block.kind == BlockKind::Ignored)
        {
            // The user protected something inside this artifact. Removing the
            // rest would leave a tree that looks installed but is not, so the
            // whole artifact stays and the reason is reported by name.
            ignored_artifacts += 1;
            continue;
        }
        if collected.stop != Stop::Complete
            || collected.root_unreadable
            || !collected.blocked.is_empty()
        {
            // Unknown is not empty. A tree whose contents could not be
            // enumerated would be left half-removed, so it is left whole.
            walk_skipped += 1;
            continue;
        }
        let mut candidates: Vec<&Path> = collected
            .entries
            .iter()
            .map(|entry| entry.path.as_path())
            .collect();
        candidates.push(&artifact.path);
        plan_candidates(plan, ctx, rule, &mut run, candidates);
    }

    run.ignored = ignored_artifacts;
    run.detail = Some(project_detail(
        &found,
        walk_skipped,
        ignored_artifacts,
        rule,
        root,
    ));

    if run.items == 0 && run.refused == 0 {
        run.status = Status::Empty;
    }
    run
}

/// The one line a user reads about a project sweep.
///
/// It names what was taken, and then - the part that matters when the answer is
/// "why is this still here" - how many artifact-shaped directories were left
/// alone and why, most frequent reason first.
fn project_detail(
    found: &project::Discovery,
    walk_skipped: usize,
    ignored_artifacts: usize,
    rule: &Rule,
    root: &Path,
) -> String {
    let mut names: Vec<String> = found
        .artifacts
        .iter()
        .map(|artifact| {
            artifact
                .path
                .strip_prefix(root)
                .unwrap_or(&artifact.path)
                .display()
                .to_string()
        })
        .collect();
    let planned = names.len();
    names.truncate(3);
    let mut detail = format!(
        "{} projects, {planned} build directories older than {}d",
        found.projects.len(),
        rule.keep_days
    );
    if !names.is_empty() {
        let more = planned - names.len();
        detail.push_str(": ");
        detail.push_str(&names.join(", "));
        if more > 0 {
            detail.push_str(&format!(" and {more} more"));
        }
    }

    // Counts, not names: a machine with forty `node_modules` directories does not
    // need forty lines, it needs to know that forty were left alone and why.
    let mut reasons: Vec<(&str, usize)> = Vec::new();
    let mut record = |reason: &'static str, count: usize| {
        if count == 0 {
            return;
        }
        match reasons.iter_mut().find(|(existing, _)| *existing == reason) {
            Some((_, total)) => *total += count,
            None => reasons.push((reason, count)),
        }
    };
    for entry in &found.skipped {
        record(entry.reason, 1);
    }
    record(
        "part of the tree could not be read, so the whole artifact was left",
        walk_skipped,
    );
    record(
        "a path your ignore file protects is inside it, so the whole artifact was left",
        ignored_artifacts,
    );
    if reasons.is_empty() {
        return detail;
    }
    reasons.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(right.0)));
    let total: usize = reasons.iter().map(|(_, count)| count).sum();
    let mut lines: Vec<String> = reasons
        .iter()
        .take(3)
        .map(|(reason, count)| format!("{reason} ({count})"))
        .collect();
    let shown: usize = reasons.iter().take(3).map(|(_, count)| count).sum();
    if total > shown {
        lines.push(format!("and {} more", total - shown));
    }
    detail.push_str(&format!("; {total} left alone: {}", lines.join(", ")));
    detail
}

/// The Hugging Face hub: the one kind whose candidates come from its own reader.
///
/// The generic walker refuses to follow symlinks, and every file in a hub
/// snapshot *is* a symlink into `blobs/`. Walking it normally would either
/// delete the blobs and leave the snapshots dangling, or plan nothing. So the
/// scan moves to [`sweep_core::model_cache`], and this function only maps its
/// verdicts onto the same statuses and the same plan funnel as every other rule.
fn execute_hf(
    rule: &Rule,
    root: &Path,
    probe: &RealProbe,
    ctx: &ValidateCtx<'_>,
    limits: &Limits,
    plan: &mut Plan,
    now: i64,
) -> RuleRun {
    let found = model_cache::scan(root, rule.keep_days, now, limits, probe);
    let mut run = base_run(rule, Status::Planned, None);
    run.scanned_bytes = found.bytes_visited;

    if found.missing_root {
        run.status = Status::NotPresent;
        return run;
    }
    if found.root_is_symlink {
        run.status = Status::SymlinkedRoot;
        run.detail =
            Some("a symlinked hub is not followed; point the rule at the real path".into());
        return run;
    }
    if found.not_a_directory {
        run.status = Status::NotADirectory;
        return run;
    }
    if found.root_unreadable {
        run.status = Status::Unreadable;
        run.detail = unreadable_detail(rule);
        return run;
    }
    if found.stop != Stop::Complete {
        run.status = Status::ScanIncomplete;
        run.detail = Some(match found.stop {
            Stop::EntryBudget => "entry budget exhausted".to_string(),
            Stop::TimeBudget => "time budget exhausted".to_string(),
            Stop::Complete => unreachable!("checked above"),
        });
        return run;
    }

    let orphans = found.candidates_of(Leftover::UnreferencedBlob);
    let incomplete = found.candidates_of(Leftover::Incomplete);
    let mut detail = format!(
        "{} repositories, {} blobs still linked, {orphans} orphaned blobs, {incomplete} \
         abandoned downloads",
        found.repos, found.referenced
    );
    if !found.preserved.is_empty() {
        let mut names = found.preserved.iter().take(3).cloned().collect::<Vec<_>>();
        if found.preserved.len() > names.len() {
            names.push(format!("and {} more", found.preserved.len() - names.len()));
        }
        detail.push_str(&format!(
            "; {} repositories preserved because their snapshots could not be read: {}",
            found.preserved.len(),
            names.join(", ")
        ));
        // Preserved-whole is a refusal to act, so it belongs in the summary a
        // user reads without `--verbose`, not only in the per-rule detail.
        run.preserved = found.preserved.clone();
    }
    run.detail = Some(detail);

    let candidates: Vec<PathBuf> = found
        .candidates
        .into_iter()
        .map(|candidate| candidate.path)
        .collect();
    plan_candidates(plan, ctx, rule, &mut run, candidates);

    if run.items == 0 && run.refused == 0 {
        run.status = Status::Empty;
    }
    run
}

/// The package cache: retention is a version count, not an age.
///
/// `paccache`'s rule is "keep the newest N versions of each package", and that
/// is the only retention that survives a machine which has not been upgraded in
/// months: an age cutoff would delete the running kernel's package on exactly
/// the system where a rollback matters. The ordering is pacman's own `vercmp`,
/// ported in [`sweep_core::version`], so `1.10` outranks `1.9` and `1.0` outranks
/// `1.0rc1`.
///
/// Selective deletion inside this root is why the child re-derives the selection
/// (`sweep_core::selection`): the elevated process must reach the same verdict
/// per path, not trust the list the parent sent.
fn execute_trash(
    rule: &Rule,
    root: &Path,
    probe: &RealProbe,
    ctx: &ValidateCtx<'_>,
    limits: &Limits,
    plan: &mut Plan,
) -> RuleRun {
    let found = trash::scan(root, limits, probe, plan.ignore());
    let mut run = base_run(rule, Status::Planned, None);

    if found.missing_root {
        run.status = Status::NotPresent;
        return run;
    }
    if found.not_a_directory {
        run.status = Status::NotADirectory;
        run.detail = Some(
            "the trash does not hold both files/ and info/, so no entry can be removed as a pair"
                .to_string(),
        );
        return run;
    }
    if found.root_unreadable {
        run.status = Status::Unreadable;
        return run;
    }
    if found.stop != Stop::Complete {
        run.status = Status::ScanIncomplete;
        run.detail = Some(match found.stop {
            Stop::EntryBudget => "entry budget exhausted".to_string(),
            Stop::TimeBudget => "time budget exhausted".to_string(),
            Stop::Complete => unreachable!("checked above"),
        });
        return run;
    }

    run.scanned_bytes = found.entries.iter().map(|entry| entry.bytes).sum();
    for entry in &found.entries {
        // The payload goes in first so its record is planned against a path the
        // plan already knows. The funnel still decides at apply time: a record
        // whose payload survived is refused, not removed.
        for path in &entry.paths {
            match plan.push(path, &rule.id, ctx) {
                Ok(_) => run.items += 1,
                Err(_) => run.refused += 1,
            }
        }
        plan.pair(&entry.record, &entry.payload);
        match plan.push(&entry.record, &rule.id, ctx) {
            Ok(_) => run.items += 1,
            Err(_) => run.refused += 1,
        }
    }

    if found.skipped > 0 {
        run.detail = Some(format!(
            "{} entries left alone: a payload without a restore record, a tree that could not be \
             read completely, or a path your ignore file protects",
            found.skipped
        ));
    }

    run.bytes = plan
        .items()
        .iter()
        .filter(|item| item.rule() == &rule.id)
        .map(|item| item.bytes())
        .sum();
    if run.items == 0 && run.refused == 0 {
        run.status = Status::Empty;
    }
    run
}

fn execute_pkg(
    rule: &Rule,
    root: &Path,
    probe: &RealProbe,
    ctx: &ValidateCtx<'_>,
    limits: &Limits,
    plan: &mut Plan,
    now: i64,
) -> RuleRun {
    // The compiler requires `keep_versions` for this kind. Keeping everything is
    // the safe reading if it were ever absent, so an impossible state cannot
    // turn into a plan.
    let keep_versions = rule.keep_versions.unwrap_or(u32::MAX);
    let found = pkg_cache::scan(root, keep_versions, rule.keep_days, now, limits, probe);
    let mut run = base_run(rule, Status::Planned, None);
    run.scanned_bytes = found.bytes_visited;

    if found.missing_root {
        run.status = Status::NotPresent;
        return run;
    }
    if found.root_is_symlink {
        run.status = Status::SymlinkedRoot;
        run.detail = Some(
            "a symlinked package cache is not followed; point the rule at the real path".into(),
        );
        return run;
    }
    if found.not_a_directory {
        run.status = Status::NotADirectory;
        return run;
    }
    if found.root_unreadable {
        run.status = Status::Unreadable;
        run.detail = unreadable_detail(rule);
        return run;
    }
    if found.stop != Stop::Complete {
        run.status = Status::ScanIncomplete;
        run.detail = Some(match found.stop {
            Stop::EntryBudget => "entry budget exhausted".to_string(),
            Stop::TimeBudget => "time budget exhausted".to_string(),
            Stop::Complete => unreachable!("checked above"),
        });
        return run;
    }

    let archives = found
        .candidates
        .iter()
        .filter(|candidate| candidate.kind == pkg_cache::Kind::Archive)
        .count();
    let signatures = found.candidates.len() - archives;
    run.detail = Some(format!(
        "{} packages, {} versions within the keep count of {keep_versions}, \
         {archives} old packages and {signatures} orphaned signatures to remove",
        found.packages, found.kept
    ));
    if found.unrecognised > 0 {
        if let Some(detail) = run.detail.as_mut() {
            detail.push_str(&format!(
                "; {} files that are not packages left alone",
                found.unrecognised
            ));
        }
    }

    let candidates: Vec<PathBuf> = found
        .candidates
        .into_iter()
        .map(|candidate| candidate.path)
        .collect();
    plan_candidates(plan, ctx, rule, &mut run, candidates);

    if run.items == 0 && run.refused == 0 {
        run.status = Status::Empty;
    }
    run
}

/// A directory that holds one entry per installed version of a tool.
///
/// The ranking is [`sweep_core::versions`]: the newest `keep_versions` entries
/// stay, and so does the entry the launcher resolves to. Two properties make the
/// result deletable rather than merely smaller:
///
/// * **The launcher is read first.** If it is missing, not a link, dangling or
///   pointing outside the root, the live entry is unknown and nothing is
///   planned. "Keep the newest" is a guess; the link is the statement.
/// * **A directory entry is taken whole.** The funnel never recurses, so an
///   entry that is a tree is walked completely and planned entry by entry. A
///   walk that could not finish, or that holds a path the ignore file protects,
///   leaves the whole entry in place: half a version is not a version.
fn execute_versions(
    rule: &Rule,
    root: &Path,
    probe: &RealProbe,
    ctx: &ValidateCtx<'_>,
    limits: &Limits,
    plan: &mut Plan,
    now: i64,
) -> RuleRun {
    let keep_versions = rule.keep_versions.unwrap_or(1);
    let Some(keep_link) = rule.keep_link.as_ref().map(|link| link.expand(ctx.xdg)) else {
        // The compiler requires `keep_link` for this kind, so this is the
        // defensive reading of an impossible state: keep everything.
        let mut run = base_run(rule, Status::KeepLinkUnknown, None);
        run.detail = Some("the rule has no keep_link, so the live version is unknown".into());
        return run;
    };

    let found = versions::scan(
        root,
        keep_versions,
        &keep_link,
        rule.keep_days,
        now,
        limits,
        probe,
    );
    let mut run = base_run(rule, Status::Planned, None);
    run.scanned_bytes = found.bytes_visited;

    if found.missing_root {
        run.status = Status::NotPresent;
        return run;
    }
    if found.root_is_symlink {
        run.status = Status::SymlinkedRoot;
        run.detail = Some(
            "a symlinked version directory is not followed; point the rule at the real path".into(),
        );
        return run;
    }
    if found.not_a_directory {
        run.status = Status::NotADirectory;
        return run;
    }
    if found.root_unreadable {
        run.status = Status::Unreadable;
        run.detail = unreadable_detail(rule);
        return run;
    }
    if found.stop != Stop::Complete {
        run.status = Status::ScanIncomplete;
        run.detail = Some(match found.stop {
            Stop::EntryBudget => "entry budget exhausted".to_string(),
            Stop::TimeBudget => "time budget exhausted".to_string(),
            Stop::Complete => unreachable!("checked above"),
        });
        return run;
    }
    if let Some(problem) = found.keep_link_problem {
        run.status = Status::KeepLinkUnknown;
        run.detail = Some(problem.message().to_string());
        return run;
    }

    let mut walk_skipped = 0usize;
    let mut ignored_entries = 0usize;
    // A release tree is removed whole, and its installer writes links inside it:
    // the standalone `codex` release is a directory holding `codex` as a link to
    // the real binary. Refusing that link would leave the directory non-empty at
    // the sink, so the user would get "directory not empty" for a removal the
    // plan promised. The flag is per rule, not per run: only this walk emits a
    // link, and the sink unlinks the link without ever following it.
    let tree_ctx = ValidateCtx {
        xdg: ctx.xdg,
        probe: ctx.probe,
        allowed: ctx.allowed,
        policy: Policy {
            allow_leaf_symlink: true,
            ..ctx.policy
        },
    };
    for candidate in &found.candidates {
        if !candidate.is_dir {
            plan_candidates(
                plan,
                &tree_ctx,
                rule,
                &mut run,
                std::iter::once(candidate.path.as_path()),
            );
            continue;
        }

        let mut spec = Spec::new(usize::MAX, limits);
        spec.include_links = true;
        spec.ignore = plan.ignore();
        let collected = scan::collect(&candidate.path, &candidate.path, 0, &spec, probe);
        run.scanned_bytes = run.scanned_bytes.saturating_add(collected.bytes);
        if collected
            .blocked
            .iter()
            .any(|block| block.kind == BlockKind::Ignored)
        {
            // The user protected something inside this version. Removing the
            // rest would leave a tree that looks installed but is not.
            ignored_entries += 1;
            continue;
        }
        if collected.stop != Stop::Complete
            || collected.root_unreadable
            || !collected.blocked.is_empty()
        {
            // Unknown is not empty: a half-removed version is worse than a whole
            // one, because the launcher may still be pointed at it.
            walk_skipped += 1;
            continue;
        }
        let mut paths: Vec<&Path> = collected
            .entries
            .iter()
            .map(|entry| entry.path.as_path())
            .collect();
        paths.push(candidate.path.as_path());
        plan_candidates(plan, &tree_ctx, rule, &mut run, paths);
    }

    run.ignored = ignored_entries;
    run.detail = Some(versions_detail(
        &found,
        keep_versions,
        walk_skipped,
        ignored_entries,
    ));

    if run.items == 0 && run.refused == 0 {
        run.status = Status::Empty;
    }
    run
}

/// The one line a user reads about a version sweep.
fn versions_detail(
    found: &versions::Scan,
    keep_versions: u32,
    walk_skipped: usize,
    ignored_entries: usize,
) -> String {
    let mut detail = format!(
        "{} entries, keeping the newest {keep_versions} and the launcher target, {} to remove",
        found.entries,
        found
            .candidates
            .len()
            .saturating_sub(walk_skipped + ignored_entries)
    );
    if found.kept > 0 {
        detail.push_str(&format!("; {} kept", found.kept));
    }
    if found.unrecognised > 0 {
        detail.push_str(&format!(
            "; {} entries left alone because they are not versions or could not be read",
            found.unrecognised
        ));
    }
    if walk_skipped > 0 {
        detail.push_str(&format!(
            "; {walk_skipped} versions left whole because their contents could not be \
             enumerated completely"
        ));
    }
    if ignored_entries > 0 {
        detail.push_str(&format!(
            "; {ignored_entries} versions left whole because a path your ignore file \
             protects is inside them"
        ));
    }
    detail
}

/// Pushes validated candidates into the plan and keeps the per-rule tally.
fn plan_candidates<I, P>(
    plan: &mut Plan,
    ctx: &ValidateCtx<'_>,
    rule: &Rule,
    run: &mut RuleRun,
    candidates: I,
) where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    // `Plan::items` is the whole plan, and a glob root runs this function once
    // per matched directory. Summing every item with this rule id would count
    // the earlier directories again on each call, so only the tail added here
    // belongs to this run. The tail is added, not assigned: a rule that plans
    // several artifacts or several version entries calls this once per entry,
    // and the run's total is the sum of all of them.
    let before = plan.items().len();
    for path in candidates {
        match plan.push(path.as_ref(), &rule.id, ctx) {
            Ok(_) => run.items += 1,
            Err(_) => run.refused += 1,
        }
    }

    run.bytes = run.bytes.saturating_add(
        plan.items()[before..]
            .iter()
            .filter(|item| item.rule() == &rule.id)
            .map(|item| item.bytes())
            .sum::<u64>(),
    );
}

/// Everything the walk enumerated, minus a directory that cannot be emptied.
fn sweep_candidates<'a>(collected: &'a Collect, root: &'a Path) -> Vec<&'a Path> {
    collected
        .entries
        .iter()
        .filter(|entry| {
            if !entry.is_dir {
                return true;
            }
            let relative = entry.path.strip_prefix(root).unwrap_or(&entry.path);
            // A directory that still holds an excluded, unreadable, symlinked or
            // claimed entry cannot be removed in one `unlinkat`; planning it would
            // only add a `directory_not_empty` refusal to the report.
            collected.blocked_within(relative).is_none()
        })
        .map(|entry| entry.path.as_path())
        .collect()
}

/// One entry per top-level subtree with the newest mtime in it.
struct Group<'a> {
    newest: i64,
    entries: Vec<&'a Entry>,
}

/// Top-level subtrees whose every entry is older than the cutoff.
fn age_candidates<'a>(
    rule: &Rule,
    collected: &'a Collect,
    root: &'a Path,
    now: i64,
    run: &mut RuleRun,
) -> Vec<&'a Path> {
    let cutoff = rule.cutoff(now);

    let mut groups: BTreeMap<PathBuf, Group<'a>> = BTreeMap::new();
    for entry in &collected.entries {
        let relative = entry.path.strip_prefix(root).unwrap_or(&entry.path);
        let Some(top) = first_component(relative) else {
            continue;
        };
        let group = groups.entry(top).or_insert_with(|| Group {
            newest: i64::MIN,
            entries: Vec::new(),
        });
        group.newest = group.newest.max(entry.mtime);
        group.entries.push(entry);
    }

    let mut candidates = Vec::new();
    let mut recent = 0usize;
    let mut blocked = 0usize;
    let mut blocker = None;
    for (top, group) in &groups {
        // A subtree that contains something we deliberately did not include is
        // not "entirely old": the newest part of it is unknown, and unknown
        // keeps it.
        if let Some(block) = collected.blocked_under(top).first() {
            blocked += 1;
            blocker.get_or_insert(format!(
                "{} holds an entry left alone: {}",
                top.display(),
                block.kind.code()
            ));
            continue;
        }
        if group.newest >= cutoff {
            recent += 1;
            continue;
        }
        candidates.extend(group.entries.iter().map(|entry| entry.path.as_path()));
    }

    if candidates.is_empty() {
        run.status = Status::Empty;
        run.detail = Some(match blocker {
            Some(blocker) => format!(
                "{blocker}; {blocked} subtrees blocked, {recent} newer than {} days",
                rule.keep_days
            ),
            None => format!(
                "{} subtrees, all newer than {} days",
                groups.len(),
                rule.keep_days
            ),
        });
    }
    candidates
}

fn blocked_detail(collected: &Collect) -> Option<String> {
    if collected.blocked.is_empty() {
        return None;
    }
    let mut counts: BTreeMap<BlockKind, usize> = BTreeMap::new();
    for block in &collected.blocked {
        *counts.entry(block.kind).or_insert(0) += 1;
    }
    let parts: Vec<String> = counts
        .into_iter()
        .map(|(kind, count)| format!("{count} {}", kind.code()))
        .collect();
    Some(format!("left alone: {}", parts.join(", ")))
}

fn summarise_refusals(plan: &Plan) -> Vec<Refusal> {
    let mut counts: BTreeMap<(String, &'static str), usize> = BTreeMap::new();
    for denied in plan.denied() {
        *counts
            .entry((denied.rule.to_string(), denied.reason.code()))
            .or_insert(0) += 1;
    }
    let mut refusals: Vec<Refusal> = counts
        .into_iter()
        .map(|((rule, code), count)| Refusal { rule, code, count })
        .collect();
    refusals.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.rule.cmp(&right.rule))
            .then_with(|| left.code.cmp(right.code))
    });
    refusals
}

fn summarise_sections(runs: &[RuleRun]) -> Vec<SectionRun> {
    Section::ALL
        .into_iter()
        .filter_map(|section| {
            let rules: Vec<&RuleRun> = runs
                .iter()
                .filter(|run| run.section == section.as_str())
                .collect();
            if rules.is_empty() {
                return None;
            }
            Some(SectionRun {
                section: section.as_str(),
                rules: rules.len(),
                items: rules.iter().map(|run| run.items).sum(),
                refused: rules.iter().map(|run| run.refused).sum(),
                bytes: rules.iter().map(|run| run.bytes).sum(),
            })
        })
        .collect()
}

fn render(report: &PipelineReport, verbose: u8) -> String {
    let mut out = String::new();
    if report.mode == "dry-run" {
        out.push_str(&format!(
            "sweep {} — dry run, nothing is deleted\n\n",
            report.command
        ));
    } else {
        out.push_str(&format!(
            "sweep {} — applying the plan, removals are permanent\n\n",
            report.command
        ));
    }

    out.push_str(&format!(
        "  {:<18} {:>5} {:>7} {:>9} {:>10}\n",
        "section", "rules", "items", "refused", "size"
    ));
    for section in &report.sections {
        out.push_str(&format!(
            "  {:<18} {:>5} {:>7} {:>9} {:>10}\n",
            section.section,
            section.rules,
            section.items,
            section.refused,
            human_bytes(section.bytes)
        ));
    }

    out.push_str(&format!(
        "\n  {:<18} {:>5} {:>7} {:>9} {:>10}\n",
        "total",
        report.totals.rules,
        report.totals.items,
        report.totals.refused,
        human_bytes(report.totals.bytes)
    ));
    out.push_str(&format!("  plan hash         {}\n", report.plan_hash));
    let report_only = report
        .rules
        .iter()
        .filter(|run| run.status == Status::ReportOnly)
        .count();
    out.push_str(&format!(
        "  {} of {} rules planned something, {report_only} reported only, {} were skipped\n",
        report.totals.planned, report.totals.rules, report.totals.skipped
    ));

    // The outcome goes above the reference material. A user who typed `clean`
    // wants to know what happened before they want the list of rules whose tools
    // are not installed on this machine.
    if report.mode != "dry-run" && report.totals.items > 0 {
        out.push_str(&format!(
            "\n  Removed {} of {} planned items, {} accounted.\n",
            report.funnel.removed,
            report.totals.items,
            human_bytes(report.funnel.bytes)
        ));
        if report.funnel.failed > 0 {
            out.push_str(&format!(
                "  {} items failed at the syscall and were left in place; the log has the \
                 reason for each.\n",
                report.funnel.failed
            ));
        }
        if let Some(log) = &report.log {
            out.push_str(&format!(
                "  Logged to {} (session {}).\n",
                log.path, log.session
            ));
        }
    }

    if verbose > 0 {
        out.push_str("\n  per rule\n");
        for rule in &report.rules {
            let detail = rule
                .detail
                .as_deref()
                .map(|detail| format!("  ({detail})"))
                .unwrap_or_default();
            out.push_str(&format!(
                "    {:<34} {:<18} {:>6} {:>9}{detail}\n",
                rule.id,
                rule.status.label(),
                rule.items,
                human_bytes(rule.bytes)
            ));
        }
    }

    let skipped: Vec<&RuleRun> = report
        .rules
        .iter()
        .filter(|run| run.status.is_skip())
        .collect();
    if !skipped.is_empty() {
        out.push_str("\n  skipped\n");
        for rule in skipped {
            let detail = rule
                .detail
                .as_deref()
                .map(|detail| format!(" — {detail}"))
                .unwrap_or_default();
            out.push_str(&format!(
                "    {:<34} {}{detail}\n",
                rule.id,
                rule.status.label()
            ));
        }
    }

    if !report.refusals.is_empty() {
        out.push_str("\n  refused by the safety kernel\n");
        for refusal in report.refusals.iter().take(20) {
            out.push_str(&format!(
                "    {:<34} {:<22} {}\n",
                refusal.rule, refusal.code, refusal.count
            ));
        }
        if report.refusals.len() > 20 {
            out.push_str(&format!(
                "    ... {} more rule/reason pairs\n",
                report.refusals.len() - 20
            ));
        }
    }

    if !report.funnel.skip_codes.is_empty() {
        out.push_str("\n  refused at the final sink\n");
        for code in &report.funnel.skip_codes {
            out.push_str(&format!("    {:<26} {}\n", code.code, code.count));
        }
    }

    for note in &report.notes {
        out.push_str(&format!("\n  note: {note}\n"));
    }

    if report.totals.items == 0 {
        out.push_str("\n  Nothing to remove. Run `sweep rules list` to see the catalog.\n");
    } else if report.mode == "dry-run" {
        out.push_str(&format!(
            "\n  Preview only: {} items, {} would be removed permanently.\n  \
             Nothing was deleted. Run `sweep {}` to apply this plan.\n",
            report.funnel.would_remove,
            human_bytes(report.funnel.bytes),
            report.command
        ));
    }
    out
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{File, FileTimes};
    use std::time::{Duration, SystemTime};

    fn xdg_at(home: &Path) -> Xdg {
        Xdg::resolve(|key| match key {
            "HOME" => Some(home.as_os_str().to_os_string()),
            _ => None,
        })
        .expect("home")
    }

    fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let temp = tempfile::tempdir().expect("tempdir");
        for (relative, body) in files {
            let path = temp.path().join(relative);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(&path, body).expect("write");
        }
        temp
    }

    fn age(path: &Path, days: i64) {
        let when = SystemTime::now() - Duration::from_secs((days.max(0) as u64) * 86_400);
        let file = File::open(path).expect("open");
        file.set_times(FileTimes::new().set_modified(when))
            .expect("set mtime");
    }

    fn report_for(temp: &tempfile::TempDir, body: &str, limits: &Limits) -> PipelineReport {
        report_for_only(temp, body, limits, &[])
    }

    fn report_for_only(
        temp: &tempfile::TempDir,
        body: &str,
        limits: &Limits,
        only: &[Section],
    ) -> PipelineReport {
        let xdg = xdg_at(temp.path());
        let set = RuleSet::from_sources(&[sweep_core::rules::Source::new("test.toml", body)], &xdg)
            .expect("rule pack loads");
        let mounts = MountTable::load().expect("mounts");
        let probe = RealProbe::new().expect("probe").with_open_scan();
        let Built { plan, mut report } = build(
            Scope::CLEAN,
            &set,
            &xdg,
            &probe,
            &mounts,
            only,
            limits,
            Mode::DryRun,
            &sweep_core::ignore::Ignore::empty(&xdg.home),
        );
        let preview = funnel::apply(&plan, &probe, Mode::DryRun, "clean", None);
        report.funnel = FunnelReport::of(&preview, Mode::DryRun);
        report
    }

    fn single_rule(id: &str, kind: &str, root: &Path, keep_days: u32) -> String {
        format!(
            r#"
[[rule]]
id = "{id}"
section = "user-essentials"
kind = "{kind}"
root = "{}"
evidence = "test tree"
recoverable = true
keep_days = {keep_days}
privilege = "user"
"#,
            root.display()
        )
    }

    #[test]
    fn a_dir_age_sweep_keeps_a_subtree_with_one_fresh_file() {
        let temp = tree(&[
            ("cache/app/old.bin", "old"),
            ("cache/app/nested/fresh.bin", "fresh"),
        ]);
        // The rule root is the parent: `app` is one top-level entry, and one
        // fresh file anywhere inside it keeps the whole of it.
        let root = temp.path().join("cache");
        age(&root.join("app/old.bin"), 90);
        age(&root.join("app/nested/fresh.bin"), 0);
        age(&root.join("app/nested"), 0);
        age(&root.join("app"), 0);

        let report = report_for(
            &temp,
            &single_rule("test.app", "dir-age", &root, 30),
            &Limits::default(),
        );
        let run = report
            .rules
            .iter()
            .find(|run| run.id == "test.app")
            .unwrap();
        assert_eq!(run.items, 0, "{run:?}");
        assert_eq!(run.status, Status::Empty);
        assert_eq!(report.totals.items, 0);
    }

    #[test]
    fn a_dir_age_sweep_removes_a_subtree_whose_every_entry_is_old() {
        let temp = tree(&[
            ("cache/app/old.bin", "old"),
            ("cache/app/nested/older.bin", "older"),
        ]);
        let root = temp.path().join("cache/app");
        for path in [
            root.join("old.bin"),
            root.join("nested/older.bin"),
            root.join("nested"),
        ] {
            age(&path, 90);
        }
        age(&root, 90);

        let report = report_for(
            &temp,
            &single_rule("test.app", "dir-age", &root, 30),
            &Limits::default(),
        );
        let run = report
            .rules
            .iter()
            .find(|run| run.id == "test.app")
            .unwrap();
        // Two files and the directory that held them.
        assert_eq!(run.items, 3, "{run:?}");
        assert_eq!(report.totals.items, 3);
        assert!(root.exists(), "a dry run must not delete anything");
    }

    #[test]
    fn a_residual_sweep_never_takes_a_claimed_root() {
        let temp = tree(&[
            ("cache/known/blob.bin", "known"),
            ("cache/unknown/blob.bin", "unknown"),
        ]);
        let base = temp.path().join("cache");
        for path in [
            base.join("known/blob.bin"),
            base.join("known"),
            base.join("unknown/blob.bin"),
            base.join("unknown"),
        ] {
            age(&path, 90);
        }
        age(&base, 90);

        let body = format!(
            "{}{}",
            single_rule("test.residual", "dir-age", &base, 7),
            single_rule("test.known", "dir-age", &base.join("known"), 365)
        );
        let report = report_for(&temp, &body, &Limits::default());
        let residual = report
            .rules
            .iter()
            .find(|run| run.id == "test.residual")
            .unwrap();
        // `known` is claimed by a rule with a year-long retention; the residual
        // sweep takes `unknown` only.
        assert_eq!(residual.items, 2, "{residual:?}");
        assert_eq!(report.totals.items, 2);
    }

    #[test]
    fn a_claimed_root_is_skipped_even_when_its_rule_is_not_selected() {
        // The claim is a statement about the path, not about this invocation.
        // It used to be built from the selected rules, so `--only` silently
        // handed the blanket sweep every root outside the selected sections.
        let temp = tree(&[
            ("cache/game/installer/blob.bin", "installer"),
            ("cache/game/token", "token"),
            ("cache/unknown/blob.bin", "unknown"),
        ]);
        let base = temp.path().join("cache");
        for path in [
            base.join("game"),
            base.join("game/token"),
            base.join("game/installer"),
            base.join("game/installer/blob.bin"),
            base.join("unknown"),
            base.join("unknown/blob.bin"),
        ] {
            age(&path, 90);
        }
        age(&base, 90);

        let body = format!(
            "{}{}",
            single_rule("test.residual", "dir-age", &base, 7),
            single_rule("test.game", "dir-sweep", &base.join("game/installer"), 0)
                .replace("section = \"user-essentials\"", "section = \"apps\"")
        );
        let report = report_for_only(&temp, &body, &Limits::default(), &[Section::UserEssentials]);
        let residual = report
            .rules
            .iter()
            .find(|run| run.id == "test.residual")
            .unwrap();
        // `game` holds a claimed child, so the whole of it is kept - including
        // the token beside the claim, which is what the walk cannot judge.
        assert_eq!(residual.items, 2, "{residual:?}");
        assert!(
            report.rules.iter().all(|run| run.id != "test.game"),
            "a section outside --only is not scanned"
        );
    }

    #[test]
    fn a_rule_whose_scan_is_incomplete_plans_nothing() {
        let temp = tree(&[("cache/app/old.bin", "old")]);
        let root = temp.path().join("cache/app");
        age(&root.join("old.bin"), 90);
        age(&root, 90);

        let limits = Limits {
            max_entries: 0,
            time_budget: Duration::from_secs(30),
        };
        let report = report_for(
            &temp,
            &single_rule("test.app", "dir-sweep", &root, 0),
            &limits,
        );
        let run = report
            .rules
            .iter()
            .find(|run| run.id == "test.app")
            .unwrap();
        assert_eq!(run.status, Status::ScanIncomplete, "{run:?}");
        assert_eq!(run.items, 0);
        assert_eq!(report.totals.items, 0);
        assert!(report
            .notes
            .iter()
            .any(|note| note.contains("partial scan")));
    }

    #[test]
    fn a_directory_holding_a_symlink_is_not_planned() {
        let temp = tree(&[("cache/app/old.bin", "old")]);
        let root = temp.path().join("cache/app");
        std::os::unix::fs::symlink("/etc/passwd", root.join("link")).unwrap();

        let report = report_for(
            &temp,
            &single_rule("test.app", "dir-sweep", &root, 0),
            &Limits::default(),
        );
        let run = report
            .rules
            .iter()
            .find(|run| run.id == "test.app")
            .unwrap();
        // The file goes, the directory cannot be emptied because the link stays.
        assert_eq!(run.items, 1, "{run:?}");
        assert!(root.exists());
        assert!(root.join("link").exists());
    }

    #[test]
    fn a_file_pattern_rule_honours_its_retention() {
        let temp = tree(&[
            ("cache/app/old.crate", "old"),
            ("cache/app/fresh.crate", "fresh"),
        ]);
        let root = temp.path().join("cache/app");
        age(&root.join("old.crate"), 90);
        age(&root.join("fresh.crate"), 0);

        let body = format!(
            r#"
[[rule]]
id = "test.crates"
section = "dev-tools"
kind = "file-pattern"
root = "{}"
pattern = "*.crate"
evidence = "the registry re-downloads what it needs"
recoverable = true
keep_days = 30
privilege = "user"
"#,
            root.display()
        );
        let report = report_for(&temp, &body, &Limits::default());
        let run = report
            .rules
            .iter()
            .find(|run| run.id == "test.crates")
            .unwrap();
        assert_eq!(run.items, 1, "only the stale match is planned: {run:?}");
        assert_eq!(report.totals.items, 1);
    }

    #[test]
    fn a_rule_whose_tool_is_missing_is_skipped_with_the_requirement() {
        let temp = tree(&[("cache/x/blob.bin", "x")]);
        let root = temp.path().join("cache/x");
        let body = format!(
            "{}\nrequires = [\"bin:definitely-not-installed-sweep-test\"]\n",
            single_rule("test.x", "dir-sweep", &root, 0)
        );
        // `requires` must appear before the end of the table; the helper already
        // closed the table, so build the rule by hand instead.
        let body = body.replace(
            "privilege = \"user\"\n\nrequires",
            "privilege = \"user\"\nrequires",
        );
        let report = report_for(&temp, &body, &Limits::default());
        let run = report.rules.iter().find(|run| run.id == "test.x").unwrap();
        assert_eq!(run.status, Status::MissingRequirement, "{run:?}");
        assert!(run
            .detail
            .as_deref()
            .unwrap_or_default()
            .contains("definitely-not-installed"));
    }

    #[test]
    fn disabling_a_rule_in_the_catalog_is_reported_not_planned() {
        let temp = tree(&[("cache/x/blob.bin", "x")]);
        let root = temp.path().join("cache/x");
        let body = format!(
            "{}\nenabled = false\n",
            single_rule("test.x", "dir-sweep", &root, 0)
        );
        let report = report_for(&temp, &body, &Limits::default());
        let run = report.rules.iter().find(|run| run.id == "test.x").unwrap();
        assert_eq!(run.status, Status::DeclaredDisabled);
        assert_eq!(report.totals.items, 0);
    }

    #[test]
    fn a_missing_root_is_not_a_finding() {
        let temp = tree(&[("cache/x/blob.bin", "x")]);
        let root = temp.path().join("cache/absent");
        let report = report_for(
            &temp,
            &single_rule("test.absent", "dir-sweep", &root, 0),
            &Limits::default(),
        );
        let run = report
            .rules
            .iter()
            .find(|run| run.id == "test.absent")
            .unwrap();
        assert_eq!(run.status, Status::NotPresent);
        assert!(report.notes.iter().any(|note| note.contains("not present")));
    }

    #[test]
    fn report_only_never_contributes_a_plan_item() {
        let temp = tree(&[("cache/x/blob.bin", "x")]);
        let root = temp.path().join("cache/x");
        let report = report_for(
            &temp,
            &single_rule("test.report", "report-only", &root, 7),
            &Limits::default(),
        );
        let run = report
            .rules
            .iter()
            .find(|run| run.id == "test.report")
            .unwrap();
        assert_eq!(run.status, Status::ReportOnly);
        assert_eq!(report.totals.items, 0);
        assert_eq!(report.funnel.would_remove, 0);
    }

    #[test]
    fn planning_is_read_only_in_both_modes_and_yields_the_same_plan() {
        let temp = tree(&[
            ("cache/app/old.bin", "old"),
            ("cache/app/nested/older.bin", "older"),
        ]);
        let root = temp.path().join("cache/app");
        for path in [
            root.join("old.bin"),
            root.join("nested/older.bin"),
            root.join("nested"),
        ] {
            age(&path, 90);
        }
        age(&root, 90);

        let body = single_rule("test.app", "dir-sweep", &root, 0);
        let xdg = xdg_at(temp.path());
        let mounts = MountTable::load().expect("mounts");
        let probe = RealProbe::new().expect("probe").with_open_scan();
        let set = || {
            RuleSet::from_sources(&[sweep_core::rules::Source::new("test.toml", &body)], &xdg)
                .expect("rule pack loads")
        };
        let limits = Limits::default();

        let dry = build(
            Scope::CLEAN,
            &set(),
            &xdg,
            &probe,
            &mounts,
            &[],
            &limits,
            Mode::DryRun,
            &sweep_core::ignore::Ignore::empty(&xdg.home),
        );
        let apply = build(
            Scope::CLEAN,
            &set(),
            &xdg,
            &probe,
            &mounts,
            &[],
            &limits,
            Mode::Apply,
            &sweep_core::ignore::Ignore::empty(&xdg.home),
        );

        // The preview and the run must describe the same plan: a different hash
        // would mean the confirmation prompt asked about something else.
        assert_eq!(dry.report.plan_hash, apply.report.plan_hash);
        assert_eq!(dry.plan.len(), apply.plan.len());
        assert_eq!(dry.report.mode, "dry-run");
        assert_eq!(apply.report.mode, "apply");
        assert_eq!(
            apply.report.funnel.removed, 0,
            "planning must not run the funnel"
        );
        assert!(root.join("old.bin").exists(), "planning must not delete");
    }

    fn versions_body(root: &Path, link: &Path, keep: u32) -> String {
        format!(
            r#"
[[rule]]
id = "test.tool.versions"
section = "user-essentials"
kind = "versions"
root = "{}"
keep_versions = {keep}
keep_link = "{}"
evidence = "test tree"
recoverable = true
privilege = "user"
"#,
            root.display(),
            link.display()
        )
    }

    /// One tool with three releases, the launcher on the oldest. With
    /// `keep_versions = 1` the middle one is the only planned entry: the oldest
    /// is live and the newest is the count.
    struct VersionsPlan {
        _temp: tempfile::TempDir,
        root: PathBuf,
        launcher: PathBuf,
        plan: Plan,
        report: PipelineReport,
        set: RuleSet,
        xdg: Xdg,
        probe: RealProbe,
    }

    fn versions_plan() -> VersionsPlan {
        let temp = tree(&[]);
        let root = temp.path().join("share/tool/versions");
        std::fs::create_dir_all(&root).expect("mkdir");
        for name in ["1.0.0", "2.0.0", "3.0.0"] {
            let path = root.join(name);
            std::fs::write(&path, "body").expect("write");
            age(&path, 90);
        }
        let launcher = temp.path().join("bin/tool");
        std::fs::create_dir_all(launcher.parent().expect("parent")).expect("mkdir");
        std::os::unix::fs::symlink(root.join("1.0.0"), &launcher).expect("symlink");

        let xdg = xdg_at(temp.path());
        let body = versions_body(&root, &launcher, 1);
        let set =
            RuleSet::from_sources(&[sweep_core::rules::Source::new("test.toml", &body)], &xdg)
                .expect("rule pack loads");
        let mounts = MountTable::load().expect("mounts");
        let probe = RealProbe::new().expect("probe").with_open_scan();
        let Built { plan, report } = build(
            Scope::CLEAN,
            &set,
            &xdg,
            &probe,
            &mounts,
            &[],
            &Limits::default(),
            Mode::Apply,
            &sweep_core::ignore::Ignore::empty(&xdg.home),
        );
        VersionsPlan {
            _temp: temp,
            root,
            launcher,
            plan,
            report,
            set,
            xdg,
            probe,
        }
    }

    fn repoint(launcher: &Path, target: &Path) {
        std::fs::remove_file(launcher).expect("unlink");
        std::os::unix::fs::symlink(target, launcher).expect("symlink");
    }

    #[test]
    fn a_launcher_that_moves_while_the_prompt_is_open_takes_its_entry_with_it() {
        let mut fixture = versions_plan();
        assert_eq!(fixture.plan.len(), 1, "only the middle release is planned");
        let planned = fixture.plan.items()[0].path().to_path_buf();
        assert_eq!(planned, fixture.root.join("2.0.0"));

        // The update finishes while the prompt is open: the link now names the
        // entry the plan was about to remove. The inode did not change, so the
        // funnel's re-check cannot catch this.
        repoint(&fixture.launcher, &planned);

        withdraw_live_versions(
            &mut fixture.plan,
            &mut fixture.report,
            &fixture.set,
            &fixture.xdg,
            &fixture.probe,
        );

        assert!(
            fixture.plan.is_empty(),
            "the entry the launcher names must leave the plan: {:?}",
            fixture.plan.items()
        );
        assert!(planned.exists(), "the re-check must not remove anything");
        let run = fixture
            .report
            .rules
            .iter()
            .find(|run| run.id == "test.tool.versions")
            .expect("run");
        assert_eq!(run.status, Status::Empty);
        assert_eq!(run.items, 0);
        assert_eq!(run.bytes, 0);
        assert_eq!(fixture.report.totals.items, 0);
        assert_eq!(fixture.report.totals.bytes, 0);
        assert!(
            fixture
                .report
                .notes
                .iter()
                .any(|note| note.contains("launcher changed")),
            "the withdrawal must be explained: {:?}",
            fixture.report.notes
        );
    }

    #[test]
    fn a_launcher_that_cannot_be_read_after_consent_keeps_everything_the_rule_planned() {
        let mut fixture = versions_plan();
        assert_eq!(fixture.plan.len(), 1);
        std::fs::remove_file(&fixture.launcher).expect("unlink");

        withdraw_live_versions(
            &mut fixture.plan,
            &mut fixture.report,
            &fixture.set,
            &fixture.xdg,
            &fixture.probe,
        );

        assert!(
            fixture.plan.is_empty(),
            "an unreadable launcher makes the live entry unknown, and unknown never deletes"
        );
        let run = fixture
            .report
            .rules
            .iter()
            .find(|run| run.id == "test.tool.versions")
            .expect("run");
        assert_eq!(run.status, Status::KeepLinkUnknown);
        assert!(
            fixture
                .report
                .notes
                .iter()
                .any(|note| note.contains("could not be read")),
            "the reason must be in the report: {:?}",
            fixture.report.notes
        );
    }

    #[test]
    fn a_launcher_that_moves_to_an_already_kept_entry_changes_nothing() {
        let mut fixture = versions_plan();
        let hash = fixture.report.plan_hash.clone();
        repoint(&fixture.launcher, &fixture.root.join("3.0.0"));

        withdraw_live_versions(
            &mut fixture.plan,
            &mut fixture.report,
            &fixture.set,
            &fixture.xdg,
            &fixture.probe,
        );

        assert_eq!(fixture.plan.len(), 1, "the planned entry is still not live");
        assert_eq!(fixture.report.plan_hash, hash);
        assert!(
            fixture.report.notes.is_empty(),
            "a re-check that withdraws nothing must stay quiet: {:?}",
            fixture.report.notes
        );
    }

    #[test]
    fn a_version_tree_that_holds_a_link_is_planned_whole() {
        // The standalone `codex` release keeps `codex` as a link to the real
        // binary inside the release directory. Refusing the link would leave the
        // directory non-empty at the sink, and the user would get "directory not
        // empty" for a removal the plan promised.
        let temp = tree(&[]);
        let root = temp.path().join("releases");
        let old = root.join("0.154.0-x86_64-unknown-linux-musl");
        std::fs::create_dir_all(old.join("bin")).expect("mkdir");
        std::fs::write(old.join("bin/codex-real"), "body").expect("write");
        std::os::unix::fs::symlink("bin/codex-real", old.join("codex")).expect("symlink");
        let live = root.join("0.160.0-x86_64-unknown-linux-musl");
        std::fs::create_dir_all(&live).expect("mkdir");
        std::fs::write(live.join("codex"), "body").expect("write");
        age(&old, 90);
        age(&live, 90);
        let launcher = temp.path().join("current");
        std::os::unix::fs::symlink(&live, &launcher).expect("symlink");

        let xdg = xdg_at(temp.path());
        let body = versions_body(&root, &launcher, 1);
        let set =
            RuleSet::from_sources(&[sweep_core::rules::Source::new("test.toml", &body)], &xdg)
                .expect("rule pack loads");
        let mounts = MountTable::load().expect("mounts");
        let probe = RealProbe::new().expect("probe").with_open_scan();
        let Built { plan, .. } = build(
            Scope::CLEAN,
            &set,
            &xdg,
            &probe,
            &mounts,
            &[],
            &Limits::default(),
            Mode::Apply,
            &sweep_core::ignore::Ignore::empty(&xdg.home),
        );

        assert!(
            plan.denied().is_empty(),
            "a link inside a release tree must not be refused: {:?}",
            plan.denied()
        );
        let link = plan
            .items()
            .iter()
            .find(|item| item.path() == old.join("codex"))
            .expect("the link is part of the tree");
        assert!(link.is_symlink(), "the plan must record that it is a link");
        assert!(
            plan.items().iter().any(|item| item.path() == old),
            "the release directory itself is planned"
        );
        assert!(
            plan.items()
                .iter()
                .all(|item| !item.path().starts_with(&live)),
            "the live release stays"
        );
    }

    #[test]
    fn human_bytes_stays_readable() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1024 * 1024 * 3), "3.0 MiB");
    }

    #[test]
    fn first_component_ignores_the_root_marker() {
        assert_eq!(
            first_component(Path::new("a/b/c")),
            Some(PathBuf::from("a"))
        );
        // Absolute paths are not passed in, and the root marker is not a name.
        assert_eq!(first_component(Path::new("/a")), None);
    }

    // ------------------------------------------------------- privilege boundary ---

    /// An elevator that answers from a canned reply and records what it was
    /// asked, so a test can assert on the request without a password.
    struct FakeElevator {
        reply: privilege::Reply,
        seen: std::cell::RefCell<Option<privilege::Request>>,
    }

    impl FakeElevator {
        fn answering(reply: privilege::Reply) -> Self {
            Self {
                reply,
                seen: std::cell::RefCell::new(None),
            }
        }
    }

    impl Elevator for FakeElevator {
        fn run(&self, request: &privilege::Request) -> io::Result<privilege::Reply> {
            *self.seen.borrow_mut() = Some(request.clone());
            Ok(self.reply.clone())
        }
    }

    /// The operation log as parsed rows. The CLI tests have their own copy; this
    /// one exists because a unit test has no access to that file.
    fn log_rows(state: &Path) -> Vec<serde_json::Value> {
        let path = state.join("operations.jsonl");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        raw.lines()
            .map(|line| serde_json::from_str(line).expect("one JSON record per line"))
            .collect()
    }

    fn reply_row(rule: &str, path: &Path, action: Action, bytes: u64) -> privilege::ItemResult {
        privilege::ItemResult {
            rule: rule.to_string(),
            path: path.display().to_string(),
            path_hex: privilege::hex(path.as_os_str().as_encoded_bytes()),
            action,
            bytes,
            code: match action {
                Action::Skipped => Some("race_changed".to_string()),
                _ => None,
            },
            detail: None,
        }
    }

    #[test]
    fn the_childs_reply_is_what_the_users_log_records() {
        // The elevated child never opens a file in the user's state directory;
        // it prints JSON lines and this process appends them. If that handoff
        // dropped rows, the audit trail would end at the password prompt.
        let home = tree(&[]);
        let state = home.path().join(".local/state/sweep");
        let mut log = Oplog::open(&state, "clean-42").expect("oplog");
        let reply = privilege::Reply {
            results: vec![
                reply_row(
                    "system.man.cache",
                    Path::new("/var/cache/man/index.db"),
                    Action::Removed,
                    4096,
                ),
                reply_row(
                    "system.fontconfig.cache",
                    Path::new("/var/cache/fontconfig/x"),
                    Action::Skipped,
                    0,
                ),
            ],
        };

        log_reply(Some(&mut log), "clean", &reply);
        drop(log);

        let rows = log_rows(&state);
        assert_eq!(rows.len(), 2, "one row per item: {rows:?}");
        assert_eq!(rows[0]["action"], "REMOVED");
        assert_eq!(rows[0]["rule"], "system.man.cache");
        assert_eq!(rows[0]["bytes"], 4096);
        assert_eq!(rows[0]["session"], "clean-42");
        assert_eq!(rows[1]["action"], "SKIPPED");
        assert_eq!(rows[1]["reason"], "race_changed");
    }

    #[test]
    fn a_plan_of_user_items_never_becomes_an_elevation_request() {
        // The boundary is decided by the rule's privilege, not by the caller's
        // wish: a plan that contains nothing root-owned must not start a
        // privileged process at all.
        let temp = tree(&[("cache/old.bin", "bytes")]);
        age(&temp.path().join("cache/old.bin"), 200);
        let xdg = xdg_at(temp.path());
        let body = single_rule("test.user", "dir-sweep", &temp.path().join("cache"), 0);
        let set =
            RuleSet::from_sources(&[sweep_core::rules::Source::new("test.toml", &body)], &xdg)
                .expect("pack loads");
        let mounts = MountTable::load().expect("mounts");
        let probe = RealProbe::new().expect("probe").with_open_scan();
        let Built { plan, .. } = build(
            Scope::CLEAN,
            &set,
            &xdg,
            &probe,
            &mounts,
            &[],
            &Limits::default(),
            Mode::Apply,
            &sweep_core::ignore::Ignore::empty(&xdg.home),
        );
        assert!(!plan.is_empty(), "the fixture must plan one file");

        let elevator = FakeElevator::answering(privilege::Reply::default());
        let error = apply_root(
            "clean",
            &plan,
            &privileged_rule_ids(&set),
            "clean-1",
            &elevator,
            None,
        )
        .expect_err("a user plan is not an elevation request");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            elevator.seen.borrow().is_none(),
            "the elevator must not run for an empty request"
        );
    }

    #[test]
    fn the_privileged_ids_are_the_enabled_system_rules_only() {
        let temp = tree(&[]);
        let xdg = xdg_at(temp.path());
        let set = RuleSet::load_builtin(&xdg).expect("catalog");
        let ids = privileged_rule_ids(&set);
        assert!(!ids.is_empty(), "M4a enables the safe system caches");
        for rule in set.rules() {
            assert_eq!(
                ids.contains(rule.id.as_str()),
                rule.privilege == Privilege::Root,
                "{} is classified wrongly",
                rule.id
            );
        }
    }

    #[test]
    fn a_privileged_run_without_the_flag_is_never_granted_consent() {
        // `--privileged` is the one path that does not consult stdin. Every
        // other path must ask, which is the behaviour a pipe cannot fake.
        assert!(matches!(
            elevate_consent("clean", 3, 4096, true),
            Elevation::Granted
        ));
    }
}
