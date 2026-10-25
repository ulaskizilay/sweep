//! `sweep clean` — the preview, in this milestone.
//!
//! M2 ships the read-only half of `clean`: it loads the catalog, decides which
//! rules apply to this machine, walks their roots, validates every candidate
//! through [`sweep_core::Plan::push`], and runs the funnel in [`Mode::DryRun`].
//! Nothing is written: no operation log, no Trash, no `unlinkat`.
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

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;

use serde::Serialize;
use sweep_core::fs_facts::MountTable;
use sweep_core::paths::is_within;
use sweep_core::probe::RealProbe;
use sweep_core::rules::{Kind, Privilege, Rule, RuleSet, Section};
use sweep_core::scan::{self, BlockKind, Collect, Entry, Limits, Select, Spec, Stop};
use sweep_core::validate::{AllowedRoot, Policy, ValidateCtx};
use sweep_core::{funnel, Mode, Plan, Xdg};

/// Why a rule contributed nothing. Machine-readable for `--json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Planned,
    ReportOnly,
    DeclaredDisabled,
    NeedsRoot,
    MissingRequirement,
    NotPresent,
    NotADirectory,
    Unreadable,
    ScanIncomplete,
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
            Status::NeedsRoot => "needs root; arrives in M4",
            Status::MissingRequirement => "tool not installed",
            Status::NotPresent => "path not present",
            Status::NotADirectory => "not a directory",
            Status::Unreadable => "permission denied",
            Status::ScanIncomplete => "scan incomplete; nothing planned",
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

#[derive(Debug, Serialize)]
struct FunnelReport {
    would_remove: usize,
    skipped: usize,
    failed: usize,
    bytes: u64,
    skip_codes: Vec<SkipCode>,
}

#[derive(Debug, Serialize)]
struct SkipCode {
    code: &'static str,
    count: usize,
}

/// Why the policy refused candidates, grouped by rule and reason.
#[derive(Debug, Serialize)]
struct Refusal {
    rule: String,
    code: &'static str,
    count: usize,
}

#[derive(Debug, Serialize)]
struct CleanReport {
    mode: &'static str,
    plan_hash: String,
    sections: Vec<SectionRun>,
    rules: Vec<RuleRun>,
    refusals: Vec<Refusal>,
    funnel: FunnelReport,
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

pub fn run(json: bool, verbose: u8, only: &[Section], dry_run: bool) -> ExitCode {
    if !dry_run {
        // Refuse rather than silently previewing: a user who typed `sweep clean`
        // meant to delete something, and doing something else while reporting
        // success is worse than doing nothing.
        eprintln!(
            "sweep clean: applying deletions arrives in M3; this build can only preview.\n\
             Run `sweep clean --dry-run` to see what would be removed."
        );
        return ExitCode::from(crate::EXIT_NOT_IMPLEMENTED);
    }

    let xdg = match Xdg::from_env() {
        Ok(xdg) => xdg,
        Err(error) => {
            eprintln!("sweep clean: {error}");
            return ExitCode::from(crate::EXIT_UNSUPPORTED_ENVIRONMENT);
        }
    };

    let set = match RuleSet::load(&xdg) {
        Ok(set) => set,
        Err(errors) => {
            eprintln!(
                "sweep clean: {} load {} refused; run `sweep rules verify` for details",
                errors.len(),
                if errors.len() == 1 { "error" } else { "errors" }
            );
            for error in &errors {
                eprintln!("  {error}");
            }
            return ExitCode::from(crate::EXIT_INVALID_RULES);
        }
    };

    let mounts = match MountTable::load() {
        Ok(mounts) => mounts,
        Err(error) => {
            eprintln!("sweep clean: cannot read the mount table: {error}");
            return ExitCode::from(crate::EXIT_UNSUPPORTED_ENVIRONMENT);
        }
    };

    let probe = match RealProbe::new() {
        Ok(probe) => probe.with_open_scan(),
        Err(error) => {
            eprintln!("sweep clean: cannot probe this filesystem: {error}");
            return ExitCode::from(crate::EXIT_UNSUPPORTED_ENVIRONMENT);
        }
    };

    let report = build(&set, &xdg, &probe, &mounts, only, &Limits::default());

    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(text) => println!("{text}"),
            Err(error) => {
                eprintln!("sweep clean: cannot serialise report: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        print!("{}", render(&report, verbose));
    }
    ExitCode::SUCCESS
}

fn build(
    set: &RuleSet,
    xdg: &Xdg,
    probe: &RealProbe,
    mounts: &MountTable,
    only: &[Section],
    limits: &Limits,
) -> CleanReport {
    let selected = set.select(only, xdg);
    let now = now_unix();

    // Every deletable root becomes an allowed root, because validation works on
    // "is this path inside something a rule declared?" and one plan mixes items
    // from several rules. Overlapping roots are fine: the deepest rule is the
    // one that records the item, thanks to the selection order.
    let deleting: Vec<&Rule> = selected
        .iter()
        .copied()
        .filter(|rule| rule.enabled && rule.privilege == Privilege::User && rule.kind.deletes())
        .collect();
    let allowed: Vec<AllowedRoot> = deleting
        .iter()
        .map(|rule| {
            let mut root =
                AllowedRoot::new(rule.expanded_root(xdg)).pinned_to_current_device(mounts);
            // A tool cache owns its directory: the sweep removes the root too.
            root.allow_root_itself = rule.kind == Kind::ToolCache;
            root
        })
        .collect();
    let roots: Vec<PathBuf> = deleting
        .iter()
        .map(|rule| rule.expanded_root(xdg))
        .collect();

    let ctx = ValidateCtx {
        xdg,
        probe,
        allowed: &allowed,
        // `clean` deletes what it plans, so the policy is the strict one. Dry
        // run is a *mode of the funnel*, not a weaker policy: the preview must
        // exercise exactly the checks the real run will.
        policy: Policy::default(),
    };

    let mut plan = Plan::new();
    let mut runs: Vec<RuleRun> = Vec::with_capacity(selected.len());
    let mut notes: Vec<String> = Vec::new();

    for rule in &selected {
        let root = rule.expanded_root(xdg);
        match skip_reason(rule, xdg) {
            Some(status) => runs.push(base_run(rule, status, skip_detail(rule, xdg, status))),
            None => runs.push(execute(
                rule, &root, probe, &ctx, limits, &mut plan, &roots, now,
            )),
        }
    }

    plan.finish();
    let preview = funnel::apply(&plan, probe, Mode::DryRun, "clean", None);

    let declared_off = runs
        .iter()
        .filter(|run| run.status == Status::DeclaredDisabled)
        .count();
    let needs_root = runs
        .iter()
        .filter(|run| run.status == Status::NeedsRoot)
        .count();
    if declared_off > 0 || needs_root > 0 {
        notes.push(format!(
            "{declared_off} rules are declared disabled by the catalog and {needs_root} need \
             privilege (M4); both groups are listed but never planned"
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

    let refusals = summarise_refusals(&plan);
    CleanReport {
        mode: "dry-run",
        plan_hash: plan.hash().to_string(),
        sections,
        rules: runs,
        refusals,
        funnel: FunnelReport {
            would_remove: preview.would_remove(),
            skipped: preview.skipped,
            failed: preview.failed,
            bytes: preview.removed_bytes,
            skip_codes: preview
                .skip_codes()
                .into_iter()
                .map(|(code, count)| SkipCode { code, count })
                .collect(),
        },
        totals,
        notes,
    }
}

fn skip_reason(rule: &Rule, xdg: &Xdg) -> Option<Status> {
    if !rule.enabled {
        return Some(Status::DeclaredDisabled);
    }
    if rule.privilege == Privilege::Root {
        return Some(Status::NeedsRoot);
    }
    if rule.missing_requirement(xdg).is_some() {
        return Some(Status::MissingRequirement);
    }
    None
}

fn skip_detail(rule: &Rule, xdg: &Xdg, status: Status) -> Option<String> {
    match status {
        Status::MissingRequirement => rule
            .missing_requirement(xdg)
            .map(|requirement| format!("requires {}", requirement.label())),
        _ => None,
    }
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
        detail,
    }
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
    // Roots another enabled rule owns: the residual cache sweep must not take a
    // target that has a retention policy of its own.
    let claimed: Vec<PathBuf> = all_roots
        .iter()
        .filter(|other| other.as_path() != root && is_within(root, other))
        .cloned()
        .collect();

    let mut spec = Spec::new(rule.max_depth, limits);
    spec.exclude = &rule.exclude;
    spec.skip_roots = &claimed;
    if rule.kind == Kind::FilePattern {
        spec.select = Select::Files(&rule.patterns);
    }

    let collected = scan::collect(root, root, 0, &spec, probe);

    let mut run = base_run(rule, Status::Planned, None);
    run.scanned_bytes = collected.bytes;

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
        run.detail = Some(format!(
            "{} entries would be measured, never deleted",
            collected.entries.len()
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
    };
    // Children first is the plan's job (`Plan::finish` sorts deepest-first); the
    // walk already emits post-order, so this stays readable even before sorting.
    candidates.sort();

    for path in candidates {
        match plan.push(path, &rule.id, ctx) {
            Ok(_) => run.items += 1,
            Err(_) => run.refused += 1,
        }
    }

    run.bytes = plan
        .items()
        .iter()
        .filter(|item| item.rule() == &rule.id)
        .map(|item| item.bytes())
        .sum();

    if run.items == 0 && run.refused == 0 {
        run.status = Status::Empty;
        if run.detail.is_none() {
            run.detail = blocked_detail(&collected);
        }
    }
    run
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
                "{} holds a {} entry",
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

fn first_component(path: &Path) -> Option<PathBuf> {
    path.components()
        .next()
        .and_then(|component| match component {
            Component::Normal(name) => Some(PathBuf::from(name)),
            _ => None,
        })
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

fn render(report: &CleanReport, verbose: u8) -> String {
    let mut out = String::new();
    out.push_str("sweep clean — dry run, nothing is deleted\n\n");

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

    if verbose > 0 {
        out.push_str("\n  per rule\n");
        for rule in &report.rules {
            let detail = rule
                .detail
                .as_deref()
                .map(|detail| format!("  ({detail})"))
                .unwrap_or_default();
            out.push_str(&format!(
                "    {:<34} {:<13} {:>6} {:>9}{detail}\n",
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
    } else {
        out.push_str(&format!(
            "\n  Preview only: {} items, {} would be removed permanently.\n  Applying deletions arrives in M3.\n",
            report.funnel.would_remove,
            human_bytes(report.funnel.bytes)
        ));
    }
    out
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
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

    fn report_for(temp: &tempfile::TempDir, body: &str, limits: &Limits) -> CleanReport {
        let xdg = xdg_at(temp.path());
        let set = RuleSet::from_sources(&[sweep_core::rules::Source::new("test.toml", body)], &xdg)
            .expect("rule pack loads");
        let mounts = MountTable::load().expect("mounts");
        let probe = RealProbe::new().expect("probe").with_open_scan();
        build(&set, &xdg, &probe, &mounts, &[], limits)
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
}
