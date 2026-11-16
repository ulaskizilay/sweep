//! The deletion plan: the only object the funnel will act on.
//!
//! [`PlanItem`] has no public constructor. The only way to obtain one is
//! [`Plan::push`], which runs [`crate::validate::validate`] first. That is a
//! type-level guarantee, not a convention: a developer cannot hand the funnel an
//! unvalidated path without editing this module.
//!
//! The plan is also the dry-run contract. It is sorted by path and carries a
//! stable hash, so `--dry-run` and the real run produce the same identity and a
//! test can assert they agree.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use crate::meta::Meta;
use crate::validate::{validate, Reason, ValidateCtx, Verdict};

/// A stable identifier such as `dev.cargo.registry-cache`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleId(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleIdError {
    Empty,
    TooLong,
    BadCharacter(char),
}

impl std::fmt::Display for RuleIdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleIdError::Empty => f.write_str("rule id is empty"),
            RuleIdError::TooLong => f.write_str("rule id is longer than 64 bytes"),
            RuleIdError::BadCharacter(c) => write!(
                f,
                "rule id contains {c:?}; allowed: a-z, 0-9, '.', '-', '_'"
            ),
        }
    }
}

impl std::error::Error for RuleIdError {}

impl RuleId {
    pub fn new(raw: impl Into<String>) -> Result<Self, RuleIdError> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(RuleIdError::Empty);
        }
        if raw.len() > 64 {
            return Err(RuleIdError::TooLong);
        }
        for character in raw.chars() {
            let allowed = character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '.' | '-' | '_');
            if !allowed {
                return Err(RuleIdError::BadCharacter(character));
            }
        }
        Ok(Self(raw))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RuleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One validated deletion candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanItem {
    /// Path the funnel acts on: symlinked ancestors resolved.
    physical: PathBuf,
    /// Components below the root, counted once when the item is built.
    ///
    /// The plan is sorted deepest-first, and recomputing this inside the
    /// comparator re-parsed both paths for every comparison - tens of millions
    /// of them on a full cache, and the largest single cost of a preview. The
    /// number cannot go stale: `physical` is private, and both are assigned
    /// together in one place.
    depth: usize,
    /// Path the rule matched, kept for display and for the log.
    literal: PathBuf,
    rule: RuleId,
    bytes: u64,
    dev: u64,
    ino: u64,
    is_dir: bool,
    /// The item was a symbolic link when it was validated.
    ///
    /// Recorded because a link is the one target whose removal must not be
    /// inferred from the path alone: the sink unlinks the link, never its
    /// target, and an item that was *not* a link must be refused if it became
    /// one while the user was reading the plan.
    is_symlink: bool,
    /// Remove this item only if that path was removed (or would be, in a
    /// preview) earlier in the same run.
    ///
    /// A trash entry is two files: the payload and the `.trashinfo` record that
    /// names it. The record is worthless once the payload is gone and misleading
    /// while it is not, so the pair is ordered rather than independent.
    after: Option<PathBuf>,
}

impl PlanItem {
    pub fn path(&self) -> &Path {
        &self.physical
    }

    pub fn literal(&self) -> &Path {
        &self.literal
    }

    pub fn rule(&self) -> &RuleId {
        &self.rule
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn dev(&self) -> u64 {
        self.dev
    }

    pub fn ino(&self) -> u64 {
        self.ino
    }

    pub fn is_dir(&self) -> bool {
        self.is_dir
    }

    pub fn is_symlink(&self) -> bool {
        self.is_symlink
    }

    /// The path that must be removed first, for an item that is one half of a
    /// pair.
    pub fn after(&self) -> Option<&Path> {
        self.after.as_deref()
    }
}

/// A refusal worth reporting: the user asked for it, policy said no.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeniedItem {
    pub path: PathBuf,
    pub rule: RuleId,
    pub reason: Reason,
}

#[derive(Debug, Clone, Default)]
pub struct Plan {
    items: Vec<PlanItem>,
    denied: Vec<DeniedItem>,
    /// Paths already in the plan, so two rules cannot schedule the same one.
    ///
    /// A hash set, not a tree: the only operations are insert, remove and
    /// (through `split`) insert, and `Path`'s `Ord` compares component by
    /// component. A million-entry cache spent five seconds of a preview in the
    /// tree's comparisons; the hash set asks the same question in one pass.
    seen: HashSet<PathBuf>,
    /// `.trashinfo` records and the payload each one depends on, keyed by the
    /// literal record path the planner pushes.
    pairs: BTreeMap<PathBuf, PathBuf>,
    /// The user's ignore file. `None` protects nothing.
    ignore: Option<crate::ignore::Ignore>,
    hash: String,
}

impl Plan {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `record` may only be removed once `payload` is gone.
    ///
    /// Both paths are literal: they are looked up by the literal the planner
    /// pushes, before validation resolves symlinked ancestors.
    pub fn pair(&mut self, record: &Path, payload: &Path) {
        self.pairs
            .insert(record.to_path_buf(), payload.to_path_buf());
    }

    /// Validates `literal` and, when allowed, records it.
    ///
    /// Returns the physical path on success, so the caller can report where the
    /// bytes actually come from.
    pub fn push(
        &mut self,
        literal: &Path,
        rule: &RuleId,
        ctx: &ValidateCtx<'_>,
    ) -> Result<PathBuf, Reason> {
        // The user's own protection is checked before any syscall, and again on
        // the resolved path below: `~/.cache` is often a symlink, so a line
        // naming the literal path and one naming the real path must both work.
        if let Some(pattern) = self.ignored(literal) {
            let reason = Reason::Ignored(pattern.to_string());
            self.deny(literal, rule, reason.clone());
            return Err(reason);
        }
        match validate(literal, ctx) {
            Verdict::Allow { physical } => {
                if let Some(pattern) = self.ignored(&physical) {
                    let reason = Reason::Ignored(pattern.to_string());
                    self.deny(literal, rule, reason.clone());
                    return Err(reason);
                }
                // Metadata is re-read here rather than passed in, so the plan
                // records the state the decision was made on.
                let meta = crate::validate::stat_for_plan(ctx.probe, &physical)
                    .map_err(|error| Reason::ProbeUnknown(error.to_string()))?;
                self.push_validated(physical, literal, rule, &meta);
                Ok(literal.to_path_buf())
            }
            Verdict::Deny(reason) => {
                self.deny(literal, rule, reason.clone());
                Err(reason)
            }
        }
    }

    /// Installs the user's ignore file.
    ///
    /// A plan built without one protects nothing, which is what every test and
    /// every caller that predates the file wants.
    pub fn set_ignore(&mut self, ignore: crate::ignore::Ignore) {
        self.ignore = Some(ignore);
    }

    /// The ignore line that protects `path`, when the user wrote one.
    pub fn ignored(&self, path: &Path) -> Option<&str> {
        self.ignore.as_ref().and_then(|ignore| ignore.matched(path))
    }

    /// The installed ignore file, for a scanner that has to skip a whole entry
    /// rather than one path.
    pub fn ignore(&self) -> Option<&crate::ignore::Ignore> {
        self.ignore.as_ref()
    }

    /// Records an already-validated item. Crate-internal: the funnel path is the
    /// public one.
    pub(crate) fn push_validated(
        &mut self,
        physical: PathBuf,
        literal: &Path,
        rule: &RuleId,
        meta: &Meta,
    ) {
        // Path-only, not `(rule, path)`: two rules that resolve to the same
        // directory must not both schedule it, or the second `unlinkat` would
        // report `ENOENT` for a success. Rules are selected deepest-root-first,
        // so the narrower rule - with the retention a human chose for that
        // target - is the one that records the item.
        if !self.seen.insert(physical.clone()) {
            return;
        }
        // A paired record (a `.trashinfo` file) is ordered after its payload. The
        // lookup is by literal path because that is what the planner pushed.
        let after = self.pairs.get(literal).cloned();
        self.items.push(PlanItem {
            depth: crate::paths::depth(&physical),
            physical,
            literal: literal.to_path_buf(),
            rule: rule.clone(),
            bytes: meta.accounted_bytes(),
            dev: meta.dev,
            ino: meta.ino,
            is_dir: meta.is_dir(),
            is_symlink: meta.is_symlink(),
            after,
        });
    }

    /// Removes an item that was validated and then refused for another reason.
    ///
    /// The elevated child validates before it asks whether the rule would have
    /// selected the path, so that a symlink or an owner mismatch is reported as
    /// what it is. The item must then leave the plan: an applied plan has no
    /// second chance to notice it.
    pub fn forget(&mut self, path: &Path) {
        self.seen.remove(path);
        self.items.retain(|item| item.physical != path);
        self.hash.clear();
    }

    pub fn deny(&mut self, path: &Path, rule: &RuleId, reason: Reason) {
        if self.denied.len() < 10_000 {
            self.denied.push(DeniedItem {
                path: path.to_path_buf(),
                rule: rule.clone(),
                reason,
            });
        }
    }

    /// Sorts and computes the dry-run identity. Call once before applying.
    ///
    /// The order is deepest-first because the funnel performs one `unlinkat` per
    /// item and can never recurse: a directory scheduled before its children
    /// would fail with `ENOTEMPTY` and be reported as skipped while its children
    /// were still there. Depth, then path, keeps the run deterministic.
    ///
    /// A directory that still holds an ignored path is dropped here as a
    /// backstop. The scanners already refuse to plan one — an ignored entry
    /// blocks its parent during the walk — so this should never fire in the
    /// shipped code, but a future kind that plans a directory without walking it
    /// must not turn a protection into `directory_not_empty` at the sink.
    pub fn finish(&mut self) {
        self.drop_ancestors_of_ignored();
        self.items.sort_by(|left, right| {
            right
                .depth
                .cmp(&left.depth)
                .then_with(|| left.physical.cmp(&right.physical))
        });
        self.hash = compute_hash(&self.items);
    }

    fn drop_ancestors_of_ignored(&mut self) {
        let ignored: Vec<(PathBuf, RuleId)> = self
            .denied
            .iter()
            .filter(|denied| matches!(denied.reason, Reason::Ignored(_)))
            .map(|denied| (denied.path.clone(), denied.rule.clone()))
            .collect();
        if ignored.is_empty() {
            return;
        }
        let mut dropped: Vec<(PathBuf, RuleId)> = Vec::new();
        self.items.retain(|item| {
            if !item.is_dir {
                return true;
            }
            let Some((_, rule)) = ignored.iter().find(|(path, _)| {
                path != &item.literal && crate::paths::is_within(&item.literal, path)
            }) else {
                return true;
            };
            dropped.push((item.literal.clone(), rule.clone()));
            false
        });
        for (path, rule) in dropped {
            self.deny(&path, &rule, Reason::HoldsIgnored);
        }
    }

    pub fn items(&self) -> &[PlanItem] {
        &self.items
    }

    /// Splits the plan into the items a predicate claims and the rest.
    ///
    /// Both halves are moved, not re-decided: they already passed validation
    /// against one context, and a second `validate` could disagree with the
    /// first — at which point the plan the user confirmed would no longer be
    /// the plan that runs. `clean` uses this to send only the root-owned items
    /// through the privilege boundary.
    pub fn split(&self, mut chosen: impl FnMut(&PlanItem) -> bool) -> (Plan, Plan) {
        let mut select = Plan::new();
        let mut rest = Plan::new();
        // The halves keep the user's protection and the pair map. Neither is
        // read again in the shipped flow - the plan is finished and refusals are
        // summarised before the split - but a half that silently lost them would
        // stop protecting a path the day someone pushes to it.
        select.ignore = self.ignore.clone();
        rest.ignore = self.ignore.clone();
        select.pairs = self.pairs.clone();
        rest.pairs = self.pairs.clone();
        for item in &self.items {
            let target = if chosen(item) { &mut select } else { &mut rest };
            target.seen.insert(item.path().to_path_buf());
            target.items.push(item.clone());
        }
        select.finish();
        rest.finish();
        (select, rest)
    }

    pub fn denied(&self) -> &[DeniedItem] {
        &self.denied
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Stable across runs and insertion order: FNV-1a over sorted
    /// `rule NUL path` records.
    pub fn hash(&self) -> &str {
        &self.hash
    }

    pub fn total_bytes(&self) -> u64 {
        self.items.iter().map(PlanItem::bytes).sum()
    }
}

/// FNV-1a, 64-bit. Not cryptographic: it only proves that two plans are the same
/// set of operations, which is what the dry-run parity test needs.
fn compute_hash(items: &[PlanItem]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for item in items {
        for byte in item.rule.as_str().as_bytes() {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash ^= 0;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        for byte in item.physical.as_os_str().as_encoded_bytes() {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash ^= 0x1e;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::{OpenInodes, RealProbe};
    use crate::validate::{AllowedRoot, Policy};
    use crate::Xdg;

    #[test]
    fn rule_ids_are_restricted() {
        assert!(RuleId::new("dev.cargo.cache").is_ok());
        assert_eq!(RuleId::new(""), Err(RuleIdError::Empty));
        assert_eq!(RuleId::new("UPPER"), Err(RuleIdError::BadCharacter('U')));
        assert_eq!(RuleId::new("a/b"), Err(RuleIdError::BadCharacter('/')));
        assert_eq!(RuleId::new("x".repeat(65)), Err(RuleIdError::TooLong));
    }

    #[test]
    fn hash_is_order_independent() {
        let rule = RuleId::new("test.rule").unwrap();
        let meta = Meta {
            dev: 1,
            ino: 2,
            blocks: 1,
            mode: libc::S_IFREG,
            ..Meta::default()
        };
        let mut first = Plan::new();
        first.push_validated(PathBuf::from("/tmp/b"), Path::new("/tmp/b"), &rule, &meta);
        first.push_validated(PathBuf::from("/tmp/a"), Path::new("/tmp/a"), &rule, &meta);
        first.finish();

        let mut second = Plan::new();
        second.push_validated(PathBuf::from("/tmp/a"), Path::new("/tmp/a"), &rule, &meta);
        second.push_validated(PathBuf::from("/tmp/b"), Path::new("/tmp/b"), &rule, &meta);
        second.finish();

        assert_eq!(first.hash(), second.hash());
        assert_eq!(first.items()[0].path(), Path::new("/tmp/a"));
    }

    #[test]
    fn duplicate_items_are_dropped() {
        let rule = RuleId::new("test.rule").unwrap();
        let meta = Meta::default();
        let mut plan = Plan::new();
        plan.push_validated(PathBuf::from("/tmp/a"), Path::new("/tmp/a"), &rule, &meta);
        plan.push_validated(PathBuf::from("/tmp/a"), Path::new("/tmp/a"), &rule, &meta);
        assert_eq!(plan.len(), 1);
    }

    #[test]
    fn a_path_claimed_by_two_rules_is_scheduled_once() {
        // Two rules can resolve to the same directory (a residual sweep and a
        // narrow one). Scheduling it twice would make the second `unlinkat`
        // report `ENOENT` for an operation that succeeded.
        let broad = RuleId::new("user.cache.residual").unwrap();
        let narrow = RuleId::new("user.thumbnails").unwrap();
        let meta = Meta::default();
        let mut plan = Plan::new();
        plan.push_validated(
            PathBuf::from("/home/u/.cache/x"),
            Path::new("/home/u/.cache/x"),
            &narrow,
            &meta,
        );
        plan.push_validated(
            PathBuf::from("/home/u/.cache/x"),
            Path::new("/home/u/.cache/x"),
            &broad,
            &meta,
        );
        assert_eq!(plan.len(), 1);
        // The first rule to claim the path keeps it, and the caller is expected
        // to select deepest-root-first so that rule is the narrow one.
        assert_eq!(plan.items()[0].rule(), &narrow);
    }

    #[test]
    fn an_ignored_path_is_refused_and_the_directory_holding_it_is_dropped() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().to_path_buf();
        let cache = home.join(".cache");
        std::fs::create_dir_all(cache.join("outer/inner")).unwrap();
        std::fs::write(cache.join("outer/inner/notes.txt"), b"body").unwrap();

        let probe = RealProbe::new()
            .unwrap()
            .with_open_inodes(OpenInodes::default());
        let xdg = Xdg::resolve(|key| match key {
            "HOME" => Some(home.as_os_str().to_os_string()),
            _ => None,
        })
        .unwrap();
        let allowed = vec![AllowedRoot::new(&cache)];
        let ctx = ValidateCtx {
            xdg: &xdg,
            probe: &probe,
            allowed: &allowed,
            policy: Policy::default(),
        };
        let rule = RuleId::new("user.cache.residual").unwrap();

        let mut plan = Plan::new();
        plan.set_ignore(
            crate::ignore::Ignore::parse(&home, ".cache/outer/inner\n", "ignore").unwrap(),
        );

        // The protected path itself: refused before any syscall.
        let error = plan
            .push(&cache.join("outer/inner"), &rule, &ctx)
            .expect_err("the ignore line protects it");
        assert_eq!(error.code(), "ignored", "{error}");

        // Its parent is a legal target on its own, but the funnel cannot empty a
        // directory that still holds something, so `finish` drops it. This is the
        // backstop the scanners are expected to make unnecessary.
        plan.push(&cache.join("outer"), &rule, &ctx)
            .expect("the parent itself is allowed");
        plan.finish();
        assert!(plan.is_empty(), "the parent must not be planned");
        assert!(
            plan.denied()
                .iter()
                .any(|denied| denied.reason.code() == "holds_ignored"),
            "the drop must be reported: {:?}",
            plan.denied()
        );
    }

    #[test]
    fn children_are_scheduled_before_their_parent() {
        // The funnel never recurses, so this order is what makes a directory
        // deletable at all: by the time its own `unlinkat` runs, its children are
        // already gone.
        let rule = RuleId::new("test.rule").unwrap();
        let meta = Meta {
            mode: libc::S_IFDIR,
            ..Meta::default()
        };
        let file_meta = Meta::default();
        let mut plan = Plan::new();
        for path in ["/tmp/a", "/tmp/a/b", "/tmp/a/b/c.bin", "/tmp/a/d.bin"] {
            plan.push_validated(
                PathBuf::from(path),
                Path::new(path),
                &rule,
                if path.ends_with(".bin") {
                    &file_meta
                } else {
                    &meta
                },
            );
        }
        plan.finish();
        let order: Vec<&Path> = plan.items().iter().map(PlanItem::path).collect();
        let position = |needle: &str| {
            order
                .iter()
                .position(|path| path.to_str() == Some(needle))
                .expect(needle)
        };
        assert!(position("/tmp/a/b/c.bin") < position("/tmp/a/b"));
        assert!(position("/tmp/a/b") < position("/tmp/a"));
        assert!(position("/tmp/a/d.bin") < position("/tmp/a"));
        // The sort reads a recorded number now, not the path. Every item must
        // carry the depth of the path it was built from, or the order would
        // silently stop being post-order.
        for item in plan.items() {
            assert_eq!(
                item.depth,
                crate::paths::depth(item.path()),
                "{} has a stale depth",
                item.path().display()
            );
        }
    }

    #[test]
    fn splitting_a_plan_accounts_for_every_item_exactly_once() {
        // `clean` splits the plan at the privilege boundary: the user half runs
        // in this process, the root half goes to the elevated child. An item
        // that lands in neither half silently disappears from the run, and one
        // that lands in both is deleted twice and reported twice.
        let user = RuleId::new("dev.go.build-cache").unwrap();
        let root = RuleId::new("system.man.cache").unwrap();
        let meta = Meta {
            blocks: 8,
            mode: libc::S_IFREG,
            ..Meta::default()
        };
        let mut plan = Plan::new();
        for (path, rule) in [
            ("/home/u/.cache/go-build/a", &user),
            ("/var/cache/man/b", &root),
            ("/home/u/.cache/go-build/c", &user),
            ("/var/cache/man/d", &root),
        ] {
            plan.push_validated(PathBuf::from(path), Path::new(path), rule, &meta);
        }
        plan.finish();

        let (root_half, user_half) = plan.split(|item| item.rule() == &root);

        assert_eq!(root_half.len(), 2);
        assert_eq!(user_half.len(), 2);
        assert_eq!(root_half.len() + user_half.len(), plan.len());
        assert!(root_half.items().iter().all(|item| item.rule() == &root));
        assert!(user_half.items().iter().all(|item| item.rule() == &user));

        // Byte accounting survives the split, because the caller sums the halves
        // and expects the same total it previewed.
        assert_eq!(
            root_half.total_bytes() + user_half.total_bytes(),
            plan.total_bytes()
        );

        // Each half is finished in its own right: deepest-first order still
        // holds, and the hashes differ, so the two halves cannot be mistaken for
        // one another in the operation log.
        assert_ne!(root_half.hash(), user_half.hash());

        // Nothing is left behind in either half.
        let mut seen: Vec<&Path> = Vec::new();
        seen.extend(root_half.items().iter().map(PlanItem::path));
        seen.extend(user_half.items().iter().map(PlanItem::path));
        for item in plan.items() {
            assert_eq!(
                seen.iter().filter(|path| **path == item.path()).count(),
                1,
                "{} must appear in exactly one half",
                item.path().display()
            );
        }
    }
}
