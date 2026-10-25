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

use std::collections::BTreeSet;
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
    /// Path the rule matched, kept for display and for the log.
    literal: PathBuf,
    rule: RuleId,
    bytes: u64,
    dev: u64,
    ino: u64,
    is_dir: bool,
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
    seen: BTreeSet<(String, PathBuf)>,
    hash: String,
}

impl Plan {
    pub fn new() -> Self {
        Self::default()
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
        match validate(literal, ctx) {
            Verdict::Allow { physical } => {
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

    /// Records an already-validated item. Crate-internal: the funnel path is the
    /// public one.
    pub(crate) fn push_validated(
        &mut self,
        physical: PathBuf,
        literal: &Path,
        rule: &RuleId,
        meta: &Meta,
    ) {
        let key = (rule.as_str().to_string(), physical.clone());
        if !self.seen.insert(key) {
            return;
        }
        self.items.push(PlanItem {
            physical,
            literal: literal.to_path_buf(),
            rule: rule.clone(),
            bytes: meta.accounted_bytes(),
            dev: meta.dev,
            ino: meta.ino,
            is_dir: meta.is_dir(),
        });
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
    pub fn finish(&mut self) {
        self.items
            .sort_by(|left, right| left.physical.cmp(&right.physical));
        self.hash = compute_hash(&self.items);
    }

    pub fn items(&self) -> &[PlanItem] {
        &self.items
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
}
