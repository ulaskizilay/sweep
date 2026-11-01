//! `sweep-core` — the safety kernel.
//!
//! Layering, outermost first:
//!
//! ```text
//! rules (M2)  →  scan (M2)  →  Plan::push  →  validate  →  funnel  →  unlinkat
//! ```
//!
//! Nothing below `funnel` decides anything; nothing above `validate` deletes
//! anything. `PlanItem` cannot be constructed outside [`plan`], so the funnel
//! only ever sees paths that passed the policy.
//!
//! # Safety contract
//!
//! * Deletion happens in exactly one place ([`funnel::apply`]) and is never
//!   recursive.
//! * Every refusal is a [`validate::Reason`], never a bare string.
//! * "We could not verify" is a refusal, not a pass.
//! * Dry run and apply consume the same [`plan::Plan`] and the same
//!   [`plan::Plan::hash`].
//!
//! `unsafe` is denied crate-wide. The single exception is [`sys`], where each
//! block carries a `// SAFETY:` justification.

#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]

pub mod fs_facts;
pub mod funnel;
pub mod meta;
pub mod model_cache;
pub mod oplog;
pub mod paths;
pub mod pkg_cache;
pub mod plan;
pub mod policy;
pub mod privilege;
pub mod probe;
pub mod project;
pub mod rules;
pub mod scan;
pub mod selection;
pub mod sys;
pub mod validate;
pub mod version;

pub use fs_facts::{FsFacts, FsType, MountInfo, MountOptions, MountTable};
pub use funnel::{apply, ItemResult, Mode, Outcome, Report};
pub use meta::Meta;
pub use oplog::{Action, Oplog, Record};
pub use paths::{Xdg, XdgError};
pub use plan::{DeniedItem, Plan, PlanItem, RuleId};
pub use probe::{FsProbe, OpenInodes, ProcRef, RealProbe};
pub use rules::{Kind, Privilege, Requirement, Rule, RuleError, RuleErrorKind, RuleSet, Section};
pub use scan::{Block, BlockKind, Collect, Entry, Limits, Select, Spec, Stats, Stop};
pub use validate::{
    is_deletable, validate, AllowedRoot, Owner, Policy, Reason, ValidateCtx, Verdict,
};

/// Crate version, reported by `sweep doctor`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
