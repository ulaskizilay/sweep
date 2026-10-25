//! The on-disk shape of a rule pack.
//!
//! These types exist only to be deserialised. Every value is a string that the
//! compiler in [`super::check`] has to earn a [`super::Rule`] from, so a typo in
//! a key is a parse error (thanks to `deny_unknown_fields`) rather than a silently
//! defaulted field. `keep_day = 30` must not degrade into `keep_days = 0`, which
//! would mean "delete everything".

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulePack {
    #[serde(default)]
    pub meta: PackMeta,
    #[serde(default, rename = "rule")]
    pub rules: Vec<RawRule>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackMeta {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRule {
    pub id: String,
    pub section: String,
    pub kind: String,
    pub root: String,
    /// Why deleting here is safe, in one sentence a user can read.
    #[serde(default)]
    pub evidence: String,
    #[serde(default)]
    pub recoverable: bool,
    #[serde(default)]
    pub keep_days: u32,
    #[serde(default)]
    pub requires: Vec<String>,
    pub privilege: String,
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Required by `kind = "file-pattern"`, refused by every other kind.
    #[serde(default)]
    pub pattern: Option<OneOrMany>,
    /// Whether the rule runs. Rules for a section that is not implemented yet
    /// ship disabled so `sweep rules list` still shows the plan.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// How many levels below the root to visit. 1 means the root's children.
    #[serde(default)]
    pub max_depth: Option<usize>,
}

/// `pattern = "*.log"` and `pattern = ["*.log", "*.txt"]` mean the same thing
/// with one value or several, which keeps a rule that hunts one artifact from
/// needing an array and a rule that hunts three from needing three rules.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    pub fn into_vec(self) -> Vec<String> {
        match self {
            OneOrMany::One(value) => vec![value],
            OneOrMany::Many(values) => values,
        }
    }
}

fn default_true() -> bool {
    true
}
