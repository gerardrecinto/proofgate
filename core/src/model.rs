//! The policy IR. The Ruby DSL emits it, the Go gateway loads it, this crate analyzes it.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PolicyError {}

pub type Result<T> = std::result::Result<T, PolicyError>;

pub fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(PolicyError(msg.into()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantKind {
    NeverAllow,
    AlwaysAllow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dimension {
    pub name: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    #[serde(default)]
    pub description: String,
    pub effect: Effect,
    #[serde(default)]
    pub when: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invariant {
    pub id: String,
    #[serde(default)]
    pub description: String,
    pub kind: InvariantKind,
    #[serde(default)]
    pub when: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    pub name: String,
    pub dimensions: Vec<Dimension>,
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub invariants: Vec<Invariant>,
}

/// Largest request space we analyze. Keeps every count exact in a JSON number.
pub const MAX_SPACE: u64 = 1 << 53;
pub const MAX_VALUES: usize = 64;

impl Policy {
    pub fn parse(json: &str) -> Result<Policy> {
        let policy: Policy =
            serde_json::from_str(json).map_err(|e| PolicyError(format!("invalid policy: {e}")))?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return err(format!("unsupported policy version {}", self.version));
        }
        if self.name.trim().is_empty() {
            return err("policy name is empty");
        }
        if self.dimensions.is_empty() {
            return err("policy has no dimensions");
        }
        let mut space: u128 = 1;
        let mut names = BTreeSet::new();
        for d in &self.dimensions {
            if d.name.is_empty() || !names.insert(d.name.as_str()) {
                return err(format!("dimension '{}' is empty or duplicated", d.name));
            }
            if d.values.is_empty() || d.values.len() > MAX_VALUES {
                return err(format!(
                    "dimension '{}' needs 1 to {MAX_VALUES} values",
                    d.name
                ));
            }
            let unique: BTreeSet<_> = d.values.iter().collect();
            if unique.len() != d.values.len() || d.values.iter().any(|v| v.is_empty()) {
                return err(format!(
                    "dimension '{}' has an empty or duplicate value",
                    d.name
                ));
            }
            space *= d.values.len() as u128;
            if space > MAX_SPACE as u128 {
                return err("request space is larger than 2^53");
            }
        }
        let mut ids = BTreeSet::new();
        for r in &self.rules {
            if r.id.is_empty() || !ids.insert(r.id.as_str()) {
                return err(format!("rule id '{}' is empty or duplicated", r.id));
            }
            self.check_when(&r.id, &r.when)?;
        }
        for i in &self.invariants {
            if i.id.is_empty() || !ids.insert(i.id.as_str()) {
                return err(format!("invariant id '{}' is empty or duplicated", i.id));
            }
            self.check_when(&i.id, &i.when)?;
        }
        Ok(())
    }

    fn check_when(&self, owner: &str, when: &BTreeMap<String, Vec<String>>) -> Result<()> {
        for (dim, values) in when {
            let Some(d) = self.dimensions.iter().find(|d| &d.name == dim) else {
                return err(format!("'{owner}' uses unknown dimension '{dim}'"));
            };
            if values.is_empty() {
                return err(format!("'{owner}' has an empty value list for '{dim}'"));
            }
            for v in values {
                if !d.values.contains(v) {
                    return err(format!("'{owner}' uses unknown value '{v}' for '{dim}'"));
                }
            }
        }
        Ok(())
    }
}
