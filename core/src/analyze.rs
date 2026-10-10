//! Checks, semantic diff and evaluation, all exact over the whole request space.

use crate::model::{err, Effect, InvariantKind, Policy, Result};
use crate::space::{count, intersect, partition, simplify, Cube, Region, Space};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub type When = BTreeMap<String, Vec<String>>;

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Hash of the canonical IR. Field order is fixed by the structs, `when` maps are sorted.
pub fn digest(policy: &Policy) -> String {
    sha256_hex(&serde_json::to_vec(policy).expect("policy serializes"))
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleStatus {
    Active,
    /// The rule matches only requests an earlier rule already decided.
    Dead,
    /// Removing the rule changes no decision.
    Redundant,
}

#[derive(Debug, Serialize)]
pub struct RuleReport {
    pub id: String,
    pub effect: Effect,
    /// Requests this rule decides after earlier rules took theirs.
    pub decides: u64,
    pub status: RuleStatus,
}

#[derive(Debug, Serialize)]
pub struct InvariantReport {
    pub id: String,
    pub description: String,
    pub kind: InvariantKind,
    pub holds: bool,
    /// Where it fails, with the rule that decided it.
    pub counterexamples: Vec<Counterexample>,
}

#[derive(Debug, Serialize)]
pub struct Counterexample {
    pub when: When,
    pub requests: u64,
    pub decided_by: String,
}

#[derive(Debug, Serialize)]
pub struct CheckReport {
    pub name: String,
    pub digest: String,
    pub space: u64,
    pub allowed: u64,
    pub denied: u64,
    pub rules: Vec<RuleReport>,
    pub invariants: Vec<InvariantReport>,
    pub ok: bool,
}

fn rule_name(policy: &Policy, r: &Region) -> String {
    r.rule
        .map_or_else(|| "default deny".into(), |i| policy.rules[i].id.clone())
}

pub fn check(policy: &Policy) -> CheckReport {
    let space = Space::new(policy);
    let regions = partition(&space, policy);

    let mut decides = vec![0u64; policy.rules.len()];
    let (mut allowed, mut denied) = (0, 0);
    for r in &regions {
        let n = count(&r.cube);
        match r.effect {
            Effect::Allow => allowed += n,
            Effect::Deny => denied += n,
        }
        if let Some(i) = r.rule {
            decides[i] += n;
        }
    }

    let rules = policy
        .rules
        .iter()
        .enumerate()
        .map(|(i, rule)| {
            let status = if decides[i] == 0 {
                RuleStatus::Dead
            } else if diff(policy, &without_rule(policy, i)).is_ok_and(|d| d.changes.is_empty()) {
                RuleStatus::Redundant
            } else {
                RuleStatus::Active
            };
            RuleReport {
                id: rule.id.clone(),
                effect: rule.effect,
                decides: decides[i],
                status,
            }
        })
        .collect();

    let invariants: Vec<InvariantReport> = policy
        .invariants
        .iter()
        .map(|inv| {
            let boxed = space.cube(&inv.when);
            let bad_effect = match inv.kind {
                InvariantKind::NeverAllow => Effect::Allow,
                InvariantKind::AlwaysAllow => Effect::Deny,
            };
            let counterexamples: Vec<Counterexample> = regions
                .iter()
                .filter(|r| r.effect == bad_effect)
                .filter_map(|r| intersect(&r.cube, &boxed).map(|c| (c, r)))
                .map(|(c, r)| Counterexample {
                    when: space.describe(&c),
                    requests: count(&c),
                    decided_by: rule_name(policy, r),
                })
                .collect();
            InvariantReport {
                id: inv.id.clone(),
                description: inv.description.clone(),
                kind: inv.kind,
                holds: counterexamples.is_empty(),
                counterexamples,
            }
        })
        .collect();

    let ok = invariants.iter().all(|i| i.holds);
    CheckReport {
        name: policy.name.clone(),
        digest: digest(policy),
        space: space.size(),
        allowed,
        denied,
        rules,
        invariants,
        ok,
    }
}

fn without_rule(policy: &Policy, i: usize) -> Policy {
    let mut p = policy.clone();
    p.rules.remove(i);
    p
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    NewlyAllowed,
    NewlyDenied,
}

#[derive(Debug, Serialize, Clone)]
pub struct Change {
    pub direction: Direction,
    pub when: When,
    pub requests: u64,
    pub was_decided_by: String,
    pub now_decided_by: String,
}

#[derive(Debug, Serialize)]
pub struct DiffReport {
    pub from_digest: String,
    pub to_digest: String,
    pub newly_allowed: u64,
    pub newly_denied: u64,
    /// Hash of the exact set of changes. An approval signs this.
    pub fingerprint: String,
    pub changes: Vec<Change>,
}

fn same_domains(a: &Policy, b: &Policy) -> bool {
    a.dimensions == b.dimensions
}

/// The exact set of requests whose decision differs between two policies.
pub fn diff(old: &Policy, new: &Policy) -> Result<DiffReport> {
    if !same_domains(old, new) {
        return err("policies have different dimensions or values, so they cannot be compared");
    }
    let space = Space::new(old);
    let (ra, rb) = (partition(&space, old), partition(&space, new));

    let mut grouped: BTreeMap<(bool, String, String), Vec<Cube>> = BTreeMap::new();
    for a in &ra {
        for b in &rb {
            if a.effect == b.effect {
                continue;
            }
            if let Some(c) = intersect(&a.cube, &b.cube) {
                let widening = b.effect == Effect::Allow;
                let key = (widening, rule_name(old, a), rule_name(new, b));
                grouped.entry(key).or_default().push(c);
            }
        }
    }

    let mut changes = Vec::new();
    let (mut allowed, mut denied) = (0, 0);
    for ((widening, was, now), cubes) in grouped {
        for c in simplify(cubes) {
            let n = count(&c);
            if widening {
                allowed += n;
            } else {
                denied += n;
            }
            changes.push(Change {
                direction: if widening {
                    Direction::NewlyAllowed
                } else {
                    Direction::NewlyDenied
                },
                when: space.describe(&c),
                requests: n,
                was_decided_by: was.clone(),
                now_decided_by: now.clone(),
            });
        }
    }
    changes.sort_by_key(|c| serde_json::to_string(c).unwrap_or_default());
    let fingerprint = sha256_hex(&serde_json::to_vec(&changes).expect("changes serialize"));
    Ok(DiffReport {
        from_digest: digest(old),
        to_digest: digest(new),
        newly_allowed: allowed,
        newly_denied: denied,
        fingerprint,
        changes,
    })
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Decision {
    pub effect: Effect,
    pub rule: String,
}

pub fn eval(policy: &Policy, request: &BTreeMap<String, String>) -> Result<Decision> {
    let space = Space::new(policy);
    let point = space.point(request)?;
    for rule in &policy.rules {
        let c = space.cube(&rule.when);
        if intersect(&c, &point).is_some() {
            return Ok(Decision {
                effect: rule.effect,
                rule: rule.id.clone(),
            });
        }
    }
    Ok(Decision {
        effect: Effect::Deny,
        rule: "default deny".into(),
    })
}

#[derive(Debug, Serialize)]
pub struct Vector {
    pub request: BTreeMap<String, String>,
    pub effect: Effect,
    pub rule: String,
}

/// Every request and its decision, for conformance tests of other evaluators.
pub fn vectors(policy: &Policy, limit: u64) -> Result<Vec<Vector>> {
    let space = Space::new(policy);
    if space.size() > limit {
        return err(format!(
            "request space {} exceeds limit {limit}",
            space.size()
        ));
    }
    let mut out = Vec::new();
    let mut idx = vec![0usize; policy.dimensions.len()];
    loop {
        let request: BTreeMap<String, String> = policy
            .dimensions
            .iter()
            .zip(&idx)
            .map(|(d, &i)| (d.name.clone(), d.values[i].clone()))
            .collect();
        let d = eval(policy, &request)?;
        out.push(Vector {
            request,
            effect: d.effect,
            rule: d.rule,
        });
        let mut k = policy.dimensions.len();
        loop {
            if k == 0 {
                return Ok(out);
            }
            k -= 1;
            idx[k] += 1;
            if idx[k] < policy.dimensions[k].values.len() {
                break;
            }
            idx[k] = 0;
        }
    }
}
