//! The prover is checked against brute force: every claim it makes about the whole space is
//! compared with evaluating each request one at a time.

use proofgate::analyze::{check, diff, digest, eval, vectors, RuleStatus};
use proofgate::model::{Dimension, Effect, Invariant, InvariantKind, Policy, Rule};
use std::collections::BTreeMap;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn dims() -> Vec<Dimension> {
    let d = |n: &str, v: &[&str]| Dimension {
        name: n.into(),
        values: v.iter().map(|s| s.to_string()).collect(),
    };
    vec![
        d("a", &["a0", "a1", "a2"]),
        d("b", &["b0", "b1"]),
        d("c", &["c0", "c1", "c2", "c3"]),
    ]
}

fn random_when(rng: &mut Rng, dims: &[Dimension]) -> BTreeMap<String, Vec<String>> {
    let mut when = BTreeMap::new();
    for d in dims {
        if rng.below(3) > 0 {
            let vals: Vec<String> = d
                .values
                .iter()
                .filter(|_| rng.below(2) == 0)
                .cloned()
                .collect();
            if !vals.is_empty() {
                when.insert(d.name.clone(), vals);
            }
        }
    }
    when
}

fn random_policy(rng: &mut Rng) -> Policy {
    let dimensions = dims();
    let rules = (0..rng.below(7))
        .map(|i| Rule {
            id: format!("r{i}"),
            description: String::new(),
            effect: if rng.below(2) == 0 {
                Effect::Allow
            } else {
                Effect::Deny
            },
            when: random_when(rng, &dimensions),
        })
        .collect();
    let invariants = (0..rng.below(3))
        .map(|i| Invariant {
            id: format!("i{i}"),
            description: String::new(),
            kind: if rng.below(2) == 0 {
                InvariantKind::NeverAllow
            } else {
                InvariantKind::AlwaysAllow
            },
            when: random_when(rng, &dimensions),
        })
        .collect();
    let p = Policy {
        version: 1,
        name: "p".into(),
        dimensions,
        rules,
        invariants,
    };
    p.validate().unwrap();
    p
}

fn matches(request: &BTreeMap<String, String>, when: &BTreeMap<String, Vec<String>>) -> bool {
    when.iter().all(|(k, vals)| vals.contains(&request[k]))
}

/// The definition of the language, written the obvious way.
fn naive(p: &Policy, request: &BTreeMap<String, String>) -> (Effect, String) {
    p.rules
        .iter()
        .find(|r| matches(request, &r.when))
        .map_or((Effect::Deny, "default deny".into()), |r| {
            (r.effect, r.id.clone())
        })
}

fn all_requests(p: &Policy) -> Vec<BTreeMap<String, String>> {
    vectors(p, 1_000_000)
        .unwrap()
        .into_iter()
        .map(|v| v.request)
        .collect()
}

#[test]
fn eval_matches_the_definition() {
    let mut rng = Rng(0x9e3779b97f4a7c15);
    for _ in 0..200 {
        let p = random_policy(&mut rng);
        for req in all_requests(&p) {
            let got = eval(&p, &req).unwrap();
            assert_eq!((got.effect, got.rule), naive(&p, &req));
        }
    }
}

#[test]
fn allowed_and_denied_counts_are_exact() {
    let mut rng = Rng(42);
    for _ in 0..200 {
        let p = random_policy(&mut rng);
        let r = check(&p);
        let reqs = all_requests(&p);
        let allowed = reqs
            .iter()
            .filter(|q| naive(&p, q).0 == Effect::Allow)
            .count() as u64;
        assert_eq!(r.allowed, allowed);
        assert_eq!(r.allowed + r.denied, reqs.len() as u64);
        for rule in &r.rules {
            let decides = reqs.iter().filter(|q| naive(&p, q).1 == rule.id).count() as u64;
            assert_eq!(rule.decides, decides, "rule {}", rule.id);
        }
    }
}

#[test]
fn diff_is_exactly_the_requests_that_changed() {
    let mut rng = Rng(7);
    for _ in 0..300 {
        let (a, b) = (random_policy(&mut rng), random_policy(&mut rng));
        let d = diff(&a, &b).unwrap();
        let (mut widened, mut narrowed) = (0, 0);
        for req in all_requests(&a) {
            match (naive(&a, &req).0, naive(&b, &req).0) {
                (Effect::Deny, Effect::Allow) => widened += 1,
                (Effect::Allow, Effect::Deny) => narrowed += 1,
                _ => {}
            }
        }
        assert_eq!((d.newly_allowed, d.newly_denied), (widened, narrowed));
        assert_eq!(
            d.changes.iter().map(|c| c.requests).sum::<u64>(),
            widened + narrowed
        );
    }
}

#[test]
fn diff_with_itself_is_empty_and_symmetric() {
    let mut rng = Rng(99);
    for _ in 0..100 {
        let (a, b) = (random_policy(&mut rng), random_policy(&mut rng));
        assert!(diff(&a, &a).unwrap().changes.is_empty());
        let (ab, ba) = (diff(&a, &b).unwrap(), diff(&b, &a).unwrap());
        assert_eq!(
            (ab.newly_allowed, ab.newly_denied),
            (ba.newly_denied, ba.newly_allowed)
        );
    }
}

#[test]
fn invariants_agree_with_brute_force() {
    let mut rng = Rng(1234);
    for _ in 0..300 {
        let p = random_policy(&mut rng);
        let r = check(&p);
        for (inv, rep) in p.invariants.iter().zip(&r.invariants) {
            let violated = all_requests(&p).iter().any(|q| {
                matches(q, &inv.when)
                    && match inv.kind {
                        InvariantKind::NeverAllow => naive(&p, q).0 == Effect::Allow,
                        InvariantKind::AlwaysAllow => naive(&p, q).0 == Effect::Deny,
                    }
            });
            assert_eq!(rep.holds, !violated, "invariant {}", inv.id);
        }
    }
}

#[test]
fn redundant_rules_really_change_nothing() {
    let mut rng = Rng(5);
    for _ in 0..200 {
        let p = random_policy(&mut rng);
        for (i, rule) in check(&p).rules.iter().enumerate() {
            if rule.status == RuleStatus::Active {
                continue;
            }
            let mut without = p.clone();
            without.rules.remove(i);
            assert!(
                diff(&p, &without).unwrap().changes.is_empty(),
                "rule {} is not redundant",
                rule.id
            );
        }
    }
}

#[test]
fn dead_and_redundant_are_reported() {
    let p = Policy::parse(
        r#"{"version":1,"name":"p","dimensions":[{"name":"a","values":["x","y"]}],
        "rules":[
          {"id":"all","effect":"allow","when":{}},
          {"id":"shadowed","effect":"deny","when":{"a":["x"]}},
          {"id":"noop","effect":"allow","when":{"a":["y"]}}]}"#,
    )
    .unwrap();
    let r = check(&p);
    assert_eq!(r.rules[0].status, RuleStatus::Active);
    assert_eq!(r.rules[1].status, RuleStatus::Dead);
    assert_eq!(r.rules[2].status, RuleStatus::Dead);
}

#[test]
fn digest_ignores_formatting_and_key_order() {
    let a = r#"{"version":1,"name":"p","dimensions":[{"name":"a","values":["x"]}],"rules":[{"id":"r","effect":"allow","when":{"a":["x"]}}]}"#;
    let b = r#"{
      "rules": [ {"when": {"a": ["x"]}, "effect": "allow", "id": "r", "description": ""} ],
      "dimensions": [ {"values": ["x"], "name": "a"} ], "name": "p", "version": 1, "invariants": []
    }"#;
    assert_eq!(
        digest(&Policy::parse(a).unwrap()),
        digest(&Policy::parse(b).unwrap())
    );
}

#[test]
fn bad_policies_are_refused_with_a_reason() {
    let cases = [
        (
            r#"{"version":2,"name":"p","dimensions":[],"rules":[]}"#,
            "unsupported policy version",
        ),
        (
            r#"{"version":1,"name":"p","dimensions":[],"rules":[]}"#,
            "no dimensions",
        ),
        (
            r#"{"version":1,"name":"p","dimensions":[{"name":"a","values":["x","x"]}],"rules":[]}"#,
            "duplicate value",
        ),
        (
            r#"{"version":1,"name":"p","dimensions":[{"name":"a","values":["x"]}],"rules":[{"id":"r","effect":"allow","when":{"b":["x"]}}]}"#,
            "unknown dimension 'b'",
        ),
        (
            r#"{"version":1,"name":"p","dimensions":[{"name":"a","values":["x"]}],"rules":[{"id":"r","effect":"allow","when":{"a":["z"]}}]}"#,
            "unknown value 'z'",
        ),
        (
            r#"{"version":1,"name":"p","dimensions":[{"name":"a","values":["x"]}],"rules":[{"id":"r","effect":"allow"},{"id":"r","effect":"deny"}]}"#,
            "duplicated",
        ),
        (
            r#"{"version":1,"name":"p","dimensions":[{"name":"a","values":["x"]}],"rules":[],"extra":1}"#,
            "unknown field",
        ),
    ];
    for (json, want) in cases {
        let e = Policy::parse(json).unwrap_err().0;
        assert!(e.contains(want), "{e} should contain {want}");
    }
}

#[test]
fn diff_refuses_different_domains() {
    let a = Policy::parse(
        r#"{"version":1,"name":"p","dimensions":[{"name":"a","values":["x"]}],"rules":[]}"#,
    )
    .unwrap();
    let b = Policy::parse(
        r#"{"version":1,"name":"p","dimensions":[{"name":"a","values":["x","y"]}],"rules":[]}"#,
    )
    .unwrap();
    assert!(diff(&a, &b).is_err());
}

#[test]
fn eval_rejects_malformed_requests() {
    let p = Policy::parse(
        r#"{"version":1,"name":"p","dimensions":[{"name":"a","values":["x"]}],"rules":[]}"#,
    )
    .unwrap();
    let req = |kv: &[(&str, &str)]| {
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };
    assert!(eval(&p, &req(&[])).is_err());
    assert!(eval(&p, &req(&[("a", "nope")])).is_err());
    assert!(eval(&p, &req(&[("a", "x"), ("z", "x")])).is_err());
}

#[test]
fn space_limit_is_enforced() {
    let dims: Vec<String> = (0..10)
        .map(|i| {
            format!(
                r#"{{"name":"d{i}","values":[{}]}}"#,
                (0..64)
                    .map(|v| format!("\"v{v}\""))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        })
        .collect();
    let json = format!(
        r#"{{"version":1,"name":"p","dimensions":[{}],"rules":[]}}"#,
        dims.join(",")
    );
    assert!(Policy::parse(&json)
        .unwrap_err()
        .0
        .contains("larger than 2^53"));
}
