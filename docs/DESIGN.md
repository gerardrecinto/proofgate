# Design

## The problem

Access policies are code, and they get refactored like code. A reviewer reads the text diff of a policy file. What matters is the diff of the decisions: which requests used to be denied and are now allowed. In a first-match policy the two have little to do with each other. Moving one rule up, or deleting a "redundant" deny, can flip requests far from the lines that changed.

Proofgate computes the decision diff exactly, proves the invariants you declared, and makes both a condition of activating a policy.

## The model

A policy declares **dimensions**, each with a finite list of values (`env`, `role`, `action`, `approved`). A request picks one value per dimension. A **rule** has an effect and a condition: for each dimension it mentions, a set of values it matches. The first rule that matches decides, and a request no rule matches is denied.

An **invariant** is a `never` (no request in this region may be allowed) or an `always` (every request in this region must be allowed).

The model is deliberately small. Finite dimensions are what make every question about a policy exactly decidable without a solver.

## How the prover works

A rule's condition is a hyper-rectangle in the request space. Store it as one 64-bit mask per dimension. Then:

- **Intersection** is a bitwise AND per dimension. It is empty if any mask is zero.
- **Difference** `A - B` splits into at most one disjoint piece per dimension: the part of `A` outside `B` on dimension `i`, restricted to `B` on dimensions before `i`.
- **Size** is the product of popcounts.

First-match semantics turn into a partition of the whole space. Walk the rules in order and give each one its box minus everything earlier rules already took. What no rule takes is the default deny. The result is a list of disjoint regions, each with the rule that decides it.

Everything else is a query over two such partitions:

- **Diff.** Intersect every region of the old policy with every region of the new one. Where the effects differ, those requests flipped. Because regions are disjoint, the counts are exact. Adjacent cubes are merged for readability, and the result is grouped by the pair of rules responsible.
- **Invariants.** Intersect the invariant's box with every region of the bad effect. Anything left is a counterexample, reported with the rule that decides it.
- **Dead and redundant rules.** A rule is dead if it decides no request. It is redundant if removing it changes no decision, which is a diff of the policy against itself minus that rule.

## Proof-carrying activation

The gateway treats a policy change as something that must come with evidence.

1. The candidate is checked. Any failed invariant rejects it.
2. The candidate is diffed against the active policy. If nothing is newly allowed, it activates. Narrowing never needs approval.
3. If anything is newly allowed, an approval token is required: `HMAC-SHA256(key, old_digest | new_digest | fingerprint)`. The fingerprint is a hash of the exact list of changes. The token authorises that change and no other, so editing the policy after approval invalidates it.
4. Activation and rejection are both appended to a hash-chained log.

Without an approval key configured, widening is always refused.

## Three languages, one contract

The Ruby DSL emits the JSON IR. The Rust prover reads it. The Go gateway reads it. Nothing else is shared, so a change to evaluation semantics has to be made twice. To keep the two evaluators from drifting:

- Rust can emit every request in a policy's space with its decision (`proofgate vectors`).
- The Go test replays all of them through the gateway's evaluator and fails on any disagreement.
- The Rust prover is itself checked against a brute-force evaluator on randomized policies: counts, diffs, invariants and redundancy, one request at a time.

The same Rust code compiles to WebAssembly for the playground. There is no JavaScript reimplementation.

## Limits

- Dimensions are finite and enumerated, at most 64 values each, and the whole space is at most 2^53 requests so counts are exact in JSON.
- No ranges, regexes, or comparisons between attributes. Bucket them into values.
- Only first-match with default deny. No priorities or deny-overrides.
- Diff needs identical dimensions in both policies. Adding a value is a separate, explicit migration.
- Many overlapping rules can fragment the partition into many cubes. It stays fast for policies with dozens of rules over a few thousand requests, which is the intended scale.

## Prior art

Semantic analysis of access policies is established work, and this project builds on that idea rather than inventing it:

- Fisler, Krishnamurthi, Meyerovich and Tschantz, "Verification and change-impact analysis of access-control policies" (ICSE 2005), introduced policy change-impact analysis in Margrave.
- AWS uses SMT-based reasoning over IAM policies (Backes et al., FMCAD 2018, Zelkova).
- Cedar was designed to be analyzable.

What Proofgate adds is a practical packaging: exact diff without a solver for a finite model, an activation gate that binds an approval to the fingerprint of the diff, and one proof engine shared by a CLI, a gateway and a browser. It has not been through a formal prior-art search.
