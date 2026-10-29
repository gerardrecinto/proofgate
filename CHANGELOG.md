# Changelog

## Unreleased

- Serialize policy proposals so approval, audit and activation use the same active bundle while concurrent decision reads remain independent.

## v0.1.0

- Rust prover: exact semantic diff between two policies, invariant proofs over the whole request space, dead and redundant rule detection, and exhaustive request vectors.
- Ruby DSL with `allow`, `deny`, `never` and `always`, and errors that point at the line.
- Go gateway: serves decisions, refuses a bundle that breaks an invariant, refuses widening without an approval bound to the exact diff, and keeps a hash-chained audit log.
- The Go evaluator is checked against the Rust one over every request in the examples.
- In-browser playground running the prover as WebAssembly.
