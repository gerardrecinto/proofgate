# Contributing

## Setup

You need Rust (stable), Go 1.22+, and Ruby 2.6+.

```
make test        # Rust tests, Go tests with the race detector, Ruby tests
make examples    # recompile examples/deploys/*.rb after editing one
make site        # build the WebAssembly playground into _site
```

## Where things live

- `core/`: the Rust prover. `space.rs` is the geometry, `analyze.rs` the checks and diff.
- `gateway/`: the Go gateway. `gate.go` is the decision to activate or refuse.
- `dsl/`: the Ruby DSL.
- `examples/deploys/`: the policies the tests, the demo and the site all use.

## Rules of the road

- The Go evaluator must agree with the Rust one on every request. `gateway/conformance_test.go` checks it. If you change evaluation semantics, change both and keep that test green.
- A claim the prover makes about the whole space needs a brute-force test in `core/tests/properties.rs` that checks it one request at a time.
- Compiled examples are committed. CI fails if they are stale.
- Branch from `main`, keep a change small, and write commit messages as one short line saying what changed.
