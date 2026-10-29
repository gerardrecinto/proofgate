# Security Policy

## Supported versions

Fixes go into the latest release. Older releases are not patched.

## Reporting a vulnerability

Do not open a public issue. Report it privately through [GitHub Security Advisories](https://github.com/gerardrecinto/proofgate/security/advisories/new).

Include the version, the policy or request that reproduces it, and the impact. Expect an acknowledgement within a few business days.

## What the pieces trust

- **Prover (Rust).** Parses JSON, never executes it, and makes no network calls. Request space is capped at 2^53 so counts stay exact.
- **Gateway (Go).** Runs the prover as a subprocess on a temp copy of the candidate bundle, with a timeout. Decision requests are size-limited, strictly validated, and answered from an in-memory evaluator that is checked against the prover over every request in the examples.
- **Bundle endpoint.** `PUT /v1/bundle` changes what is enforced. Put it behind your own authentication and network policy. The gateway's own protection is the invariant and approval gate, which stops a bad policy, not an unauthorized caller.
- **Approvals.** An HMAC over the old digest, the new digest and the fingerprint of the changed requests. Keep the key out of the policy repo. Without a key configured, any widening is refused.
- **Audit log.** Hash-chained, so edits and deletions are detectable. It does not stop someone with file access from truncating the tail, so ship the head hash somewhere you trust.

## What a green result does not mean

Proofgate proves facts about the policy you wrote, over the dimensions you declared. It does not know about attributes you left out, or whether your invariants are the right ones.

## Controls on this repo

CodeQL, gitleaks, `cargo audit` and `govulncheck` run on every change. CodeQL is scheduled weekly; the other security checks run daily. Dependabot raises weekly updates. Release archives carry signed build provenance and a checksum file.
