#!/usr/bin/env bash
# Walk the whole flow: compile in Ruby, prove in Rust, gate in Go. Needs `make build` first.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
cleanup() {
  if [ -n "${pid:-}" ]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT
cp "$root"/examples/deploys/* "$work"/ && cd "$work"
export PATH="$root/dsl/bin:$root/core/target/release:$root/bin:$PATH"
echo demo-key > key
say() { printf '\n\033[1m# %s\033[0m\n' "$*"; sleep 1; }
run() { printf '$ %s\n' "$*"; sleep 0.6; eval "$*"; sleep 1.8; }
msg() { sed 's/,"evidence".*//; s/^{"error":/  refused: /'; }

say "Ruby: write the policy, compile it"
run "proofgate-rb compile policy_v2.rb -o v2.json && echo compiled v2.json"

say "Rust: what does the proposed change really do?"
run "proofgate diff policy.json v2.json"

say "Go: the gateway serves v1 and refuses that change"
proofgate-gateway serve -addr 127.0.0.1:8099 -prover "$root/core/target/release/proofgate" \
  -bundle policy.json -audit audit.jsonl -approval-key-file key 2>/dev/null &
pid=$!; sleep 1
run "curl -s -X PUT --data-binary @v2.json localhost:8099/v1/bundle | msg"

say "A broken invariant is refused outright"
run "curl -s -X PUT --data-binary @policy_broken.json localhost:8099/v1/bundle | msg"

say "An approval is bound to that exact change"
run "proofgate-gateway approve -key-file key policy.json v2.json > token"
run "curl -s -X PUT -H \"X-Proofgate-Approval: \$(cat token)\" --data-binary @v2.json localhost:8099/v1/bundle"

say "Every activation and rejection is on a hash chain"
run "proofgate-gateway verify-audit audit.jsonl"
