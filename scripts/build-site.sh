#!/usr/bin/env bash
# Build the Rust prover to WebAssembly and assemble the static site in ./_site.
set -euo pipefail
cd "$(dirname "$0")/.."
rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true
(cd core && cargo build --release --target wasm32-unknown-unknown --lib)
rm -rf _site && mkdir -p _site/presets
cp site/* _site/
cp core/target/wasm32-unknown-unknown/release/proofgate.wasm _site/
for f in policy policy_v2 policy_broken; do cp "examples/deploys/$f.json" "_site/presets/$f.json"; done
echo "site ready in _site"
