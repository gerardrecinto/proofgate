// Runs the built WebAssembly prover on the example policies and checks the known answer.
import { readFileSync } from "node:fs";

const enc = new TextEncoder();
const dec = new TextDecoder();
const { instance } = await WebAssembly.instantiate(readFileSync("_site/proofgate.wasm"));
const x = instance.exports;

function run(op, a, b = "") {
  const put = (bytes) => {
    const ptr = x.pg_alloc(bytes.length || 1);
    new Uint8Array(x.memory.buffer, ptr, bytes.length).set(bytes);
    return ptr;
  };
  const [A, B] = [enc.encode(a), enc.encode(b)];
  const [pa, pb] = [put(A), put(B)];
  x.pg_run(op, pa, A.length, pb, B.length);
  const out = dec.decode(new Uint8Array(x.memory.buffer, x.pg_result_ptr(), x.pg_result_len()));
  x.pg_free(pa, A.length || 1);
  x.pg_free(pb, B.length || 1);
  return JSON.parse(out);
}

const read = (n) => readFileSync(`examples/deploys/${n}.json`, "utf8");
const diff = run(1, read("policy"), read("policy_v2"));
const broken = run(0, read("policy_broken"));
const bad = run(0, "{}");

const checks = [
  [diff.newly_allowed === 7 && diff.newly_denied === 0, "v1 to v2 newly allows exactly 7 requests"],
  [broken.ok === false, "the broken policy fails an invariant"],
  [typeof bad.error === "string", "invalid input returns an error object"],
];
for (const [ok, what] of checks) console.log(`${ok ? "ok  " : "FAIL"} ${what}`);
process.exit(checks.every(([ok]) => ok) ? 0 : 1);
