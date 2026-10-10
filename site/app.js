// Runs the real Rust prover, compiled to WebAssembly, in the page.
const enc = new TextEncoder();
const dec = new TextDecoder();
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

let wasm;

function put(bytes) {
  const ptr = wasm.pg_alloc(bytes.length || 1);
  new Uint8Array(wasm.memory.buffer, ptr, bytes.length).set(bytes);
  return ptr;
}

function run(op, a, b = "") {
  const A = enc.encode(a), B = enc.encode(b);
  const pa = put(A), pb = put(B);
  wasm.pg_run(op, pa, A.length, pb, B.length);
  const out = dec.decode(new Uint8Array(wasm.memory.buffer, wasm.pg_result_ptr(), wasm.pg_result_len()));
  wasm.pg_free(pa, A.length || 1);
  wasm.pg_free(pb, B.length || 1);
  return JSON.parse(out);
}

const conds = (when) => {
  const keys = Object.keys(when);
  if (!keys.length) return "<code>any request</code>";
  return keys.map((k) => `<code>${esc(k)} = ${esc(when[k].join(" | "))}</code>`).join("");
};

function render() {
  const oldText = $("old").value, newText = $("new").value;
  const verdict = $("verdict"), changes = $("changes"), invs = $("invariants");
  const checked = run(0, newText);
  if (checked.error) {
    verdict.innerHTML = "";
    changes.innerHTML = invs.innerHTML = `<div class="err">${esc(checked.error)}</div>`;
    return;
  }
  const diff = run(1, oldText, newText);
  if (diff.error) {
    verdict.innerHTML = `<div class="verdict v-bad">Cannot compare<small>${esc(diff.error)}</small></div>`;
    changes.innerHTML = "";
  }

  invs.innerHTML = checked.invariants.length
    ? checked.invariants.map((i) => `<div class="inv"><span class="pill ${i.holds ? "ok" : "no"}">${i.holds ? "PROVEN" : "FAILS"}</span><div>${esc(i.description || i.id)}${i.counterexamples.slice(0, 3).map((c) => `<div class="why">${c.requests} requests, decided by <code>${esc(c.decided_by)}</code></div><div class="conds">${conds(c.when)}</div>`).join("")}</div></div>`).join("")
    : '<div class="why">No invariants declared.</div>';

  if (diff.error) return;
  changes.innerHTML = diff.changes.length
    ? diff.changes.map((c) => `<div class="change"><span class="dir ${c.direction === "newly_allowed" ? "up" : "down"}">${c.direction === "newly_allowed" ? "NEWLY ALLOWED" : "NEWLY DENIED"}</span><b>${c.requests} request${c.requests === 1 ? "" : "s"}</b><div class="conds">${conds(c.when)}</div><div class="why">was <code>${esc(c.was_decided_by)}</code>, now <code>${esc(c.now_decided_by)}</code></div></div>`).join("")
    : '<div class="why">No request gets a different decision.</div>';

  const fp = diff.fingerprint.slice(0, 12);
  if (!checked.ok) {
    const failed = checked.invariants.filter((i) => !i.holds).map((i) => i.id).join(", ");
    verdict.innerHTML = `<div class="verdict v-bad">Blocked: an invariant fails<small>The gateway rejects this bundle (${esc(failed)}) and keeps serving the active policy.</small></div>`;
  } else if (diff.newly_allowed > 0) {
    verdict.innerHTML = `<div class="verdict v-warn">Needs approval: ${diff.newly_allowed} newly allowed request${diff.newly_allowed === 1 ? "" : "s"}<small>Invariants hold, but access widens. The gateway wants an approval token for fingerprint <code>${fp}</code>, which is not valid for any other change.</small></div>`;
  } else if (diff.newly_denied > 0) {
    verdict.innerHTML = `<div class="verdict v-ok">Safe to activate: narrows access only<small>${diff.newly_denied} request${diff.newly_denied === 1 ? "" : "s"} newly denied, none newly allowed, every invariant proven.</small></div>`;
  } else {
    verdict.innerHTML = `<div class="verdict v-info">No decision changes<small>Every request gets the same answer as before, whatever the diff of the file looks like.</small></div>`;
  }
}

async function preset(name) {
  const text = await (await fetch(`presets/${name}.json`)).text();
  $("new").value = text;
  document.querySelectorAll(".chip").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.preset === name)));
  render();
}

async function main() {
  const { instance } = await WebAssembly.instantiateStreaming(fetch("proofgate.wasm"));
  wasm = instance.exports;
  $("old").value = await (await fetch("presets/policy.json")).text();
  document.querySelectorAll(".chip").forEach((b) => b.addEventListener("click", () => preset(b.dataset.preset)));
  $("old").addEventListener("input", render);
  $("new").addEventListener("input", () => {
    document.querySelectorAll(".chip").forEach((b) => b.setAttribute("aria-pressed", "false"));
    render();
  });
  await preset("policy_v2");
}

main().catch((e) => {
  $("verdict").innerHTML = `<div class="verdict v-bad">Could not start<small>${esc(e.message)}</small></div>`;
});
