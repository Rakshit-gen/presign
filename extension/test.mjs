// node --test extension/test.mjs (after extension/build.sh)
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { loadPresign } from "./presign.js";

const here = new URL(".", import.meta.url);
const fixtures = new URL("../crates/presign/tests/fixtures/", import.meta.url);

test("wasm build gives the same verdicts as the fixtures expect", async () => {
  const presign = await loadPresign(readFileSync(new URL("presign.wasm", here)));
  const bybit = JSON.parse(readFileSync(new URL("bybit_safetx_typed.json", fixtures)));
  const r = presign.analyze(bybit).ok;
  assert.equal(r.verdict, "critical");
  assert.equal(r.findings[0].code, "safe.delegatecall");
  assert.match(r.hashes.signing, /^0x[0-9a-f]{64}$/);

  const transfer = JSON.parse(readFileSync(new URL("eth_transfer.json", fixtures)));
  assert.notEqual(presign.analyze(transfer).ok.verdict, "critical");
  assert.match(presign.analyze({ method: "eth_foo" }).error, /./);

  // Repeated calls keep working: buffers are freed and reused correctly.
  for (let i = 0; i < 50; i++) {
    for (const f of readdirSync(fixtures)) {
      assert.ok(presign.analyze(JSON.parse(readFileSync(new URL(f, fixtures)))).ok);
    }
  }
});

function page() {
  const window = new EventTarget();
  const posted = [];
  window.postMessage = (data) => {
    posted.push(data);
    queueMicrotask(() => window.dispatchEvent(Object.assign(new Event("message"), { data, source: window })));
  };
  const calls = [];
  window.ethereum = { request: async (args) => (calls.push(args.method), "0xsigned") };
  runInNewContext(readFileSync(new URL("inject.js", here), "utf8"), { window, Event, CustomEvent, queueMicrotask });
  const answer = (allow) =>
    window.addEventListener("message", (e) => {
      if (e.data.type === "presign:check") window.postMessage({ type: "presign:verdict", id: e.data.id, allow });
    });
  return { window, posted, calls, answer };
}

test("signing requests wait for the verdict and reject with 4001", async () => {
  const { window, calls, answer } = page();
  answer(false);
  await assert.rejects(window.ethereum.request({ method: "eth_signTypedData_v4", params: [] }), { code: 4001 });
  assert.deepEqual(calls, []);
});

test("allowed signing requests reach the wallet", async () => {
  const { window, calls, answer } = page();
  answer(true);
  assert.equal(await window.ethereum.request({ method: "personal_sign", params: ["0x00", "0x00"] }), "0xsigned");
  assert.deepEqual(calls, ["personal_sign"]);
});

test("read-only calls pass straight through", async () => {
  const { window, posted, calls } = page();
  await window.ethereum.request({ method: "eth_chainId" });
  assert.deepEqual(calls, ["eth_chainId"]);
  assert.equal(posted.length, 0);
});

test("providers set later and EIP-6963 providers are wrapped", async () => {
  const { window, answer } = page();
  answer(false);
  window.ethereum = { request: async () => "late" };
  await assert.rejects(window.ethereum.request({ method: "eth_sign", params: [] }), { code: 4001 });
  const announced = { request: async () => "6963" };
  window.dispatchEvent(Object.assign(new Event("eip6963:announceProvider"), { detail: { provider: announced } }));
  await assert.rejects(announced.request({ method: "eth_sendTransaction", params: [{}] }), { code: 4001 });
});
