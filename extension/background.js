import { loadPresign } from "./presign.js";

const presign = fetch(chrome.runtime.getURL("presign.wasm"))
  .then((r) => r.arrayBuffer())
  .then(loadPresign);

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  presign
    .then((p) => reply(p.analyze(msg.request)))
    .catch((e) => reply({ error: String(e) }));
  return true;
});
