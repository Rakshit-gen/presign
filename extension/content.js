// Extension side of the page bridge: asks the service worker for a verdict
// and, for high or critical requests, asks the user before letting it through.
const BLOCKING = new Set(["high", "critical"]);

window.addEventListener("message", async (e) => {
  if (e.source !== window || e.data?.type !== "presign:check") return;
  const { id, request } = e.data;
  let reply;
  try {
    reply = await chrome.runtime.sendMessage({ request });
  } catch (err) {
    reply = { error: String(err) };
  }
  const report = reply?.ok;
  const allow = report && !BLOCKING.has(report.verdict) ? true : await ask(report, reply?.error);
  window.postMessage({ type: "presign:verdict", id, allow }, "*");
});

function ask(report, error) {
  return new Promise((resolve) => {
    const host = document.createElement("div");
    const root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
      .wrap { position: fixed; inset: 0; z-index: 2147483647; background: rgba(0,0,0,.45);
              display: flex; align-items: center; justify-content: center; font: 14px/1.45 system-ui, sans-serif; }
      .box { background: #fff; color: #111; max-width: 560px; width: calc(100% - 32px);
             max-height: 80vh; overflow: auto; padding: 20px; border-radius: 6px; border: 1px solid #ccc; }
      h2 { margin: 0 0 4px; font-size: 18px; }
      .verdict { color: #b00020; font-weight: 600; text-transform: uppercase; }
      ul { padding-left: 18px; }
      li { margin: 6px 0; word-break: break-word; }
      code { font: 12px ui-monospace, monospace; word-break: break-all; }
      .row { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; }
      button { font: inherit; padding: 8px 14px; border-radius: 4px; border: 1px solid #888; background: #fff; cursor: pointer; }
      button.reject { background: #111; color: #fff; border-color: #111; }`;
    const wrap = el("div", "wrap");
    const box = el("div", "box");
    box.append(el("h2", "", "presign"));
    if (report) {
      const p = el("p");
      p.append("Verdict: ", el("span", "verdict", report.verdict));
      box.append(p);
      const list = el("ul");
      for (const f of report.findings) list.append(el("li", "", `[${f.severity}] ${f.message}`));
      box.append(list);
      if (report.hashes) {
        box.append(el("p", "", "Compare with your hardware wallet screen:"));
        for (const [k, v] of Object.entries(report.hashes)) {
          const line = el("div");
          line.append(`${k}: `, el("code", "", v));
          box.append(line);
        }
      }
    } else {
      box.append(el("p", "", `presign could not read this request: ${error ?? "unknown error"}`));
    }
    const row = el("div", "row");
    const sign = el("button", "", "Continue to wallet");
    const reject = el("button", "reject", "Reject");
    row.append(sign, reject);
    box.append(row);
    wrap.append(box);
    root.append(style, wrap);
    const done = (allow) => {
      host.remove();
      resolve(allow);
    };
    sign.addEventListener("click", () => done(true));
    reject.addEventListener("click", () => done(false));
    (document.body ?? document.documentElement).append(host);
    reject.focus();
  });
}

function el(tag, cls = "", text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}
