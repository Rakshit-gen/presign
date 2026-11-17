// Runs in the page. Wraps every wallet provider's request() so signing
// methods wait for presign's verdict before reaching the wallet.
(() => {
  const SIGNING = new Set([
    "eth_sendTransaction",
    "eth_signTypedData",
    "eth_signTypedData_v3",
    "eth_signTypedData_v4",
    "eth_sign",
    "personal_sign",
  ]);
  const pending = new Map();
  let seq = 0;

  window.addEventListener("message", (e) => {
    if (e.source !== window || e.data?.type !== "presign:verdict") return;
    const resolve = pending.get(e.data.id);
    if (!resolve) return;
    pending.delete(e.data.id);
    resolve(e.data.allow === true);
  });

  const check = (request) =>
    new Promise((resolve) => {
      const id = `${Date.now()}-${++seq}`;
      pending.set(id, resolve);
      window.postMessage({ type: "presign:check", id, request }, "*");
    });

  const wrapped = new WeakSet();
  function wrap(provider) {
    if (!provider || typeof provider.request !== "function" || wrapped.has(provider)) return;
    const original = provider.request.bind(provider);
    const request = async (args) => {
      if (args && SIGNING.has(args.method)) {
        const allow = await check({ method: args.method, params: args.params ?? [] });
        if (!allow) {
          throw Object.assign(new Error("presign: the user rejected the request"), { code: 4001 });
        }
      }
      return original(args);
    };
    try {
      Object.defineProperty(provider, "request", { value: request, configurable: true, writable: true });
    } catch {
      try {
        provider.request = request;
      } catch {
        return;
      }
    }
    wrapped.add(provider);
  }

  // EIP-6963: wrap each announced provider before the dapp's listener sees it.
  window.addEventListener("eip6963:announceProvider", (e) => wrap(e.detail?.provider));

  // window.ethereum, whether the wallet set it before or after this script.
  let current = window.ethereum;
  wrap(current);
  try {
    Object.defineProperty(window, "ethereum", {
      configurable: true,
      get: () => current,
      set: (v) => {
        current = v;
        wrap(v);
      },
    });
  } catch {
    // Some wallets define window.ethereum as non-configurable; it is wrapped above.
  }
})();
