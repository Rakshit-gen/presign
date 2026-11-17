# presign browser extension

Checks every signing request a site sends to your wallet (transactions,
typed data, `eth_sign`, `personal_sign`) with presign compiled to
WebAssembly, before the wallet's own prompt opens. High and critical
requests stop on a warning that lists the findings and EIP-712 hashes, with
a choice to reject or continue to the wallet. Everything else passes through
without a prompt. Nothing leaves the browser.

## Load it

```sh
extension/build.sh          # builds presign.wasm into this folder
node --test extension/test.mjs
```

Then in Chrome, open `chrome://extensions`, turn on Developer mode, choose
Load unpacked and pick this folder.

## How it hooks in

- `inject.js` runs in the page at `document_start`. It wraps `request()` on
  `window.ethereum` (including a provider assigned later) and on every
  provider announced through EIP-6963.
- `content.js` relays each signing request to the service worker and shows
  the warning in a closed shadow root. Findings are inserted as text, never
  HTML, since `personal_sign` messages are attacker-written.
- `background.js` runs the WebAssembly build. The analysis runs there
  because a page's CSP can forbid WebAssembly in the page itself.

## Limits

This is a warning layer inside a page the attacker may control. A script
written specifically against presign can post its own allow message or keep
a reference to the unwrapped provider, so it stops drainer kits that call the
wallet the normal way, not one built to evade it. Legacy `send` and
`sendAsync` calls are not wrapped. For an enforcement point, put
`presign-server` or the library behind the wallet or signing service instead.
