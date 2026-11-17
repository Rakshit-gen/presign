# presign

Reads the exact transaction or signature request a wallet is about to sign and
says in plain English what it does, before you sign it. It catches the
patterns behind most wallet drains: unlimited approvals, gasless Permit and
Permit2 signatures, zero-price Seaport listings, Safe delegatecalls, EIP-7702
delegations and blind `eth_sign` hashes.

It checks the raw bytes and typed data, not what the dapp's UI claims. For
typed data it also prints the EIP-712 hashes, so you can compare them with
what your hardware wallet shows. Bybit lost about $1.5B in February 2025
because the Safe UI showed one transaction while the signers' Ledgers signed
another. Comparing those hashes on the device screen is how that gets caught.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/Rakshit-gen/presign/main/scripts/install.sh | sh
```

Installs a static binary into `~/.local/bin` after checking its SHA256 against
the release. To build from source instead (Rust 1.85+):

```sh
cargo install --git https://github.com/Rakshit-gen/presign
```

## Usage

Input is the EIP-1193 request a dapp passes to `window.ethereum.request`, as a
file or on stdin.

```sh
presign tests/fixtures/bybit_safetx_typed.json
```

```
verdict: CRITICAL
signing hash: 0x00816067f634281378513f1457cf38371f6085a15e35cbca0062011abb05e18e
domain hash:  0x3abafb4fc69bc9effe736580564843cff706e076fa459a6490d7e3a1d5509f12
message hash: 0xea68fc75e93bf7286b1257680ca8e2033bfadd8e1cb8a23f3ca18f1031ecf1e0
check these match your hardware wallet screen before approving
  [critical] delegatecall to 0x96221423681A6d52E184D440a8eFCEbB105C7242 (unknown address): that contract's code runs as your Safe and can rewrite its logic, change owners and drain every asset. This is the pattern used to steal about $1.5B from Bybit in February 2025.
```

That fixture uses the real `to`, `data` and `operation` values from the Bybit
transaction. The nonce is made up, so the hashes differ from the ones Bybit's
signers saw.

`--json` prints the same report as JSON for use in other tools. Exit codes:
`0` nothing high risk, `1` high or critical risk found, `2` bad input.

As a library:

```rust
let report = presign::analyze(&request_json)?;
if report.verdict() >= presign::Severity::High { /* block or warn */ }
```

## What it checks

| Request | Pattern | Verdict |
|---|---|---|
| `approve`, `increaseAllowance` | unlimited allowance to an unknown spender | high |
| `setApprovalForAll` | every NFT in a collection to an unknown operator | high |
| EIP-2612 `Permit`, DAI `Permit` | gasless approval to an unknown spender | high, critical if unlimited |
| Permit2 `PermitSingle`, `PermitBatch`, `PermitTransferFrom` | gasless approval to an unknown spender | high, critical if unlimited or multi-token |
| Seaport `OrderComponents` | items offered with no payment back to the offerer | critical |
| Safe `execTransaction`, `SafeTx` typed data | `operation = 1` delegatecall to anything but MultiSendCallOnly | critical |
| Safe `multiSend` batch | each inner call is decoded and checked | per call |
| Safe self-calls | owner, threshold, module, guard or fallback handler changes | high, module is critical |
| EIP-7702 `authorizationList` | delegating your account to contract code | critical |
| `eth_sign` | raw hash signature | critical |
| `personal_sign` | 32 unreadable bytes | high |
| typed data | fields that do not match the declared types | high |

Spenders on a short allowlist of verified mainnet contracts (Permit2, Uniswap
Universal Router, 1inch v6, Seaport 1.6, the OpenSea conduit, Safe
MultiSendCallOnly) drop to low. The list is in `src/lib.rs`.

## Measured vs Claimed

| Claim | Value | How measured | Date |
|---|---|---|---|
| EIP-712 hashes are correct | matches spec vector | `eip712_hashes_match_the_spec_example` test, Mail example from EIP-712 | 2026-11-17 |
| Verdicts on known patterns | 22 of 22 fixtures | `cargo test`; fixtures in `tests/fixtures` are built by hand, not captured from live attacks | 2026-11-17 |
| Recall on real drainer requests | not measured yet | | |
| False positive rate on normal requests | not measured yet | | |
| p50 / p99 latency per request | not measured yet | | |

## How it works

Everything runs offline in one pass over the request. Calldata is decoded
with `alloy-sol-types`, EIP-712 hashes come from `alloy-dyn-abi`, and each
finding is a severity plus a sentence. The verdict is the highest severity
found. Safe and MultiSend calls are followed recursively up to four levels,
and anything nested deeper is reported as high rather than passed.

## Limits

- No simulation. It reads intent from the request but cannot see what an
  unknown contract will do when called. An unknown function selector is
  reported as low.
- The allowlist covers Ethereum mainnet addresses only.
- `approve(address,uint256)` has the same selector for ERC-20 and ERC-721, so
  an NFT approval shows its token id as an amount.
- For `execTransaction` calldata, the Safe hash needs the Safe's on-chain
  nonce, so hashes are only printed for `SafeTx` typed data.
- `personal_sign` text is shown but not checked against the requesting site,
  so Sign-In with Ethereum domain spoofing is not detected.

## License

MIT
