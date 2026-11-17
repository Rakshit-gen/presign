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
the release. To build from source instead (Rust 1.90+):

```sh
cargo install --git https://github.com/Rakshit-gen/presign presign-cli
```

## Usage

Input is the EIP-1193 request a dapp passes to `window.ethereum.request`, as a
file or on stdin.

```sh
presign crates/presign/tests/fixtures/bybit_safetx_typed.json
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

With `--rpc URL` (or `PRESIGN_RPC`), presign also looks up every unknown
spender's code. An approval or permit to a plain wallet, or to a wallet
running EIP-7702 delegated code, is raised to critical: apps take approvals
through contracts, drainers collect them in wallets. A failed lookup shows up
as its own finding.

```sh
presign --rpc https://ethereum-rpc.publicnode.com crates/presign/tests/fixtures/increase_allowance_unknown.json
```

## HTTP API

`presign-server` serves the same analysis over HTTP:

```sh
docker build -t presign-server . && docker run -p 8080:8080 presign-server
curl -s localhost:8080/v1/analyze --data @crates/presign/tests/fixtures/bybit_exec_transaction.json
```

| Route | |
|---|---|
| `POST /v1/analyze` | EIP-1193 request in, report JSON out. 400 bad JSON, 422 not a signing request, 413 over the body limit |
| `GET /healthz` | liveness |
| `GET /metrics` | Prometheus: requests by verdict, rejects, latency histogram |

Settings come from the environment: `PRESIGN_ADDR` (default `0.0.0.0:8080`),
`PRESIGN_RPC`, `PRESIGN_MAX_BODY` (bytes, default 262144) and
`PRESIGN_RPC_TIMEOUT_MS` (default 3000). If chain lookups run past the
timeout, the offline report is returned with `"online": "timeout"`.

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
| Safe `execTransaction`, `SafeTx` typed data | `operation = 1` delegatecall to anything but Safe's MultiSend contracts | critical |
| Safe `multiSend` batch | each inner call is decoded and checked | per call |
| Safe self-calls | owner, threshold, module, guard or fallback handler changes | high, module is critical |
| EIP-7702 `authorizationList` | delegating your account to contract code | critical, medium for the audited implementations ethereum.org lists |
| `eth_sign` | raw hash signature | critical |
| `personal_sign` | 32 unreadable bytes | high |
| typed data | fields that do not match the declared types | high |

Spenders on a short allowlist of verified mainnet contracts (Permit2, Uniswap
Universal Router, 1inch v6, Seaport 1.6, the OpenSea conduit, Safe
MultiSend) drop to low. The list is in `crates/presign/src/known.rs`.

## Measured vs Claimed

| Claim | Value | How measured | Date |
|---|---|---|---|
| EIP-712 hashes are correct | matches spec vector | `eip712_hashes_match_the_spec_example` test, Mail example from EIP-712 | 2026-11-17 |
| Verdicts on known patterns | 22 of 22 fixtures | `cargo test`; fixtures in `crates/presign/tests/fixtures` are built by hand, not captured from live attacks | 2026-11-17 |
| Recall on real drainer requests | 75.7% offline, 79.6% with `--rpc` (178 and 187 of 235); 93.2% and 97.9% excluding contract calls to the drainer | holdout of 300 ScamSniffer-listed drainers not used for any tuning; 95% CIs and method in [docs/eval.md](docs/eval.md) | 2026-11-17 |
| False positive rate on normal requests | 3.9% (22/568); 0.6% (3/502) on ordinary transactions | benign requests from one hour of mainnet blocks, same holdout | 2026-11-17 |
| In-process latency per request | p50 0.7 to 1.0 µs, p99 57 to 120 µs | `presign-eval score`, Apple M4, single thread; p99 varied across runs | 2026-11-17 |
| Server throughput, offline | 159k req/s (Safe tx), 106k req/s (EIP-712 permit), 0 failed | local, synthetic: Apple M4, 10 cores, release build, `ab -k -n 100000 -c 32`, after a 5000-request warm-up; see [docs/benchmarks.md](docs/benchmarks.md) | 2026-11-17 |
| Server latency, offline | client p50 under 1 ms, p99 1 ms; handler mean 27 µs, 97.3% under 100 µs, 99.7% under 250 µs | same runs; client side from `ab` (whole ms only), handler side from the `/metrics` histogram over all 210,000 requests | 2026-11-17 |

## How it works

By default everything runs offline in one pass over the request. Calldata is decoded
with `alloy-sol-types`, EIP-712 hashes come from `alloy-dyn-abi`, and each
finding is a severity plus a sentence. The verdict is the highest severity
found. Safe and MultiSend calls are followed recursively up to four levels,
and anything nested deeper is reported as high rather than passed.

## Limits

- No simulation. It reads intent from the request but cannot see what an
  unknown contract will do when called. An unknown function selector is
  reported as low, and this is where most measured misses are.
- A permit to any unknown spender is high, which is most of the measured
  false alarms. See [docs/eval.md](docs/eval.md) for the breakdown.
- The allowlist covers Ethereum mainnet addresses only.
- `approve(address,uint256)` has the same selector for ERC-20 and ERC-721, so
  an NFT approval shows its token id as an amount.
- For `execTransaction` calldata, the Safe hash needs the Safe's on-chain
  nonce, so hashes are only printed for `SafeTx` typed data.
- `personal_sign` text is shown but not checked against the requesting site,
  so Sign-In with Ethereum domain spoofing is not detected.

## License

MIT
