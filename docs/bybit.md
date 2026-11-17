# The Bybit transaction, decoded

On 21 February 2025 Bybit's Ethereum cold wallet, a Safe multisig, lost about
$1.5B. The signers approved what their Safe web interface showed as a
routine transfer. The front end they were served had been modified, and the
transaction their hardware wallets actually signed was different.

The fixture `crates/presign/tests/fixtures/bybit_safetx_typed.json` holds the
SafeTx that was signed, with the real values:

| Field | Value |
|---|---|
| Safe | `0x1Db92e2EeBC8E0c075a02BeA49a2935BcD2dFCF4` |
| `to` | `0x96221423681A6d52E184D440a8eFCEbB105C7242` |
| `data` | `transfer(0xbDd077f651EBe7f7b3cE16fe5F2b025BE2969516, 0)` |
| `operation` | `1` (delegatecall) |
| `safeTxGas` | `45746` |

The nonce in the fixture is made up, so the hashes below are not the ones
Bybit's signers saw.

## Why this transfer is not a transfer

With `operation = 1` the Safe does not call `to`. It runs `to`'s code inside
itself, with the Safe's own storage. The contract at `0x9622…` has a function
behind the `transfer(address,uint256)` selector that writes its first
argument into storage slot 0. A Safe proxy keeps its implementation address
in slot 0. After this one call, the Safe's logic was the attacker's contract
at `0xbDd0…`, which then swept the ETH and tokens out.

Nothing in the decoded call looks like an approval or a large amount. The
only signal is the operation byte and an unknown target.

## What presign prints

```
$ presign crates/presign/tests/fixtures/bybit_safetx_typed.json
verdict: CRITICAL
signing hash: 0x00816067f634281378513f1457cf38371f6085a15e35cbca0062011abb05e18e
domain hash:  0x3abafb4fc69bc9effe736580564843cff706e076fa459a6490d7e3a1d5509f12
message hash: 0xea68fc75e93bf7286b1257680ca8e2033bfadd8e1cb8a23f3ca18f1031ecf1e0
check these match your hardware wallet screen before approving
  [critical] delegatecall to 0x96221423681A6d52E184D440a8eFCEbB105C7242 (unknown address): ...
```

The same verdict comes from the `execTransaction` calldata form
(`bybit_exec_transaction.json`), which is what a relayer or co-signing
service sees.

There are two independent ways to catch it:

1. **The rule.** Any delegatecall from a Safe to something other than
   MultiSendCallOnly is critical. Legitimate Safe use almost never needs
   anything else, so the rule has no allowlist of exceptions to get wrong.
2. **The hashes.** The signing hash is computed from the bytes, not from
   what the UI rendered. If a tampered UI shows a harmless transfer, the
   hash for that transfer will not match the one on the Ledger screen.
   Ledger shows the domain and message hashes for Safe signatures, so a
   signer comparing them with presign's output, run on a separate machine,
   would see the mismatch.

Both run offline in one pass. There is no chain lookup involved.
