# Threat model

## What presign sees

One EIP-1193 request, exactly as a dapp passes it to
`window.ethereum.request`: `eth_sendTransaction`, `eth_signTypedData_v4`
(and v3), `eth_sign` or `personal_sign`. That is the last point where the
user's intent and the bytes that will be signed can be compared, so every
check reads the bytes rather than anything the dapp says about them.

With `--rpc` or `PRESIGN_RPC`, it can also read one piece of chain state:
the code at an approval's spender address.

## Who is trusted

| Party | Trusted? | Why it matters |
|---|---|---|
| The dapp or site making the request | No | Drainer kits are dapps. Any label, amount or preview a site shows is ignored. |
| The wallet or multisig UI | No | Bybit's signers were shown one transaction while their devices signed another. presign decodes the request independently and prints the EIP-712 hashes so they can be compared with the hardware wallet screen. |
| The hardware wallet screen | Yes | It is the one display an attacker who owns the browser cannot change. The hash check only works if someone reads it. |
| The allowlist in `known.rs` | Yes | Each address was checked on Etherscan. A wrong entry would downgrade a real drain to low, so entries are few and mainnet only. |
| The RPC node | Partly | See below. |
| The machine running presign | Yes | Malware on that machine can change presign's output too. Running it somewhere other than the signing browser (a CLI on another host, the server behind the wallet backend) is what keeps it independent. |

## RPC node

Online checks can only add findings. They never remove or lower one the
offline pass produced. So a lying or unreachable node can at worst hide the
"spender is a plain wallet" escalation; the offline verdict still stands.
When a lookup fails, that becomes its own medium finding rather than a silent
pass. The server returns the offline report, marked `"online": "timeout"`,
when lookups run past `PRESIGN_RPC_TIMEOUT_MS`.

## In scope

- Approvals and permits that hand a spender control of tokens or NFTs:
  `approve`, `increaseAllowance`, `setApprovalForAll`, EIP-2612 and DAI
  permits, every Permit2 signature type.
- Seaport orders that give items away without payment to the signer.
- Safe transactions that delegatecall, change owners, threshold, modules,
  guards or fallback handler, including calls hidden inside MultiSend
  batches up to four levels deep.
- EIP-7702 authorizations, which hand an EOA's code to a contract, including
  chain id 0 authorizations that apply on every chain.
- Signatures over raw hashes (`eth_sign`, 32-byte `personal_sign`), which can
  authorize anything.

## Out of scope

- What an unknown contract does when called. presign has no simulator; a call
  to an unrecognized function is low. A victim paying ETH into a fake
  "claim" function is the main pattern this misses, and the eval measures it.
- Whether the site is the one the user meant to visit. Phishing domains and
  Sign-In with Ethereum domain mismatches are not checked.
- Address poisoning on plain transfers. A transfer to a lookalike address is
  decoded but not compared with the user's address book.
- Chains other than Ethereum mainnet for the allowlist. Decoding and hashing
  work on any EVM chain; trusted addresses do not carry over.
- Chain state at signing time versus later. The spender lookup reads the
  latest block, which is what matters when deciding to sign now.

## Failure behaviour

Unreadable input is an error (CLI exit 2, HTTP 400 or 422), never a pass.
Input that parses but cannot be understood is a finding: malformed typed
data, unknown Safe operation values and over-deep nesting are high, and
hostile calldata is covered by a no-panic test.
