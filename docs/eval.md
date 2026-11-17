# Evaluation

presign was scored on wallet requests rebuilt from real Ethereum mainnet
activity: requests that led to drains by addresses on ScamSniffer's
blacklist, and requests from ordinary recent blocks. All numbers below were
measured on 2026-11-17.

## Headline (clean holdout)

| | Offline | Online (`--rpc`) |
|---|---|---|
| Recall, drainer requests flagged high or critical | 75.7% (178/235), CI 69.9% to 80.8% | 79.6% (187/235), CI 74.0% to 84.2% |
| Recall without `victim_call` (see below) | 93.2% (178/191), CI 88.7% to 96.0% | 97.9% (187/191), CI 94.7% to 99.2% |
| False positive rate, benign requests flagged high or critical | 3.9% (22/568), CI 2.6% to 5.8% | 3.9% (22/568), CI 2.6% to 5.8% |
| False positive rate on ordinary transactions only | 0.6% (3/502), CI 0.2% to 1.7% | same |
| Latency per request, p50 / p99 | 0.7 to 1.0 µs / 57 to 120 µs | not measured (would time the node) |

Intervals are 95% Wilson score intervals. Latency is single-threaded,
in-process `presign::analyze` on an Apple M4, five timed passes per request.
p99 moved between 49 and 120 µs across runs on the same day while other
builds were running, so it is given as a range.

The holdout was not used to make any change to presign. It was built after
the changes listed under "What changed after the dev set", from drainers
the dev set did not sample, and scored with transactions shared with the dev
set removed.

## Reproduce

```sh
cargo build --release -p presign-eval
# dev set: first 300 drainers of the seeded ranking
./target/release/presign-eval build --out eval/data
# holdout: the next 300 drainers, built later so its blocks are newer
./target/release/presign-eval build --out eval/holdout --offset 300
./target/release/presign-eval score --data eval/holdout --exclude eval/data
./target/release/presign-eval score --data eval/holdout --exclude eval/data \
  --rpc https://ethereum-rpc.publicnode.com
```

Each build takes about 90 minutes because Blockscout's free API is paced at
about one request a second. The datasets are not committed: the blacklist is
GPL-3.0. Each build writes a `manifest.json` with the blacklist commit
(`82fb7b1b` for both builds here), seed, drainer offset, block range and
sample counts, and lists any drainers or blocks it had to skip (none in
either build).

## How samples are labelled

**Drainer** samples start from a seeded random sample of the 2,530 addresses
on ScamSniffer's blacklist. For each address, up to 5 of each:

- `victim_approval`: tokens the address pulled from a wallet with
  `transferFrom` or `safeTransferFrom`. The owner's `Approval` or
  `ApprovalForAll` naming the address, within 10,000 blocks before the pull,
  leads to the owner's approve transaction, which becomes the
  `eth_sendTransaction` request they signed.
- `permit`, `permit_dai`, `permit2_*`: permits the address redeemed, rebuilt
  into the `eth_signTypedData_v4` request the owner signed. The calldata
  carries every signed field; the token's EIP-712 name and version and the
  EIP-2612 nonce are placeholders, which changes the hash but not the
  verdict.
- `seaport_order`: Seaport orders the address fulfilled that another wallet
  signed and that gave away an NFT, rebuilt into the `OrderComponents`
  request.
- `victim_call`: contract calls other wallets sent to the address.

Tokens an owner sent by hand are skipped. On-chain, a victim tricked into
sending and someone moving tokens between their own wallets look the same.

**Benign** samples come from 300 consecutive recent blocks: three seeded
random transactions per block, plus every permit redemption and Seaport
fulfillment in range, rebuilt the same way. Anything touching a listed
address is skipped.

## What changed after the dev set

The dev set is the first build (`eval/data`). Its numbers, before any
change, were recall 59.3% (194/327), CI 53.9% to 64.5%, and false positive
rate 4.9% (52/1054), offline. Reading every error led to three changes:

1. **Label fix.** 37 drainer-labelled Seaport orders (36 of them misses)
   were bids: WETH offered
   for an NFT, filled by the drainer while selling stolen NFTs to honest
   bidders. The bidder signed them and lost nothing. The builder no longer
   labels an order as a drainer request unless it gives away an NFT. With
   them removed, the dev set scores 65.5% (190/290) offline.
2. **Safe MultiSend.** One benign Safe transaction delegatecalled Safe's
   MultiSend 1.5.0. Delegatecall into any official MultiSend deployment
   (from `safe-global/safe-deployments`) is now accepted, and each call in
   the batch is still checked, so a hidden delegatecall stays critical.
3. **Audited 7702 delegates.** 8 of 9 benign EIP-7702 transactions delegated
   to smart-account implementations. Delegation to the six audited
   implementations ethereum.org lists is now medium. The list was taken from
   ethereum.org, not from the dev set, so Tangem, ZeroDev Kernel and others
   seen in the data are still critical.

Online mode was added before the dev set was scored and was not tuned on it.

## Where it fails

**`victim_call` (44 of 57 holdout misses).** A wallet calling a function on
the listed contract, sometimes with ETH. presign rates an unknown function
on an unknown contract as low, and 21 of the dev set's 85 calls sent ETH.
Catching these needs either simulation or contract reputation, neither of
which presign has. The labels are also the noisiest here: calls like
`withdraw()` on a drainer contract are likely the operator's own wallets,
not victims, so some of these are not misses at all.

**Limited approvals (9 offline misses, 0 online).** An approval for a
specific amount to an unknown spender is medium offline. Online, every one of
these spenders is a plain wallet and is raised to critical.

**Seaport orders with payment (4).** Orders that pay the offerer something.
The check compares recipients, not prices, so a token payment is enough to
pass. Finding underpriced orders needs price data.

**Benign permits (15 of 20 holdout permits flagged).** Any permit to an
unknown spender is high, and that rule produces most false alarms. The
builder only sees permits redeemed by a direct top-level `permit()` call,
which is how drainers redeem them; apps usually redeem permits inside their
own contracts, which the builder does not capture. So benign permits here
lean toward the drainer-like pattern, and some are probably unlisted
drainers: one wallet redeemed 16 USDC permits in an hour of dev blocks, each
followed by a `transferFrom`. The 3.9% false positive rate includes them as
genuinely benign.

**Online mode does not lower anything.** A permit to a contract stays high,
by design: online findings only add severity, so a lying node cannot make a
request look safer. That is why online mode raises recall and leaves the
false positive rate where it was.

## Known biases

- The blacklist is a public list; drainers not on it are invisible, and
  benign samples may contain some.
- Blockscout returns the latest 50 transactions or transfers per address,
  so long-lived drainers are sampled from their recent activity.
- Benign blocks are one hour of mainnet; activity mix changes over time.
- Spender lookups read the latest block, not the block where the request
  was signed.
