# Benchmarks

Local, synthetic numbers. They show the cost of the analysis itself, not of
a deployment.

## presign-server, offline

Machine: Apple M4, 10 cores, macOS (Darwin arm64). Release build, online
checks off, loopback. Measured 2026-11-17.

```sh
cargo build --release -p presign-server
PRESIGN_ADDR=127.0.0.1:18080 ./target/release/presign-server &
F=crates/presign/tests/fixtures
for f in bybit_exec_transaction permit_unlimited_unknown; do
  ab -q -k -n 5000 -c 32 -p $F/$f.json -T application/json http://127.0.0.1:18080/v1/analyze >/dev/null
  ab -k -n 100000 -c 32 -p $F/$f.json -T application/json http://127.0.0.1:18080/v1/analyze
done
curl -s localhost:18080/metrics | grep presign_analyze_seconds
```

| Payload | Requests | Failed | Throughput | Mean | p50 | p95 | p99 | Max |
|---|---|---|---|---|---|---|---|---|
| Safe `execTransaction` with delegatecall (`bybit_exec_transaction`) | 100,000 | 0 | 159,266 req/s | 0.201 ms | <1 ms | <1 ms | 1 ms | 3 ms |
| EIP-712 Permit (`permit_unlimited_unknown`) | 100,000 | 0 | 105,847 req/s | 0.302 ms | <1 ms | 1 ms | 1 ms | 7 ms |

`ab` reports percentiles in whole milliseconds, and its mean is per request
across all 32 connections. The permit costs more because it computes the
EIP-712 domain, message and signing hashes.

Handler time from the server's own histogram, all 210,000 requests
including warm-ups:

| ≤ 50 µs | ≤ 100 µs | ≤ 250 µs | ≤ 500 µs | ≤ 1 ms | ≤ 10 ms | mean |
|---|---|---|---|---|---|---|
| 79.1% | 97.3% | 99.7% | 99.9% | 99.99% | 100% | 27 µs |

Every response was a critical verdict, as expected for both payloads.

With `PRESIGN_RPC` set, each unknown spender adds one `eth_getCode` round
trip, so latency is the node's latency. That path is not benchmarked here.
