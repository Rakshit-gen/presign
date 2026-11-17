#!/bin/sh
# Builds presign.wasm into this folder so it can be loaded unpacked.
set -eu
cd "$(dirname "$0")/.."
cargo build --release -p presign-wasm --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/presign_wasm.wasm extension/presign.wasm
