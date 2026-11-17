//! Lenient parsing of JSON-RPC values and human-readable amounts.

use alloy_primitives::{Address, U256, hex, utils::format_ether};
use serde_json::Value;

/// No real token balance comes close to 2^128 base units, so anything at or
/// above it is an "infinite" approval in practice.
pub(crate) fn unlimited(x: U256) -> bool {
    x >= U256::from(1) << 128
}

pub(crate) fn amount(x: U256) -> String {
    if unlimited(x) {
        "an unlimited amount".into()
    } else {
        format!("{x} base units")
    }
}

pub(crate) fn eth(wei: U256) -> String {
    let s = format_ether(wei);
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

pub(crate) fn parse_addr(v: &Value) -> Option<Address> {
    v.as_str()?.parse().ok()
}

pub(crate) fn parse_num(v: &Value) -> Option<U256> {
    match v {
        Value::String(s) => s.parse().ok(),
        Value::Number(n) => n.as_u64().map(U256::from),
        _ => None,
    }
}

pub(crate) fn parse_bytes(v: &Value) -> Option<Vec<u8>> {
    hex::decode(v.as_str()?).ok()
}
