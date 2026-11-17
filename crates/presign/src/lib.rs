//! Decode what a wallet is about to sign and flag known drainer patterns.
//!
//! Input is an EIP-1193 request object (`{"method": ..., "params": [...]}`), the
//! same shape a dapp passes to `window.ethereum.request`. Analysis is offline:
//! no RPC calls, no simulation.

mod calldata;
mod known;
pub mod online;
mod parse;
mod report;
mod safe;
mod sign;
mod typed;

pub use report::{Finding, Hashes, Report, Severity};

use alloy_primitives::U256;
use parse::{parse_addr, parse_bytes, parse_num};
use serde_json::Value;

/// Analyze one EIP-1193 request. Errors mean the request itself is malformed.
pub fn analyze(req: &Value) -> Result<Report, String> {
    let method = req["method"].as_str().ok_or("missing \"method\"")?;
    let params = req["params"].as_array().ok_or("missing \"params\" array")?;
    let mut r = Report::default();
    match method {
        "eth_sendTransaction" => {
            let tx = params
                .first()
                .ok_or("eth_sendTransaction needs a transaction object")?;
            let to = match &tx["to"] {
                Value::Null => None,
                v => Some(parse_addr(v).ok_or("\"to\" is not an address")?),
            };
            let data_field = if tx["data"].is_null() {
                &tx["input"]
            } else {
                &tx["data"]
            };
            let data = match data_field {
                Value::Null => Vec::new(),
                v => parse_bytes(v).ok_or("\"data\" is not hex")?,
            };
            let value = match &tx["value"] {
                Value::Null => U256::ZERO,
                v => parse_num(v).ok_or("\"value\" is not a number")?,
            };
            if let Some(list) = tx.get("authorizationList") {
                sign::authorizations(&mut r, list)?;
            }
            if to.is_none() {
                r.add(
                    "tx.deploy",
                    Severity::Medium,
                    "deploys a new contract; its code is not checked",
                );
            } else {
                calldata::call(&mut r, to, &data, value, 0);
            }
        }
        m if m.starts_with("eth_signTypedData") => {
            let td = params
                .iter()
                .find_map(|p| {
                    let v = match p {
                        Value::String(s) => serde_json::from_str::<Value>(s).ok(),
                        Value::Object(_) => Some(p.clone()),
                        _ => None,
                    };
                    v.filter(|v| v["primaryType"].is_string())
                })
                .ok_or("no EIP-712 typed data found in params")?;
            match typed::eip712_hashes(&td) {
                Ok(h) => r.hashes = Some(h),
                Err(e) => r.add(
                    "typed.mismatch",
                    Severity::High,
                    format!(
                        "typed data does not match its own type definitions ({e}); \
                         a wallet may display something different from what gets signed"
                    ),
                ),
            }
            typed::typed(&mut r, &td);
        }
        "eth_sign" => r.add(
            "sign.eth_sign",
            Severity::Critical,
            "eth_sign signs a raw hash you cannot read. That hash can be a valid \
             signature for a transaction that moves everything you own.",
        ),
        "personal_sign" => {
            let msg = params
                .first()
                .and_then(Value::as_str)
                .ok_or("personal_sign needs a message")?;
            sign::personal(&mut r, msg);
        }
        _ => return Err(format!("unsupported method {method}")),
    }
    Ok(r)
}
