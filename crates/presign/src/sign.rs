//! Raw signing methods and EIP-7702 authorizations.

use crate::known::who;
use crate::parse::{parse_addr, parse_num};
use crate::report::{Report, Severity};
use alloy_primitives::hex;
use serde_json::Value;

/// EIP-7702 (type 4) transactions carry signed authorizations that point an
/// account at another contract's code. Once set, that code runs for every call
/// to the account, so it controls all of the account's assets.
pub(crate) fn authorizations(r: &mut Report, list: &Value) -> Result<(), String> {
    let list = list
        .as_array()
        .ok_or("\"authorizationList\" is not an array")?;
    for auth in list {
        let target =
            parse_addr(&auth["address"]).ok_or("authorization has no valid \"address\"")?;
        let chain = parse_num(&auth["chainId"]).ok_or("authorization has no valid \"chainId\"")?;
        if target.is_zero() {
            r.add(
                Severity::Info,
                "clears the EIP-7702 delegation on your account",
            );
            continue;
        }
        let scope = if chain.is_zero() {
            "on every EVM chain at once (chainId 0)".to_string()
        } else {
            format!("on chain {chain}")
        };
        r.add(
            Severity::Critical,
            format!(
                "EIP-7702 delegation: hands your account to the code at {} {scope}. \
                 That code can move every asset you hold, now and later, until the \
                 delegation is cleared.",
                who(target)
            ),
        );
    }
    Ok(())
}

pub(crate) fn personal(r: &mut Report, msg: &str) {
    let bytes = match msg.strip_prefix("0x").map(hex::decode) {
        Some(Ok(b)) => b,
        _ => msg.as_bytes().to_vec(),
    };
    match String::from_utf8(bytes) {
        Ok(text) if !text.chars().any(|c| c.is_control() && !c.is_whitespace()) => r.add(
            Severity::Info,
            format!("signs a readable text message: {text:?}"),
        ),
        Ok(_) | Err(_) if msg.len() == 66 => r.add(
            Severity::High,
            "signs 32 unreadable bytes, which is the size of a transaction hash. \
             Treat this like a blind signature.",
        ),
        _ => r.add(
            Severity::Medium,
            "signs binary data that is not readable text",
        ),
    }
}
