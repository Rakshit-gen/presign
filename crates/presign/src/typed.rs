//! EIP-712 typed data: hashes plus Permit, Permit2, Seaport and SafeTx checks.

use crate::known::{PERMIT2, known, who};
use crate::parse::{amount, parse_addr, parse_bytes, parse_num, unlimited};
use crate::report::{Hashes, Report, Severity};
use crate::safe::safe_tx;
use alloy_dyn_abi::TypedData;
use alloy_primitives::{Address, U256};
use serde_json::Value;

pub(crate) fn eip712_hashes(td: &Value) -> Result<Hashes, String> {
    let parsed: TypedData = serde_json::from_value(td.clone()).map_err(|e| e.to_string())?;
    Ok(Hashes {
        signing: parsed.eip712_signing_hash().map_err(|e| e.to_string())?,
        domain: parsed.domain.separator(),
        message: parsed.hash_struct().map_err(|e| e.to_string())?,
    })
}

pub(crate) fn typed(r: &mut Report, td: &Value) {
    let primary = td["primaryType"].as_str().unwrap_or_default();
    let domain = &td["domain"];
    let m = &td["message"];
    let contract = parse_addr(&domain["verifyingContract"]);
    let name = domain["name"].as_str().unwrap_or_default();

    if contract == Some(PERMIT2) || name == "Permit2" {
        return permit2(r, primary, m);
    }
    match primary {
        "Permit" => permit(r, contract, m),
        "OrderComponents" if name == "Seaport" => seaport(r, m),
        "SafeTx" => {
            let fields = (
                parse_addr(&m["to"]),
                parse_num(&m["value"]),
                parse_bytes(&m["data"]),
                parse_num(&m["operation"]).and_then(|o| u8::try_from(o).ok()),
            );
            match fields {
                (Some(to), Some(value), Some(data), Some(op)) => {
                    safe_tx(r, to, value, &data, op, 0)
                }
                _ => r.add(
                    "safe.malformed",
                    Severity::High,
                    "SafeTx message is malformed",
                ),
            }
        }
        _ => r.add(
            "typed.unrecognized",
            Severity::Info,
            format!("typed message {primary} from {name:?} matches no known risky type"),
        ),
    }
}

fn permit(r: &mut Report, token: Option<Address>, m: &Value) {
    let Some(spender) = parse_addr(&m["spender"]) else {
        return r.add(
            "permit.malformed",
            Severity::High,
            "Permit message has no readable spender",
        );
    };
    // DAI-style permits carry `allowed: true` instead of an amount, and grant the maximum.
    let amt = match (&m["allowed"], parse_num(&m["value"])) {
        (Value::Bool(true), _) => U256::MAX,
        (Value::Bool(false), _) => U256::ZERO,
        (_, Some(v)) => v,
        _ => {
            return r.add(
                "permit.malformed",
                Severity::High,
                "Permit message has no readable amount",
            );
        }
    };
    let sev = match (known(spender).is_some(), unlimited(amt)) {
        (true, true) => Severity::Medium,
        (true, false) => Severity::Low,
        (false, true) => Severity::Critical,
        (false, false) => Severity::High,
    };
    let token = token.map_or_else(|| "an unknown token".into(), |t| format!("token {t}"));
    r.add_with(
        "permit.approval",
        spender,
        sev,
        format!(
            "gasless approval: lets {} take {} of {token}. No transaction is sent, so \
             nothing shows on-chain until they use it.",
            who(spender),
            amount(amt)
        ),
    );
}

fn permit2(r: &mut Report, primary: &str, m: &Value) {
    let items: Vec<&Value> = match (&m["details"], &m["permitted"]) {
        (Value::Array(a), _) | (_, Value::Array(a)) => a.iter().collect(),
        (o @ Value::Object(_), _) | (_, o @ Value::Object(_)) => vec![o],
        _ => Vec::new(),
    };
    let tokens: Option<Vec<(Address, U256)>> = items
        .iter()
        .map(|it| Some((parse_addr(&it["token"])?, parse_num(&it["amount"])?)))
        .collect();
    let (Some(spender), Some(tokens)) = (parse_addr(&m["spender"]), tokens) else {
        return r.add(
            "permit2.malformed",
            Severity::High,
            format!("Permit2 {primary} is malformed"),
        );
    };
    if tokens.is_empty() {
        return r.add(
            "permit2.malformed",
            Severity::High,
            format!("Permit2 {primary} names no tokens"),
        );
    }
    let any_unlimited = tokens.iter().any(|(_, a)| unlimited(*a));
    let sev = match (known(spender).is_some(), tokens.len() > 1 || any_unlimited) {
        (true, _) => Severity::Low,
        (false, true) => Severity::Critical,
        (false, false) => Severity::High,
    };
    let list = tokens
        .iter()
        .map(|(t, a)| format!("{} of {t}", amount(*a)))
        .collect::<Vec<_>>()
        .join(", ");
    r.add_with(
        "permit2.approval",
        spender,
        sev,
        format!(
            "Permit2 {primary}: lets {} take {list}. No transaction is sent, so nothing \
             shows on-chain until they use it.",
            who(spender)
        ),
    );
}

fn seaport(r: &mut Report, m: &Value) {
    let (Some(offerer), Some(offer), Some(consideration)) = (
        parse_addr(&m["offerer"]),
        m["offer"].as_array(),
        m["consideration"].as_array(),
    ) else {
        return r.add(
            "seaport.malformed",
            Severity::High,
            "Seaport order is malformed",
        );
    };
    let paid_to_you = consideration
        .iter()
        .filter(|c| parse_addr(&c["recipient"]) == Some(offerer))
        .filter_map(|c| parse_num(&c["startAmount"]))
        .fold(U256::ZERO, |acc, x| acc.saturating_add(x));
    if offer.is_empty() {
        r.add(
            "seaport.empty_offer",
            Severity::Info,
            "Seaport order offers nothing from your wallet",
        );
    } else if paid_to_you.is_zero() {
        r.add(
            "seaport.zero_payment",
            Severity::Critical,
            format!(
                "Seaport order hands over {} item(s) you own and pays you nothing. \
                 Drainers use this to buy NFTs for zero.",
                offer.len()
            ),
        );
    } else {
        r.add(
            "seaport.listing",
            Severity::Info,
            format!(
                "Seaport listing of {} item(s) with payment going back to you",
                offer.len()
            ),
        );
    }
}
