//! Decode what a wallet is about to sign and flag known drainer patterns.
//!
//! Input is an EIP-1193 request object (`{"method": ..., "params": [...]}`), the
//! same shape a dapp passes to `window.ethereum.request`. Analysis is offline:
//! no RPC calls, no simulation.

use alloy_dyn_abi::TypedData;
use alloy_primitives::{Address, B256, U256, address, hex, utils::format_ether};
use alloy_sol_types::{SolCall, sol};
use serde_json::{Value, json};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct Report {
    pub findings: Vec<Finding>,
    /// Set for typed-data requests: the hashes a hardware wallet displays.
    pub hashes: Option<Hashes>,
}

/// EIP-712 hashes computed from the exact typed data in the request.
/// `signing` is what gets signed (and what Safe calls the safeTxHash);
/// `domain` and `message` are what Ledger shows when blind signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hashes {
    pub signing: B256,
    pub domain: B256,
    pub message: B256,
}

impl Report {
    /// The highest severity among all findings.
    pub fn verdict(&self) -> Severity {
        self.findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "verdict": self.verdict().to_string(),
            "hashes": self.hashes.map(|h| json!({
                "signing": h.signing, "domain": h.domain, "message": h.message,
            })),
            "findings": self.findings.iter()
                .map(|f| json!({"severity": f.severity.to_string(), "message": f.message}))
                .collect::<Vec<_>>(),
        })
    }

    fn add(&mut self, severity: Severity, message: impl Into<String>) {
        self.findings.push(Finding {
            severity,
            message: message.into(),
        });
    }
}

sol! {
    function approve(address spender, uint256 amount);
    function increaseAllowance(address spender, uint256 addedValue);
    function setApprovalForAll(address operator, bool approved);
    function transfer(address to, uint256 amount);
    function execTransaction(
        address to, uint256 value, bytes data, uint8 operation,
        uint256 safeTxGas, uint256 baseGas, uint256 gasPrice,
        address gasToken, address refundReceiver, bytes signatures
    );
    function multiSend(bytes transactions);
    function addOwnerWithThreshold(address owner, uint256 threshold);
    function removeOwner(address prevOwner, address owner, uint256 threshold);
    function swapOwner(address prevOwner, address oldOwner, address newOwner);
    function changeThreshold(uint256 threshold);
    function enableModule(address module);
    function setGuard(address guard);
    function setFallbackHandler(address handler);
}

const PERMIT2: Address = address!("000000000022D473030F116dDEE9F6B43aC78BA3");

/// Ethereum mainnet contracts that routinely receive approvals or delegatecalls.
const KNOWN: &[(Address, &str)] = &[
    (PERMIT2, "Uniswap Permit2"),
    (
        address!("66a9893cC07D91D95644AEDD05D03f95e1dBA8Af"),
        "Uniswap Universal Router v2",
    ),
    (
        address!("3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"),
        "Uniswap Universal Router v1.2",
    ),
    (
        address!("111111125421cA6dc452d289314280a0f8842A65"),
        "1inch Aggregation Router v6",
    ),
    (
        address!("0000000000000068F116a894984e2DB1123eB395"),
        "OpenSea Seaport 1.6",
    ),
    (
        address!("1E0049783F008A0085193E00003D00cd54003c71"),
        "OpenSea Conduit",
    ),
    (
        address!("40A2aCCbd92BCA938b02010E17A5b8929b49130D"),
        "Safe MultiSendCallOnly 1.3.0",
    ),
    (
        address!("9641d764fc13c8B624c04430C7356C1C7C8102e2"),
        "Safe MultiSendCallOnly 1.4.1",
    ),
];

/// Nested Safe and MultiSend calls are followed at most this deep.
const MAX_DEPTH: u8 = 4;

fn known(a: Address) -> Option<&'static str> {
    KNOWN.iter().find(|(k, _)| *k == a).map(|(_, n)| *n)
}

fn who(a: Address) -> String {
    match known(a) {
        Some(name) => format!("{name} ({a})"),
        None => format!("{a} (unknown address)"),
    }
}

/// No real token balance comes close to 2^128 base units, so anything at or
/// above it is an "infinite" approval in practice.
fn unlimited(x: U256) -> bool {
    x >= U256::from(1) << 128
}

fn amount(x: U256) -> String {
    if unlimited(x) {
        "an unlimited amount".into()
    } else {
        format!("{x} base units")
    }
}

fn eth(wei: U256) -> String {
    let s = format_ether(wei);
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

fn parse_addr(v: &Value) -> Option<Address> {
    v.as_str()?.parse().ok()
}

fn parse_num(v: &Value) -> Option<U256> {
    match v {
        Value::String(s) => s.parse().ok(),
        Value::Number(n) => n.as_u64().map(U256::from),
        _ => None,
    }
}

fn parse_bytes(v: &Value) -> Option<Vec<u8>> {
    hex::decode(v.as_str()?).ok()
}

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
                authorizations(&mut r, list)?;
            }
            if to.is_none() {
                r.add(
                    Severity::Medium,
                    "deploys a new contract; its code is not checked",
                );
            } else {
                call(&mut r, to, &data, value, 0);
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
            match eip712_hashes(&td) {
                Ok(h) => r.hashes = Some(h),
                Err(e) => r.add(
                    Severity::High,
                    format!(
                        "typed data does not match its own type definitions ({e}); \
                         a wallet may display something different from what gets signed"
                    ),
                ),
            }
            typed(&mut r, &td);
        }
        "eth_sign" => r.add(
            Severity::Critical,
            "eth_sign signs a raw hash you cannot read. That hash can be a valid \
             signature for a transaction that moves everything you own.",
        ),
        "personal_sign" => {
            let msg = params
                .first()
                .and_then(Value::as_str)
                .ok_or("personal_sign needs a message")?;
            personal(&mut r, msg);
        }
        _ => return Err(format!("unsupported method {method}")),
    }
    Ok(r)
}

fn eip712_hashes(td: &Value) -> Result<Hashes, String> {
    let parsed: TypedData = serde_json::from_value(td.clone()).map_err(|e| e.to_string())?;
    Ok(Hashes {
        signing: parsed.eip712_signing_hash().map_err(|e| e.to_string())?,
        domain: parsed.domain.separator(),
        message: parsed.hash_struct().map_err(|e| e.to_string())?,
    })
}

/// EIP-7702 (type 4) transactions carry signed authorizations that point an
/// account at another contract's code. Once set, that code runs for every call
/// to the account, so it controls all of the account's assets.
fn authorizations(r: &mut Report, list: &Value) -> Result<(), String> {
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

fn personal(r: &mut Report, msg: &str) {
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

fn call(r: &mut Report, to: Option<Address>, data: &[u8], value: U256, depth: u8) {
    if depth > MAX_DEPTH {
        r.add(
            Severity::High,
            "calls are nested too deeply to inspect; refusing to call it safe",
        );
        return;
    }
    let target = to.map(who).unwrap_or_else(|| "a new contract".into());
    if !value.is_zero() {
        r.add(
            Severity::Info,
            format!("sends {} ETH to {target}", eth(value)),
        );
    }
    let Some(sel) = data.get(..4) else {
        if value.is_zero() {
            r.add(Severity::Info, "carries no data and no ETH");
        }
        return;
    };
    let token = to.map(|a| a.to_string()).unwrap_or_default();
    let sel: [u8; 4] = sel.try_into().expect("slice is 4 bytes");

    macro_rules! decode {
        ($t:ty) => {
            match <$t>::abi_decode(data) {
                Ok(c) => c,
                Err(_) => {
                    r.add(
                        Severity::High,
                        format!("{} on {target} has malformed arguments", <$t>::SIGNATURE),
                    );
                    return;
                }
            }
        };
    }

    match sel {
        approveCall::SELECTOR => {
            let c = decode!(approveCall);
            approval(r, &token, c.spender, c.amount, false);
        }
        increaseAllowanceCall::SELECTOR => {
            let c = decode!(increaseAllowanceCall);
            approval(r, &token, c.spender, c.addedValue, true);
        }
        setApprovalForAllCall::SELECTOR => {
            let c = decode!(setApprovalForAllCall);
            if !c.approved {
                r.add(
                    Severity::Info,
                    format!("revokes {} from collection {token}", who(c.operator)),
                );
            } else {
                let sev = if known(c.operator).is_some() {
                    Severity::Low
                } else {
                    Severity::High
                };
                r.add(
                    sev,
                    format!(
                        "gives {} control of every NFT you own in collection {token}, \
                         including ones you receive later",
                        who(c.operator)
                    ),
                );
            }
        }
        transferCall::SELECTOR => {
            let c = decode!(transferCall);
            r.add(
                Severity::Info,
                format!(
                    "sends {} of token {token} to {}",
                    amount(c.amount),
                    who(c.to)
                ),
            );
        }
        execTransactionCall::SELECTOR => {
            let c = decode!(execTransactionCall);
            safe_tx(r, c.to, c.value, &c.data, c.operation, depth);
        }
        multiSendCall::SELECTOR => {
            let c = decode!(multiSendCall);
            multisend(r, &c.transactions, depth);
        }
        enableModuleCall::SELECTOR => {
            let c = decode!(enableModuleCall);
            r.add(
                Severity::Critical,
                format!(
                    "enables {} as a Safe module. A module can move funds without any \
                     owner signatures.",
                    who(c.module)
                ),
            );
        }
        addOwnerWithThresholdCall::SELECTOR
        | removeOwnerCall::SELECTOR
        | swapOwnerCall::SELECTOR
        | changeThresholdCall::SELECTOR => r.add(
            Severity::High,
            format!("changes who controls the Safe at {target}"),
        ),
        setGuardCall::SELECTOR | setFallbackHandlerCall::SELECTOR => r.add(
            Severity::High,
            format!("replaces a security hook on the Safe at {target}"),
        ),
        _ => r.add(
            Severity::Low,
            format!(
                "calls unknown function 0x{} on {target}; it cannot be decoded offline",
                hex::encode(sel)
            ),
        ),
    }
}

fn approval(r: &mut Report, token: &str, spender: Address, amt: U256, increase: bool) {
    if amt.is_zero() && !increase {
        r.add(
            Severity::Info,
            format!("revokes the approval of {} on token {token}", who(spender)),
        );
        return;
    }
    let sev = match (known(spender).is_some(), unlimited(amt)) {
        (true, true) => Severity::Low,
        (true, false) => Severity::Info,
        (false, true) => Severity::High,
        (false, false) => Severity::Medium,
    };
    let message = if increase {
        format!(
            "raises how much {} can take from token {token} by {}",
            who(spender),
            amount(amt)
        )
    } else {
        format!(
            "lets {} take {} of token {token}",
            who(spender),
            amount(amt)
        )
    };
    r.add(sev, message);
}

fn safe_tx(r: &mut Report, to: Address, value: U256, data: &[u8], op: u8, depth: u8) {
    match op {
        0 => call(r, Some(to), data, value, depth + 1),
        1 if known(to).is_some_and(|n| n.starts_with("Safe MultiSendCallOnly")) => {
            r.add(
                Severity::Info,
                format!("batch of calls through {}", who(to)),
            );
            call(r, Some(to), data, value, depth + 1);
        }
        1 => r.add(
            Severity::Critical,
            format!(
                "delegatecall to {}: that contract's code runs as your Safe and can \
                 rewrite its logic, change owners and drain every asset. This is the \
                 pattern used to steal about $1.5B from Bybit in February 2025.",
                who(to)
            ),
        ),
        _ => r.add(Severity::High, format!("unknown Safe operation type {op}")),
    }
}

/// MultiSend packs each call as: operation (1) | to (20) | value (32) | len (32) | data.
fn multisend(r: &mut Report, mut buf: &[u8], depth: u8) {
    while !buf.is_empty() {
        if buf.len() < 85 {
            r.add(Severity::High, "MultiSend batch is truncated");
            return;
        }
        let op = buf[0];
        let to = Address::from_slice(&buf[1..21]);
        let value = U256::from_be_slice(&buf[21..53]);
        let len = U256::from_be_slice(&buf[53..85]);
        let Some(end) = usize::try_from(len)
            .ok()
            .and_then(|l| l.checked_add(85))
            .filter(|&e| e <= buf.len())
        else {
            r.add(Severity::High, "MultiSend batch has an invalid length");
            return;
        };
        safe_tx(r, to, value, &buf[85..end], op, depth + 1);
        buf = &buf[end..];
    }
}

fn typed(r: &mut Report, td: &Value) {
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
                _ => r.add(Severity::High, "SafeTx message is malformed"),
            }
        }
        _ => r.add(
            Severity::Info,
            format!("typed message {primary} from {name:?} matches no known risky type"),
        ),
    }
}

fn permit(r: &mut Report, token: Option<Address>, m: &Value) {
    let Some(spender) = parse_addr(&m["spender"]) else {
        return r.add(Severity::High, "Permit message has no readable spender");
    };
    // DAI-style permits carry `allowed: true` instead of an amount, and grant the maximum.
    let amt = match (&m["allowed"], parse_num(&m["value"])) {
        (Value::Bool(true), _) => U256::MAX,
        (Value::Bool(false), _) => U256::ZERO,
        (_, Some(v)) => v,
        _ => return r.add(Severity::High, "Permit message has no readable amount"),
    };
    let sev = match (known(spender).is_some(), unlimited(amt)) {
        (true, true) => Severity::Medium,
        (true, false) => Severity::Low,
        (false, true) => Severity::Critical,
        (false, false) => Severity::High,
    };
    let token = token.map_or_else(|| "an unknown token".into(), |t| format!("token {t}"));
    r.add(
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
        return r.add(Severity::High, format!("Permit2 {primary} is malformed"));
    };
    if tokens.is_empty() {
        return r.add(Severity::High, format!("Permit2 {primary} names no tokens"));
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
    r.add(
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
        return r.add(Severity::High, "Seaport order is malformed");
    };
    let paid_to_you = consideration
        .iter()
        .filter(|c| parse_addr(&c["recipient"]) == Some(offerer))
        .filter_map(|c| parse_num(&c["startAmount"]))
        .fold(U256::ZERO, |acc, x| acc.saturating_add(x));
    if offer.is_empty() {
        r.add(
            Severity::Info,
            "Seaport order offers nothing from your wallet",
        );
    } else if paid_to_you.is_zero() {
        r.add(
            Severity::Critical,
            format!(
                "Seaport order hands over {} item(s) you own and pays you nothing. \
                 Drainers use this to buy NFTs for zero.",
                offer.len()
            ),
        );
    } else {
        r.add(
            Severity::Info,
            format!(
                "Seaport listing of {} item(s) with payment going back to you",
                offer.len()
            ),
        );
    }
}
