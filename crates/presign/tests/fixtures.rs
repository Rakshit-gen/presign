use presign::{Severity, Severity::*, analyze};
use serde_json::{Value, json};
use std::fs;

/// Fixture name, expected verdict, and the code of the most severe finding.
const CASES: &[(&str, Severity, &str)] = &[
    ("approve_revoke", Info, "approval.revoke"),
    ("approve_unlimited_permit2", Low, "approval.unlimited"),
    ("approve_unlimited_unknown", High, "approval.unlimited"),
    ("bybit_exec_transaction", Critical, "safe.delegatecall"),
    ("bybit_safetx_typed", Critical, "safe.delegatecall"),
    ("eth_sign_hash", Critical, "sign.eth_sign"),
    ("eip7702_clear", Info, "eip7702.clear"),
    (
        "eip7702_delegation_any_chain",
        Critical,
        "eip7702.delegation",
    ),
    ("eth_transfer", Info, "tx.eth_value"),
    ("increase_allowance_unknown", High, "approval.unlimited"),
    ("permit_dai_allowed", Critical, "permit.approval"),
    ("permit_unlimited_unknown", Critical, "permit.approval"),
    ("permit2_batch_unknown", Critical, "permit2.approval"),
    ("permit2_single_uniswap", Low, "permit2.approval"),
    ("personal_sign_hash", High, "sign.blind_hash"),
    ("personal_sign_text", Info, "sign.text"),
    ("safe_multisend_hidden_approve", High, "approval.unlimited"),
    ("seaport_listing", Info, "seaport.listing"),
    ("seaport_zero_price", Critical, "seaport.zero_payment"),
    ("set_approval_for_all_opensea", Low, "nft.approval_for_all"),
    ("set_approval_for_all_unknown", High, "nft.approval_for_all"),
    ("unknown_function", Low, "tx.unknown_function"),
];

fn load(name: &str) -> Value {
    let raw = fs::read_to_string(format!("tests/fixtures/{name}.json")).unwrap();
    serde_json::from_str(&raw).unwrap()
}

#[test]
fn fixtures_have_expected_verdicts() {
    for (name, want, code) in CASES {
        let r = analyze(&load(name)).unwrap();
        assert_eq!(r.verdict(), *want, "{name}: {:#?}", r.findings);
        let top = r.top().unwrap();
        assert_eq!(top.code, *code, "{name}");
    }
}

#[test]
fn every_fixture_is_covered() {
    let on_disk = fs::read_dir("tests/fixtures").unwrap().count();
    assert_eq!(on_disk, CASES.len());
}

#[test]
fn bybit_finding_names_the_delegatecall_target() {
    let r = analyze(&load("bybit_exec_transaction")).unwrap();
    assert!(
        r.findings[0]
            .message
            .contains("0x96221423681A6d52E184D440a8eFCEbB105C7242")
    );
}

fn send(data: &str) -> Value {
    json!({"method": "eth_sendTransaction", "params": [{
        "to": "0x1db92e2eebc8e0c075a02bea49a2935bcd2dfcf4", "data": data
    }]})
}

#[test]
fn hostile_calldata_is_flagged_not_panicked_on() {
    // approve selector with truncated arguments
    assert_eq!(analyze(&send("0x095ea7b3dead")).unwrap().verdict(), High);
    // multiSend whose packed length field points past the end of the buffer
    let bad_len = format!(
        "0x8d80ff0a{:064x}{:064x}00{}{:064x}{}",
        32,
        85,
        "11".repeat(20),
        0,
        "f".repeat(64)
    );
    assert_eq!(analyze(&send(&bad_len)).unwrap().verdict(), High);
}

#[test]
fn malformed_requests_are_errors() {
    for req in [
        json!({}),
        json!({"method": "eth_sendTransaction"}),
        json!({"method": "eth_sendTransaction", "params": [{"to": "nope"}]}),
        json!({"method": "eth_signTypedData_v4", "params": ["0xabc", "{}"]}),
        json!({"method": "wallet_unknown", "params": []}),
    ] {
        assert!(analyze(&req).is_err(), "{req}");
    }
}

#[test]
fn deeply_nested_safe_calls_stop_at_the_depth_limit() {
    let safe = "1db92e2eebc8e0c075a02bea49a2935bcd2dfcf4";
    let mut data = "deadbeef".to_string();
    for _ in 0..10 {
        let inner_len = data.len() / 2;
        let padded = format!("{data}{}", "0".repeat((64 - data.len() % 64) % 64));
        data = format!(
            "6a761202{:0>64}{:064x}{:064x}{:064x}{}{:064x}{:064x}{}{}",
            safe,
            0,
            320,
            0,
            "0".repeat(64 * 5),
            352 + padded.len() / 2,
            inner_len,
            padded,
            "0".repeat(64)
        );
    }
    let r = analyze(&send(&format!("0x{data}"))).unwrap();
    assert!(
        r.findings
            .iter()
            .any(|f| f.message.contains("nested too deeply"))
    );
}

#[test]
fn eip712_hashes_match_the_spec_example() {
    // Mail example from https://eips.ethereum.org/EIPS/eip-712
    let td = json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}
            ],
            "Person": [{"name": "name", "type": "string"}, {"name": "wallet", "type": "address"}],
            "Mail": [
                {"name": "from", "type": "Person"}, {"name": "to", "type": "Person"},
                {"name": "contents", "type": "string"}
            ]
        },
        "primaryType": "Mail",
        "domain": {
            "name": "Ether Mail", "version": "1", "chainId": 1,
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
        },
        "message": {
            "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
            "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
            "contents": "Hello, Bob!"
        }
    });
    let req = json!({"method": "eth_signTypedData_v4", "params": ["0x00", td]});
    let h = analyze(&req).unwrap().hashes.unwrap();
    let hex = |b: alloy_primitives::B256| b.to_string();
    assert_eq!(
        hex(h.signing),
        "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
    );
    assert_eq!(
        hex(h.domain),
        "0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
    );
    assert_eq!(
        hex(h.message),
        "0xc52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
    );
}

#[test]
fn every_typed_data_fixture_gets_hashes() {
    for (name, _, _) in CASES {
        let req = load(name);
        if req["method"]
            .as_str()
            .unwrap()
            .starts_with("eth_signTypedData")
        {
            assert!(analyze(&req).unwrap().hashes.is_some(), "{name}");
        }
    }
}

#[test]
fn approvals_name_the_spender_as_counterparty() {
    let r = analyze(&load("approve_unlimited_unknown")).unwrap();
    let spender: alloy_primitives::Address = "0x9d6c4a1e3b7f02a8c5e1d94b6a3f70c2e8b15d47"
        .parse()
        .unwrap();
    assert_eq!(r.findings[0].counterparty, Some(spender));
}

/// SafeTx typed data that delegatecalls `to` with `data`.
fn safe_tx_typed(to: &str, data: &str) -> Value {
    let mut req = load("bybit_safetx_typed");
    let mut typed: Value = serde_json::from_str(req["params"][1].as_str().unwrap()).unwrap();
    typed["message"]["to"] = json!(to);
    typed["message"]["data"] = json!(data);
    req["params"][1] = json!(typed.to_string());
    req
}

/// multiSend(bytes) calldata for one packed inner call.
fn multisend_of(op: u8, to: &str, inner: &str) -> String {
    let inner = inner.trim_start_matches("0x");
    let packed = format!(
        "{op:02x}{}{:064x}{:064x}{inner}",
        to.trim_start_matches("0x"),
        0,
        inner.len() / 2
    );
    let padded = format!("{packed:0<width$}", width = packed.len().div_ceil(64) * 64);
    format!("0x8d80ff0a{:064x}{:064x}{padded}", 32, packed.len() / 2)
}

#[test]
fn delegatecall_to_safe_multisend_is_allowed_but_its_calls_are_still_checked() {
    let multisend_150 = "0x218543288004CD07832472D464648173c77D7eB7";
    let usdc = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
    let transfer = format!(
        "0xa9059cbb{:0>64}{:064x}",
        "5b38da6a701c568545dcfcb03fcb875f56beddc4", 1
    );

    let plain = analyze(&safe_tx_typed(
        multisend_150,
        &multisend_of(0, usdc, &transfer),
    ))
    .unwrap();
    assert!(plain.verdict() < High, "{:?}", plain.findings);
    assert!(plain.findings.iter().any(|f| f.code == "safe.multisend"));

    let bybit_target = "0x96221423681a6d52e184d440a8efcebb105c7242";
    let hidden = analyze(&safe_tx_typed(
        multisend_150,
        &multisend_of(1, bybit_target, &transfer),
    ))
    .unwrap();
    assert_eq!(hidden.verdict(), Critical);
    assert_eq!(hidden.top().unwrap().code, "safe.delegatecall");
}

#[test]
fn delegation_to_an_audited_7702_account_is_medium_and_anything_else_critical() {
    let mut req = load("eip7702_delegation_any_chain");
    let calibur = "0x000000009B1D0aF20D8C6d0A44e162d11F9b8f00";
    req["params"][0]["authorizationList"][0]["address"] = json!(calibur);
    req["params"][0]["authorizationList"][0]["chainId"] = json!("0x1");
    let r = analyze(&req).unwrap();
    assert_eq!(r.verdict(), Medium, "{:?}", r.findings);
    assert_eq!(r.top().unwrap().code, "eip7702.audited_delegate");
    assert!(r.top().unwrap().message.contains("Uniswap Calibur"));

    req["params"][0]["authorizationList"][0]["address"] =
        json!("0xd6CEDDe84be40893d153Be9d467CD6aD37875b28");
    assert_eq!(analyze(&req).unwrap().verdict(), Critical);
}
