use presign::{Severity, Severity::*, analyze};
use serde_json::{Value, json};
use std::fs;

const CASES: &[(&str, Severity)] = &[
    ("approve_revoke", Info),
    ("approve_unlimited_permit2", Low),
    ("approve_unlimited_unknown", High),
    ("bybit_exec_transaction", Critical),
    ("bybit_safetx_typed", Critical),
    ("eth_sign_hash", Critical),
    ("eip7702_clear", Info),
    ("eip7702_delegation_any_chain", Critical),
    ("eth_transfer", Info),
    ("increase_allowance_unknown", High),
    ("permit_dai_allowed", Critical),
    ("permit_unlimited_unknown", Critical),
    ("permit2_batch_unknown", Critical),
    ("permit2_single_uniswap", Low),
    ("personal_sign_hash", High),
    ("personal_sign_text", Info),
    ("safe_multisend_hidden_approve", High),
    ("seaport_listing", Info),
    ("seaport_zero_price", Critical),
    ("set_approval_for_all_opensea", Low),
    ("set_approval_for_all_unknown", High),
    ("unknown_function", Low),
];

fn load(name: &str) -> Value {
    let raw = fs::read_to_string(format!("tests/fixtures/{name}.json")).unwrap();
    serde_json::from_str(&raw).unwrap()
}

#[test]
fn fixtures_have_expected_verdicts() {
    for (name, want) in CASES {
        let r = analyze(&load(name)).unwrap();
        assert_eq!(r.verdict(), *want, "{name}: {:#?}", r.findings);
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
    for (name, _) in CASES {
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
