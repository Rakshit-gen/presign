//! Checks that need chain state, layered on top of an offline [`Report`].
//!
//! The rules only read through [`ChainView`], so they run the same against a
//! live node, a cache, or a test double.

use crate::known::known;
use crate::report::{Report, Severity};
use alloy_primitives::Address;
use std::collections::HashMap;

/// Read access to chain state.
pub trait ChainView {
    /// Deployed bytecode at `address` (empty for a plain wallet).
    fn code(&mut self, address: Address) -> Result<Vec<u8>, String>;
}

/// Finding codes whose counterparty receives the power to move the signer's assets.
const GRANTS: &[&str] = &[
    "approval.unlimited",
    "approval.limited",
    "nft.approval_for_all",
    "permit.approval",
    "permit2.approval",
];

/// EIP-7702 delegation designator: an account whose code is `0xef0100 || address`.
const DELEGATION_PREFIX: [u8; 3] = [0xef, 0x01, 0x00];

enum Account {
    Wallet,
    Delegated(Address),
    Contract,
}

fn classify(code: &[u8]) -> Account {
    match code {
        [] => Account::Wallet,
        [p0, p1, p2, rest @ ..] if [*p0, *p1, *p2] == DELEGATION_PREFIX && rest.len() == 20 => {
            Account::Delegated(Address::from_slice(rest))
        }
        _ => Account::Contract,
    }
}

/// Adds findings that depend on chain state. Lookups are cached per address.
/// A failed lookup is reported as a finding rather than silently skipped.
pub fn enrich(report: &mut Report, chain: &mut dyn ChainView) {
    let mut cache: HashMap<Address, Result<Vec<u8>, String>> = HashMap::new();
    let grantees: Vec<Address> = report
        .findings
        .iter()
        .filter(|f| GRANTS.contains(&f.code))
        .filter_map(|f| f.counterparty)
        .filter(|a| known(*a).is_none())
        .collect();

    for spender in grantees {
        if cache.contains_key(&spender) {
            continue;
        }
        let code = chain.code(spender);
        match &code {
            Err(e) => report.add_with(
                "online.lookup_failed",
                spender,
                Severity::Medium,
                format!(
                    "could not check {spender} on-chain ({e}); judge it on the offline findings"
                ),
            ),
            Ok(code) => match classify(code) {
                Account::Wallet => report.add_with(
                    "spender.wallet",
                    spender,
                    Severity::Critical,
                    format!(
                        "the spender {spender} is a plain wallet, not a contract. Apps take \
                         approvals through contracts; approvals to a wallet are how drainers \
                         collect tokens."
                    ),
                ),
                Account::Delegated(to) => report.add_with(
                    "spender.delegated_wallet",
                    spender,
                    Severity::Critical,
                    format!(
                        "the spender {spender} is a wallet running delegated EIP-7702 code \
                         from {to}, not an app contract"
                    ),
                ),
                Account::Contract => {}
            },
        }
        cache.insert(spender, code);
    }
}

#[cfg(feature = "rpc")]
pub use rpc::Rpc;

#[cfg(feature = "rpc")]
mod rpc {
    use super::ChainView;
    use alloy_primitives::{Address, hex};
    use serde_json::{Value, json};
    use std::time::Duration;

    /// [`ChainView`] over Ethereum JSON-RPC.
    pub struct Rpc {
        url: String,
        agent: ureq::Agent,
    }

    impl Rpc {
        pub fn new(url: impl Into<String>, timeout: Duration) -> Self {
            let agent = ureq::Agent::config_builder()
                .timeout_global(Some(timeout))
                .build()
                .into();
            Self {
                url: url.into(),
                agent,
            }
        }

        fn call(&self, method: &str, params: Value) -> Result<Value, String> {
            let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
            let mut resp = self
                .agent
                .post(&self.url)
                .header("user-agent", concat!("presign/", env!("CARGO_PKG_VERSION")))
                .send_json(&body)
                .map_err(|e| e.to_string())?;
            let reply: Value = resp.body_mut().read_json().map_err(|e| e.to_string())?;
            match reply.get("error") {
                Some(err) => Err(format!("{method}: {err}")),
                None => Ok(reply["result"].clone()),
            }
        }
    }

    impl ChainView for Rpc {
        fn code(&mut self, address: Address) -> Result<Vec<u8>, String> {
            let code = self.call("eth_getCode", json!([address, "latest"]))?;
            hex::decode(code.as_str().ok_or("eth_getCode returned no string")?)
                .map_err(|e| e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use serde_json::json;

    struct Fake(HashMap<Address, Vec<u8>>);

    impl ChainView for Fake {
        fn code(&mut self, a: Address) -> Result<Vec<u8>, String> {
            self.0
                .get(&a)
                .cloned()
                .ok_or_else(|| "node unavailable".into())
        }
    }

    const SPENDER: Address = address!("9d6c4a1e3b7f02a8c5e1d94b6a3f70c2e8b15d47");

    fn limited_approval() -> Report {
        let req = json!({"method": "eth_sendTransaction", "params": [{
            "to": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "data": format!("0x095ea7b3{:0>64}{:064x}", "9d6c4a1e3b7f02a8c5e1d94b6a3f70c2e8b15d47", 5),
        }]});
        crate::analyze(&req).unwrap()
    }

    #[test]
    fn approval_to_a_wallet_becomes_critical() {
        let mut r = limited_approval();
        assert_eq!(r.verdict(), Severity::Medium);
        enrich(&mut r, &mut Fake(HashMap::from([(SPENDER, vec![])])));
        assert_eq!(r.verdict(), Severity::Critical);
        assert_eq!(r.top().unwrap().code, "spender.wallet");
    }

    #[test]
    fn approval_to_a_contract_is_unchanged() {
        let mut r = limited_approval();
        enrich(
            &mut r,
            &mut Fake(HashMap::from([(SPENDER, vec![0x60, 0x80])])),
        );
        assert_eq!(r.verdict(), Severity::Medium);
    }

    #[test]
    fn delegated_wallet_is_recognised() {
        let mut code = DELEGATION_PREFIX.to_vec();
        code.extend_from_slice(&[0x11; 20]);
        let mut r = limited_approval();
        enrich(&mut r, &mut Fake(HashMap::from([(SPENDER, code)])));
        assert_eq!(r.top().unwrap().code, "spender.delegated_wallet");
    }

    #[test]
    fn failed_lookup_is_reported_not_ignored() {
        let mut r = limited_approval();
        enrich(&mut r, &mut Fake(HashMap::new()));
        assert!(r.findings.iter().any(|f| f.code == "online.lookup_failed"));
    }
}
