//! Mainnet contracts that routinely and legitimately receive approvals.

use alloy_primitives::{Address, address};

pub(crate) const PERMIT2: Address = address!("000000000022D473030F116dDEE9F6B43aC78BA3");

/// Ethereum mainnet contracts that routinely receive approvals or delegatecalls.
/// Safe addresses are from safe-global/safe-deployments.
pub(crate) const KNOWN: &[(Address, &str)] = &[
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
        address!("A238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761"),
        "Safe MultiSend 1.3.0",
    ),
    (
        address!("998739BFdAAdde7C933B942a68053933098f9EDa"),
        "Safe MultiSend 1.3.0 (eip155)",
    ),
    (
        address!("38869bf66a61cF6bDB996A6aE40D5853Fd43B526"),
        "Safe MultiSend 1.4.1",
    ),
    (
        address!("218543288004CD07832472D464648173c77D7eB7"),
        "Safe MultiSend 1.5.0",
    ),
    (
        address!("40A2aCCbd92BCA938b02010E17A5b8929b49130D"),
        "Safe MultiSendCallOnly 1.3.0",
    ),
    (
        address!("A1dabEF33b3B82c7814B6D82A79e50F4AC44102B"),
        "Safe MultiSendCallOnly 1.3.0 (eip155)",
    ),
    (
        address!("9641d764fc13c8B624c04430C7356C1C7C8102e2"),
        "Safe MultiSendCallOnly 1.4.1",
    ),
    (
        address!("A83c336B20401Af773B6219BA5027174338D1836"),
        "Safe MultiSendCallOnly 1.5.0",
    ),
];

pub(crate) fn known(a: Address) -> Option<&'static str> {
    KNOWN.iter().find(|(k, _)| *k == a).map(|(_, n)| *n)
}

pub(crate) fn who(a: Address) -> String {
    match known(a) {
        Some(name) => format!("{name} ({a})"),
        None => format!("{a} (unknown address)"),
    }
}

/// Audited EIP-7702 account implementations, as listed by ethereum.org
/// (roadmap/pectra/7702). Delegating to one of these is how wallets turn on
/// smart-account features; delegating to anything else is how drainers take
/// over an account.
pub(crate) const DELEGATES: &[(Address, &str)] = &[
    (
        address!("000000009B1D0aF20D8C6d0A44e162d11F9b8f00"),
        "Uniswap Calibur",
    ),
    (
        address!("69007702764179f14F51cdce752f4f775d74E139"),
        "Alchemy SemiModularAccount7702",
    ),
    (
        address!("5A7FC11397E9a8AD41BF10bf13F22B0a63f96f6d"),
        "Ambire AmbireAccount7702",
    ),
    (
        address!("63c0c19a282a1b52b07dd5a65b58948a07dae32b"),
        "MetaMask EIP7702StatelessDeleGator",
    ),
    (
        address!("4Cd241E8d1510e30b2076397afc7508Ae59C66c9"),
        "eth-infinitism Simple7702Account",
    ),
    (
        address!("17c11FDdADac2b341F2455aFe988fec4c3ba26e3"),
        "Luganodes Pectra batch contract",
    ),
];

pub(crate) fn delegate(a: Address) -> Option<&'static str> {
    DELEGATES.iter().find(|(k, _)| *k == a).map(|(_, n)| *n)
}
