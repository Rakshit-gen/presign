//! Rebuilds the request a user signed from the transaction that later used it.
//!
//! A permit signature never appears on-chain by itself. When someone redeems
//! it, the transaction calldata carries every signed field, so the original
//! `eth_signTypedData_v4` request can be reconstructed. Fields that are not in
//! the calldata (the token's EIP-712 name and version, and the EIP-2612 nonce)
//! are filled with placeholders; they change the hash, not the verdict.

use alloy_primitives::{Address, U256, address};
use alloy_sol_types::{SolCall, sol};
use serde_json::{Value, json};

pub const PERMIT2: Address = address!("000000000022D473030F116dDEE9F6B43aC78BA3");

mod eip2612 {
    alloy_sol_types::sol! {
        function permit(address owner, address spender, uint256 value, uint256 deadline,
                        uint8 v, bytes32 r, bytes32 s);
    }
}

mod dai {
    alloy_sol_types::sol! {
        function permit(address holder, address spender, uint256 nonce, uint256 expiry,
                        bool allowed, uint8 v, bytes32 r, bytes32 s);
    }
}

sol! {
    struct TokenPermissions { address token; uint256 amount; }
    struct PermitTransferFrom { TokenPermissions permitted; uint256 nonce; uint256 deadline; }
    struct PermitBatchTransferFrom { TokenPermissions[] permitted; uint256 nonce; uint256 deadline; }
    struct SignatureTransferDetails { address to; uint256 requestedAmount; }
    struct PermitDetails { address token; uint160 amount; uint48 expiration; uint48 nonce; }
    struct PermitSingle { PermitDetails details; address spender; uint256 sigDeadline; }
    struct PermitBatch { PermitDetails[] details; address spender; uint256 sigDeadline; }

    function permit(address owner, PermitSingle permitSingle, bytes signature);
    function permit(address owner, PermitBatch permitBatch, bytes signature);
    function permitTransferFrom(PermitTransferFrom permit, SignatureTransferDetails transferDetails,
                                address owner, bytes signature);
    function permitTransferFrom(PermitBatchTransferFrom permit,
                                SignatureTransferDetails[] transferDetails,
                                address owner, bytes signature);
}

fn field(name: &str, ty: &str) -> Value {
    json!({"name": name, "type": ty})
}

fn sign_request(owner: Address, typed: Value) -> Value {
    json!({"method": "eth_signTypedData_v4", "params": [owner, typed.to_string()]})
}

fn permit2_domain() -> Value {
    json!({"name": "Permit2", "chainId": 1, "verifyingContract": PERMIT2})
}

fn permit2_domain_type() -> Value {
    json!([
        field("name", "string"),
        field("chainId", "uint256"),
        field("verifyingContract", "address")
    ])
}

fn details_json(d: &PermitDetails) -> Value {
    json!({
        "token": d.token,
        "amount": d.amount.to_string(),
        "expiration": d.expiration.to_string(),
        "nonce": d.nonce.to_string(),
    })
}

fn permissions_json(p: &TokenPermissions) -> Value {
    json!({"token": p.token, "amount": p.amount.to_string()})
}

/// Turns a permit-redeeming transaction back into the signature request the
/// owner approved. `sender` is the transaction's `from`, which Permit2's
/// SignatureTransfer treats as the spender. Returns the kind and the request.
pub fn signature_request(
    sender: Address,
    to: Address,
    input: &[u8],
    token_name: &str,
) -> Option<(&'static str, Value)> {
    let sel: [u8; 4] = input.get(..4)?.try_into().ok()?;
    let details_types = json!([
        field("token", "address"),
        field("amount", "uint160"),
        field("expiration", "uint48"),
        field("nonce", "uint48")
    ]);
    let permissions_types = json!([field("token", "address"), field("amount", "uint256")]);
    let erc20_domain_type = json!([
        field("name", "string"),
        field("version", "string"),
        field("chainId", "uint256"),
        field("verifyingContract", "address")
    ]);
    let erc20_domain =
        json!({"name": token_name, "version": "1", "chainId": 1, "verifyingContract": to});

    if to == PERMIT2 {
        return match sel {
            permit_0Call::SELECTOR => {
                let c = permit_0Call::abi_decode(input).ok()?;
                let p = c.permitSingle;
                Some((
                    "permit2_single",
                    sign_request(
                        c.owner,
                        json!({
                            "types": {
                                "EIP712Domain": permit2_domain_type(),
                                "PermitSingle": [field("details", "PermitDetails"),
                                    field("spender", "address"), field("sigDeadline", "uint256")],
                                "PermitDetails": details_types,
                            },
                            "primaryType": "PermitSingle",
                            "domain": permit2_domain(),
                            "message": {
                                "details": details_json(&p.details),
                                "spender": p.spender,
                                "sigDeadline": p.sigDeadline.to_string(),
                            },
                        }),
                    ),
                ))
            }
            permit_1Call::SELECTOR => {
                let c = permit_1Call::abi_decode(input).ok()?;
                let p = c.permitBatch;
                Some((
                    "permit2_batch",
                    sign_request(
                        c.owner,
                        json!({
                            "types": {
                                "EIP712Domain": permit2_domain_type(),
                                "PermitBatch": [field("details", "PermitDetails[]"),
                                    field("spender", "address"), field("sigDeadline", "uint256")],
                                "PermitDetails": details_types,
                            },
                            "primaryType": "PermitBatch",
                            "domain": permit2_domain(),
                            "message": {
                                "details": p.details.iter().map(details_json).collect::<Vec<_>>(),
                                "spender": p.spender,
                                "sigDeadline": p.sigDeadline.to_string(),
                            },
                        }),
                    ),
                ))
            }
            permitTransferFrom_0Call::SELECTOR => {
                let c = permitTransferFrom_0Call::abi_decode(input).ok()?;
                let p = c.permit;
                Some((
                    "permit2_transfer",
                    sign_request(
                        c.owner,
                        json!({
                            "types": {
                                "EIP712Domain": permit2_domain_type(),
                                "PermitTransferFrom": [field("permitted", "TokenPermissions"),
                                    field("spender", "address"), field("nonce", "uint256"),
                                    field("deadline", "uint256")],
                                "TokenPermissions": permissions_types,
                            },
                            "primaryType": "PermitTransferFrom",
                            "domain": permit2_domain(),
                            "message": {
                                "permitted": permissions_json(&p.permitted),
                                "spender": sender,
                                "nonce": p.nonce.to_string(),
                                "deadline": p.deadline.to_string(),
                            },
                        }),
                    ),
                ))
            }
            permitTransferFrom_1Call::SELECTOR => {
                let c = permitTransferFrom_1Call::abi_decode(input).ok()?;
                let p = c.permit;
                Some((
                    "permit2_batch_transfer",
                    sign_request(
                        c.owner,
                        json!({
                            "types": {
                                "EIP712Domain": permit2_domain_type(),
                                "PermitBatchTransferFrom": [field("permitted", "TokenPermissions[]"),
                                    field("spender", "address"), field("nonce", "uint256"),
                                    field("deadline", "uint256")],
                                "TokenPermissions": permissions_types,
                            },
                            "primaryType": "PermitBatchTransferFrom",
                            "domain": permit2_domain(),
                            "message": {
                                "permitted": p.permitted.iter().map(permissions_json).collect::<Vec<_>>(),
                                "spender": sender,
                                "nonce": p.nonce.to_string(),
                                "deadline": p.deadline.to_string(),
                            },
                        }),
                    ),
                ))
            }
            _ => None,
        };
    }

    match sel {
        eip2612::permitCall::SELECTOR => {
            let c = eip2612::permitCall::abi_decode(input).ok()?;
            Some((
                "permit",
                sign_request(
                    c.owner,
                    json!({
                        "types": {
                            "EIP712Domain": erc20_domain_type,
                            "Permit": [field("owner", "address"), field("spender", "address"),
                                field("value", "uint256"), field("nonce", "uint256"),
                                field("deadline", "uint256")],
                        },
                        "primaryType": "Permit",
                        "domain": erc20_domain,
                        "message": {
                            "owner": c.owner,
                            "spender": c.spender,
                            "value": c.value.to_string(),
                            "nonce": "0",
                            "deadline": c.deadline.to_string(),
                        },
                    }),
                ),
            ))
        }
        dai::permitCall::SELECTOR => {
            let c = dai::permitCall::abi_decode(input).ok()?;
            Some((
                "permit_dai",
                sign_request(
                    c.holder,
                    json!({
                        "types": {
                            "EIP712Domain": erc20_domain_type,
                            "Permit": [field("holder", "address"), field("spender", "address"),
                                field("nonce", "uint256"), field("expiry", "uint256"),
                                field("allowed", "bool")],
                        },
                        "primaryType": "Permit",
                        "domain": erc20_domain,
                        "message": {
                            "holder": c.holder,
                            "spender": c.spender,
                            "nonce": c.nonce.to_string(),
                            "expiry": c.expiry.to_string(),
                            "allowed": c.allowed,
                        },
                    }),
                ),
            ))
        }
        _ => None,
    }
}

/// The transaction itself as the `eth_sendTransaction` request its sender signed.
pub fn send_request(
    from: Address,
    to: Option<Address>,
    value: U256,
    input: &str,
    authorizations: Option<&Value>,
) -> Value {
    let mut tx = json!({
        "from": from,
        "to": to,
        "value": format!("{value:#x}"),
        "data": input,
    });
    if let Some(list) = authorizations {
        tx["authorizationList"] = list.clone();
    }
    json!({"method": "eth_sendTransaction", "params": [tx]})
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_sol_types::SolCall;

    #[test]
    fn eip2612_permit_round_trips_into_a_request_presign_flags() {
        let owner = address!("5b38da6a701c568545dcfcb03fcb875f56beddc4");
        let thief = address!("9d6c4a1e3b7f02a8c5e1d94b6a3f70c2e8b15d47");
        let usdc = address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
        let call = eip2612::permitCall {
            owner,
            spender: thief,
            value: U256::MAX,
            deadline: U256::from(1u64 << 40),
            v: 27,
            r: Default::default(),
            s: Default::default(),
        };
        let (kind, req) = signature_request(thief, usdc, &call.abi_encode(), "USD Coin").unwrap();
        assert_eq!(kind, "permit");
        let report = presign::analyze(&req).unwrap();
        assert_eq!(report.verdict(), presign::Severity::Critical);
        assert!(report.hashes.is_some());
    }

    #[test]
    fn permit2_transfer_uses_the_sender_as_spender() {
        let owner = address!("5b38da6a701c568545dcfcb03fcb875f56beddc4");
        let thief = address!("9d6c4a1e3b7f02a8c5e1d94b6a3f70c2e8b15d47");
        let call = permitTransferFrom_0Call {
            permit: PermitTransferFrom {
                permitted: TokenPermissions {
                    token: address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
                    amount: U256::from(5_000_000u64),
                },
                nonce: U256::from(7),
                deadline: U256::from(1u64 << 40),
            },
            transferDetails: SignatureTransferDetails {
                to: thief,
                requestedAmount: U256::from(5_000_000u64),
            },
            owner,
            signature: Default::default(),
        };
        let (kind, req) = signature_request(thief, PERMIT2, &call.abi_encode(), "").unwrap();
        assert_eq!(kind, "permit2_transfer");
        let report = presign::analyze(&req).unwrap();
        assert_eq!(report.top().unwrap().counterparty, Some(thief));
    }
}
