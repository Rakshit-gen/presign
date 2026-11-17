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

mod seaport {
    alloy_sol_types::sol! {
        struct OfferItem { uint8 itemType; address token; uint256 identifierOrCriteria;
                           uint256 startAmount; uint256 endAmount; }
        struct ConsiderationItem { uint8 itemType; address token; uint256 identifierOrCriteria;
                                   uint256 startAmount; uint256 endAmount; address recipient; }
        struct OrderParameters { address offerer; address zone; OfferItem[] offer;
                                 ConsiderationItem[] consideration; uint8 orderType;
                                 uint256 startTime; uint256 endTime; bytes32 zoneHash;
                                 uint256 salt; bytes32 conduitKey;
                                 uint256 totalOriginalConsiderationItems; }
        struct Order { OrderParameters parameters; bytes signature; }
        struct AdvancedOrder { OrderParameters parameters; uint120 numerator; uint120 denominator;
                               bytes signature; bytes extraData; }
        struct CriteriaResolver { uint256 orderIndex; uint8 side; uint256 index;
                                  uint256 identifier; bytes32[] criteriaProof; }
        struct FulfillmentComponent { uint256 orderIndex; uint256 itemIndex; }
        struct Fulfillment { FulfillmentComponent[] offerComponents;
                             FulfillmentComponent[] considerationComponents; }

        function fulfillOrder(Order order, bytes32 fulfillerConduitKey);
        function fulfillAdvancedOrder(AdvancedOrder advancedOrder,
                                      CriteriaResolver[] criteriaResolvers,
                                      bytes32 fulfillerConduitKey, address recipient);
        function fulfillAvailableOrders(Order[] orders,
                                        FulfillmentComponent[][] offerFulfillments,
                                        FulfillmentComponent[][] considerationFulfillments,
                                        bytes32 fulfillerConduitKey, uint256 maximumFulfilled);
        function fulfillAvailableAdvancedOrders(AdvancedOrder[] advancedOrders,
                                                CriteriaResolver[] criteriaResolvers,
                                                FulfillmentComponent[][] offerFulfillments,
                                                FulfillmentComponent[][] considerationFulfillments,
                                                bytes32 fulfillerConduitKey, address recipient,
                                                uint256 maximumFulfilled);
        function matchOrders(Order[] orders, Fulfillment[] fulfillments);
        function matchAdvancedOrders(AdvancedOrder[] orders, CriteriaResolver[] criteriaResolvers,
                                     Fulfillment[] fulfillments, address recipient);
    }
}

/// Seaport deployments by version, read from each contract's `information()`.
const SEAPORTS: &[(Address, &str)] = &[
    (address!("00000000006c3852cbEf3e08E8dF289169EdE581"), "1.1"),
    (address!("00000000000001ad428e4906aE43D8F9852d0dD6"), "1.4"),
    (address!("00000000000000ADc04C56Bf30aC9d3c0aAF14dC"), "1.5"),
    (address!("0000000000000068F116a894984e2DB1123eB395"), "1.6"),
];

/// The signed orders a Seaport fulfillment carries, as (parameters, signature).
fn seaport_orders(input: &[u8]) -> Option<Vec<(seaport::OrderParameters, Vec<u8>)>> {
    use seaport::*;
    let sel: [u8; 4] = input.get(..4)?.try_into().ok()?;
    let plain = |o: Order| (o.parameters, o.signature.to_vec());
    let advanced = |o: AdvancedOrder| (o.parameters, o.signature.to_vec());
    Some(match sel {
        fulfillOrderCall::SELECTOR => vec![plain(fulfillOrderCall::abi_decode(input).ok()?.order)],
        fulfillAdvancedOrderCall::SELECTOR => {
            vec![advanced(
                fulfillAdvancedOrderCall::abi_decode(input)
                    .ok()?
                    .advancedOrder,
            )]
        }
        fulfillAvailableOrdersCall::SELECTOR => {
            let c = fulfillAvailableOrdersCall::abi_decode(input).ok()?;
            c.orders.into_iter().map(plain).collect()
        }
        fulfillAvailableAdvancedOrdersCall::SELECTOR => {
            let c = fulfillAvailableAdvancedOrdersCall::abi_decode(input).ok()?;
            c.advancedOrders.into_iter().map(advanced).collect()
        }
        matchOrdersCall::SELECTOR => {
            let c = matchOrdersCall::abi_decode(input).ok()?;
            c.orders.into_iter().map(plain).collect()
        }
        matchAdvancedOrdersCall::SELECTOR => {
            let c = matchAdvancedOrdersCall::abi_decode(input).ok()?;
            c.orders.into_iter().map(advanced).collect()
        }
        _ => return None,
    })
}

/// Rebuilds the `OrderComponents` request for the first order in a Seaport
/// fulfillment that someone other than `sender` signed. The on-chain counter
/// is not in the calldata, so it is set to 0.
fn seaport_request(sender: Address, to: Address, input: &[u8]) -> Option<Value> {
    let version = SEAPORTS.iter().find(|(a, _)| *a == to)?.1;
    let (p, _) = seaport_orders(input)?
        .into_iter()
        .find(|(p, sig)| p.offerer != sender && !sig.is_empty())?;
    let original = usize::try_from(p.totalOriginalConsiderationItems).ok()?;
    let item = |i: &seaport::OfferItem| {
        json!({"itemType": i.itemType, "token": i.token,
               "identifierOrCriteria": i.identifierOrCriteria.to_string(),
               "startAmount": i.startAmount.to_string(), "endAmount": i.endAmount.to_string()})
    };
    let consideration = |c: &seaport::ConsiderationItem| {
        json!({"itemType": c.itemType, "token": c.token,
               "identifierOrCriteria": c.identifierOrCriteria.to_string(),
               "startAmount": c.startAmount.to_string(), "endAmount": c.endAmount.to_string(),
               "recipient": c.recipient})
    };
    let item_fields = [
        field("itemType", "uint8"),
        field("token", "address"),
        field("identifierOrCriteria", "uint256"),
        field("startAmount", "uint256"),
        field("endAmount", "uint256"),
    ];
    let mut consideration_fields = item_fields.to_vec();
    consideration_fields.push(field("recipient", "address"));
    Some(sign_request(
        p.offerer,
        json!({
            "types": {
                "EIP712Domain": [field("name", "string"), field("version", "string"),
                    field("chainId", "uint256"), field("verifyingContract", "address")],
                "OrderComponents": [field("offerer", "address"), field("zone", "address"),
                    field("offer", "OfferItem[]"), field("consideration", "ConsiderationItem[]"),
                    field("orderType", "uint8"), field("startTime", "uint256"),
                    field("endTime", "uint256"), field("zoneHash", "bytes32"),
                    field("salt", "uint256"), field("conduitKey", "bytes32"),
                    field("counter", "uint256")],
                "OfferItem": item_fields,
                "ConsiderationItem": consideration_fields,
            },
            "primaryType": "OrderComponents",
            "domain": {"name": "Seaport", "version": version, "chainId": 1,
                       "verifyingContract": to},
            "message": {
                "offerer": p.offerer,
                "zone": p.zone,
                "offer": p.offer.iter().map(item).collect::<Vec<_>>(),
                "consideration": p.consideration.iter().take(original)
                    .map(consideration).collect::<Vec<_>>(),
                "orderType": p.orderType,
                "startTime": p.startTime.to_string(),
                "endTime": p.endTime.to_string(),
                "zoneHash": p.zoneHash,
                "salt": p.salt.to_string(),
                "conduitKey": p.conduitKey,
                "counter": "0",
            },
        }),
    ))
}

/// Turns a permit-redeeming or Seaport-fulfilling transaction back into the
/// signature request the owner approved. `sender` is the transaction's `from`, which Permit2's
/// SignatureTransfer treats as the spender. Returns the kind and the request.
pub fn signature_request(
    sender: Address,
    to: Address,
    input: &[u8],
    token_name: &str,
) -> Option<(&'static str, Value)> {
    let sel: [u8; 4] = input.get(..4)?.try_into().ok()?;
    if SEAPORTS.iter().any(|(a, _)| *a == to) {
        return seaport_request(sender, to, input).map(|r| ("seaport_order", r));
    }
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
    fn seaport_selectors_match_the_deployed_abi() {
        use seaport::*;
        assert_eq!(fulfillOrderCall::SELECTOR, [0xb3, 0xa3, 0x4c, 0x4c]);
        assert_eq!(fulfillAdvancedOrderCall::SELECTOR, [0xe7, 0xac, 0xab, 0x24]);
        assert_eq!(
            fulfillAvailableAdvancedOrdersCall::SELECTOR,
            [0x87, 0x20, 0x1b, 0x41]
        );
        assert_eq!(matchAdvancedOrdersCall::SELECTOR, [0xf2, 0xd1, 0x2b, 0x12]);
    }

    #[test]
    fn zero_price_seaport_fulfillment_rebuilds_into_a_critical_order() {
        use seaport::*;
        let victim = address!("5b38da6a701c568545dcfcb03fcb875f56beddc4");
        let thief = address!("9d6c4a1e3b7f02a8c5e1d94b6a3f70c2e8b15d47");
        let nft = OfferItem {
            itemType: 2,
            token: address!("bc4ca0eda7647a8ab7c2061c2e118a18a936f13d"),
            identifierOrCriteria: U256::from(1234),
            startAmount: U256::from(1),
            endAmount: U256::from(1),
        };
        let to_thief = ConsiderationItem {
            itemType: 0,
            token: Address::ZERO,
            identifierOrCriteria: U256::ZERO,
            startAmount: U256::from(1),
            endAmount: U256::from(1),
            recipient: thief,
        };
        let call = fulfillAdvancedOrderCall {
            advancedOrder: AdvancedOrder {
                parameters: OrderParameters {
                    offerer: victim,
                    zone: Address::ZERO,
                    offer: vec![nft],
                    consideration: vec![to_thief],
                    orderType: 0,
                    startTime: U256::ZERO,
                    endTime: U256::MAX,
                    zoneHash: Default::default(),
                    salt: U256::from(9),
                    conduitKey: Default::default(),
                    totalOriginalConsiderationItems: U256::from(1),
                },
                numerator: 1u8.try_into().unwrap(),
                denominator: 1u8.try_into().unwrap(),
                signature: vec![1; 65].into(),
                extraData: Default::default(),
            },
            criteriaResolvers: vec![],
            fulfillerConduitKey: Default::default(),
            recipient: thief,
        };
        let seaport16 = SEAPORTS[3].0;
        let (kind, req) = signature_request(thief, seaport16, &call.abi_encode(), "").unwrap();
        assert_eq!(kind, "seaport_order");
        assert_eq!(req["params"][0], json!(victim));
        let report = presign::analyze(&req).unwrap();
        assert_eq!(report.top().unwrap().code, "seaport.zero_payment");
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
