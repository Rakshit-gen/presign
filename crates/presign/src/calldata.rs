//! Decoding of transaction calldata.

use crate::known::{known, who};
use crate::parse::{amount, eth, unlimited};
use crate::report::{Report, Severity};
use crate::safe::{multisend, safe_tx};
use alloy_primitives::{Address, U256, hex};
use alloy_sol_types::{SolCall, sol};

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

/// Nested Safe and MultiSend calls are followed at most this deep.
pub(crate) const MAX_DEPTH: u8 = 4;

pub(crate) fn call(r: &mut Report, to: Option<Address>, data: &[u8], value: U256, depth: u8) {
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
