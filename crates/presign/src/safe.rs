//! Safe multisig transactions and MultiSend batches.

use crate::calldata::call;
use crate::known::{known, who};
use crate::report::{Report, Severity};
use alloy_primitives::{Address, U256};

pub(crate) fn safe_tx(r: &mut Report, to: Address, value: U256, data: &[u8], op: u8, depth: u8) {
    match op {
        0 => call(r, Some(to), data, value, depth + 1),
        1 if known(to).is_some_and(|n| n.starts_with("Safe MultiSendCallOnly")) => {
            r.add(
                "safe.multisend",
                Severity::Info,
                format!("batch of calls through {}", who(to)),
            );
            call(r, Some(to), data, value, depth + 1);
        }
        1 => r.add_with(
            "safe.delegatecall",
            to,
            Severity::Critical,
            format!(
                "delegatecall to {}: that contract's code runs as your Safe and can \
                 rewrite its logic, change owners and drain every asset. This is the \
                 pattern used to steal about $1.5B from Bybit in February 2025.",
                who(to)
            ),
        ),
        _ => r.add(
            "safe.unknown_operation",
            Severity::High,
            format!("unknown Safe operation type {op}"),
        ),
    }
}

/// MultiSend packs each call as: operation (1) | to (20) | value (32) | len (32) | data.
pub(crate) fn multisend(r: &mut Report, mut buf: &[u8], depth: u8) {
    while !buf.is_empty() {
        if buf.len() < 85 {
            r.add(
                "safe.malformed",
                Severity::High,
                "MultiSend batch is truncated",
            );
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
            r.add(
                "safe.malformed",
                Severity::High,
                "MultiSend batch has an invalid length",
            );
            return;
        };
        safe_tx(r, to, value, &buf[85..end], op, depth + 1);
        buf = &buf[end..];
    }
}
