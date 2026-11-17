//! Builds the labeled dataset from public chain data.
//!
//! Drainer samples start from addresses on ScamSniffer's blacklist:
//!
//! - contract calls victims sent to the address, such as fake "claim" functions;
//! - tokens the address pulled from a wallet with `transferFrom` or
//!   `safeTransferFrom`, traced back to the owner's `Approval` or
//!   `ApprovalForAll` naming the address, and from there to the owner's own
//!   approve transaction or the permit the drainer redeemed. Tokens the owner
//!   sent by hand are skipped, since they cannot be told apart from a transfer
//!   between the owner's own wallets;
//! - permits the address redeemed itself, rebuilt into the signed request.
//!
//! Benign samples come from recent mainnet blocks: a seeded random slice of
//! all transactions plus every permit redemption in range, skipping anything
//! that touches a listed address.

use crate::net::Http;
use crate::rebuild::{send_request, signature_request};
use alloy_primitives::{Address, U256, hex, keccak256};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::Duration;

const SCAMSNIFFER_LIST: &str =
    "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json";
const SCAMSNIFFER_HEAD: &str =
    "https://api.github.com/repos/scamsniffer/scam-database/commits/main";
const BLOCKSCOUT: &str = "https://eth.blockscout.com/api/v2";
const APPROVAL: &str = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
const APPROVAL_FOR_ALL: &str = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31";
/// transferFrom, safeTransferFrom(address,address,uint256), safeTransferFrom(...,bytes)
const PULL_METHODS: &[&str] = &[
    "transferFrom",
    "safeTransferFrom",
    "0x23b872dd",
    "0x42842e0e",
    "0xb88d4fde",
];
/// How far before a drain to look for the victim's approval. Drainers
/// usually sweep within minutes; 10,000 blocks is about 1.4 days.
const APPROVAL_WINDOW: u64 = 10_000;

pub struct Options {
    /// RPC for recent blocks (benign samples).
    pub rpc: String,
    /// RPC that serves historical logs and transactions.
    pub archive_rpc: String,
    pub drainers: usize,
    pub per_drainer: usize,
    pub blocks: u64,
    pub benign_per_block: usize,
    pub seed: String,
}

/// Deterministic shuffle key: the same seed always picks the same sample.
fn rank(seed: &str, item: &[u8]) -> [u8; 32] {
    keccak256([seed.as_bytes(), item].concat()).0
}

fn addr(v: &Value) -> Option<Address> {
    v.as_str()?.parse().ok()
}

fn hex_u256(v: &Value) -> U256 {
    v.as_str()
        .and_then(|s| U256::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or_default()
}

fn pad(a: Address) -> String {
    format!("0x{:0>64}", hex::encode(a))
}

struct Writer {
    out: BufWriter<File>,
    seen: HashSet<String>,
    counts: BTreeMap<String, usize>,
}

impl Writer {
    fn push(
        &mut self,
        label: &str,
        kind: &str,
        source: &str,
        request: Value,
    ) -> Result<(), String> {
        if !self.seen.insert(format!("{label}:{source}")) {
            return Ok(());
        }
        *self.counts.entry(format!("{label}/{kind}")).or_default() += 1;
        let line = json!({"label": label, "kind": kind, "source": source, "request": request});
        writeln!(self.out, "{line}").map_err(|e| e.to_string())
    }
}

struct Sources {
    explorer: Http,
    archive: Http,
    archive_rpc: String,
}

pub fn build(dir: &Path, opt: &Options) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let mut src = Sources {
        explorer: Http::new(Duration::from_millis(1100)),
        archive: Http::new(Duration::from_millis(250)),
        archive_rpc: opt.archive_rpc.clone(),
    };
    let mut recent = Http::new(Duration::from_millis(50));

    let head_commit = src.explorer.get_json(SCAMSNIFFER_HEAD)?["sha"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let list: Vec<Address> =
        serde_json::from_value::<Vec<String>>(src.explorer.get_json(SCAMSNIFFER_LIST)?)
            .map_err(|e| format!("unexpected blacklist format: {e}"))?
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
    let listed: HashSet<Address> = list.iter().copied().collect();
    eprintln!(
        "blacklist: {} addresses at commit {head_commit}",
        list.len()
    );

    let mut sample = list.clone();
    sample.sort_by_key(|a| rank(&opt.seed, a.as_slice()));
    sample.truncate(opt.drainers);

    let file = File::create(dir.join("dataset.jsonl")).map_err(|e| e.to_string())?;
    let mut w = Writer {
        out: BufWriter::new(file),
        seen: HashSet::new(),
        counts: BTreeMap::new(),
    };

    let mut skipped_drainers = Vec::new();
    for (i, drainer) in sample.iter().enumerate() {
        eprintln!("drainer {}/{}: {drainer}", i + 1, sample.len());
        if let Err(e) = drainer_samples(&mut src, &mut w, *drainer, &listed, opt.per_drainer) {
            eprintln!("  skipped: {e}");
            skipped_drainers.push(drainer.to_string());
        }
    }

    let head = recent.rpc(&opt.rpc, "eth_blockNumber", json!([]))?;
    let head = u64::from_str_radix(head.as_str().unwrap_or("0x0").trim_start_matches("0x"), 16)
        .map_err(|e| e.to_string())?;
    let first = head.saturating_sub(opt.blocks) + 1;
    let mut skipped_blocks = Vec::new();
    for n in first..=head {
        if (n - first) % 50 == 0 {
            eprintln!("block {n} ({}/{})", n - first + 1, opt.blocks);
        }
        let params = json!([format!("{n:#x}"), true]);
        match recent.rpc(&opt.rpc, "eth_getBlockByNumber", params) {
            Ok(block) => benign_samples(&mut w, &block, &listed, opt)?,
            Err(e) => {
                eprintln!("  block {n} skipped: {e}");
                skipped_blocks.push(n);
            }
        }
    }
    w.out.flush().map_err(|e| e.to_string())?;

    let manifest = json!({
        "scamsniffer_commit": head_commit,
        "blacklist_size": list.len(),
        "drainers_sampled": sample.len(),
        "per_drainer_cap": opt.per_drainer,
        "approval_window_blocks": APPROVAL_WINDOW,
        "blocks": [first, head],
        "benign_per_block": opt.benign_per_block,
        "seed": opt.seed,
        "skipped_drainers": skipped_drainers,
        "skipped_blocks": skipped_blocks,
        "counts": w.counts,
    });
    let pretty = serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?;
    fs::write(dir.join("manifest.json"), pretty).map_err(|e| e.to_string())?;
    eprintln!(
        "{}",
        serde_json::to_string_pretty(&manifest["counts"]).unwrap_or_default()
    );
    Ok(())
}

fn drainer_samples(
    src: &mut Sources,
    w: &mut Writer,
    drainer: Address,
    listed: &HashSet<Address>,
    cap: usize,
) -> Result<(), String> {
    // Contract calls that victims sent straight to the drainer.
    let incoming = src.explorer.get_json(&format!(
        "{BLOCKSCOUT}/addresses/{drainer}/transactions?filter=to"
    ))?;
    let mut taken = 0;
    for tx in incoming["items"].as_array().into_iter().flatten() {
        let (Some(from), Some(input)) = (addr(&tx["from"]["hash"]), tx["raw_input"].as_str())
        else {
            continue;
        };
        let is_call = input.len() >= 10 && tx["to"]["is_contract"].as_bool() == Some(true);
        if taken >= cap || !is_call || tx["status"] != "ok" || listed.contains(&from) {
            continue;
        }
        let value = tx["value"]
            .as_str()
            .and_then(|v| v.parse().ok())
            .unwrap_or_default();
        let source = tx["hash"].as_str().unwrap_or_default();
        let req = send_request(from, Some(drainer), value, input, None);
        w.push("drainer", "victim_call", source, req)?;
        taken += 1;
    }

    // Tokens the drainer pulled out of victims' wallets, traced back to the
    // approval or permit that allowed it.
    let pulled = src.explorer.get_json(&format!(
        "{BLOCKSCOUT}/addresses/{drainer}/token-transfers?filter=to&type=ERC-20,ERC-721"
    ))?;
    let mut pairs = HashSet::new();
    let mut taken = 0;
    for t in pulled["items"].as_array().into_iter().flatten() {
        if taken >= cap {
            break;
        }
        let (Some(victim), Some(token), Some(block)) = (
            addr(&t["from"]["hash"]),
            addr(&t["token"]["address_hash"]),
            t["block_number"].as_u64(),
        ) else {
            continue;
        };
        let pulled_by_drainer = t["method"]
            .as_str()
            .is_some_and(|m| PULL_METHODS.contains(&m));
        if !pulled_by_drainer
            || victim.is_zero()
            || listed.contains(&victim)
            || !pairs.insert((victim, token))
        {
            continue;
        }
        let Some(transfer_hash) = t["transaction_hash"].as_str() else {
            continue;
        };
        let transfer = src.archive.rpc(
            &src.archive_rpc,
            "eth_getTransactionByHash",
            json!([transfer_hash]),
        )?;
        if addr(&transfer["from"]) == Some(victim) {
            // The holder sent the token themselves. That can be a scam victim,
            // or someone moving tokens between their own wallets; nothing
            // on-chain tells them apart, so it is left out of the labels.
            continue;
        }
        let topic = if t["token"]["type"] == "ERC-721" {
            APPROVAL_FOR_ALL
        } else {
            APPROVAL
        };
        let filter = json!([{
            "address": token,
            "fromBlock": format!("{:#x}", block.saturating_sub(APPROVAL_WINDOW)),
            "toBlock": format!("{block:#x}"),
            "topics": [topic, pad(victim), pad(drainer)],
        }]);
        let logs = src.archive.rpc(&src.archive_rpc, "eth_getLogs", filter)?;
        let Some(hash) = logs
            .as_array()
            .and_then(|l| l.last())
            .and_then(|l| l["transactionHash"].as_str())
        else {
            continue;
        };
        let tx = src
            .archive
            .rpc(&src.archive_rpc, "eth_getTransactionByHash", json!([hash]))?;
        let (Some(from), Some(to), Some(input)) =
            (addr(&tx["from"]), addr(&tx["to"]), tx["input"].as_str())
        else {
            continue;
        };
        if from == victim {
            let req = send_request(from, Some(to), hex_u256(&tx["value"]), input, None);
            w.push("drainer", "victim_approval", hash, req)?;
            taken += 1;
        } else if let Ok(bytes) = hex::decode(input)
            && let Some((kind, req)) = signature_request(from, to, &bytes, "Token")
        {
            w.push("drainer", kind, hash, req)?;
            taken += 1;
        }
    }

    // Permits the drainer redeemed itself.
    let outgoing = src.explorer.get_json(&format!(
        "{BLOCKSCOUT}/addresses/{drainer}/transactions?filter=from"
    ))?;
    let mut taken = 0;
    for tx in outgoing["items"].as_array().into_iter().flatten() {
        if taken >= cap {
            break;
        }
        let (Some(to), Some(input)) = (addr(&tx["to"]["hash"]), tx["raw_input"].as_str()) else {
            continue;
        };
        let Ok(bytes) = hex::decode(input) else {
            continue;
        };
        let name = tx["to"]["name"].as_str().unwrap_or("Token");
        if let Some((kind, req)) = signature_request(drainer, to, &bytes, name) {
            w.push(
                "drainer",
                kind,
                tx["hash"].as_str().unwrap_or_default(),
                req,
            )?;
            taken += 1;
        }
    }
    Ok(())
}

fn benign_samples(
    w: &mut Writer,
    block: &Value,
    listed: &HashSet<Address>,
    opt: &Options,
) -> Result<(), String> {
    let mut general = Vec::new();
    for tx in block["transactions"].as_array().into_iter().flatten() {
        let (Some(from), Some(input), Some(hash)) =
            (addr(&tx["from"]), tx["input"].as_str(), tx["hash"].as_str())
        else {
            continue;
        };
        let to = addr(&tx["to"]);
        if listed.contains(&from) || to.is_some_and(|t| listed.contains(&t)) {
            continue;
        }
        let bytes = hex::decode(input).unwrap_or_default();
        if let Some(t) = to
            && let Some((kind, req)) = signature_request(from, t, &bytes, "Token")
        {
            let spender_listed = presign::analyze(&req)
                .ok()
                .and_then(|r| r.top().and_then(|f| f.counterparty))
                .is_some_and(|s| listed.contains(&s));
            if !spender_listed {
                w.push("benign", kind, hash, req)?;
            }
            continue;
        }
        general.push((rank(&opt.seed, hash.as_bytes()), from, to, tx, input, hash));
    }
    general.sort_by_key(|g| g.0);
    for (_, from, to, tx, input, hash) in general.into_iter().take(opt.benign_per_block) {
        let auths = tx.get("authorizationList");
        let kind = if auths.is_some() { "tx_7702" } else { "tx" };
        let req = send_request(from, to, hex_u256(&tx["value"]), input, auths);
        w.push("benign", kind, hash, req)?;
    }
    Ok(())
}
