//! bsb-bond: one party's on-chain agent for a storage deal: the sentinel bond and the payment channel.
//!
//! Each process runs with its own key (BSB_SEED) and its own fee wallet, and sees the other side only
//! through public data: the deal and channel files and the chain itself. The provider learns a revealed r
//! from the challenge transaction's witness, not from the client. Neither side relies on a presigned
//! transaction before checking the other side's signature on it and, where it matters, the funding
//! output on chain.
//!
//!   info                                   this party's x-only key and fee address
//!   bond-fund      <deal>          provider  fund Bond_0, presign every Challenge_i  → <deal>.p.json
//!   bond-presign   <deal>          client    check the bond on chain and the provider's signatures,
//!                                            presign every Respond_i                 → <deal>.c.json
//!   bond-accept    <deal>          provider  check the client's Respond_i signatures
//!   bond-challenge <deal> <i> <r>  client    cosign Challenge_i, revealing r_i
//!   bond-respond   <deal> <i>      provider  if Challenge_i is on chain, read r_i from it, ask the
//!                                            provider's own server for the windows, submit Respond_i
//!   bond-forfeit   <deal> <i>      client    take the bond after Δ blocks without an answer
//!   bond-refund    <deal> <i>      provider  take the bond back from Bond_i once the term has ended
//!   bond-status    <deal>          either    which challenge and respond transactions confirmed
//!   chan-open      <chan>          client    fund a one-way payment channel to the provider
//!   chan-check     <chan>          provider  check the channel's funding output on chain
//!   chan-sign      <chan> <paid>   client    sign the state that pays the provider <paid> sats in total
//!   chan-verify    <chan> <paid> <sig>  provider  check such a signature
//!   chan-close     <chan> <paid> <sig>  provider  countersign the latest state and broadcast it
//!
//! The channel is a Spilman-style one-way channel. One output pays to a 2-of-2 leaf, and the client can
//! refund it alone after `t_refund`. Each payment is a new client-signed state paying the provider more.
//! The provider keeps the latest and closes before `t_refund`. Results print as one JSON line; an error
//! prints {"error": ...} and exits 1. Test keys only: never point this at a real network.

#[path = "../common.rs"]
mod common;

use bitcoin::absolute::LockTime;
use bitcoin::opcodes::all::*;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::taproot::LeafVersion;
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxOut, Txid, XOnlyPublicKey};
use common::rpc::Rpc;
use common::*;
use serde_json::{json, Value};

const CHAN_FEE: Amount = Amount::from_sat(1_000);
const DUST: u64 = 330;

fn die(msg: impl std::fmt::Display) -> ! {
    println!("{}", json!({ "error": msg.to_string() }));
    std::process::exit(1);
}
fn read_json(path: &str) -> Value {
    let s = std::fs::read_to_string(path).unwrap_or_else(|e| die(format!("{path}: {e}")));
    serde_json::from_str(&s).unwrap_or_else(|e| die(format!("{path}: {e}")))
}
fn write_json(path: &str, v: &Value) {
    std::fs::write(path, serde_json::to_string_pretty(v).unwrap()).unwrap_or_else(|e| die(format!("{path}: {e}")));
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn xonly(v: &Value) -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&unhex(v.as_str().unwrap_or_else(|| die("missing key")))).unwrap_or_else(|e| die(e))
}
fn spk_of(secp: &Secp256k1<All>, x: &XOnlyPublicKey) -> ScriptBuf {
    Address::p2tr(secp, *x, None, Network::Regtest).script_pubkey()
}
fn sats(v: &Value) -> u64 {
    (v.as_f64().unwrap_or(0.0) * 1e8).round() as u64
}

/// Confirmations of a transaction: None if the node has never seen it, Some(0) if it is in the mempool.
fn confirmations(node: &Node, txid: &Txid) -> Option<u64> {
    node.rpc.call("getrawtransaction", json!([txid.to_string(), true])).ok().map(|v| v["confirmations"].as_u64().unwrap_or(0))
}

struct Deal {
    path: String,
    url: String,
    sha: String,
    p: XOnlyPublicKey,
    c: XOnlyPublicKey,
    t_end: u32,
    sh: Vec<([u8; 32], Vec<[u8; 32]>)>,
}

fn load_deal(path: &str) -> Deal {
    let v = read_json(path);
    let sens = v["sentinels"].as_array().unwrap_or_else(|| die("deal: sentinels"));
    Deal {
        path: path.to_string(),
        url: v["provider_url"].as_str().unwrap_or_else(|| die("deal: provider_url")).to_string(),
        sha: v["sha256"].as_str().unwrap_or_else(|| die("deal: sha256")).to_string(),
        p: xonly(&v["provider_x"]),
        c: xonly(&v["client_x"]),
        t_end: v["t_end"].as_u64().unwrap_or_else(|| die("deal: t_end")) as u32,
        sh: sens
            .iter()
            .map(|s| {
                let hs = match s["hs"].as_array() {
                    Some(a) => a.iter().map(|h| arr32(&unhex(h.as_str().unwrap()))).collect(),
                    None => vec![arr32(&unhex(s["h"].as_str().unwrap()))],
                };
                (arr32(&unhex(s["s"].as_str().unwrap())), hs)
            })
            .collect(),
    }
}

struct Bond {
    ch: Chain,
    fund_op: OutPoint,
    challenge: Vec<Transaction>,
    respond: Vec<Transaction>,
    sig_p: Vec<Vec<u8>>,
    sig_c: Vec<Vec<u8>>,
}

/// The deal's chain plus whatever presignatures exist so far (<deal>.p.json, <deal>.c.json).
fn load_bond(secp: &Secp256k1<All>, d: &Deal) -> Bond {
    let ch = build_chain(secp, nums(), &d.p, &d.c, &d.sh, d.t_end);
    let p = read_json(&d.path.replace(".json", ".p.json"));
    let fund_op = OutPoint { txid: p["fund_txid"].as_str().unwrap_or_else(|| die("no fund_txid")).parse().unwrap(), vout: 0 };
    let (challenge, respond) = chain_txs(&ch, fund_op);
    let sigs = |v: &Value, k: &str| -> Vec<Vec<u8>> { v[k].as_array().map(|a| a.iter().map(|s| unhex(s.as_str().unwrap())).collect()).unwrap_or_default() };
    let cpath = d.path.replace(".json", ".c.json");
    let c = if std::path::Path::new(&cpath).exists() { read_json(&cpath) } else { json!({}) };
    Bond { ch, fund_op, challenge, respond, sig_p: sigs(&p, "sig_p_challenge"), sig_c: sigs(&c, "sig_c_respond") }
}

fn bond_prev(b: &Bond, i: usize) -> TxOut {
    TxOut { value: BOND, script_pubkey: b.ch.bonds[i].spk.clone() }
}
fn challenged_prev(b: &Bond, i: usize) -> TxOut {
    TxOut { value: BOND, script_pubkey: b.ch.challenged[i].spk.clone() }
}

/// The provider's agent asks its own Blossom server for r ‖ window, one item per window.
fn ask_provider(d: &Deal, r: &[u8], m: usize) -> Result<Vec<Vec<u8>>, String> {
    let url = format!("{}/sentinel/{}?r={}&m={m}", d.url, d.sha, hex(r));
    match ureq::get(&url).call() {
        Ok(resp) => {
            let v: Value = resp.into_json().map_err(|e| e.to_string())?;
            let items = v["items"].as_array().ok_or("no items")?;
            Ok(items.iter().map(|x| unhex(x.as_str().unwrap_or(""))).collect())
        }
        Err(ureq::Error::Status(code, resp)) => Err(format!("HTTP {code} {}", resp.header("x-reason").unwrap_or(""))),
        Err(e) => Err(e.to_string()),
    }
}

// ───────────────────────────── payment channel ─────────────────────────────

struct Chan {
    path: String,
    p: XOnlyPublicKey,
    c: XOnlyPublicKey,
    capacity: Amount,
    t_refund: u32,
    st: State,
    coop: ScriptBuf,
}

fn load_chan(secp: &Secp256k1<All>, path: &str) -> (Chan, Value) {
    let v = read_json(path);
    let p = xonly(&v["provider_x"]);
    let c = xonly(&v["client_x"]);
    let t_refund = v["t_refund"].as_u64().unwrap_or_else(|| die("channel: t_refund")) as u32;
    let coop = Builder::new().push_x_only_key(&c).push_opcode(OP_CHECKSIGVERIFY).push_x_only_key(&p).push_opcode(OP_CHECKSIG).into_script();
    let refund = Builder::new().push_int(t_refund as i64).push_opcode(OP_CLTV).push_opcode(OP_DROP).push_x_only_key(&c).push_opcode(OP_CHECKSIG).into_script();
    let st = state(secp, nums(), &[&coop, &refund]);
    let capacity = Amount::from_sat(v["capacity_sats"].as_u64().unwrap_or_else(|| die("channel: capacity_sats")));
    (Chan { path: path.to_string(), p, c, capacity, t_refund, st, coop }, v)
}

fn funding(v: &Value) -> OutPoint {
    OutPoint {
        txid: v["funding_txid"].as_str().unwrap_or_else(|| die("channel not opened")).parse().unwrap(),
        vout: v["funding_vout"].as_u64().unwrap_or(0) as u32,
    }
}

/// The state paying the provider `paid` sats in total; the client's change carries the fee.
fn chan_state(secp: &Secp256k1<All>, ch: &Chan, op: OutPoint, paid: u64) -> Transaction {
    if paid < DUST || paid + CHAN_FEE.to_sat() + DUST > ch.capacity.to_sat() {
        die(format!("paid {paid} sats is outside {DUST}..capacity minus fee and dust"));
    }
    Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![txin(op, Sequence::ENABLE_RBF_NO_LOCKTIME)],
        output: vec![
            TxOut { value: Amount::from_sat(paid), script_pubkey: spk_of(secp, &ch.p) },
            TxOut { value: ch.capacity - Amount::from_sat(paid) - CHAN_FEE, script_pubkey: spk_of(secp, &ch.c) },
        ],
    }
}

fn index(s: &str) -> usize {
    s.parse().unwrap_or_else(|_| die("index must be a number"))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |i: usize| -> String { args.get(i).cloned().unwrap_or_else(|| die(format!("missing argument {i}"))) };
    let seed = std::env::var("BSB_SEED").unwrap_or_else(|_| die("BSB_SEED is not set"));
    let url = std::env::var("BSB_RPC").unwrap_or_else(|_| "http://127.0.0.1:18543".into());
    let secp = Secp256k1::new();
    let me = party(&secp, &seed);
    let fee = party(&secp, &format!("bsb/fee|{seed}"));
    let fee_addr = Address::p2tr(&secp, fee.x, None, Network::Regtest);
    let node = Node { rpc: Rpc::new(&url, "bsb", "bsb-regtest-only"), secp, fee, fee_addr };
    let secp = &node.secp;
    let chain = node.rpc.call("getblockchaininfo", json!([])).unwrap_or_else(|e| die(format!("bitcoind: {e}")));
    if chain["chain"] != "regtest" {
        die("refusing to run anywhere but regtest");
    }
    let out = match args.get(1).map(String::as_str) {
        Some("info") => json!({ "x": me.x.to_string(), "fee_address": node.fee_addr.to_string() }),

        Some("bond-fund") => {
            let d = load_deal(&arg(2));
            if d.p != me.x { die("this key is not the deal's provider"); }
            let ch = build_chain(secp, nums(), &d.p, &d.c, &d.sh, d.t_end);
            let fund = node.fund(&ch.bonds[0].spk);
            node.send(&fund).unwrap_or_else(|e| die(format!("fund: {e}")));
            let (challenge, _) = chain_txs(&ch, OutPoint { txid: fund.compute_txid(), vout: 0 });
            let sigs: Vec<String> = (0..challenge.len())
                .map(|i| hex(&script_sig(secp, &challenge[i], &TxOut { value: BOND, script_pubkey: ch.bonds[i].spk.clone() }, &ch.challenge_leaves[i], &me)))
                .collect();
            let v = json!({ "fund_txid": fund.compute_txid().to_string(), "fund_vsize": fund.vsize(), "bond_sats": BOND.to_sat(), "sig_p_challenge": sigs });
            write_json(&d.path.replace(".json", ".p.json"), &v);
            v
        }

        Some("bond-presign") => {
            let d = load_deal(&arg(2));
            if d.c != me.x { die("this key is not the deal's client"); }
            let b = load_bond(secp, &d);
            // The bond must exist on chain, unspent, at the address both sides derived.
            let utxo = node.rpc.call("gettxout", json!([b.fund_op.txid.to_string(), b.fund_op.vout, false])).unwrap_or(Value::Null);
            if utxo.is_null() { die("bond output is not confirmed and unspent"); }
            if utxo["scriptPubKey"]["hex"].as_str() != Some(hex(b.ch.bonds[0].spk.as_bytes()).as_str()) { die("bond output pays the wrong script"); }
            if sats(&utxo["value"]) != BOND.to_sat() { die("bond output has the wrong value"); }
            for i in 0..b.challenge.len() {
                if b.sig_p.len() <= i || !verify_script_sig(secp, &b.challenge[i], &bond_prev(&b, i), &b.ch.challenge_leaves[i], &d.p, &b.sig_p[i]) {
                    die(format!("provider's signature on Challenge_{i} does not verify"));
                }
            }
            let sigs: Vec<String> = (0..b.respond.len())
                .map(|i| hex(&script_sig(secp, &b.respond[i], &challenged_prev(&b, i), &b.ch.respond_leaves[i], &me)))
                .collect();
            let v = json!({ "sig_c_respond": sigs, "checked": { "bond_confirmations": utxo["confirmations"], "provider_signatures": b.challenge.len() } });
            write_json(&d.path.replace(".json", ".c.json"), &v);
            v
        }

        Some("bond-accept") => {
            let d = load_deal(&arg(2));
            if d.p != me.x { die("this key is not the deal's provider"); }
            let b = load_bond(secp, &d);
            if b.sig_c.len() != b.respond.len() { die("missing client signatures"); }
            for i in 0..b.respond.len() {
                if !verify_script_sig(secp, &b.respond[i], &challenged_prev(&b, i), &b.ch.respond_leaves[i], &d.c, &b.sig_c[i]) {
                    die(format!("client's signature on Respond_{i} does not verify"));
                }
            }
            json!({ "ok": true, "respond_signatures": b.respond.len() })
        }

        Some("bond-challenge") => {
            let d = load_deal(&arg(2));
            if d.c != me.x { die("this key is not the deal's client"); }
            let i = index(&arg(3));
            let r = unhex(&arg(4));
            let b = load_bond(secp, &d);
            if i >= b.challenge.len() { die("no such sentinel"); }
            let sig_c = script_sig(secp, &b.challenge[i], &bond_prev(&b, i), &b.ch.challenge_leaves[i], &me);
            let tx = with_witness(b.challenge[i].clone(), vec![r, b.sig_p[i].clone(), sig_c, b.ch.challenge_leaves[i].to_bytes(), control(&b.ch.bonds[i], &b.ch.challenge_leaves[i])]);
            node.submit_package(&tx).unwrap_or_else(|e| die(format!("challenge: {e}")));
            json!({ "txid": tx.compute_txid().to_string(), "vsize": tx.vsize() })
        }

        Some("bond-respond") => {
            let d = load_deal(&arg(2));
            if d.p != me.x { die("this key is not the deal's provider"); }
            let i = index(&arg(3));
            let b = load_bond(secp, &d);
            if i >= b.challenge.len() { die("no such sentinel"); }
            if confirmations(&node, &b.respond[i].compute_txid()).is_some() {
                json!({ "status": "already" })
            } else {
                match confirmations(&node, &b.challenge[i].compute_txid()) {
                    None | Some(0) => json!({ "status": "idle" }),
                    Some(_) => {
                        // Read r_i from the challenge's witness on chain.
                        let raw = node.rpc.call("getrawtransaction", json!([b.challenge[i].compute_txid().to_string(), true])).unwrap();
                        let r = unhex(raw["vin"][0]["txinwitness"][0].as_str().unwrap_or(""));
                        match ask_provider(&d, &r, d.sh[i].1.len()) {
                            Err(e) => json!({ "status": "no-answer", "r": hex(&r), "error": e }),
                            Ok(items) => {
                                let sig_p = script_sig(secp, &b.respond[i], &challenged_prev(&b, i), &b.ch.respond_leaves[i], &me);
                                let mut wit: Vec<Vec<u8>> = items.into_iter().rev().collect();
                                wit.extend([b.sig_c[i].clone(), sig_p, b.ch.respond_leaves[i].to_bytes(), control(&b.ch.challenged[i], &b.ch.respond_leaves[i])]);
                                let tx = with_witness(b.respond[i].clone(), wit);
                                match node.submit_package(&tx) {
                                    Ok(_) => json!({ "status": "responded", "r": hex(&r), "txid": tx.compute_txid().to_string(), "vsize": tx.vsize() }),
                                    Err(e) => json!({ "status": "rejected", "r": hex(&r), "error": e.split(", input 0").next().unwrap_or(&e) }),
                                }
                            }
                        }
                    }
                }
            }
        }

        Some("bond-forfeit") => {
            let d = load_deal(&arg(2));
            if d.c != me.x { die("this key is not the deal's client"); }
            let i = index(&arg(3));
            let b = load_bond(secp, &d);
            let mut tx = Transaction {
                version: Version(2),
                lock_time: LockTime::ZERO,
                input: vec![txin(OutPoint { txid: b.challenge[i].compute_txid(), vout: 0 }, Sequence::from_height(DELTA))],
                output: vec![TxOut { value: BOND - CLOSE_FEE, script_pubkey: spk_of(secp, &me.x) }],
            };
            let sig = script_sig(secp, &tx, &challenged_prev(&b, i), &b.ch.forfeit, &me);
            tx = with_witness(tx, vec![sig, b.ch.forfeit.to_bytes(), control(&b.ch.challenged[i], &b.ch.forfeit)]);
            node.send(&tx).unwrap_or_else(|e| die(format!("forfeit: {e}")));
            json!({ "txid": tx.compute_txid().to_string(), "vsize": tx.vsize() })
        }

        Some("bond-refund") => {
            let d = load_deal(&arg(2));
            if d.p != me.x { die("this key is not the deal's provider"); }
            let i = index(&arg(3));
            let b = load_bond(secp, &d);
            let op = if i == 0 { b.fund_op } else { OutPoint { txid: b.respond[i - 1].compute_txid(), vout: 0 } };
            let mut tx = Transaction {
                version: Version(2),
                lock_time: LockTime::from_height(d.t_end).unwrap(),
                input: vec![txin(op, Sequence::ENABLE_LOCKTIME_NO_RBF)],
                output: vec![TxOut { value: BOND - CLOSE_FEE, script_pubkey: spk_of(secp, &me.x) }],
            };
            let sig = script_sig(secp, &tx, &bond_prev(&b, i), &b.ch.refund, &me);
            tx = with_witness(tx, vec![sig, b.ch.refund.to_bytes(), control(&b.ch.bonds[i], &b.ch.refund)]);
            node.send(&tx).unwrap_or_else(|e| die(format!("refund: {e}")));
            json!({ "txid": tx.compute_txid().to_string(), "vsize": tx.vsize() })
        }

        Some("bond-status") => {
            let d = load_deal(&arg(2));
            let b = load_bond(secp, &d);
            let rows: Vec<Value> = (0..b.challenge.len())
                .map(|i| json!({
                    "i": i,
                    "challenge_txid": b.challenge[i].compute_txid().to_string(),
                    "challenge": confirmations(&node, &b.challenge[i].compute_txid()),
                    "respond_txid": b.respond[i].compute_txid().to_string(),
                    "respond": confirmations(&node, &b.respond[i].compute_txid()),
                }))
                .collect();
            json!({ "fund_txid": b.fund_op.txid.to_string(), "states": rows, "height": node.rpc.height() })
        }

        Some("chan-open") => {
            let path = arg(2);
            let (ch, mut v) = load_chan(secp, &path);
            if ch.c != me.x { die("this key is not the channel's client"); }
            let (op, prev) = node.fee_utxo();
            let fee = Amount::from_sat(FEERATE * 154);
            let mut tx = Transaction {
                version: Version(2),
                lock_time: LockTime::ZERO,
                input: vec![txin(op, Sequence::ENABLE_RBF_NO_LOCKTIME)],
                output: vec![
                    TxOut { value: ch.capacity, script_pubkey: ch.st.spk.clone() },
                    TxOut { value: prev.value - ch.capacity - fee, script_pubkey: node.fee_addr.script_pubkey() },
                ],
            };
            node.sign_fee_input(&mut tx, 0, &[prev]);
            node.send(&tx).unwrap_or_else(|e| die(format!("channel open: {e}")));
            v["funding_txid"] = json!(tx.compute_txid().to_string());
            v["funding_vout"] = json!(0);
            v["address"] = json!(Address::from_script(&ch.st.spk, Network::Regtest).unwrap().to_string());
            write_json(&ch.path, &v);
            v
        }

        Some("chan-check") => {
            let (ch, v) = load_chan(secp, &arg(2));
            if ch.p != me.x { die("this key is not the channel's provider"); }
            let op = funding(&v);
            let utxo = node.rpc.call("gettxout", json!([op.txid.to_string(), op.vout, false])).unwrap_or(Value::Null);
            if utxo.is_null() { die("channel funding is not confirmed and unspent"); }
            if utxo["scriptPubKey"]["hex"].as_str() != Some(hex(ch.st.spk.as_bytes()).as_str()) { die("channel funding pays the wrong script"); }
            if sats(&utxo["value"]) != ch.capacity.to_sat() { die("channel funding has the wrong value"); }
            if node.rpc.height() + 144 > ch.t_refund { die("channel refund is too close"); }
            json!({ "ok": true, "confirmations": utxo["confirmations"], "capacity_sats": ch.capacity.to_sat(), "t_refund": ch.t_refund })
        }

        Some("chan-sign") => {
            let (ch, v) = load_chan(secp, &arg(2));
            if ch.c != me.x { die("this key is not the channel's client"); }
            let paid: u64 = arg(3).parse().unwrap_or_else(|_| die("paid"));
            let prev = TxOut { value: ch.capacity, script_pubkey: ch.st.spk.clone() };
            let tx = chan_state(secp, &ch, funding(&v), paid);
            json!({ "paid": paid, "sig": hex(&script_sig(secp, &tx, &prev, &ch.coop, &me)) })
        }

        Some(cmd @ ("chan-verify" | "chan-close")) => {
            let (ch, v) = load_chan(secp, &arg(2));
            if ch.p != me.x { die("this key is not the channel's provider"); }
            let paid: u64 = arg(3).parse().unwrap_or_else(|_| die("paid"));
            let sig_c = unhex(&arg(4));
            let prev = TxOut { value: ch.capacity, script_pubkey: ch.st.spk.clone() };
            let tx = chan_state(secp, &ch, funding(&v), paid);
            if !verify_script_sig(secp, &tx, &prev, &ch.coop, &ch.c, &sig_c) { die("client signature does not verify"); }
            if cmd == "chan-verify" {
                json!({ "ok": true, "paid": paid })
            } else {
                let sig_p = script_sig(secp, &tx, &prev, &ch.coop, &me);
                let ctrl = ch.st.spend.control_block(&(ch.coop.clone(), LeafVersion::TapScript)).unwrap().serialize();
                let tx = with_witness(tx, vec![sig_p, sig_c, ch.coop.to_bytes(), ctrl]);
                node.send(&tx).unwrap_or_else(|e| die(format!("close: {e}")));
                json!({ "txid": tx.compute_txid().to_string(), "vsize": tx.vsize(), "paid": paid, "change": (ch.capacity - Amount::from_sat(paid) - CHAN_FEE).to_sat() })
            }
        }

        _ => die("usage: see the header of regtest/src/bin/bond.rs"),
    };
    println!("{out}");
}
