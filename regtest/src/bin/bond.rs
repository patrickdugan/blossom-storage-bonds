//! bsb-bond: the on-chain side of one real deal from layer1/bonded.ts.
//!
//!   bsb-bond fund <deal.json>                  fund Bond_0 and presign the chain; writes <deal>.state.json
//!   bsb-bond enforce <deal.json> <challenges>  challenge sentinels 0.. in order; writes <deal>.result.json
//!
//! The deal file names the provider's Blossom URL, the replica's sha256 and the k sentinels left after
//! cut and choose (r, s, h). For each challenge the client reveals r_i on chain. The provider's agent then
//! asks the provider's own sidecar (GET /sentinel/<sha>?r=) for r_i ‖ window, built from whatever bytes
//! that server still stores, and submits Respond_i with it. Bitcoin Core's script check decides. Nothing
//! in this tool compares the answer to h_i first. If the provider has no answer or Core rejects it, the
//! client waits Δ blocks and forfeits the bond. A bond whose every challenge was answered is closed
//! cooperatively by MuSig2.
//!
//! The provider and client keys are derived from seeds in the deal file. That is test code: one process
//! here plays both parties' on-chain agents, which a real deployment never does.

#[path = "../common.rs"]
mod common;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::Version;
use bitcoin::{Address, Network, OutPoint, Sequence, Transaction, TxOut, Witness};
use common::rpc::Rpc;
use common::*;
use serde_json::{json, Value};

struct Deal {
    name: String,
    url: String,
    sha: String,
    p: Party,
    c: Party,
    r: Vec<Vec<u8>>,
    sh: Vec<([u8; 32], Vec<[u8; 32]>)>,
}

fn load(path: &str, secp: &Secp256k1<bitcoin::secp256k1::All>) -> Deal {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).expect("deal file")).expect("deal json");
    let sens = v["sentinels"].as_array().expect("sentinels");
    Deal {
        name: v["name"].as_str().unwrap().to_string(),
        url: v["provider_url"].as_str().unwrap().to_string(),
        sha: v["sha256"].as_str().unwrap().to_string(),
        p: party(secp, v["provider_seed"].as_str().unwrap()),
        c: party(secp, v["client_seed"].as_str().unwrap()),
        r: sens.iter().map(|s| unhex(s["r"].as_str().unwrap())).collect(),
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

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (cmd, deal_path) = (args.get(1).map(String::as_str), args.get(2).cloned().unwrap_or_default());
    let url = std::env::var("BSB_RPC").unwrap_or_else(|_| "http://127.0.0.1:18543".into());
    let secp = Secp256k1::new();
    let fee = party(&secp, "bsb/fee-wallet");
    let fee_addr = Address::p2tr(&secp, fee.x, None, Network::Regtest);
    let node = Node { rpc: Rpc::new(&url, "bsb", "bsb-regtest-only"), secp, fee, fee_addr };
    let secp = &node.secp;
    let chain = node.rpc.call("getblockchaininfo", json!([])).expect("bitcoind regtest not reachable");
    assert_eq!(chain["chain"], "regtest", "refusing to run anywhere but regtest");
    if node.rpc.height() < 220 {
        node.mine(220 - node.rpc.height());
    }

    let d = load(&deal_path, secp);
    let ctx = musig_ctx(&d.p, &d.c);
    let internal = internal_key(&ctx);
    let state_path = deal_path.replace(".json", ".state.json");

    match cmd {
        Some("fund") => {
            let t_end = node.rpc.height() + 4_320;
            let ch = build_chain(secp, internal, &d.p, &d.c, &d.sh, t_end);
            let fund = node.fund(&ch.bonds[0].spk);
            node.send(&fund).expect("fund");
            node.mine(1);
            let presigned = presign_chain(secp, &ch, &d.p, &d.c, OutPoint { txid: fund.compute_txid(), vout: 0 });
            let out = json!({
                "name": d.name, "fund_txid": fund.compute_txid().to_string(), "t_end": t_end,
                "bond_sats": BOND.to_sat(), "k": d.sh.len(), "funded_at": node.rpc.height(),
                "bond_address": Address::from_script(&ch.bonds[0].spk, Network::Regtest).unwrap().to_string(),
                "presigned_challenges": presigned.challenge.iter().map(|t| t.compute_txid().to_string()).collect::<Vec<_>>(),
            });
            std::fs::write(&state_path, serde_json::to_string_pretty(&out).unwrap()).unwrap();
            println!("{}", out);
        }
        Some("enforce") => {
            let n: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1).min(d.sh.len());
            let st: Value = serde_json::from_str(&std::fs::read_to_string(&state_path).expect("run fund first")).unwrap();
            let t_end = st["t_end"].as_u64().unwrap() as u32;
            let fund_op = OutPoint { txid: st["fund_txid"].as_str().unwrap().parse().unwrap(), vout: 0 };
            let ch = build_chain(secp, internal, &d.p, &d.c, &d.sh, t_end);
            let ps = presign_chain(secp, &ch, &d.p, &d.c, fund_op);
            let mut steps = vec![];
            let mut outcome = "closed";
            let mut last_bond = fund_op;
            let mut final_txid = String::new();
            let mut step_vsize;
            for i in 0..n {
                // Client: cosign the presigned Challenge_i, revealing r_i.
                let bond_prev = TxOut { value: BOND, script_pubkey: ch.bonds[i].spk.clone() };
                let sig_c = script_sig(secp, &ps.challenge[i], &bond_prev, &ch.challenge_leaves[i], &d.c);
                let ctx_tx = with_witness(ps.challenge[i].clone(), vec![
                    d.r[i].clone(), ps.sig_p_challenge[i].clone(), sig_c, ch.challenge_leaves[i].to_bytes(), control(&ch.bonds[i], &ch.challenge_leaves[i]),
                ]);
                node.submit_package(&ctx_tx).expect("challenge");
                step_vsize = ctx_tx.vsize();
                node.mine(1);
                let challenged_op = OutPoint { txid: ctx_tx.compute_txid(), vout: 0 };
                let mut step = json!({ "i": i, "r": hex(&d.r[i]), "challenge_txid": ctx_tx.compute_txid().to_string(), "challenge_vsize": step_vsize });

                // Provider: answer from its own storage, and let Core judge.
                let answered = match ask_provider(&d, &d.r[i], d.sh[i].1.len()) {
                    Err(e) => { step["answer"] = json!(format!("none: {e}")); false }
                    Ok(items) => {
                        step["windows"] = json!(items.len());
                        let prev = TxOut { value: BOND, script_pubkey: ch.challenged[i].spk.clone() };
                        let sig_p = script_sig(secp, &ps.respond[i], &prev, &ch.respond_leaves[i], &d.p);
                        let mut wit: Vec<Vec<u8>> = items.into_iter().rev().collect();
                        wit.extend([ps.sig_c_respond[i].clone(), sig_p, ch.respond_leaves[i].to_bytes(), control(&ch.challenged[i], &ch.respond_leaves[i])]);
                        let rtx = with_witness(ps.respond[i].clone(), wit);
                        match node.submit_package(&rtx) {
                            Ok(_) => {
                                node.mine(1);
                                step["answer"] = json!("accepted by Core");
                                step["respond_txid"] = json!(rtx.compute_txid().to_string());
                                step["respond_vsize"] = json!(rtx.vsize());
                                last_bond = OutPoint { txid: rtx.compute_txid(), vout: 0 };
                                true
                            }
                            Err(e) => {
                                let short = e.split(", input 0").next().unwrap_or(&e).to_string();
                                step["answer"] = json!(format!("rejected by Core: {short}"));
                                false
                            }
                        }
                    }
                };
                if !answered {
                    // Client: Δ blocks of silence, then the forfeit leaf.
                    node.mine(DELTA as u32 - 1);
                    let mut tx = Transaction {
                        version: Version(2),
                        lock_time: LockTime::ZERO,
                        input: vec![txin(challenged_op, Sequence::from_height(DELTA))],
                        output: vec![TxOut { value: BOND - CLOSE_FEE, script_pubkey: p2tr_spk(secp, &d.c) }],
                    };
                    let prev = TxOut { value: BOND, script_pubkey: ch.challenged[i].spk.clone() };
                    let sig = script_sig(secp, &tx, &prev, &ch.forfeit, &d.c);
                    tx = with_witness(tx, vec![sig, ch.forfeit.to_bytes(), control(&ch.challenged[i], &ch.forfeit)]);
                    node.send(&tx).expect("forfeit");
                    node.mine(1);
                    step["forfeit_txid"] = json!(tx.compute_txid().to_string());
                    final_txid = tx.compute_txid().to_string();
                    steps.push(step);
                    outcome = "forfeited";
                    break;
                }
                steps.push(step);
            }
            if outcome == "closed" {
                // Every challenge answered: close cooperatively from the current bond state.
                let at = steps.len();
                let mut close = Transaction {
                    version: Version(2),
                    lock_time: LockTime::ZERO,
                    input: vec![txin(last_bond, Sequence::ENABLE_RBF_NO_LOCKTIME)],
                    output: vec![TxOut { value: BOND - CLOSE_FEE, script_pubkey: p2tr_spk(secp, &d.p) }],
                };
                let prev = TxOut { value: BOND, script_pubkey: ch.bonds[at].spk.clone() };
                let msg = SighashCache::new(&close)
                    .taproot_key_spend_signature_hash(0, &Prevouts::All(&[prev]), TapSighashType::Default)
                    .unwrap()
                    .to_byte_array();
                let merkle = ch.bonds[at].spend.merkle_root().unwrap().to_byte_array();
                close.input[0].witness = Witness::from_slice(&[musig_keypath_sig(&ctx, merkle, msg, &d.p, &d.c)]);
                node.send(&close).expect("cooperative close");
                node.mine(1);
                final_txid = close.compute_txid().to_string();
            }
            let to = if outcome == "forfeited" { "client" } else { "provider" };
            let out = json!({
                "name": d.name, "outcome": outcome, "bond_to": to, "bond_sats": BOND.to_sat(),
                "final_txid": final_txid, "final_confirmations": node.rpc.call("getrawtransaction", json!([final_txid, true])).unwrap()["confirmations"],
                "challenges": steps, "height": node.rpc.height(),
            });
            std::fs::write(deal_path.replace(".json", ".result.json"), serde_json::to_string_pretty(&out).unwrap()).unwrap();
            println!("{}", out);
        }
        _ => {
            eprintln!("usage: bsb-bond fund <deal.json> | bsb-bond enforce <deal.json> <challenges>");
            std::process::exit(2);
        }
    }
}
