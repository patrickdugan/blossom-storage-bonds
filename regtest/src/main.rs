//! Phase 1: the sentinel bond chain from docs/design.md §2 as real transactions on Bitcoin Core regtest.
//!
//! Setup presigns the whole chain before anything is broadcast: the provider signs every Challenge_i,
//! the client signs every Respond_i, over real BIP341 script-path sighashes. Bond states have a MuSig2
//! (provider, client) internal key, so the cooperative close is a MuSig2 keypath spend. Presigned
//! transactions are zero-fee TRUC (v3) parents with a zero-value P2A anchor, submitted with a CPFP
//! child through `submitpackage`.
//!
//! Scenarios, each checked against the node's verdict:
//!   S1  challenge → respond (bond re-armed) → challenge → forfeit after Δ, with the failure cases
//!   S2  refund at the term's end, and not one block before
//!   S3  cooperative MuSig2 keypath close
//!   S4  the first design's 520-byte answer: refused by the mempool (tapscript stack items over 80 bytes
//!       are non-standard), mined directly with generateblock, and 521 bytes refused by consensus
//!
//! The sentinels come from fixtures/sentinels.json (written by model/fixture.ts) and every hash in it
//! is rechecked here. Nonce seeds and keys are fixed test values: never reuse this code for real keys.

mod rpc;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::opcodes::all::*;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{All, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey};
use musig2::{CompactSignature, FirstRound, KeyAggContext, PartialSignature, SecNonceSpices};
use rpc::Rpc;
use serde_json::{json, Value};

const BOND: Amount = Amount::from_sat(100_000_000);
const DELTA: u16 = 144;
const FEERATE: u64 = 2; // sat/vB for CPFP packages and self-funded spends
const CLOSE_FEE: Amount = Amount::from_sat(1_000);
const MAX_STANDARD_ITEM: usize = 80; // MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE, policy/policy.h

// ───────────────────────────── fixture ─────────────────────────────

struct Sentinel {
    r: Vec<u8>,
    s: [u8; 32],
    h: [u8; 32],
    preimage: Vec<u8>,
    wrong: Vec<u8>,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn arr32(v: &[u8]) -> [u8; 32] {
    v.try_into().unwrap()
}

fn parse_sentinel(s: &Value, item_len: usize) -> Sentinel {
    let t = Sentinel {
        r: unhex(s["r"].as_str().unwrap()),
        s: arr32(&unhex(s["s"].as_str().unwrap())),
        h: arr32(&unhex(s["h"].as_str().unwrap())),
        preimage: unhex(s["preimage"].as_str().unwrap()),
        wrong: unhex(s["wrong_preimage"].as_str().unwrap()),
    };
    assert_eq!(sha256::Hash::hash(&t.r).to_byte_array(), t.s, "s = SHA256(r)");
    assert_eq!(sha256::Hash::hash(&t.preimage).to_byte_array(), t.h, "h = SHA256(r ‖ window)");
    assert_eq!(&t.preimage[..t.r.len()], &t.r[..], "the preimage starts with r");
    assert_eq!(t.preimage.len(), item_len);
    assert_ne!(sha256::Hash::hash(&t.wrong).to_byte_array(), t.h);
    t
}

/// The standard sentinels (one 80-byte item each) and the wide one (one 520-byte item).
fn load_sentinels() -> (Vec<Sentinel>, Sentinel) {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/sentinels.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).expect("run model/fixture.ts first")).unwrap();
    let std = v["sentinels"].as_array().unwrap().iter().map(|s| parse_sentinel(s, MAX_STANDARD_ITEM)).collect();
    (std, parse_sentinel(&v["wide"], 520))
}

// ───────────────────────────── keys and leaves ─────────────────────────────

struct Party {
    kp: Keypair,
    x: XOnlyPublicKey,
    sk: SecretKey,
}

fn party(secp: &Secp256k1<All>, label: &str) -> Party {
    let sk = SecretKey::from_slice(sha256::Hash::hash(label.as_bytes()).as_byte_array()).unwrap();
    let kp = Keypair::from_secret_key(secp, &sk);
    Party { kp, x: kp.x_only_public_key().0, sk }
}

fn challenge_leaf(c: &Party, p: &Party, s: [u8; 32]) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(&c.x).push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(&p.x).push_opcode(OP_CHECKSIGVERIFY)
        .push_opcode(OP_SHA256).push_slice(s).push_opcode(OP_EQUAL)
        .into_script()
}
fn refund_leaf(p: &Party, t_end: u32) -> ScriptBuf {
    Builder::new()
        .push_int(t_end as i64).push_opcode(OP_CLTV).push_opcode(OP_DROP)
        .push_x_only_key(&p.x).push_opcode(OP_CHECKSIG)
        .into_script()
}
fn respond_leaf(p: &Party, c: &Party, h: [u8; 32]) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(&p.x).push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(&c.x).push_opcode(OP_CHECKSIGVERIFY)
        .push_opcode(OP_SHA256).push_slice(h).push_opcode(OP_EQUAL)
        .into_script()
}
fn forfeit_leaf(c: &Party, delta: u16) -> ScriptBuf {
    Builder::new()
        .push_int(delta as i64).push_opcode(OP_CSV).push_opcode(OP_DROP)
        .push_x_only_key(&c.x).push_opcode(OP_CHECKSIG)
        .into_script()
}

fn p2a() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![0x51, 0x02, 0x4e, 0x73])
}

fn musig_ctx(p: &Party, c: &Party) -> KeyAggContext {
    let pts: Vec<musig2::secp::Point> = [p, c]
        .iter()
        .map(|q| musig2::secp::Point::from_slice(&q.kp.public_key().serialize()).unwrap())
        .collect();
    KeyAggContext::new(pts).unwrap()
}

/// A taproot state: one leaf at depth 0, or two at depth 1.
struct State {
    spend: TaprootSpendInfo,
    spk: ScriptBuf,
}

fn state(secp: &Secp256k1<All>, internal: XOnlyPublicKey, leaves: &[&ScriptBuf]) -> State {
    let b = match leaves {
        [a] => TaprootBuilder::new().add_leaf(0, (*a).clone()).unwrap(),
        [a, b] => TaprootBuilder::new().add_leaf(1, (*a).clone()).unwrap().add_leaf(1, (*b).clone()).unwrap(),
        _ => unreachable!(),
    };
    let spend = b.finalize(secp, internal).unwrap();
    let spk = ScriptBuf::new_p2tr_tweaked(spend.output_key());
    State { spend, spk }
}

fn control(st: &State, leaf: &ScriptBuf) -> Vec<u8> {
    st.spend.control_block(&(leaf.clone(), LeafVersion::TapScript)).unwrap().serialize()
}

// ───────────────────────────── transactions ─────────────────────────────

fn txin(prev: OutPoint, seq: Sequence) -> TxIn {
    TxIn { previous_output: prev, script_sig: ScriptBuf::new(), sequence: seq, witness: Witness::new() }
}

/// A zero-fee TRUC parent: the whole bond to `to`, plus a zero-value P2A anchor.
fn presigned(prev: OutPoint, to: &ScriptBuf) -> Transaction {
    Transaction {
        version: Version(3),
        lock_time: LockTime::ZERO,
        input: vec![txin(prev, Sequence::ENABLE_RBF_NO_LOCKTIME)],
        output: vec![
            TxOut { value: BOND, script_pubkey: to.clone() },
            TxOut { value: Amount::ZERO, script_pubkey: p2a() },
        ],
    }
}

fn script_sig(secp: &Secp256k1<All>, tx: &Transaction, prev: &TxOut, leaf: &ScriptBuf, who: &Party) -> Vec<u8> {
    let lh = TapLeafHash::from_script(leaf, LeafVersion::TapScript);
    let sh = SighashCache::new(tx)
        .taproot_script_spend_signature_hash(0, &Prevouts::All(&[prev.clone()]), lh, TapSighashType::Default)
        .unwrap();
    secp.sign_schnorr_no_aux_rand(&Message::from_digest(sh.to_byte_array()), &who.kp).serialize().to_vec()
}

fn with_witness(mut tx: Transaction, items: Vec<Vec<u8>>) -> Transaction {
    tx.input[0].witness = Witness::from_slice(&items);
    tx
}

// ───────────────────────────── node and fee wallet ─────────────────────────────

struct Node {
    rpc: Rpc,
    secp: Secp256k1<All>,
    fee: Party,
    fee_addr: Address,
}

impl Node {
    fn mine(&self, n: u32) {
        self.rpc.call("generatetoaddress", json!([n, self.fee_addr.to_string()])).unwrap();
    }

    /// The largest confirmed, mature output paying the fee key.
    fn fee_utxo(&self) -> (OutPoint, TxOut) {
        let tip = self.rpc.height() as u64;
        let r = self.rpc.call("scantxoutset", json!(["start", [format!("addr({})", self.fee_addr)]])).unwrap();
        let best = r["unspents"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|u| !u["coinbase"].as_bool().unwrap_or(true) || u["height"].as_u64().unwrap() + 100 <= tip)
            .max_by_key(|u| (u["amount"].as_f64().unwrap() * 1e8) as u64)
            .expect("no mature fee UTXO");
        let op = OutPoint { txid: best["txid"].as_str().unwrap().parse().unwrap(), vout: best["vout"].as_u64().unwrap() as u32 };
        let value = Amount::from_sat((best["amount"].as_f64().unwrap() * 1e8).round() as u64);
        (op, TxOut { value, script_pubkey: self.fee_addr.script_pubkey() })
    }

    fn sign_fee_input(&self, tx: &mut Transaction, idx: usize, prevouts: &[TxOut]) {
        let sh = SighashCache::new(&*tx)
            .taproot_key_spend_signature_hash(idx, &Prevouts::All(prevouts), TapSighashType::Default)
            .unwrap();
        let tweaked = self.fee.kp.tap_tweak(&self.secp, None);
        let sig = self.secp.sign_schnorr_no_aux_rand(&Message::from_digest(sh.to_byte_array()), &tweaked.to_keypair());
        tx.input[idx].witness = Witness::from_slice(&[sig.serialize().to_vec()]);
    }

    /// The provider (here the fee key) funds a bond: one keypath input, bond and change outputs.
    fn fund(&self, spk: &ScriptBuf) -> Transaction {
        let (op, prev) = self.fee_utxo();
        let fee = Amount::from_sat(FEERATE * 154);
        let mut tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![txin(op, Sequence::ENABLE_RBF_NO_LOCKTIME)],
            output: vec![
                TxOut { value: BOND, script_pubkey: spk.clone() },
                TxOut { value: prev.value - BOND - fee, script_pubkey: self.fee_addr.script_pubkey() },
            ],
        };
        self.sign_fee_input(&mut tx, 0, &[prev]);
        tx
    }

    /// CPFP child of a zero-fee parent: spends the P2A anchor plus one fee input.
    fn child(&self, parent: &Transaction) -> Transaction {
        let (op, prev) = self.fee_utxo();
        let anchor = OutPoint { txid: parent.compute_txid(), vout: 1 };
        let fee = Amount::from_sat(FEERATE * (parent.vsize() as u64 + 153));
        let mut tx = Transaction {
            version: Version(3),
            lock_time: LockTime::ZERO,
            input: vec![txin(anchor, Sequence::ENABLE_RBF_NO_LOCKTIME), txin(op, Sequence::ENABLE_RBF_NO_LOCKTIME)],
            output: vec![TxOut { value: prev.value - fee, script_pubkey: self.fee_addr.script_pubkey() }],
        };
        let prevouts = [parent.output[1].clone(), prev];
        self.sign_fee_input(&mut tx, 1, &prevouts);
        tx
    }

    fn submit_package(&self, parent: &Transaction) -> Result<Transaction, String> {
        let child = self.child(parent);
        let r = self.rpc.call("submitpackage", json!([[serialize_hex(parent), serialize_hex(&child)]]))?;
        if r["package_msg"].as_str() == Some("success") {
            return Ok(child);
        }
        let errs: Vec<String> = r["tx-results"]
            .as_object()
            .map(|m| m.values().filter_map(|t| t["error"].as_str().map(String::from)).collect())
            .unwrap_or_default();
        Err(format!("{}: {}", r["package_msg"].as_str().unwrap_or("?"), errs.join("; ")))
    }

    /// Mine a block containing `tx` without the mempool: consensus rules only, no relay policy.
    fn mine_raw(&self, tx: &Transaction) -> Result<(), String> {
        self.rpc.call("generateblock", json!([self.fee_addr.to_string(), [serialize_hex(tx)]])).map(|_| ())
    }

    fn send(&self, tx: &Transaction) -> Result<(), String> {
        self.rpc.call("sendrawtransaction", json!([serialize_hex(tx)])).map(|_| ())
    }

    /// Core's own vsize for a confirmed transaction (txindex is on).
    fn core_vsize(&self, tx: &Transaction) -> u64 {
        let r = self.rpc.call("getrawtransaction", json!([tx.compute_txid().to_string(), true])).unwrap();
        r["vsize"].as_u64().unwrap()
    }
}

// ───────────────────────────── reporting ─────────────────────────────

#[derive(Default)]
struct Report {
    sizes: Vec<Value>,
    checks: Vec<Value>,
    failed: usize,
}

impl Report {
    fn size(&mut self, node: &Node, name: &str, tx: &Transaction, model: Option<u64>) {
        let core = node.core_vsize(tx);
        assert_eq!(core, tx.vsize() as u64, "rust-bitcoin and Core agree on vsize");
        println!("  size  {name:<28} {core:>4} vB   model {}", model.map_or("—".into(), |m| m.to_string()));
        self.sizes.push(json!({ "tx": name, "vsize": core, "model": model, "txid": tx.compute_txid().to_string() }));
    }

    fn accept(&mut self, name: &str, r: Result<(), String>) {
        let ok = r.is_ok();
        println!("  {}  accept {name}{}", if ok { "ok  " } else { "FAIL" }, r.as_ref().err().map_or(String::new(), |e| format!(": {e}")));
        if !ok { self.failed += 1; }
        self.checks.push(json!({ "check": name, "expect": "accept", "pass": ok, "node": r.err() }));
    }

    fn reject(&mut self, name: &str, r: Result<(), String>, want: &str) {
        let (ok, msg) = match &r {
            Ok(()) => (false, "accepted".to_string()),
            Err(e) => (e.contains(want), e.clone()),
        };
        println!("  {}  reject {name}: {msg}", if ok { "ok  " } else { "FAIL" });
        if !ok { self.failed += 1; }
        self.checks.push(json!({ "check": name, "expect": format!("reject containing {want:?}"), "pass": ok, "node": msg }));
    }
}

// ───────────────────────────── main ─────────────────────────────

fn main() {
    let url = std::env::var("BSB_RPC").unwrap_or_else(|_| "http://127.0.0.1:18543".into());
    let rpc = Rpc::new(&url, "bsb", "bsb-regtest-only");
    let secp = Secp256k1::new();
    let fee = party(&secp, "bsb/fee-wallet");
    let fee_addr = Address::p2tr(&secp, fee.x, None, Network::Regtest);
    let node = Node { rpc, secp, fee, fee_addr };
    let secp = &node.secp;

    let chain: Value = node.rpc.call("getblockchaininfo", json!([])).expect("bitcoind regtest not reachable");
    assert_eq!(chain["chain"], "regtest", "refusing to run anywhere but regtest");
    let version = node.rpc.call("getnetworkinfo", json!([])).unwrap()["subversion"].clone();
    println!("node {version} at height {}", node.rpc.height());
    if node.rpc.height() < 220 {
        node.mine(220 - node.rpc.height());
    }

    let (sen, wide) = load_sentinels();
    let k = sen.len();
    let p = party(secp, "bsb/provider");
    let c = party(secp, "bsb/client");
    let ctx = musig_ctx(&p, &c);
    let agg: musig2::secp::Point = ctx.aggregated_pubkey();
    let internal = XOnlyPublicKey::from_slice(&agg.serialize_xonly()).unwrap();
    let mut rep = Report::default();

    // ── setup: build and presign the whole chain for a bond whose term ends at t_end ──
    struct Chain {
        bonds: Vec<State>,
        challenged: Vec<State>,
        challenge_leaves: Vec<ScriptBuf>,
        respond_leaves: Vec<ScriptBuf>,
        refund: ScriptBuf,
        forfeit: ScriptBuf,
    }
    let build = |sen: &[Sentinel], t_end: u32| -> Chain {
        let refund = refund_leaf(&p, t_end);
        let forfeit = forfeit_leaf(&c, DELTA);
        let challenge_leaves: Vec<ScriptBuf> = sen.iter().map(|s| challenge_leaf(&c, &p, s.s)).collect();
        let respond_leaves: Vec<ScriptBuf> = sen.iter().map(|s| respond_leaf(&p, &c, s.h)).collect();
        let mut bonds: Vec<State> = challenge_leaves.iter().map(|l| state(secp, internal, &[l, &refund])).collect();
        bonds.push(state(secp, internal, &[&refund]));
        let challenged = respond_leaves.iter().map(|l| state(secp, internal, &[l, &forfeit])).collect();
        Chain { bonds, challenged, challenge_leaves, respond_leaves, refund, forfeit }
    };

    // Presigned transactions for a chain funded at `fund_op`. The provider signs every Challenge_i, the
    // client every Respond_i, before anything is broadcast.
    struct Presigned {
        challenge: Vec<Transaction>,
        respond: Vec<Transaction>,
        sig_p_challenge: Vec<Vec<u8>>,
        sig_c_respond: Vec<Vec<u8>>,
    }
    let presign = |ch: &Chain, fund_op: OutPoint| -> Presigned {
        let (mut challenge, mut respond, mut sp, mut sc) = (vec![], vec![], vec![], vec![]);
        let mut bond_op = fund_op;
        for i in 0..ch.challenge_leaves.len() {
            let ctx_tx = presigned(bond_op, &ch.challenged[i].spk);
            sp.push(script_sig(secp, &ctx_tx, &TxOut { value: BOND, script_pubkey: ch.bonds[i].spk.clone() }, &ch.challenge_leaves[i], &p));
            let challenged_op = OutPoint { txid: ctx_tx.compute_txid(), vout: 0 };
            let rtx = presigned(challenged_op, &ch.bonds[i + 1].spk);
            sc.push(script_sig(secp, &rtx, &TxOut { value: BOND, script_pubkey: ch.challenged[i].spk.clone() }, &ch.respond_leaves[i], &c));
            bond_op = OutPoint { txid: rtx.compute_txid(), vout: 0 };
            challenge.push(ctx_tx);
            respond.push(rtx);
        }
        Presigned { challenge, respond, sig_p_challenge: sp, sig_c_respond: sc }
    };

    // ════════════ S1: challenge → respond → challenge → forfeit ════════════
    println!("\nS1  challenge, respond, challenge, forfeit (k = {k}, Δ = {DELTA})");
    let ch = build(&sen, node.rpc.height() + 10_000);
    let fund = node.fund(&ch.bonds[0].spk);
    rep.accept("fund Bond_0", node.send(&fund));
    node.mine(1);
    rep.size(&node, "fund", &fund, Some(154));
    let ps = presign(&ch, OutPoint { txid: fund.compute_txid(), vout: 0 });
    let bond_prev = |i: usize| TxOut { value: BOND, script_pubkey: ch.bonds[i].spk.clone() };
    let challenged_prev = |i: usize| TxOut { value: BOND, script_pubkey: ch.challenged[i].spk.clone() };

    let challenge_tx = |i: usize, r: &[u8], sig_p: &[u8], sig_c: Vec<u8>| {
        with_witness(ps.challenge[i].clone(), vec![
            r.to_vec(), sig_p.to_vec(), sig_c, ch.challenge_leaves[i].to_bytes(), control(&ch.bonds[i], &ch.challenge_leaves[i]),
        ])
    };
    let sig_c_challenge = |i: usize| script_sig(secp, &ps.challenge[i], &bond_prev(i), &ch.challenge_leaves[i], &c);
    let respond_tx = |i: usize, pre: &[u8]| {
        let sig_p = script_sig(secp, &ps.respond[i], &challenged_prev(i), &ch.respond_leaves[i], &p);
        with_witness(ps.respond[i].clone(), vec![
            pre.to_vec(), ps.sig_c_respond[i].clone(), sig_p, ch.respond_leaves[i].to_bytes(), control(&ch.challenged[i], &ch.respond_leaves[i]),
        ])
    };

    // Failure cases on Challenge_0 first: nothing confirms, so Bond_0 is still unspent afterwards.
    let wrong_r = sha256::Hash::hash(b"not the secret").to_byte_array();
    rep.reject("Challenge_0 with the wrong r", node.submit_package(&challenge_tx(0, &wrong_r, &ps.sig_p_challenge[0], sig_c_challenge(0))).map(|_| ()), "script-verify");
    rep.reject("Challenge_0 without the client's signature", node.submit_package(&challenge_tx(0, &sen[0].r, &ps.sig_p_challenge[0], vec![])).map(|_| ()), "script-verify");
    rep.reject("Challenge_0 with Challenge_1's provider presignature", node.submit_package(&challenge_tx(0, &sen[0].r, &ps.sig_p_challenge[1], sig_c_challenge(0))).map(|_| ()), "script-verify");

    let c0 = challenge_tx(0, &sen[0].r, &ps.sig_p_challenge[0], sig_c_challenge(0));
    let child = node.submit_package(&c0);
    rep.accept("Challenge_0 (reveals r_0)", child.as_ref().map(|_| ()).map_err(|e| e.clone()));
    node.mine(1);
    rep.size(&node, "Challenge_i", &c0, Some(187));
    if let Ok(ch0) = &child { rep.size(&node, "CPFP child", ch0, Some(153)); }

    rep.reject("Respond_0 with the same window of the next chunk", node.submit_package(&respond_tx(0, &sen[0].wrong)).map(|_| ()), "script-verify");
    let mut long = sen[0].preimage.clone();
    long.push(0);
    rep.reject("Respond_0 with an 81-byte item", node.submit_package(&respond_tx(0, &long)).map(|_| ()), "bad-witness-nonstandard");

    let r0 = respond_tx(0, &sen[0].preimage);
    rep.accept("Respond_0 (r_0 ‖ window, bond re-armed as Bond_1)", node.submit_package(&r0).map(|_| ()));
    node.mine(1);
    rep.size(&node, "Respond_i", &r0, Some(203));

    let c1 = challenge_tx(1, &sen[1].r, &ps.sig_p_challenge[1], sig_c_challenge(1));
    rep.accept("Challenge_1 from Bond_1", node.submit_package(&c1).map(|_| ()));
    node.mine(1);

    // Forfeit: the client alone after Δ confirmations of Challenged_1.
    let forfeit_tx = {
        let mut tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![txin(OutPoint { txid: c1.compute_txid(), vout: 0 }, Sequence::from_height(DELTA))],
            output: vec![TxOut { value: BOND - CLOSE_FEE, script_pubkey: Address::p2tr(secp, c.x, None, Network::Regtest).script_pubkey() }],
        };
        let sig = script_sig(secp, &tx, &challenged_prev(1), &ch.forfeit, &c);
        tx = with_witness(tx, vec![sig, ch.forfeit.to_bytes(), control(&ch.challenged[1], &ch.forfeit)]);
        tx
    };
    node.mine(DELTA as u32 - 2); // Challenged_1 now has Δ − 1 confirmations; the next block would be the Δ-th
    rep.reject("Forfeit_1 one block early", node.send(&forfeit_tx), "non-BIP68-final");
    node.mine(1);
    rep.accept("Forfeit_1 after Δ blocks of silence", node.send(&forfeit_tx));
    node.mine(1);
    rep.size(&node, "Forfeit_i", &forfeit_tx, None);

    // ════════════ S2: refund at the term's end ════════════
    println!("\nS2  refund at the term's end");
    let t_end = node.rpc.height() + 12;
    let ch2 = build(&sen, t_end);
    let fund2 = node.fund(&ch2.bonds[0].spk);
    rep.accept("fund Bond_0 (term ends at {t_end})".replace("{t_end}", &t_end.to_string()).as_str(), node.send(&fund2));
    node.mine(1);
    let refund_tx = {
        let mut tx = Transaction {
            version: Version(2),
            lock_time: LockTime::from_height(t_end).unwrap(),
            input: vec![txin(OutPoint { txid: fund2.compute_txid(), vout: 0 }, Sequence::ENABLE_LOCKTIME_NO_RBF)],
            output: vec![TxOut { value: BOND - CLOSE_FEE, script_pubkey: Address::p2tr(secp, p.x, None, Network::Regtest).script_pubkey() }],
        };
        let prev = TxOut { value: BOND, script_pubkey: ch2.bonds[0].spk.clone() };
        let sig = script_sig(secp, &tx, &prev, &ch2.refund, &p);
        tx = with_witness(tx, vec![sig, ch2.refund.to_bytes(), control(&ch2.bonds[0], &ch2.refund)]);
        tx
    };
    node.mine(t_end - 1 - node.rpc.height()); // tip = t_end − 1: the next block is t_end, so locktime t_end is not final yet
    rep.reject("Refund one block before the term ends", node.send(&refund_tx), "non-final");
    node.mine(1);
    rep.accept("Refund at the term's end", node.send(&refund_tx));
    node.mine(1);
    rep.size(&node, "Refund", &refund_tx, None);

    // ════════════ S3: cooperative MuSig2 keypath close ════════════
    println!("\nS3  cooperative close (MuSig2 keypath)");
    let ch3 = build(&sen, node.rpc.height() + 10_000);
    let fund3 = node.fund(&ch3.bonds[0].spk);
    rep.accept("fund Bond_0", node.send(&fund3));
    node.mine(1);
    let mut close = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![txin(OutPoint { txid: fund3.compute_txid(), vout: 0 }, Sequence::ENABLE_RBF_NO_LOCKTIME)],
        output: vec![
            TxOut { value: BOND - CLOSE_FEE - Amount::from_sat(10_000), script_pubkey: Address::p2tr(secp, p.x, None, Network::Regtest).script_pubkey() },
            TxOut { value: Amount::from_sat(10_000), script_pubkey: Address::p2tr(secp, c.x, None, Network::Regtest).script_pubkey() },
        ],
    };
    let prev = TxOut { value: BOND, script_pubkey: ch3.bonds[0].spk.clone() };
    let msg: [u8; 32] = SighashCache::new(&close)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&[prev]), TapSighashType::Default)
        .unwrap()
        .to_byte_array();
    let merkle = ch3.bonds[0].spend.merkle_root().unwrap().to_byte_array();
    let tctx = ctx.clone().with_taproot_tweak(&merkle).unwrap();
    let tweaked: musig2::secp::Point = tctx.aggregated_pubkey();
    assert_eq!(tweaked.serialize_xonly(), ch3.bonds[0].spend.output_key().to_x_only_public_key().serialize(), "MuSig2 tweak matches the taproot output key");
    let scalar = |q: &Party| musig2::secp::Scalar::from_slice(&q.sk.secret_bytes()).unwrap();
    let mut r_p = FirstRound::new(tctx.clone(), [1u8; 32], 0, SecNonceSpices::new().with_seckey(scalar(&p)).with_message(&msg)).unwrap();
    let mut r_c = FirstRound::new(tctx.clone(), [2u8; 32], 1, SecNonceSpices::new().with_seckey(scalar(&c)).with_message(&msg)).unwrap();
    r_p.receive_nonce(1, r_c.our_public_nonce()).unwrap();
    r_c.receive_nonce(0, r_p.our_public_nonce()).unwrap();
    let mut s_p = r_p.finalize(scalar(&p), msg).unwrap();
    let s_c = r_c.finalize(scalar(&c), msg).unwrap();
    let part_c: PartialSignature = s_c.our_signature();
    s_p.receive_signature(1, part_c).unwrap();
    let sig: CompactSignature = s_p.finalize().unwrap();
    close.input[0].witness = Witness::from_slice(&[sig.serialize().to_vec()]);
    rep.accept("Cooperative close by MuSig2 keypath", node.send(&close));
    node.mine(1);
    rep.size(&node, "Cooperative close", &close, Some(154));

    // ════════════ S4: the first design's 520-byte answer ════════════
    println!("\nS4  a 520-byte answer: valid by consensus, refused by relay");
    let ch4 = build(std::slice::from_ref(&wide), node.rpc.height() + 10_000);
    let fund4 = node.fund(&ch4.bonds[0].spk);
    rep.accept("fund Bond_0 (one wide sentinel)", node.send(&fund4));
    node.mine(1);
    let ps4 = presign(&ch4, OutPoint { txid: fund4.compute_txid(), vout: 0 });
    let sig_c4 = script_sig(secp, &ps4.challenge[0], &TxOut { value: BOND, script_pubkey: ch4.bonds[0].spk.clone() }, &ch4.challenge_leaves[0], &c);
    let c4 = with_witness(ps4.challenge[0].clone(), vec![
        wide.r.clone(), ps4.sig_p_challenge[0].clone(), sig_c4, ch4.challenge_leaves[0].to_bytes(), control(&ch4.bonds[0], &ch4.challenge_leaves[0]),
    ]);
    rep.accept("Challenge_0 with a 32-byte r", node.submit_package(&c4).map(|_| ()));
    node.mine(1);
    rep.size(&node, "Challenge_i (32-byte r)", &c4, Some(191));
    let prev4 = TxOut { value: BOND, script_pubkey: ch4.challenged[0].spk.clone() };
    let respond_w = |pre: &[u8]| {
        let sig_p = script_sig(secp, &ps4.respond[0], &prev4, &ch4.respond_leaves[0], &p);
        with_witness(ps4.respond[0].clone(), vec![
            pre.to_vec(), ps4.sig_c_respond[0].clone(), sig_p, ch4.respond_leaves[0].to_bytes(), control(&ch4.challenged[0], &ch4.respond_leaves[0]),
        ])
    };
    rep.reject("Respond_0 with one 520-byte item, through the mempool", node.submit_package(&respond_w(&wide.preimage)).map(|_| ()), "bad-witness-nonstandard");
    let mut wide_long = wide.preimage.clone();
    wide_long.push(0);
    rep.reject("Respond_0 with a 521-byte item, mined directly", node.mine_raw(&respond_w(&wide_long)), "Push value size limit");
    let r4 = respond_w(&wide.preimage);
    rep.accept("Respond_0 with one 520-byte item, mined directly", node.mine_raw(&r4));
    rep.size(&node, "Respond_i (520-byte item)", &r4, Some(314));

    // ── results ──
    let out = json!({
        "node": version,
        "k": k, "delta": DELTA, "bond_sats": BOND.to_sat(),
        "wide_leaf_bytes": ch4.respond_leaves[0].len(),
        "leaf_bytes": {
            "challenge": ch.challenge_leaves[0].len(), "respond": ch.respond_leaves[0].len(),
            "refund": ch2.refund.len(), "forfeit": ch.forfeit.len(),
        },
        "sizes": rep.sizes, "checks": rep.checks, "failed": rep.failed,
    });
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../results/regtest.json");
    std::fs::create_dir_all(concat!(env!("CARGO_MANIFEST_DIR"), "/../results")).unwrap();
    std::fs::write(path, serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
    println!("\n{} checks, {} failed; wrote results/regtest.json", rep.checks.len(), rep.failed);
    std::process::exit(if rep.failed == 0 { 0 } else { 1 });
}
