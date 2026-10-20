//! Shared by the regtest harness (main.rs) and the deal-bond tool (bin/bond.rs): keys, leaves, taproot
//! states, presigned transactions, and the node plus fee wallet.

#![allow(dead_code)]

#[path = "rpc.rs"]
pub mod rpc;

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
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey};
use musig2::{CompactSignature, FirstRound, KeyAggContext, PartialSignature, SecNonceSpices};
use rpc::Rpc;
use serde_json::{json, Value};

pub const BOND: Amount = Amount::from_sat(100_000_000);
pub const DELTA: u16 = 144;
pub const FEERATE: u64 = 2; // sat/vB for CPFP packages and self-funded spends
pub const CLOSE_FEE: Amount = Amount::from_sat(1_000);
pub const MAX_STANDARD_ITEM: usize = 80; // MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE, policy/policy.h

// ───────────────────────────── fixture ─────────────────────────────

pub struct Sentinel {
    pub r: Vec<u8>,
    pub s: [u8; 32],
    pub h: [u8; 32],
    pub preimage: Vec<u8>,
    pub wrong: Vec<u8>,
}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
pub fn arr32(v: &[u8]) -> [u8; 32] {
    v.try_into().unwrap()
}

pub fn parse_sentinel(s: &Value, item_len: usize) -> Sentinel {
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
pub fn load_sentinels() -> (Vec<Sentinel>, Sentinel) {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/sentinels.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).expect("run model/fixture.ts first")).unwrap();
    let std = v["sentinels"].as_array().unwrap().iter().map(|s| parse_sentinel(s, MAX_STANDARD_ITEM)).collect();
    (std, parse_sentinel(&v["wide"], 520))
}

// ───────────────────────────── keys and leaves ─────────────────────────────

pub struct Party {
    pub kp: Keypair,
    pub x: XOnlyPublicKey,
    pub sk: SecretKey,
}

pub fn party(secp: &Secp256k1<All>, label: &str) -> Party {
    let sk = SecretKey::from_slice(sha256::Hash::hash(label.as_bytes()).as_byte_array()).unwrap();
    let kp = Keypair::from_secret_key(secp, &sk);
    Party { kp, x: kp.x_only_public_key().0, sk }
}

pub fn challenge_leaf(c: &XOnlyPublicKey, p: &XOnlyPublicKey, s: [u8; 32]) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(c).push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(p).push_opcode(OP_CHECKSIGVERIFY)
        .push_opcode(OP_SHA256).push_slice(s).push_opcode(OP_EQUAL)
        .into_script()
}
pub fn refund_leaf(p: &XOnlyPublicKey, t_end: u32) -> ScriptBuf {
    Builder::new()
        .push_int(t_end as i64).push_opcode(OP_CLTV).push_opcode(OP_DROP)
        .push_x_only_key(p).push_opcode(OP_CHECKSIG)
        .into_script()
}
/// One h is the one-window leaf. More add `SHA256 <h_j> EQUALVERIFY` per window; the witness then carries
/// item_{m-1} … item_0 under the two signatures, so item_0 is checked first.
pub fn respond_leaf(p: &XOnlyPublicKey, c: &XOnlyPublicKey, hs: &[[u8; 32]]) -> ScriptBuf {
    let mut b = Builder::new()
        .push_x_only_key(p).push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(c).push_opcode(OP_CHECKSIGVERIFY);
    for (j, h) in hs.iter().enumerate() {
        b = b.push_opcode(OP_SHA256).push_slice(*h).push_opcode(if j + 1 < hs.len() { OP_EQUALVERIFY } else { OP_EQUAL });
    }
    b.into_script()
}
pub fn forfeit_leaf(c: &XOnlyPublicKey, delta: u16) -> ScriptBuf {
    Builder::new()
        .push_int(delta as i64).push_opcode(OP_CSV).push_opcode(OP_DROP)
        .push_x_only_key(c).push_opcode(OP_CHECKSIG)
        .into_script()
}

pub fn p2a() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![0x51, 0x02, 0x4e, 0x73])
}

pub fn musig_ctx(p: &Party, c: &Party) -> KeyAggContext {
    let pts: Vec<musig2::secp::Point> = [p, c]
        .iter()
        .map(|q| musig2::secp::Point::from_slice(&q.kp.public_key().serialize()).unwrap())
        .collect();
    KeyAggContext::new(pts).unwrap()
}

/// A taproot state: one leaf at depth 0, or two at depth 1.
pub struct State {
    pub spend: TaprootSpendInfo,
    pub spk: ScriptBuf,
}

pub fn state(secp: &Secp256k1<All>, internal: XOnlyPublicKey, leaves: &[&ScriptBuf]) -> State {
    let b = match leaves {
        [a] => TaprootBuilder::new().add_leaf(0, (*a).clone()).unwrap(),
        [a, b] => TaprootBuilder::new().add_leaf(1, (*a).clone()).unwrap().add_leaf(1, (*b).clone()).unwrap(),
        _ => unreachable!(),
    };
    let spend = b.finalize(secp, internal).unwrap();
    let spk = ScriptBuf::new_p2tr_tweaked(spend.output_key());
    State { spend, spk }
}

pub fn control(st: &State, leaf: &ScriptBuf) -> Vec<u8> {
    st.spend.control_block(&(leaf.clone(), LeafVersion::TapScript)).unwrap().serialize()
}

// ───────────────────────────── transactions ─────────────────────────────

pub fn txin(prev: OutPoint, seq: Sequence) -> TxIn {
    TxIn { previous_output: prev, script_sig: ScriptBuf::new(), sequence: seq, witness: Witness::new() }
}

/// A zero-fee TRUC parent: the whole bond to `to`, plus a zero-value P2A anchor.
pub fn presigned(prev: OutPoint, to: &ScriptBuf) -> Transaction {
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

pub fn script_sig(secp: &Secp256k1<All>, tx: &Transaction, prev: &TxOut, leaf: &ScriptBuf, who: &Party) -> Vec<u8> {
    let lh = TapLeafHash::from_script(leaf, LeafVersion::TapScript);
    let sh = SighashCache::new(tx)
        .taproot_script_spend_signature_hash(0, &Prevouts::All(&[prev.clone()]), lh, TapSighashType::Default)
        .unwrap();
    secp.sign_schnorr_no_aux_rand(&Message::from_digest(sh.to_byte_array()), &who.kp).serialize().to_vec()
}

pub fn with_witness(mut tx: Transaction, items: Vec<Vec<u8>>) -> Transaction {
    tx.input[0].witness = Witness::from_slice(&items);
    tx
}

// ───────────────────────────── node and fee wallet ─────────────────────────────

pub struct Node {
    pub rpc: Rpc,
    pub secp: Secp256k1<All>,
    pub fee: Party,
    pub fee_addr: Address,
}

impl Node {
    pub fn mine(&self, n: u32) {
        self.rpc.call("generatetoaddress", json!([n, self.fee_addr.to_string()])).unwrap();
    }

    /// The largest confirmed, mature output paying the fee key.
    pub fn fee_utxo(&self) -> (OutPoint, TxOut) {
        let tip = self.rpc.height() as u64;
        // Core runs one UTXO-set scan at a time; other parties' agents may be scanning on the same node.
        let mut tries = 0;
        let r = loop {
            match self.rpc.call("scantxoutset", json!(["start", [format!("addr({})", self.fee_addr)]])) {
                Ok(r) => break r,
                Err(e) if e.contains("in progress") && tries < 100 => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => panic!("scantxoutset: {e}"),
            }
        };
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

    pub fn sign_fee_input(&self, tx: &mut Transaction, idx: usize, prevouts: &[TxOut]) {
        let sh = SighashCache::new(&*tx)
            .taproot_key_spend_signature_hash(idx, &Prevouts::All(prevouts), TapSighashType::Default)
            .unwrap();
        let tweaked = self.fee.kp.tap_tweak(&self.secp, None);
        let sig = self.secp.sign_schnorr_no_aux_rand(&Message::from_digest(sh.to_byte_array()), &tweaked.to_keypair());
        tx.input[idx].witness = Witness::from_slice(&[sig.serialize().to_vec()]);
    }

    /// The provider (here the fee key) funds a bond: one keypath input, bond and change outputs.
    pub fn fund(&self, spk: &ScriptBuf) -> Transaction {
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
    pub fn child(&self, parent: &Transaction) -> Transaction {
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

    pub fn submit_package(&self, parent: &Transaction) -> Result<Transaction, String> {
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
    pub fn mine_raw(&self, tx: &Transaction) -> Result<(), String> {
        self.rpc.call("generateblock", json!([self.fee_addr.to_string(), [serialize_hex(tx)]])).map(|_| ())
    }

    pub fn send(&self, tx: &Transaction) -> Result<(), String> {
        self.rpc.call("sendrawtransaction", json!([serialize_hex(tx)])).map(|_| ())
    }

    /// Core's own vsize for a confirmed transaction (txindex is on).
    pub fn core_vsize(&self, tx: &Transaction) -> u64 {
        let r = self.rpc.call("getrawtransaction", json!([tx.compute_txid().to_string(), true])).unwrap();
        r["vsize"].as_u64().unwrap()
    }
}

// ───────────────────────────── chains, presigning, cooperative close ─────────────────────────────

pub fn internal_key(ctx: &KeyAggContext) -> XOnlyPublicKey {
    let agg: musig2::secp::Point = ctx.aggregated_pubkey();
    XOnlyPublicKey::from_slice(&agg.serialize_xonly()).unwrap()
}

/// The k + 1 bond states and k challenged states for sentinels (s_i, h_i), with the refund at `t_end`.
pub struct Chain {
    pub bonds: Vec<State>,
    pub challenged: Vec<State>,
    pub challenge_leaves: Vec<ScriptBuf>,
    pub respond_leaves: Vec<ScriptBuf>,
    pub refund: ScriptBuf,
    pub forfeit: ScriptBuf,
}

pub fn build_chain(secp: &Secp256k1<All>, internal: XOnlyPublicKey, p: &XOnlyPublicKey, c: &XOnlyPublicKey, sh: &[([u8; 32], Vec<[u8; 32]>)], t_end: u32) -> Chain {
    let refund = refund_leaf(p, t_end);
    let forfeit = forfeit_leaf(c, DELTA);
    let challenge_leaves: Vec<ScriptBuf> = sh.iter().map(|(s, _)| challenge_leaf(c, p, *s)).collect();
    let respond_leaves: Vec<ScriptBuf> = sh.iter().map(|(_, hs)| respond_leaf(p, c, hs)).collect();
    let mut bonds: Vec<State> = challenge_leaves.iter().map(|l| state(secp, internal, &[l, &refund])).collect();
    bonds.push(state(secp, internal, &[&refund]));
    let challenged = respond_leaves.iter().map(|l| state(secp, internal, &[l, &forfeit])).collect();
    Chain { bonds, challenged, challenge_leaves, respond_leaves, refund, forfeit }
}

/// Every Challenge_i (signed by the provider) and Respond_i (signed by the client), before broadcast.
pub struct Presigned {
    pub challenge: Vec<Transaction>,
    pub respond: Vec<Transaction>,
    pub sig_p_challenge: Vec<Vec<u8>>,
    pub sig_c_respond: Vec<Vec<u8>>,
}

/// The unsigned presigned transactions of a chain funded at `fund_op`: every Challenge_i and Respond_i.
/// Both parties compute the same bytes and txids from public data.
pub fn chain_txs(ch: &Chain, fund_op: OutPoint) -> (Vec<Transaction>, Vec<Transaction>) {
    let (mut challenge, mut respond) = (vec![], vec![]);
    let mut bond_op = fund_op;
    for i in 0..ch.challenge_leaves.len() {
        let ctx_tx = presigned(bond_op, &ch.challenged[i].spk);
        let rtx = presigned(OutPoint { txid: ctx_tx.compute_txid(), vout: 0 }, &ch.bonds[i + 1].spk);
        bond_op = OutPoint { txid: rtx.compute_txid(), vout: 0 };
        challenge.push(ctx_tx);
        respond.push(rtx);
    }
    (challenge, respond)
}

pub fn presign_chain(secp: &Secp256k1<All>, ch: &Chain, p: &Party, c: &Party, fund_op: OutPoint) -> Presigned {
    let (challenge, respond) = chain_txs(ch, fund_op);
    let sp = (0..challenge.len()).map(|i| script_sig(secp, &challenge[i], &TxOut { value: BOND, script_pubkey: ch.bonds[i].spk.clone() }, &ch.challenge_leaves[i], p)).collect();
    let sc = (0..respond.len()).map(|i| script_sig(secp, &respond[i], &TxOut { value: BOND, script_pubkey: ch.challenged[i].spk.clone() }, &ch.respond_leaves[i], c)).collect();
    Presigned { challenge, respond, sig_p_challenge: sp, sig_c_respond: sc }
}

/// BIP341 script-path sighash for input 0 of `tx`, spending `prev` through `leaf`.
pub fn script_sighash(tx: &Transaction, prev: &TxOut, leaf: &ScriptBuf) -> Message {
    let lh = TapLeafHash::from_script(leaf, LeafVersion::TapScript);
    let sh = SighashCache::new(tx)
        .taproot_script_spend_signature_hash(0, &Prevouts::All(&[prev.clone()]), lh, TapSighashType::Default)
        .unwrap();
    Message::from_digest(sh.to_byte_array())
}

/// Check a counterparty's BIP340 signature over that sighash: what each side does before it relies on a
/// presigned transaction.
pub fn verify_script_sig(secp: &Secp256k1<All>, tx: &Transaction, prev: &TxOut, leaf: &ScriptBuf, who: &XOnlyPublicKey, sig: &[u8]) -> bool {
    match bitcoin::secp256k1::schnorr::Signature::from_slice(sig) {
        Ok(s) => secp.verify_schnorr(&s, &script_sighash(tx, prev, leaf), who).is_ok(),
        Err(_) => false,
    }
}

/// BIP341's provably unspendable internal key (H = lift_x(SHA256(G))), for outputs with no keypath.
pub fn nums() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&[
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
        0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
    ]).unwrap()
}

/// Two-party MuSig2 over a keypath sighash, with the taproot tweak for `merkle`. Fixed nonce seeds mixed
/// with the message: test code only.
pub fn musig_keypath_sig(ctx: &KeyAggContext, merkle: [u8; 32], msg: [u8; 32], p: &Party, c: &Party) -> Vec<u8> {
    let tctx = ctx.clone().with_taproot_tweak(&merkle).unwrap();
    let scalar = |q: &Party| musig2::secp::Scalar::from_slice(&q.sk.secret_bytes()).unwrap();
    let mut r_p = FirstRound::new(tctx.clone(), [1u8; 32], 0, SecNonceSpices::new().with_seckey(scalar(p)).with_message(&msg)).unwrap();
    let mut r_c = FirstRound::new(tctx, [2u8; 32], 1, SecNonceSpices::new().with_seckey(scalar(c)).with_message(&msg)).unwrap();
    r_p.receive_nonce(1, r_c.our_public_nonce()).unwrap();
    r_c.receive_nonce(0, r_p.our_public_nonce()).unwrap();
    let mut s_p = r_p.finalize(scalar(p), msg).unwrap();
    let s_c = r_c.finalize(scalar(c), msg).unwrap();
    let part: PartialSignature = s_c.our_signature();
    s_p.receive_signature(1, part).unwrap();
    let sig: CompactSignature = s_p.finalize().unwrap();
    sig.serialize().to_vec()
}

pub fn p2tr_spk(secp: &Secp256k1<All>, who: &Party) -> ScriptBuf {
    Address::p2tr(secp, who.x, None, bitcoin::Network::Regtest).script_pubkey()
}
