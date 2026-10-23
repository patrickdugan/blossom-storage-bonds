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
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey};
use musig2::{CompactSignature, FirstRound, KeyAggContext, PartialSignature, SecNonceSpices};
use rpc::Rpc;
use serde_json::{json, Value};

pub const BOND: Amount = Amount::from_sat(100_000_000);
pub const DELTA: u16 = 144;
pub const FEERATE: u64 = 2; // sat/vB for CPFP packages and self-funded spends
pub const CLOSE_FEE: Amount = Amount::from_sat(1_000);
pub const MAX_STANDARD_ITEM: usize = 80; // MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE, policy/policy.h

// ───────────────────────────── networks ─────────────────────────────

/// How fees are chosen. Regtest keeps the fixed values every earlier phase measured with (FEERATE for
/// funding and CPFP, CLOSE_FEE for forfeits and refunds), so its transactions stay byte-identical.
#[derive(Clone, Debug, PartialEq)]
pub enum Fees {
    Regtest,
    /// sat/vB, from BSB_FEE_RATE.
    Fixed(u64),
    /// estimatesmartfee at `target` blocks, clamped to 1..=`max` sat/vB, and `fallback` when the node has
    /// no estimate (signet blocks are often near empty, and a young node has no data). The cap matters on
    /// signet: Core 31 issue #35507 has estimatesmartfee answering hundreds to thousands of sat/vB on a
    /// near-empty mempool, and faucet coins are scarce.
    Estimate { target: u16, fallback: u64, max: u64 },
}

/// What differs between regtest and a pilot network: the chain, how deep an output must be before a
/// party relies on it, and fees.
#[derive(Clone, Debug, PartialEq)]
pub struct NetCfg {
    pub network: Network,
    /// Confirmations before a party relies on an output the other side created (a bond, a channel).
    pub confs: u32,
    pub fees: Fees,
}

impl NetCfg {
    pub fn regtest() -> NetCfg {
        NetCfg { network: Network::Regtest, confs: 1, fees: Fees::Regtest }
    }

    /// The name Core reports in getblockchaininfo.chain.
    pub fn core_chain(&self) -> &'static str {
        match self.network {
            Network::Regtest => "regtest",
            Network::Signet => "signet",
            _ => unreachable!("only regtest and signet are configured"),
        }
    }

    /// From BSB_NETWORK (regtest or signet; anything else, mainnet above all, is refused), BSB_CONFS
    /// (default 1 on regtest, 3 elsewhere), and BSB_FEE_RATE, or else BSB_FEE_TARGET, BSB_FEE_FALLBACK
    /// and BSB_MAX_FEE_RATE for estimation off regtest.
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<NetCfg, String> {
        let network = match get("BSB_NETWORK").as_deref().unwrap_or("regtest") {
            "regtest" => Network::Regtest,
            "signet" => Network::Signet,
            other => return Err(format!("BSB_NETWORK={other}: only regtest and signet are supported, never mainnet")),
        };
        let num = |k: &str, d: u64| -> Result<u64, String> {
            get(k).map_or(Ok(d), |v| v.parse::<u64>().map_err(|_| format!("{k} must be a whole number")))
        };
        let regtest = network == Network::Regtest;
        let confs = num("BSB_CONFS", if regtest { 1 } else { 3 })? as u32;
        if confs == 0 { return Err("BSB_CONFS must be at least 1".into()); }
        let fees = match get("BSB_FEE_RATE") {
            Some(_) => Fees::Fixed(num("BSB_FEE_RATE", 0)?.max(1)),
            None if regtest => Fees::Regtest,
            None => Fees::Estimate { target: num("BSB_FEE_TARGET", 6)? as u16, fallback: num("BSB_FEE_FALLBACK", 2)?.max(1), max: num("BSB_MAX_FEE_RATE", 10)?.max(1) },
        };
        Ok(NetCfg { network, confs, fees })
    }
}

/// The RPC URL and credentials. Regtest defaults to scripts/regtest-node.sh's fixed test values; any
/// other network needs BSB_RPC_COOKIE (the node's .cookie file) or BSB_RPC_USER and BSB_RPC_PASS, and
/// refuses the regtest password.
pub fn rpc_from_env(net: &NetCfg, get: impl Fn(&str) -> Option<String>) -> Result<Rpc, String> {
    let regtest = net.network == Network::Regtest;
    let url = get("BSB_RPC").unwrap_or_else(|| if regtest { "http://127.0.0.1:18543".into() } else { "http://127.0.0.1:38332".into() });
    let (user, pass) = if let Some(path) = get("BSB_RPC_COOKIE") {
        let s = std::fs::read_to_string(&path).map_err(|e| format!("BSB_RPC_COOKIE {path}: {e}"))?;
        let (u, p) = s.trim().split_once(':').ok_or("cookie file is not user:password")?;
        (u.to_string(), p.to_string())
    } else if let (Some(u), Some(p)) = (get("BSB_RPC_USER"), get("BSB_RPC_PASS")) {
        (u, p)
    } else if regtest {
        ("bsb".into(), "bsb-regtest-only".into())
    } else {
        return Err("off regtest, set BSB_RPC_COOKIE or BSB_RPC_USER and BSB_RPC_PASS".into());
    };
    if !regtest && pass == "bsb-regtest-only" {
        return Err("refusing the fixed regtest RPC password off regtest".into());
    }
    Ok(Rpc::new(&url, &user, &pass))
}

/// Off regtest a party's seed must be fresh: 32 random bytes as 64 hex digits, generated per party and
/// per run. Every fixed test seed in this repository is a readable label ("bsb/provider/honest", ...),
/// so the format alone refuses them; a constant byte string (the MuSig2 nonce seeds' shape) is refused
/// too. On regtest any label is allowed, which keeps the earlier runs' keys.
pub fn check_seed(net: &NetCfg, seed: &str) -> Result<(), String> {
    if net.network == Network::Regtest { return Ok(()); }
    if seed.len() != 64 || !seed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("off regtest BSB_SEED must be 32 fresh random bytes in hex, not a fixed test value ({} chars given)", seed.len()));
    }
    let b = unhex(&seed.to_ascii_lowercase());
    if b.iter().all(|x| *x == b[0]) { return Err("BSB_SEED is a constant byte string".into()); }
    Ok(())
}

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
    presigned_value(prev, to, BOND)
}

pub fn presigned_value(prev: OutPoint, to: &ScriptBuf, bond: Amount) -> Transaction {
    Transaction {
        version: Version(3),
        lock_time: LockTime::ZERO,
        input: vec![txin(prev, Sequence::ENABLE_RBF_NO_LOCKTIME)],
        output: vec![
            TxOut { value: bond, script_pubkey: to.clone() },
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
    pub net: NetCfg,
}

impl Node {
    pub fn mine(&self, n: u32) {
        assert_eq!(self.net.network, Network::Regtest, "only regtest mines");
        self.rpc.call("generatetoaddress", json!([n, self.fee_addr.to_string()])).unwrap();
    }

    /// sat/vB for what this party funds now: the bond, a channel, a CPFP child.
    pub fn fee_rate(&self) -> u64 {
        match self.net.fees {
            Fees::Regtest => FEERATE,
            Fees::Fixed(r) => r,
            Fees::Estimate { target, fallback, max } => {
                let est = self.rpc.call("estimatesmartfee", json!([target, "conservative"])).ok().and_then(|v| v["feerate"].as_f64());
                // BTC/kvB to sat/vB, rounded up.
                est.map_or(fallback, |btc_kvb| (btc_kvb * 1e5).ceil() as u64).clamp(1, max)
            }
        }
    }

    /// The fee of a forfeit or refund, a one-input spend whose witness size is known before signing.
    pub fn close_fee(&self, vsize: usize) -> Amount {
        match self.net.fees {
            Fees::Regtest => CLOSE_FEE,
            _ => Amount::from_sat(self.fee_rate() * vsize as u64),
        }
    }

    /// The largest confirmed, mature output paying the fee key that no mempool transaction spends yet
    /// (off regtest, blocks are slow enough that two of this party's spends can wait in one interval).
    pub fn fee_utxo(&self) -> (OutPoint, TxOut) {
        self.fee_coins()
            .into_iter()
            .max_by_key(|(_, o)| o.value)
            .expect("no mature, unspent fee UTXO (fund the fee address; off regtest, fee-split it so parallel spends do not wait for a block)")
    }

    /// Every confirmed, mature output paying the fee key that no mempool transaction spends yet, in the
    /// order Core's scan lists them.
    pub fn fee_coins(&self) -> Vec<(OutPoint, TxOut)> {
        let tip = self.rpc.height() as u64;
        // Core runs one UTXO-set scan at a time; other parties' agents may be scanning on the same node.
        // A scan of signet's UTXO set takes seconds, so wait up to two minutes.
        let t0 = std::time::Instant::now();
        let r = loop {
            match self.rpc.call("scantxoutset", json!(["start", [format!("addr({})", self.fee_addr)]])) {
                Ok(r) => break r,
                Err(e) if e.contains("in progress") && t0.elapsed().as_secs() < 120 => std::thread::sleep(std::time::Duration::from_millis(50)),
                Err(e) => panic!("scantxoutset: {e}"),
            }
        };
        let mature: Vec<&Value> = r["unspents"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|u| !u["coinbase"].as_bool().unwrap_or(true) || u["height"].as_u64().unwrap() + 100 <= tip)
            .collect();
        let spent: Vec<bool> = if mature.is_empty() {
            vec![]
        } else {
            let q: Vec<Value> = mature.iter().map(|u| json!({ "txid": u["txid"], "vout": u["vout"] })).collect();
            match self.rpc.call("gettxspendingprevout", json!([q])) {
                Ok(v) => v.as_array().unwrap().iter().map(|x| x.get("spendingtxid").is_some()).collect(),
                Err(_) => vec![false; mature.len()],
            }
        };
        mature
            .iter()
            .zip(spent.iter())
            .filter(|(_, s)| !**s)
            .map(|(u, _)| {
                let op = OutPoint { txid: u["txid"].as_str().unwrap().parse().unwrap(), vout: u["vout"].as_u64().unwrap() as u32 };
                let value = Amount::from_sat((u["amount"].as_f64().unwrap() * 1e8).round() as u64);
                (op, TxOut { value, script_pubkey: self.fee_addr.script_pubkey() })
            })
            .collect()
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
        self.fund_value(spk, BOND)
    }

    /// One keypath input when the largest coin covers the bond, the fee and change (always on regtest,
    /// and byte-identical to phase 1); otherwise the next largest coins as well, since faucet coins are
    /// small.
    pub fn fund_value(&self, spk: &ScriptBuf, bond: Amount) -> Transaction {
        let rate = self.fee_rate();
        let dust = Amount::from_sat(330);
        let mut ins = vec![self.fee_utxo()];
        // vsize with n keypath inputs, bond and change: 154 for one, about 57.5 more per extra input.
        let build = |ins: &[(OutPoint, TxOut)], change: Amount| Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: ins.iter().map(|(op, _)| txin(*op, Sequence::ENABLE_RBF_NO_LOCKTIME)).collect(),
            output: vec![
                TxOut { value: bond, script_pubkey: spk.clone() },
                TxOut { value: change, script_pubkey: self.fee_addr.script_pubkey() },
            ],
        };
        let fee_for = |ins: &[(OutPoint, TxOut)]| {
            if ins.len() == 1 { return Amount::from_sat(rate * 154); }
            let mut probe = build(ins, Amount::ZERO);
            for i in &mut probe.input { i.witness = Witness::from_slice(&[vec![0u8; 64]]); }
            Amount::from_sat(rate * probe.vsize() as u64)
        };
        let total = |ins: &[(OutPoint, TxOut)]| ins.iter().map(|(_, o)| o.value).sum::<Amount>();
        if total(&ins) < bond + fee_for(&ins) + dust {
            let first = ins[0].0;
            let mut rest: Vec<(OutPoint, TxOut)> = self.fee_coins().into_iter().filter(|(op, _)| *op != first).collect();
            rest.sort_by(|a, b| b.1.value.cmp(&a.1.value));
            for c in rest {
                if total(&ins) >= bond + fee_for(&ins) + dust { break; }
                ins.push(c);
            }
            if total(&ins) < bond + fee_for(&ins) + dust {
                panic!("the fee wallet ({} in {} coins) cannot fund a {} bond plus fee", total(&ins), ins.len(), bond);
            }
        }
        let fee = fee_for(&ins);
        let mut tx = build(&ins, total(&ins) - bond - fee);
        let prevouts: Vec<TxOut> = ins.iter().map(|(_, o)| o.clone()).collect();
        for i in 0..ins.len() { self.sign_fee_input(&mut tx, i, &prevouts); }
        tx
    }

    /// CPFP child of a zero-fee parent: spends the P2A anchor plus one fee input. Off regtest the rate is
    /// estimated when the package goes out, so a fee rise during Δ is paid by whoever broadcasts then.
    pub fn child(&self, parent: &Transaction) -> Transaction { self.child_at(parent, self.fee_rate()) }

    /// A CPFP child at an explicit fee rate (sat/vB over parent + child): a party bidding to win a race.
    pub fn child_at(&self, parent: &Transaction, rate: u64) -> Transaction {
        let (op, prev) = self.fee_utxo();
        let anchor = OutPoint { txid: parent.compute_txid(), vout: 1 };
        let fee = Amount::from_sat(rate * (parent.vsize() as u64 + 153));
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
        self.submit_package_at(parent, self.fee_rate())
    }

    pub fn submit_package_at(&self, parent: &Transaction, rate: u64) -> Result<Transaction, String> {
        let child = self.child_at(parent, rate);
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
    /// The value every state carries: BOND unless the deal names another.
    pub bond: Amount,
}

pub fn build_chain(secp: &Secp256k1<All>, internal: XOnlyPublicKey, p: &XOnlyPublicKey, c: &XOnlyPublicKey, sh: &[([u8; 32], Vec<[u8; 32]>)], t_end: u32) -> Chain {
    let refund = refund_leaf(p, t_end);
    let forfeit = forfeit_leaf(c, DELTA);
    let challenge_leaves: Vec<ScriptBuf> = sh.iter().map(|(s, _)| challenge_leaf(c, p, *s)).collect();
    let respond_leaves: Vec<ScriptBuf> = sh.iter().map(|(_, hs)| respond_leaf(p, c, hs)).collect();
    let mut bonds: Vec<State> = challenge_leaves.iter().map(|l| state(secp, internal, &[l, &refund])).collect();
    bonds.push(state(secp, internal, &[&refund]));
    let challenged = respond_leaves.iter().map(|l| state(secp, internal, &[l, &forfeit])).collect();
    Chain { bonds, challenged, challenge_leaves, respond_leaves, refund, forfeit, bond: BOND }
}

impl Chain {
    pub fn with_bond(mut self, bond: Amount) -> Chain {
        self.bond = bond;
        self
    }
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
        let ctx_tx = presigned_value(bond_op, &ch.challenged[i].spk, ch.bond);
        let rtx = presigned_value(OutPoint { txid: ctx_tx.compute_txid(), vout: 0 }, &ch.bonds[i + 1].spk, ch.bond);
        bond_op = OutPoint { txid: rtx.compute_txid(), vout: 0 };
        challenge.push(ctx_tx);
        respond.push(rtx);
    }
    (challenge, respond)
}

pub fn presign_chain(secp: &Secp256k1<All>, ch: &Chain, p: &Party, c: &Party, fund_op: OutPoint) -> Presigned {
    let (challenge, respond) = chain_txs(ch, fund_op);
    let sp = (0..challenge.len()).map(|i| script_sig(secp, &challenge[i], &TxOut { value: ch.bond, script_pubkey: ch.bonds[i].spk.clone() }, &ch.challenge_leaves[i], p)).collect();
    let sc = (0..respond.len()).map(|i| script_sig(secp, &respond[i], &TxOut { value: ch.bond, script_pubkey: ch.challenged[i].spk.clone() }, &ch.respond_leaves[i], c)).collect();
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
/// with the message: test code only. Only the regtest harness (main.rs) calls this, and it refuses any
/// chain but regtest; bsb-bond, the tool a pilot runs, has no keypath close.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(kv: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| kv.iter().find(|(a, _)| *a == k).map(|(_, v)| v.to_string())
    }

    #[test]
    fn regtest_is_the_default_and_keeps_the_fixed_fees() {
        let n = NetCfg::from_env(env(&[])).unwrap();
        assert_eq!(n, NetCfg::regtest());
        assert_eq!((n.confs, &n.fees), (1, &Fees::Regtest));
        let r = rpc_from_env(&n, env(&[]));
        assert!(r.is_ok());
    }

    #[test]
    fn signet_defaults_and_refusals() {
        let n = NetCfg::from_env(env(&[("BSB_NETWORK", "signet")])).unwrap();
        assert_eq!(n.network, Network::Signet);
        assert_eq!(n.confs, 3);
        assert_eq!(n.fees, Fees::Estimate { target: 6, fallback: 2, max: 10 });
        assert_eq!(n.core_chain(), "signet");
        assert!(NetCfg::from_env(env(&[("BSB_NETWORK", "mainnet")])).is_err());
        assert!(NetCfg::from_env(env(&[("BSB_NETWORK", "bitcoin")])).is_err());
        assert!(NetCfg::from_env(env(&[("BSB_NETWORK", "signet"), ("BSB_CONFS", "0")])).is_err());
        assert_eq!(NetCfg::from_env(env(&[("BSB_NETWORK", "signet"), ("BSB_FEE_RATE", "7")])).unwrap().fees, Fees::Fixed(7));
        // No default credentials off regtest, and never the regtest password.
        assert!(rpc_from_env(&n, env(&[])).is_err());
        assert!(rpc_from_env(&n, env(&[("BSB_RPC_USER", "bsb"), ("BSB_RPC_PASS", "bsb-regtest-only")])).is_err());
        assert!(rpc_from_env(&n, env(&[("BSB_RPC_USER", "u"), ("BSB_RPC_PASS", "a-real-secret")])).is_ok());
    }

    #[test]
    fn fixed_seeds_are_refused_off_regtest() {
        let s = NetCfg::from_env(env(&[("BSB_NETWORK", "signet")])).unwrap();
        for fixed in ["bsb/provider/honest", "bsb/client/full-stack", "bsb/fee-wallet", &"01".repeat(32), &"02".repeat(32), &"00".repeat(32), ""] {
            assert!(check_seed(&s, fixed).is_err(), "{fixed}");
            assert!(check_seed(&NetCfg::regtest(), fixed).is_ok());
        }
        assert!(check_seed(&s, "6b1f0c2d9a7e44c3b8f1d2e3a4b5c6d7e8f90112233445566778899aabbccddee").is_err(), "65 chars");
        assert!(check_seed(&s, "6b1f0c2d9a7e44c3b8f1d2e3a4b5c6d7e8f90112233445566778899aabbccdde").is_ok());
    }

    #[test]
    fn a_chain_with_another_bond_value_changes_only_the_values() {
        let secp = Secp256k1::new();
        let (p, c) = (party(&secp, "p"), party(&secp, "c"));
        let sh = vec![([7u8; 32], vec![[8u8; 32]])];
        let op = OutPoint { txid: "0000000000000000000000000000000000000000000000000000000000000001".parse().unwrap(), vout: 0 };
        let a = build_chain(&secp, nums(), &p.x, &c.x, &sh, 500);
        assert_eq!(a.bond, BOND);
        let (ca, _) = chain_txs(&a, op);
        assert_eq!(ca[0], presigned(op, &a.challenged[0].spk), "the default chain is the phase 1 bytes");
        let b = build_chain(&secp, nums(), &p.x, &c.x, &sh, 500).with_bond(Amount::from_sat(250_000));
        let (cb, rb) = chain_txs(&b, op);
        assert_eq!(cb[0].output[0].value, Amount::from_sat(250_000));
        assert_eq!(rb[0].output[0].value, Amount::from_sat(250_000));
        assert_eq!(cb[0].output[0].script_pubkey, ca[0].output[0].script_pubkey);
    }
}
