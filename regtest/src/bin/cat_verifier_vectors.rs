//! ADR-016: the ADR-015 §7 experiment. A one-transaction stronger-fork refutation leaf built with OP_CAT
//! (BIP347), with the payout bound by a setup-presigned SIGHASH_SINGLE|ANYONECANPAY signature.
//!
//! The refutation is against a provider claim frozen at funding: "no chain from the checkpoint has more
//! than N-1 headers' work by the cutoff". Regtest has a fixed target (nBits 0x207fffff, no retarget),
//! so on this chain "stronger" means "N valid linked headers". The leaf, for each header:
//! - rebuilds the 80 bytes as version(4) || prev || merkle+time(36) || 0x207fffff || nonce(4), using
//!   OP_CAT, with prev = the checkpoint or the previous header's computed hash;
//! - checks each field's size, so no bytes can shift between fields;
//! - re-binds the hash to a witness split lo(29) || hi(3) with OP_CAT, then checks
//!   0 <= hi < 0x7fffff. That is strictly below the regtest target, which is the consensus PoW rule
//!   minus a measure-zero edge.
//!
//! The headers are real: they are mined here on Bitcoin's regtest genesis, and rust-bitcoin's
//! `Header::validate_pow` confirms each honest one. Each case carries two verdicts:
//! - `core_valid`: stock Bitcoin Core 26. Any 0x7e leaf is OP_SUCCESS, so every case is valid.
//! - `bip347_valid`: Core 26 with `research/bip347-check/bip347.patch` applied.
//! Nothing is broadcast, funded or mined on any network. The fabricated outpoints and test keys are public.
#[path = "../common.rs"]
mod common;
use common::*;
use bitcoin::absolute::LockTime;
use bitcoin::block::Header;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::encode::{deserialize, serialize, serialize_hex};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::opcodes::all::*;
use bitcoin::opcodes::Opcode;
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::transaction::Version;
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut, Txid, Witness};
use serde_json::{json, Value};

const CAT: u8 = 0x7e;
const BITS: [u8; 4] = [0xff, 0xff, 0x7f, 0x20]; // nBits 0x207fffff, little-endian
const VALUE: Amount = Amount::from_sat(100_000_000);

fn push(b: Builder, data: &[u8]) -> Builder {
    b.push_slice(PushBytesBuf::try_from(data.to_vec()).unwrap())
}
fn hash256(b: &[u8]) -> [u8; 32] {
    sha256d::Hash::hash(b).to_byte_array()
}

#[derive(Clone)]
struct Hdr {
    bytes: Vec<u8>, // 80 serialized bytes
}
impl Hdr {
    fn hash(&self) -> [u8; 32] { hash256(&self.bytes) }
    fn version(&self) -> Vec<u8> { self.bytes[0..4].to_vec() }
    fn tail(&self) -> Vec<u8> { self.bytes[36..72].to_vec() }
    fn nonce(&self) -> Vec<u8> { self.bytes[76..80].to_vec() }
}
/// The leaf's PoW predicate: hi = hash[29..32] as a script number, 0 <= hi < 0x7fffff.
fn leaf_pow(h: &[u8; 32]) -> bool {
    let hi = h[29] as u32 | (h[30] as u32) << 8 | (h[31] as u32) << 16;
    h[31] < 0x80 && hi < 0x7fffff
}
/// Mine a header on `prev`. `want_pow` false grinds for a header that fails the target instead.
fn mine(prev: [u8; 32], i: u32, bits: [u8; 4], salt: u8, want_pow: bool) -> Hdr {
    let mut b = Vec::with_capacity(80);
    b.extend_from_slice(&0x2000_0000u32.to_le_bytes());
    b.extend_from_slice(&prev);
    b.extend_from_slice(&hash256(&[b"bsb/adr016 merkle".as_slice(), &i.to_le_bytes(), &[salt]].concat()));
    b.extend_from_slice(&(1_296_688_602u32 + 600 * (i + 1)).to_le_bytes()); // after regtest genesis time
    b.extend_from_slice(&bits);
    b.extend_from_slice(&[0u8; 4]);
    for nonce in 0u32.. {
        b[76..80].copy_from_slice(&nonce.to_le_bytes());
        let h = hash256(&b);
        if leaf_pow(&h) == want_pow { return Hdr { bytes: b }; }
    }
    unreachable!()
}
fn chain(checkpoint: [u8; 32], n: usize, salt: u8) -> Vec<Hdr> {
    let mut v = Vec::new();
    let mut prev = checkpoint;
    for i in 0..n {
        let h = mine(prev, i as u32, BITS, salt, true);
        prev = h.hash();
        v.push(h);
    }
    v
}
/// Witness items for the headers, bottom to top, so header 1's items end up on top:
/// per header, top first: version, tail, nonce, lo29, hi3.
fn header_items(hs: &[Hdr]) -> Vec<Vec<u8>> {
    let mut items = Vec::new();
    for h in hs.iter().rev() {
        let hash = h.hash();
        items.push(hash[29..].to_vec());
        items.push(hash[..29].to_vec());
        items.push(h.nonce());
        items.push(h.tail());
        items.push(h.version());
    }
    items
}

/// The refutation leaf for exactly `n` headers from `checkpoint`, gated by the setup key's signature.
fn leaf(setup: &bitcoin::XOnlyPublicKey, checkpoint: &[u8; 32], n: usize) -> ScriptBuf {
    let cat = Opcode::from(CAT);
    let mut b = push(Builder::new(), &setup.serialize()).push_opcode(OP_CHECKSIGVERIFY);
    b = push(b, checkpoint);
    for _ in 0..n {
        // [.. hi lo nonce tail version prev]
        b = b.push_opcode(OP_SWAP).push_opcode(OP_SIZE).push_int(4).push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_SWAP).push_opcode(cat) // version||prev
            .push_opcode(OP_SWAP).push_opcode(OP_SIZE).push_int(36).push_opcode(OP_EQUALVERIFY)
            .push_opcode(cat); // ||merkle||time
        b = push(b, &BITS).push_opcode(cat) // ||bits, fixed by the leaf
            .push_opcode(OP_SWAP).push_opcode(OP_SIZE).push_int(4).push_opcode(OP_EQUALVERIFY)
            .push_opcode(cat) // ||nonce: 80 bytes
            .push_opcode(OP_HASH256) // [.. hi lo H]
            .push_opcode(OP_ROT) // [.. lo H hi]
            .push_opcode(OP_SIZE).push_int(3).push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_DUP).push_opcode(OP_DUP).push_int(0).push_opcode(OP_GREATERTHANOREQUAL).push_opcode(OP_VERIFY)
            .push_int(0x7fffff).push_opcode(OP_LESSTHAN).push_opcode(OP_VERIFY) // [.. lo H hi]
            .push_opcode(OP_ROT).push_opcode(OP_SWAP).push_opcode(cat) // [.. H lo||hi]
            .push_opcode(OP_OVER).push_opcode(OP_EQUALVERIFY); // [.. H]: the next prev
    }
    b.push_opcode(OP_DROP).push_int(1).into_script()
}

struct Case { name: String, attack: &'static str, tx: Transaction, spent: Vec<TxOut>, core: bool, bip347: bool, design: bool, note: &'static str }
fn row(c: &Case) -> Value {
    json!({
        "name": c.name, "attack": c.attack, "raw_hex": serialize_hex(&c.tx),
        "spent_outputs": c.spent.iter().map(|o| json!({"script_pub_key": hex(o.script_pubkey.as_bytes()), "value": o.value.to_sat()})).collect::<Vec<_>>(),
        "input_index": 0, "core_valid": c.core, "bip347_valid": c.bip347, "design_ok": c.design,
        "counterexample": c.core && !c.design, "weight": c.tx.weight().to_wu(), "note": c.note,
    })
}
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn main() {
    let secp = Secp256k1::new();
    let client = party(&secp, "bsb-adr016-client");
    let attacker = party(&secp, "bsb-adr016-attacker");
    let setup = party(&secp, "bsb-adr016-setup-signer"); // public test key; A5 erasure is an assumption
    let genesis = serialize(&genesis_block(Network::Regtest).header);
    let checkpoint = hash256(&genesis);
    let mut display = checkpoint; display.reverse();
    assert_eq!(hex(&display), "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206", "regtest genesis");

    let mut cases = Vec::new();
    let mut report = Vec::new();
    for &n in &[8usize, 151] {
        let honest = chain(checkpoint, n, 0);
        for h in &honest {
            let hd: Header = deserialize(&h.bytes).unwrap();
            hd.validate_pow(hd.target()).expect("honest header meets the regtest target");
        }
        let lf = leaf(&setup.x, &checkpoint, n);
        let st = state(&secp, nums(), &[&lf]);
        let prev = TxOut { value: VALUE, script_pubkey: st.spk.clone() };
        let cb = control(&st, &lf);
        let pay = |who: &Party| TxOut { value: VALUE - Amount::from_sat(2_000), script_pubkey: p2tr_spk(&secp, who) };
        let base = Transaction {
            version: Version(2), lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint { txid: Txid::from_byte_array([0x16; 32]), vout: 0 },
                script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }],
            output: vec![pay(&client)],
        };
        let lh = TapLeafHash::from_script(&lf, LeafVersion::TapScript);
        let sh = SighashCache::new(&base)
            .taproot_script_spend_signature_hash(0, &Prevouts::One(0, prev.clone()), lh, TapSighashType::SinglePlusAnyoneCanPay)
            .unwrap();
        let mut sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(sh.to_byte_array()), &setup.kp).serialize().to_vec();
        sig.push(TapSighashType::SinglePlusAnyoneCanPay as u8);
        let spend = |tx: &Transaction, items: Vec<Vec<u8>>| {
            let mut w = items;
            w.push(sig.clone());
            w.push(lf.to_bytes());
            w.push(cb.clone());
            let mut t = tx.clone();
            t.input[0].witness = Witness::from_slice(&w);
            t
        };
        let mut add = |name: &str, attack: &'static str, tx: Transaction, spent: Vec<TxOut>, ok: bool, note: &'static str| {
            cases.push(Case { name: format!("N{n}/{name}"), attack, tx, spent, core: true, bip347: ok, design: ok, note });
        };
        let honest_tx = spend(&base, header_items(&honest));
        report.push(json!({"n": n, "leaf_bytes": lf.len(), "witness_items": honest_tx.input[0].witness.len(),
            "weight": honest_tx.weight().to_wu(), "vsize": honest_tx.vsize()}));
        add("honest_stronger_fork", "none", honest_tx.clone(), vec![prev.clone()], true,
            "N real linked regtest headers from the checkpoint refute a claim of N-1");
        if n != 8 { continue; }
        add("claim_length_only", "a fork no stronger than the claim (N-1 headers)",
            spend(&base, header_items(&honest[..n - 1])), vec![prev.clone()], false, "stack underflow: the leaf demands N headers");
        let longer = chain(checkpoint, n + 1, 0);
        add("one_extra_header", "N+1 headers", spend(&base, header_items(&longer)), vec![prev.clone()], false,
            "clean-stack rule: the leaf is exact-N; a longer fork must drop its tip");
        // Broken link: header 4 replaced by a valid-PoW header mined on a different parent.
        let mut broken = honest.clone();
        broken[3] = mine([0x33; 32], 3, BITS, 7, true);
        add("broken_link", "header 4 mined on another parent", spend(&base, header_items(&broken)), vec![prev.clone()], false,
            "the leaf hashes header 4 over header 3's computed hash, which no longer matches the supplied limbs");
        // Under target: header 5 whose hash fails the target, with truthful limbs.
        let mut weak = honest.clone();
        weak[4] = mine(weak[3].hash(), 4, BITS, 9, false);
        let wh: Header = deserialize(&weak[4].bytes).unwrap();
        assert!(wh.validate_pow(wh.target()).is_err(), "the weak header really fails regtest PoW");
        // Headers after it must link to it for the attack to be pure PoW.
        let mut p = weak[4].hash();
        for i in 5..n { weak[i] = mine(p, i as u32, BITS, 9, true); p = weak[i].hash(); }
        add("under_target_header", "one header above the target", spend(&base, header_items(&weak)), vec![prev.clone()], false,
            "hi >= 0x7fffff or the sign bit is set: OP_LESSTHAN or OP_GREATERTHANOREQUAL fails");
        // Easier bits: a header mined for nBits 0x2100ffff, offered as if it met 0x207fffff.
        let mut easy = honest.clone();
        easy[0] = mine(checkpoint, 0, [0xff, 0xff, 0x00, 0x21], 11, true);
        add("different_nbits", "header 1 mined for other nBits", spend(&base, header_items(&easy)), vec![prev.clone()], false,
            "the leaf writes 0x207fffff itself, so the rebuilt header hashes differently");
        // Lying limbs: claim hi = 0 for header 2.
        let mut items = header_items(&honest);
        let k = items.len() - 1 - 5 - 4; // header 2's hi3 item (header 1 is the top five)
        items[k] = vec![0, 0, 0];
        add("forged_hash_limbs", "header 2's hash split replaced by a low value", spend(&base, items), vec![prev.clone()], false,
            "lo||hi must equal the computed HASH256");
        // Field shift: move one byte from header 1's tail into its version.
        let mut items = header_items(&honest);
        let top = items.len() - 1;
        let mut ver = items[top].clone();
        ver.push(items[top - 1][0]);
        items[top] = ver;
        items[top - 1] = items[top - 1][1..].to_vec();
        add("shifted_fields", "version 5 bytes, tail 35", spend(&base, items), vec![prev.clone()], false,
            "field sizes are checked, so prev sits at offset 4 exactly as Bitcoin parses it");
        // Wrong checkpoint: a fork mined from mainnet's genesis hash.
        let mainnet_cp = hash256(&serialize(&genesis_block(Network::Bitcoin).header));
        add("wrong_checkpoint", "fork rooted elsewhere", spend(&base, header_items(&chain(mainnet_cp, n, 0))), vec![prev.clone()], false,
            "the leaf starts from the regtest genesis hash");
        // Payout.
        let mut redirected = base.clone();
        redirected.output[0] = pay(&attacker);
        add("redirect_output0", "honest headers, output 0 redirected", spend(&redirected, header_items(&honest)), vec![prev.clone()], false,
            "SINGLE|ANYONECANPAY binds output 0: front-running by copying the witness pays the client anyway");
        let fee_in = TxOut { value: Amount::from_sat(60_000), script_pubkey: p2tr_spk(&secp, &attacker) };
        let mut sponsored = base.clone();
        sponsored.input.push(TxIn { previous_output: OutPoint { txid: Txid::from_byte_array([0x17; 32]), vout: 2 },
            script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() });
        sponsored.output.push(TxOut { value: Amount::from_sat(50_000), script_pubkey: p2tr_spk(&secp, &attacker) });
        add("sponsor_adds_fee_input", "none (fee sponsorship)", spend(&sponsored, header_items(&honest)), vec![prev.clone(), fee_in], true,
            "any challenger can attach fees; input 0 is the one checked");
        let mut bare = base.clone();
        bare.input[0].witness = Witness::from_slice(&[lf.to_bytes(), cb.clone()]);
        add("empty_witness", "no headers, no signature", bare, vec![prev.clone()], false,
            "invalid once CAT is real; anyone-can-spend on stock Core (OP_SUCCESS126)");
    }
    let out = json!({
        "schema": "bsb/cat-verifier-vectors/v1", "adr": "ADR-016",
        "checkpoint_display": hex(&display),
        "interpreters": {
            "core_valid": "Bitcoin Core 26 libbitcoinconsensus, unmodified (OP_CAT is OP_SUCCESS126 in tapscript)",
            "bip347_valid": "Bitcoin Core 26 libbitcoinconsensus + research/bip347-check/bip347.patch (BIP347 semantics, local research patch, not activated consensus)"
        },
        "sizes": report,
        "warning": "unfunded fabricated outpoints, public test keys; never broadcast",
        "cases": cases.iter().map(row).collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
