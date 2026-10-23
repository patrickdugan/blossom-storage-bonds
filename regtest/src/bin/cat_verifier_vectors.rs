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

const MAINNET_32250_32262: [&str; 13] = [
    "01000000bfeeabd547eb6fc8fa4152725030d8ca0e03ce03f912700601fa3ad2000000000cfc1c060eea439947fb50b9f082ef626f66608cd32b2c93604e8c05caabda96f1e13a4bffff001d5a661f02", // 32250 000000002931f8c7a9fe1a6f122dd5777d09d81dc107e051d7f78efef09c1719
    "0100000019179cf0fe8ef7d751e007c11dd8097d77d52d126f1afea9c7f83129000000003c5e7fd03948b4e413c69bcbf6208d407910d9d3e0bdde65c572d46e14b526f146e23a4bffff001d9e369a01", // 32251 00000000360d826e18e72b3f5f3a05a43989131e512319a3b24aaa24b1010aa9
    "01000000a90a01b124aa4ab2a31923511e138939a4053a5f3f2be7186e820d3600000000fb6e3ed118edc6171a2e50a8484ba7c33fe6bd6efb49e90b8b7d0b0ea5e800b862e23a4bffff001d6db69d00", // 32252 000000003d5eb2328f71644f2540cf6acc343f90d1594b2ef916ad4d4a7f5d2d
    "010000002d5d7f4a4dad16f92e4b59d1903f34cc6acf40254f64718f32b25e3d00000000c2a630dbfefd5a55a939d39388d1daad1ff2ca22de59ddfd1464b494e61acb0410e93a4bffff001de3c38c1e", // 32253 000000000e27ee2a3899aec79a8aa08f138e320a66fa7fa3f2e4b9fd05e42a67
    "01000000672ae405fdb9e4f2a37ffa660a328e138fa08a9ac7ae99382aee270e00000000342fedae2d72975552ac0797556817d11006ec322e2bf97ce88f91caf39525794fe93a4bffff001d94282401", // 32254 000000006baebaa74cecde6c6787c26ee0a616a3c333261bff36653babdac149
    "0100000049c1daab3b6536ff1b2633c3a316a6e06ec287676cdeec4ca7baae6b00000000ac10b36b8f354b3353207de15940a5edbc05bb8364af75b4b5409e7823f2b48923ec3a4bffff001dbd5fa412", // 32255 00000000984f962134a7291e3693075ae03e521f0ee33378ec30a334d860034b
    "010000004b0360d834a330ec7833e30e1f523ee05a0793361e29a73421964f980000000027b64a020af294e903feed93768705336a20090612a043f47af462a2f5e5b564f8ee3a4b6ad8001dd3a43707", // 32256 000000004f2886a170adb7204cb0c7a824217dd24d11a74423d564c4e0904967
    "01000000674990e0c464d52344a7114dd27d2124a8c7b04c20b7ad70a186284f000000003423d663d7a4e64f42d403f8e054201a70acdb973219787803b3081f9888144d70f23a4b6ad8001d13365f10", // 32257 0000000078bb40a0a5aae645f86e144cab79209726b98d74e2f311c6d31aa52e
    "010000002ea51ad3c611f3e2748db926972079ab4c146ef845e6aaa5a040bb7800000000fbcc9a38285f50868401f6bc51078b4579f951af590e5e8f418e285dde420a1c29f73a4b6ad8001d1acf3906", // 32258 000000006e35246abda2e8f2ab945780ea7619c74a3ee5db5ca6ff0f4d5b88c6
    "01000000c6885b4d0fffa65cdbe53e4ac71976ea805794abf2e8a2bd6a24356e00000000ffdb82a1bb8bd3063972628aab966d9c8a08521e334107461473beb550ccde8b24fb3a4b6ad8001de6e47107", // 32259 000000008a5b32a0610b2b0eeb5390e30e157324bf28c09ab83ccbb99184c38b
    "010000008bc38491b9cb3cb89ac028bf2473150ee39053eb0e2b0b61a0325b8a00000000219837e507d74c270c47e099ed1f6abbce4d30cb80942684f29a57a914c5f004c3fb3a4b6ad8001de2b0cf02", // 32260 0000000007bfbe7ec5510ccf80c5a291bf8fc603dd79f5d6a69fae6039f8a35e
    "010000005ea3f83960ae9fa6d6f579dd03c68fbf91a2c580cf0c51c57ebebf0700000000081bea146b8337ea402d3c8e466d61d3f7b53ffb066fcd8def70781bcd35882c60ff3a4b6ad8001dbcaaed02", // 32261 0000000078f9b45db32ef92aaa94778984971cede7488ae502632399a91b2e7d
    "010000007d2e1ba999236302e58a48e7ed1c9784897794aa2af92eb35db4f978000000000d6d9d56c25650f5735fb201766c23d332b727687d557ee2e4556fbe994922a3dc003b4b6ad8001dfb631608", // 32262 00000000ac0ed7590ab09965d1f477df5588485944aee4797c13ef2b09f62089
];

/// ADR-019: the refutation leaf for a difficulty schedule pinned at setup, one nBits per header.
/// Take nBits with exponent e and mantissa m. A hash (as a little-endian 256-bit number) meets the
/// target m * 256^(e-3) when its top 32-e bytes are zero and the 3 bytes below them, read as a
/// non-negative script number, are below m. The equality edge is excluded, as in ADR-016.
/// Witness per header, top first: version, tail, nonce, lo(e-3), m3(3), z(32-e) when e < 32.
fn leaf_sched(setup: &bitcoin::XOnlyPublicKey, checkpoint: &[u8; 32], schedule: &[[u8; 4]]) -> ScriptBuf {
    let cat = Opcode::from(CAT);
    let mut b = push(Builder::new(), &setup.serialize()).push_opcode(OP_CHECKSIGVERIFY);
    b = push(b, checkpoint);
    for bits in schedule {
        let e = bits[3] as usize;
        let m = u32::from_le_bytes([bits[0], bits[1], bits[2], 0]);
        assert!((3..=32).contains(&e) && m < 0x80_0000, "nBits outside the supported encoding");
        b = b.push_opcode(OP_SWAP).push_opcode(OP_SIZE).push_int(4).push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_SWAP).push_opcode(cat)
            .push_opcode(OP_SWAP).push_opcode(OP_SIZE).push_int(36).push_opcode(OP_EQUALVERIFY)
            .push_opcode(cat);
        b = push(b, bits).push_opcode(cat) // nBits for this height, pinned at setup
            .push_opcode(OP_SWAP).push_opcode(OP_SIZE).push_int(4).push_opcode(OP_EQUALVERIFY)
            .push_opcode(cat).push_opcode(OP_HASH256) // [.. (z) m3 lo H]
            .push_opcode(OP_TOALTSTACK) // [.. (z) m3 lo]
            .push_opcode(OP_SWAP) // [.. (z) lo m3]
            .push_opcode(OP_SIZE).push_int(3).push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_DUP).push_opcode(OP_DUP).push_int(0).push_opcode(OP_GREATERTHANOREQUAL).push_opcode(OP_VERIFY)
            .push_int(m as i64).push_opcode(OP_LESSTHAN).push_opcode(OP_VERIFY)
            .push_opcode(cat); // [.. (z) lo||m3]
        if e < 32 {
            b = b.push_opcode(OP_SWAP).push_opcode(OP_DUP); // [.. lom z z]
            b = push(b, &vec![0u8; 32 - e]).push_opcode(OP_EQUALVERIFY).push_opcode(cat); // [.. lo||m3||z]
        }
        b = b.push_opcode(OP_FROMALTSTACK).push_opcode(OP_TUCK).push_opcode(OP_EQUALVERIFY); // [.. H]
    }
    b.push_opcode(OP_DROP).push_int(1).into_script()
}

/// Witness items for `leaf_sched`, bottom to top, so header 1's items end up on top.
fn sched_items(hs: &[Hdr], schedule: &[[u8; 4]]) -> Vec<Vec<u8>> {
    let mut items = Vec::new();
    for (h, bits) in hs.iter().zip(schedule).rev() {
        let e = bits[3] as usize;
        let hash = h.hash();
        if e < 32 { items.push(hash[e..].to_vec()); }
        items.push(hash[e - 3..e].to_vec());
        items.push(hash[..e - 3].to_vec());
        items.push(h.nonce());
        items.push(h.tail());
        items.push(h.version());
    }
    items
}

struct Case { name: String, attack: &'static str, tx: Transaction, spent: Vec<TxOut>, core: bool, bip347: bool, design: bool, note: &'static str, extra: Value }
fn row(c: &Case) -> Value {
    json!({
        "name": c.name, "attack": c.attack, "raw_hex": serialize_hex(&c.tx),
        "spent_outputs": c.spent.iter().map(|o| json!({"script_pub_key": hex(o.script_pubkey.as_bytes()), "value": o.value.to_sat()})).collect::<Vec<_>>(),
        "input_index": 0, "core_valid": c.core, "bip347_valid": c.bip347, "design_ok": c.design,
        "counterexample": c.core && !c.design, "weight": c.tx.weight().to_wu(), "note": c.note, "check": c.extra,
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
            cases.push(Case { name: format!("N{n}/{name}"), attack, tx, spent, core: true, bip347: ok, design: ok, note,
                extra: json!({"kind": "fork", "n": n}) });
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

    // ── ADR-017: dynamic frozen claims through a presigned freeze set ──
    // Bond B has two leaves. In the freeze leaf, the provider picks one of the setup-presigned
    // freeze_k transactions. In the forfeit leaf, the client takes the bond if no freeze happened by
    // T_FREEZE. Each freeze output F_k holds an exact-(k+1) OP_CAT refutation leaf paying the client,
    // and a provider refund at T_DEADLINE.
    let provider = party(&secp, "bsb-adr017-provider");
    const T_FREEZE: u32 = 500;
    const T_DEADLINE: u32 = 644;
    let claims = [3usize, 5, 7];
    let fee = Amount::from_sat(1_000);
    let cltv_leaf = |t: u32, who: &bitcoin::XOnlyPublicKey| Builder::new().push_int(t as i64)
        .push_opcode(OP_CLTV).push_opcode(OP_DROP).push_x_only_key(who).push_opcode(OP_CHECKSIG).into_script();
    let freeze_leaf = Builder::new().push_x_only_key(&provider.x).push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(&setup.x).push_opcode(OP_CHECKSIG).into_script();
    let forfeit_leaf = cltv_leaf(T_FREEZE, &client.x);
    let refund_leaf = cltv_leaf(T_DEADLINE, &provider.x);
    let bond = state(&secp, nums(), &[&freeze_leaf, &forfeit_leaf]);
    let bond_out = TxOut { value: VALUE, script_pubkey: bond.spk.clone() };
    let bond_op = OutPoint { txid: Txid::from_byte_array([0x18; 32]), vout: 0 };
    let f_state = |k: usize| {
        let rl = leaf(&setup.x, &checkpoint, k + 1);
        let st = state(&secp, nums(), &[&rl, &refund_leaf]);
        (rl, st)
    };
    let one_in = |op: OutPoint, seq: Sequence, lock: u32, out: TxOut| Transaction {
        version: Version(2), lock_time: LockTime::from_consensus(lock),
        input: vec![TxIn { previous_output: op, script_sig: ScriptBuf::new(), sequence: seq, witness: Witness::new() }],
        output: vec![out],
    };
    let with_w = |mut tx: Transaction, w: Vec<Vec<u8>>| { tx.input[0].witness = Witness::from_slice(&w); tx };
    let mut freeze_spks = serde_json::Map::new();
    // Presign every freeze_k (setup key, SIGHASH_DEFAULT); the provider adds its signature at cutoff.
    let mut presigned_setup = Vec::new();
    for &k in &claims {
        let (_, st) = f_state(k);
        freeze_spks.insert(k.to_string(), json!(hex(st.spk.as_bytes())));
        let tx = one_in(bond_op, Sequence::MAX, 0, TxOut { value: VALUE - fee, script_pubkey: st.spk.clone() });
        let sig = script_sig(&secp, &tx, &bond_out, &freeze_leaf, &setup);
        presigned_setup.push((k, tx, sig));
    }
    let mut fcase = |name: &str, attack: &'static str, tx: Transaction, spent: Vec<TxOut>, core: bool, bip347: bool, design: bool, note: &'static str, extra: Value| {
        cases.push(Case { name: format!("F/{name}"), attack, tx, spent, core, bip347, design, note, extra });
    };
    let bcb_f = control(&bond, &freeze_leaf);
    let bcb_x = control(&bond, &forfeit_leaf);
    let f5_tx = presigned_setup[1].1.clone();
    let setup5 = presigned_setup[1].2.clone();
    let prov5 = script_sig(&secp, &f5_tx, &bond_out, &freeze_leaf, &provider);
    fcase("freeze_claim5_honest", "none", with_w(f5_tx.clone(), vec![setup5.clone(), prov5.clone(), freeze_leaf.to_bytes(), bcb_f.clone()]),
        vec![bond_out.clone()], true, true, true, "the provider completes the presigned freeze for its claim (5 headers)",
        json!({"kind": "freeze", "claim": 5}));
    let (_, f4) = f_state(4);
    let unlisted = one_in(bond_op, Sequence::MAX, 0, TxOut { value: VALUE - fee, script_pubkey: f4.spk.clone() });
    let prov_u = script_sig(&secp, &unlisted, &bond_out, &freeze_leaf, &provider);
    fcase("freeze_unlisted_claim", "claim 4, which setup never presigned", with_w(unlisted, vec![setup5.clone(), prov_u, freeze_leaf.to_bytes(), bcb_f.clone()]),
        vec![bond_out.clone()], false, false, false, "only enumerated claims can be frozen (Game 3)", json!({"kind": "freeze", "claim": 4}));
    let to_prov = one_in(bond_op, Sequence::MAX, 0, TxOut { value: VALUE - fee, script_pubkey: p2tr_spk(&secp, &provider) });
    let prov_r = script_sig(&secp, &to_prov, &bond_out, &freeze_leaf, &provider);
    fcase("freeze_redirect_to_provider", "provider pays itself through the freeze leaf", with_w(to_prov, vec![setup5.clone(), prov_r, freeze_leaf.to_bytes(), bcb_f.clone()]),
        vec![bond_out.clone()], false, false, false, "the setup signature commits to the freeze output", json!({"kind": "freeze", "claim": null}));
    fcase("freeze_without_setup_signature", "provider alone", with_w(f5_tx.clone(), vec![vec![], prov5.clone(), freeze_leaf.to_bytes(), bcb_f.clone()]),
        vec![bond_out.clone()], false, false, false, "the empty setup signature makes CHECKSIG false", json!({"kind": "freeze", "claim": 5}));
    let lock = Sequence::ENABLE_LOCKTIME_NO_RBF;
    let forfeit_tx = one_in(bond_op, lock, T_FREEZE, TxOut { value: VALUE - fee, script_pubkey: p2tr_spk(&secp, &client) });
    let cs = script_sig(&secp, &forfeit_tx, &bond_out, &forfeit_leaf, &client);
    fcase("no_freeze_forfeit_at_t_freeze", "none", with_w(forfeit_tx.clone(), vec![cs, forfeit_leaf.to_bytes(), bcb_x.clone()]),
        vec![bond_out.clone()], true, true, true, "a provider that never freezes forfeits", json!({"kind": "cltv", "t": T_FREEZE}));
    let early = one_in(bond_op, lock, T_FREEZE - 1, forfeit_tx.output[0].clone());
    let cs_e = script_sig(&secp, &early, &bond_out, &forfeit_leaf, &client);
    fcase("no_freeze_forfeit_early", "client forfeits before T_FREEZE", with_w(early, vec![cs_e, forfeit_leaf.to_bytes(), bcb_x.clone()]),
        vec![bond_out.clone()], false, false, false, "CLTV", json!({"kind": "cltv", "t": T_FREEZE}));
    let ps = script_sig(&secp, &forfeit_tx, &bond_out, &forfeit_leaf, &provider);
    fcase("provider_uses_forfeit_leaf", "provider signs the client's leaf", with_w(forfeit_tx.clone(), vec![ps, forfeit_leaf.to_bytes(), bcb_x.clone()]),
        vec![bond_out.clone()], false, false, false, "the bond has no provider exit except a freeze", json!({"kind": "cltv", "t": T_FREEZE, "wrong_signer": true}));
    // Spends of the frozen output F_5.
    let (rl5, st5) = f_state(5);
    let f5_out = TxOut { value: VALUE - fee, script_pubkey: st5.spk.clone() };
    let f5_op = OutPoint { txid: f5_tx.compute_txid(), vout: 0 };
    let ref_base = one_in(f5_op, Sequence::MAX, 0, TxOut { value: VALUE - fee - fee, script_pubkey: p2tr_spk(&secp, &client) });
    let lh = TapLeafHash::from_script(&rl5, LeafVersion::TapScript);
    let sh = SighashCache::new(&ref_base)
        .taproot_script_spend_signature_hash(0, &Prevouts::One(0, f5_out.clone()), lh, TapSighashType::SinglePlusAnyoneCanPay).unwrap();
    let mut rsig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(sh.to_byte_array()), &setup.kp).serialize().to_vec();
    rsig.push(TapSighashType::SinglePlusAnyoneCanPay as u8);
    let rcb = control(&st5, &rl5);
    let refute = |hs: &[Hdr]| {
        let mut w = header_items(hs);
        w.push(rsig.clone());
        w.push(rl5.to_bytes());
        w.push(rcb.clone());
        with_w(ref_base.clone(), w)
    };
    let six = chain(checkpoint, 6, 0);
    fcase("refute_claim5_with_6", "none", refute(&six), vec![f5_out.clone()], true, true, true,
        "a 6-header fork refutes the frozen claim of 5", json!({"kind": "fork", "n": 6}));
    fcase("refute_claim5_with_5", "a fork equal to the claim", refute(&six[..5]), vec![f5_out.clone()], true, false, false,
        "needs strictly more work than the claim", json!({"kind": "fork", "n": 6}));
    let nine = chain(checkpoint, 9, 0);
    fcase("refute_claim5_with_prefix_of_9", "none (a longer fork truncated to 6)", refute(&nine[..6]), vec![f5_out.clone()], true, true, true,
        "any longer fork's 6-header prefix is itself a valid stronger fork", json!({"kind": "fork", "n": 6}));
    let rcb2 = control(&st5, &refund_leaf);
    let refund_tx = one_in(f5_op, lock, T_DEADLINE, TxOut { value: VALUE - fee - fee, script_pubkey: p2tr_spk(&secp, &provider) });
    let rs = script_sig(&secp, &refund_tx, &f5_out, &refund_leaf, &provider);
    fcase("refund_claim5_at_deadline", "none", with_w(refund_tx.clone(), vec![rs, refund_leaf.to_bytes(), rcb2.clone()]),
        vec![f5_out.clone()], true, true, true, "an unrefuted provider refunds at the deadline", json!({"kind": "cltv", "t": T_DEADLINE}));
    let refund_early = one_in(f5_op, lock, T_DEADLINE - 1, refund_tx.output[0].clone());
    let rse = script_sig(&secp, &refund_early, &f5_out, &refund_leaf, &provider);
    fcase("refund_claim5_early", "provider refunds before the deadline", with_w(refund_early, vec![rse, refund_leaf.to_bytes(), rcb2.clone()]),
        vec![f5_out.clone()], false, false, false, "CLTV keeps the refutation window open", json!({"kind": "cltv", "t": T_DEADLINE}));

    // ── ADR-019: a pinned difficulty schedule across a real mainnet retarget ──
    // These are Bitcoin mainnet blocks 32251..32262, rooted at block 32250's hash. nBits moves from
    // 1d00ffff to 1d00d86a at 32256, the first difficulty change.
    let mhs: Vec<Hdr> = MAINNET_32250_32262.iter().map(|h| Hdr { bytes: unhex(h) }).collect();
    for w in mhs.windows(2) { assert_eq!(&w[1].bytes[4..36], &w[0].hash()[..], "mainnet headers link"); }
    for h in &mhs {
        let hd: Header = deserialize(&h.bytes).unwrap();
        hd.validate_pow(hd.target()).expect("real mainnet header meets its own target");
    }
    let mcp = mhs[0].hash();
    let fork = &mhs[1..];
    let real_sched: Vec<[u8; 4]> = fork.iter().map(|h| [h.bytes[72], h.bytes[73], h.bytes[74], h.bytes[75]]).collect();
    assert_eq!(real_sched[4], [0xff, 0xff, 0x00, 0x1d]);
    assert_eq!(real_sched[5], [0x6a, 0xd8, 0x00, 0x1d]);
    let sched_hex = |s: &[[u8; 4]]| s.iter().map(|b| hex(b)).collect::<Vec<_>>();
    let msched_case = |leaf_sched_bits: &[[u8; 4]], who: &Party, hs: &[Hdr], items: Option<Vec<Vec<u8>>>| {
        let lf = leaf_sched(&setup.x, &mcp, leaf_sched_bits);
        let st = state(&secp, nums(), &[&lf]);
        let prev = TxOut { value: VALUE, script_pubkey: st.spk.clone() };
        let cb = control(&st, &lf);
        let base = Transaction {
            version: Version(2), lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint { txid: Txid::from_byte_array([0x19; 32]), vout: 0 },
                script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }],
            output: vec![TxOut { value: VALUE - Amount::from_sat(2_000), script_pubkey: p2tr_spk(&secp, &client) }],
        };
        let lh = TapLeafHash::from_script(&lf, LeafVersion::TapScript);
        let sh = SighashCache::new(&base)
            .taproot_script_spend_signature_hash(0, &Prevouts::One(0, prev.clone()), lh, TapSighashType::SinglePlusAnyoneCanPay)
            .unwrap();
        let mut sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(sh.to_byte_array()), &setup.kp).serialize().to_vec();
        sig.push(TapSighashType::SinglePlusAnyoneCanPay as u8);
        let mut tx = base.clone();
        tx.output[0].script_pubkey = p2tr_spk(&secp, who);
        let mut w = items.unwrap_or_else(|| sched_items(hs, leaf_sched_bits));
        w.push(sig);
        w.push(lf.to_bytes());
        w.push(cb);
        tx.input[0].witness = Witness::from_slice(&w);
        (tx, prev, lf.len())
    };
    let mut mcase = |name: &str, attack: &'static str, sched: &[[u8; 4]], who: &Party, hs: &[Hdr], items: Option<Vec<Vec<u8>>>, ok: bool, note: &'static str| {
        let (tx, prev, leaf_len) = msched_case(sched, who, hs, items);
        let n = sched.len();
        cases.push(Case { name: format!("M/{name}"), attack, tx, spent: vec![prev], core: true, bip347: ok, design: ok, note,
            extra: json!({"kind": "fork_sched", "checkpoint": hex(&mcp), "schedule": sched_hex(sched), "n": n, "leaf_bytes": leaf_len}) });
    };
    mcase("honest_mainnet_retarget", "none", &real_sched, &client, fork, None, true,
        "12 real mainnet headers across the 32256 retarget, each checked against its pinned nBits");
    let flat = vec![[0xffu8, 0xff, 0x00, 0x1d]; 12];
    mcase("pinned_without_retarget", "a schedule that misses the retarget (completeness limit)", &flat, &client, fork, None, false,
        "the leaf rebuilds header 32256 with nBits 1d00ffff, so its hash no longer matches; a fork off the pinned schedule is refused");
    mcase("truncated_11_of_12", "one header short", &real_sched, &client, &fork[..11],
        Some(sched_items(&fork[..11], &real_sched[..11])), false, "the leaf demands every pinned height");
    let mut weak = fork.to_vec();
    let last = weak.len() - 1;
    weak[last].bytes[76] ^= 0x01; // nonce change: the tip no longer meets its target
    let wh: Header = deserialize(&weak[last].bytes).unwrap();
    assert!(wh.validate_pow(wh.target()).is_err(), "the altered tip fails mainnet PoW");
    mcase("weak_tip", "tip header above its target (truthful limbs)", &real_sched, &client, &weak, None, false,
        "its top bytes are not zero, or the mantissa limb is too large");
    let mut lie = sched_items(fork, &real_sched);
    let top = lie.len() - 1;
    lie[top - 4] = vec![0, 0, 0]; // header 1's m3 limb
    mcase("forged_mantissa_limb", "header 1's mantissa limb replaced by zero", &real_sched, &client, fork, Some(lie), false,
        "lo||m3||z must equal the computed HASH256");
    mcase("redirect_output0", "honest headers, output 0 redirected", &real_sched, &attacker, fork, None, false,
        "the SINGLE|ANYONECANPAY setup signature binds output 0");
    let out = json!({
        "schema": "bsb/cat-verifier-vectors/v1", "adr": "ADR-016",
        "checkpoint_display": hex(&display),
        "interpreters": {
            "core_valid": "Bitcoin Core 26 libbitcoinconsensus, unmodified (OP_CAT is OP_SUCCESS126 in tapscript)",
            "bip347_valid": "Bitcoin Core 26 libbitcoinconsensus + research/bip347-check/bip347.patch (BIP347 semantics, local research patch, not activated consensus)"
        },
        "sizes": report,
        "freeze": {"t_freeze": T_FREEZE, "t_deadline": T_DEADLINE, "claims": claims, "freeze_spks": freeze_spks},
        "warning": "unfunded fabricated outpoints, public test keys; never broadcast",
        "cases": cases.iter().map(row).collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
