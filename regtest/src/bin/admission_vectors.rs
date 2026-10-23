//! ADR-015: can a fixed Taproot leaf admit a stronger-fork certificate and bind the verdict to the payout?
//!
//! Real rust-bitcoin P2TR script-path spends of fabricated outpoints, with public test keys. Every case
//! is checked by `research/consensus-check --bin tapscript-vectors` against Bitcoin Core 26 consensus
//! flags (VERIFY_TAPROOT, spent outputs supplied). Nothing is broadcast, funded or mined.
//!
//! Each case records two verdicts. `core_valid` is what Bitcoin consensus does, and the checker asserts
//! it. `design_ok` is what the design intends. A case with `core_valid && !design_ok` is a consensus-valid
//! counterexample to that design.
//!
//! Leaves:
//! - L1 naive_link: with no OP_CAT, a header is an opaque 80-byte item. The leaf can hash it but cannot
//!   read its prev-hash field, so a separately supplied prev-hash claim never gets bound to the header.
//! - L2 pow_no_cat: HASH256 output is 32 bytes, and Script arithmetic takes at most 4-byte operands, so a
//!   target comparison fails for every input, including the real genesis header.
//! - L3 cat_link: the OP_CAT version of L1. In tapscript today, 0x7e is OP_SUCCESS126, so the leaf is
//!   anyone-can-spend with any witness.
//! - L4 cert_hashlock: a sound check of one certificate fixed at setup, with no signature. The verdict
//!   doesn't bind the outputs, so a copied witness with redirected outputs is valid.
//! - L5 cert_presigned_acp: L4 plus a setup key's SIGHASH_SINGLE|ANYONECANPAY signature, as in BitVM2's
//!   disprove. Output 0 is bound, and anyone may add fee inputs and outputs. The certificate still has
//!   to be fixed at setup.
//! - L6 hidden_success: L5's output with a second, unaudited leaf (OP_SUCCESS80) in the same tree.
#[path = "../common.rs"]
mod common;
use common::*;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::{sha256, sha256d, Hash};
use bitcoin::opcodes::all::*;
use bitcoin::opcodes::Opcode;
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut, Txid, Witness};
use serde_json::{json, Value};

// Bitcoin mainnet genesis and block 1 headers: real chain data, so "linked" has its ordinary meaning.
const GENESIS: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
const BLOCK1: &str = "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299";
const VALUE: Amount = Amount::from_sat(100_000_000);

fn push(b: Builder, data: &[u8]) -> Builder {
    b.push_slice(PushBytesBuf::try_from(data.to_vec()).unwrap())
}
fn hash256(b: &[u8]) -> [u8; 32] {
    sha256d::Hash::hash(b).to_byte_array()
}
fn single_leaf(secp: &Secp256k1<bitcoin::secp256k1::All>, leaf: &ScriptBuf) -> (ScriptBuf, Vec<u8>) {
    let st = state(secp, nums(), &[leaf]);
    (st.spk.clone(), control(&st, leaf))
}
fn spend_tx(outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([0x15; 32]), vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs,
    }
}
fn witness(mut tx: Transaction, items: Vec<Vec<u8>>) -> Transaction {
    tx.input[0].witness = Witness::from_slice(&items);
    tx
}

struct Case {
    name: String,
    leaf: &'static str,
    attack: &'static str,
    tx: Transaction,
    spent: Vec<TxOut>,
    core_valid: bool,
    design_ok: bool,
    note: &'static str,
}
fn row(c: &Case) -> Value {
    json!({
        "name": c.name, "leaf": c.leaf, "attack": c.attack,
        "raw_hex": serialize_hex(&c.tx),
        "spent_outputs": c.spent.iter().map(|o| json!({
            "script_pub_key": hex(o.script_pubkey.as_bytes()), "value": o.value.to_sat() })).collect::<Vec<_>>(),
        "input_index": 0,
        "core_valid": c.core_valid, "design_ok": c.design_ok,
        "counterexample": c.core_valid && !c.design_ok,
        "note": c.note,
    })
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let secp = Secp256k1::new();
    let client = party(&secp, "bsb-adr015-client");
    let attacker = party(&secp, "bsb-adr015-attacker");
    let setup = party(&secp, "bsb-adr015-setup-signer"); // public test key: "erased" only by assumption
    let genesis = unhex(GENESIS);
    let block1 = unhex(BLOCK1);
    let g_hash = hash256(&genesis);
    assert_eq!(&block1[4..36], &g_hash[..], "block 1 commits to the genesis hash");
    assert_eq!(genesis.len(), MAX_STANDARD_ITEM, "a header is exactly the 80-byte standard item limit");
    let pay = |who: &Party| TxOut { value: VALUE - Amount::from_sat(1_000), script_pubkey: p2tr_spk(&secp, who) };
    let mut cases: Vec<Case> = Vec::new();

    // L1: anchored to genesis, then "header 2 extends header 1" as best the leaf can say without OP_CAT.
    // Witness (bottom to top): prev_claim, h2, h1.
    let l1 = Builder::new()
        .push_opcode(OP_SIZE).push_int(80).push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_HASH256).push_opcode(OP_DUP);
    let l1 = push(l1, &g_hash).push_opcode(OP_EQUALVERIFY).push_opcode(OP_TOALTSTACK)
        .push_opcode(OP_SIZE).push_int(80).push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_HASH256).push_opcode(OP_DROP) // h2's hash: nothing to compare its fields with
        .push_opcode(OP_FROMALTSTACK).push_opcode(OP_EQUAL)
        .into_script();
    let (spk1, cb1) = single_leaf(&secp, &l1);
    let prev1 = TxOut { value: VALUE, script_pubkey: spk1.clone() };
    let mut forged = block1.clone();
    forged[4..36].copy_from_slice(&[0x42; 32]); // points at a block that does not exist
    let mut garbage = vec![0x99u8; 80];
    garbage[0] = 0x04;
    for (name, h2, ok) in [
        ("L1/honest_block1", block1.clone(), true),
        ("L1/forged_prev_field", forged.clone(), false),
        ("L1/arbitrary_80_bytes", garbage.clone(), false),
    ] {
        cases.push(Case {
            name: name.into(), leaf: "naive_link",
            attack: if ok { "none" } else { "unlinked header accepted as linked" },
            tx: witness(spend_tx(vec![pay(&client)]), vec![g_hash.to_vec(), h2, genesis.clone(), l1.to_bytes(), cb1.clone()]),
            spent: vec![prev1.clone()], core_valid: true, design_ok: ok,
            note: "Script without OP_CAT/OP_SUBSTR cannot read a header's prev-hash field; the claimed prev hash is bound to h1, never to h2",
        });
    }

    // L2: PoW target comparison on a hash.
    let l2 = Builder::new().push_opcode(OP_HASH256).push_int(0x00ffff).push_opcode(OP_LESSTHAN).into_script();
    let (spk2, cb2) = single_leaf(&secp, &l2);
    let prev2 = TxOut { value: VALUE, script_pubkey: spk2 };
    // Control: the same hash computed and size-checked in a leaf without the comparison is valid, so L2
    // fails at OP_LESSTHAN and not at leaf construction.
    let l2c = Builder::new().push_opcode(OP_HASH256).push_opcode(OP_SIZE).push_int(32)
        .push_opcode(OP_EQUALVERIFY).push_opcode(OP_DROP).push_int(1).into_script();
    let (spk2c, cb2c) = single_leaf(&secp, &l2c);
    cases.push(Case {
        name: "L2/control_hash_only".into(), leaf: "pow_no_cat_control", attack: "none",
        tx: witness(spend_tx(vec![pay(&client)]), vec![genesis.clone(), l2c.to_bytes(), cb2c]),
        spent: vec![TxOut { value: VALUE, script_pubkey: spk2c }], core_valid: true, design_ok: true,
        note: "control: HASH256 of the header and its 32-byte size are fine; only the numeric comparison fails",
    });
    cases.push(Case {
        name: "L2/honest_genesis_pow".into(), leaf: "pow_no_cat", attack: "none",
        tx: witness(spend_tx(vec![pay(&client)]), vec![genesis.clone(), l2.to_bytes(), cb2]),
        spent: vec![prev2], core_valid: false, design_ok: true,
        note: "OP_LESSTHAN on a 32-byte operand is a script-number error: no 256-bit target check is expressible on a hash without splitting it, and splitting needs OP_CAT to re-bind the parts",
    });

    // L3: the OP_CAT design. Intended: <v><prev><rest> CAT CAT HASH256 links h2 to H(h1).
    let l3 = Builder::new()
        .push_opcode(OP_SIZE).push_int(80).push_opcode(OP_EQUALVERIFY).push_opcode(OP_HASH256)
        .push_opcode(OP_SWAP).push_opcode(Opcode::from(0x7e)) // OP_CAT: OP_SUCCESS126 in tapscript today
        .push_opcode(OP_SWAP).push_opcode(Opcode::from(0x7e))
        .push_opcode(OP_HASH256).push_opcode(OP_DROP).push_int(1)
        .into_script();
    let (spk3, cb3) = single_leaf(&secp, &l3);
    let prev3 = TxOut { value: VALUE, script_pubkey: spk3 };
    cases.push(Case {
        name: "L3/honest_cat_link".into(), leaf: "cat_link", attack: "none",
        tx: witness(spend_tx(vec![pay(&client)]),
            vec![block1[36..].to_vec(), block1[..4].to_vec(), genesis.clone(), l3.to_bytes(), cb3.clone()]),
        spent: vec![prev3.clone()], core_valid: true, design_ok: true,
        note: "valid, but only because the leaf contains OP_SUCCESS126",
    });
    cases.push(Case {
        name: "L3/empty_witness_redirect".into(), leaf: "cat_link", attack: "no certificate at all, payout to attacker",
        tx: witness(spend_tx(vec![pay(&attacker)]), vec![l3.to_bytes(), cb3]),
        spent: vec![prev3], core_valid: true, design_ok: false,
        note: "BIP342 OP_SUCCESSx: any leaf containing 0x7e succeeds before execution. A CAT-based verifier deployed today is anyone-can-spend",
    });

    // L4: sound check of a fixed certificate (SHA256 preimage), no signature.
    let cert = b"bsb/adr015 fixed stronger-fork certificate: 151 headers, work 0x...".to_vec();
    let cert_h = sha256::Hash::hash(&cert).to_byte_array();
    let l4 = push(Builder::new().push_opcode(OP_SHA256), &cert_h).push_opcode(OP_EQUAL).into_script();
    let (spk4, cb4) = single_leaf(&secp, &l4);
    let prev4 = TxOut { value: VALUE, script_pubkey: spk4 };
    for (name, who, ok, attack) in [
        ("L4/challenger_claims", &client, true, "none"),
        ("L4/witness_copied_redirect", &attacker, false, "mempool copy of the certificate, payout redirected"),
    ] {
        cases.push(Case {
            name: name.into(), leaf: "cert_hashlock", attack,
            tx: witness(spend_tx(vec![pay(who)]), vec![cert.clone(), l4.to_bytes(), cb4.clone()]),
            spent: vec![prev4.clone()], core_valid: true, design_ok: ok,
            note: "the verdict is sound but binds no output: whoever sees the certificate first can take the bond",
        });
    }
    let mut bad_cert = cert.clone();
    bad_cert[0] ^= 1;
    cases.push(Case {
        name: "L4/invalid_certificate".into(), leaf: "cert_hashlock", attack: "invalid certificate",
        tx: witness(spend_tx(vec![pay(&attacker)]), vec![bad_cert, l4.to_bytes(), cb4]),
        spent: vec![prev4], core_valid: false, design_ok: false, note: "control",
    });

    // L5: L4 plus a setup-presigned SINGLE|ANYONECANPAY signature over output 0 (BitVM2 disprove shape).
    let l5 = push(Builder::new(), &setup.x.serialize()).push_opcode(OP_CHECKSIGVERIFY).push_opcode(OP_SHA256);
    let l5 = push(l5, &cert_h).push_opcode(OP_EQUAL).into_script();
    let hidden = Builder::new().push_opcode(Opcode::from(0x50)).into_script(); // OP_SUCCESS80
    let st5 = state(&secp, nums(), &[&l5]);
    let st6 = state(&secp, nums(), &[&l5, &hidden]);
    for (st, with_hidden) in [(&st5, false), (&st6, true)] {
        let prev = TxOut { value: VALUE, script_pubkey: st.spk.clone() };
        let cb = control(st, &l5);
        let base = spend_tx(vec![pay(&client)]);
        let lh = TapLeafHash::from_script(&l5, LeafVersion::TapScript);
        let sh = SighashCache::new(&base)
            .taproot_script_spend_signature_hash(0, &Prevouts::One(0, prev.clone()), lh, TapSighashType::SinglePlusAnyoneCanPay)
            .unwrap();
        let mut sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(sh.to_byte_array()), &setup.kp).serialize().to_vec();
        sig.push(TapSighashType::SinglePlusAnyoneCanPay as u8);
        let w = |tx: Transaction| witness(tx, vec![cert.clone(), sig.clone(), l5.to_bytes(), cb.clone()]);
        if !with_hidden {
            cases.push(Case {
                name: "L5/presigned_payout".into(), leaf: "cert_presigned_acp", attack: "none",
                tx: w(base.clone()), spent: vec![prev.clone()], core_valid: true, design_ok: true,
                note: "output 0 fixed by the setup signature; this certificate was enumerated at setup",
            });
            cases.push(Case {
                name: "L5/redirect_output0".into(), leaf: "cert_presigned_acp", attack: "witness copied, output 0 redirected",
                tx: w(spend_tx(vec![pay(&attacker)])), spent: vec![prev.clone()], core_valid: false, design_ok: false,
                note: "the presigned SINGLE signature binds the verdict to output 0",
            });
            // A challenger adds its own fee input and change output: allowed by ANYONECANPAY|SINGLE.
            let fee_in = TxOut { value: Amount::from_sat(50_000), script_pubkey: p2tr_spk(&secp, &attacker) };
            let mut sponsored = base.clone();
            sponsored.input.push(TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([0x16; 32]), vout: 1 },
                script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new(),
            });
            sponsored.output.push(TxOut { value: Amount::from_sat(40_000), script_pubkey: p2tr_spk(&secp, &attacker) });
            cases.push(Case {
                name: "L5/sponsor_adds_fee_input".into(), leaf: "cert_presigned_acp", attack: "none (fee sponsorship)",
                tx: w(sponsored), spent: vec![prev.clone(), fee_in], core_valid: true, design_ok: true,
                note: "input 0 checked only; the sponsor input is unsigned here and would need its own witness",
            });
            let mut other = cert.clone();
            other.extend_from_slice(b" (a different, stronger certificate found after setup)");
            cases.push(Case {
                name: "L5/new_certificate_after_setup".into(), leaf: "cert_presigned_acp",
                attack: "a genuinely stronger certificate unknown at setup",
                tx: witness(base.clone(), vec![other, sig.clone(), l5.to_bytes(), cb.clone()]),
                spent: vec![prev.clone()], core_valid: false, design_ok: true,
                note: "permissionless admission fails: the leaf can only recognise what setup enumerated",
            });
        } else {
            let hcb = control(st, &hidden);
            cases.push(Case {
                name: "L6/hidden_leaf_drains".into(), leaf: "hidden_success",
                attack: "unenumerated Taproot leaf beside the audited one",
                tx: witness(spend_tx(vec![pay(&attacker)]), vec![hidden.to_bytes(), hcb]),
                spent: vec![prev.clone()], core_valid: true, design_ok: false,
                note: "auditing L5 alone proves nothing about the output: every leaf in the tree is a spend path",
            });
            cases.push(Case {
                name: "L6/audited_leaf_still_bound".into(), leaf: "cert_presigned_acp", attack: "witness copied, output 0 redirected",
                tx: witness(spend_tx(vec![pay(&attacker)]), vec![cert.clone(), sig.clone(), l5.to_bytes(), cb.clone()]),
                spent: vec![prev.clone()], core_valid: false, design_ok: false, note: "control",
            });
        }
    }
    let _ = TaprootBuilder::new(); // keep the import explicit for readers comparing with common::state

    let out = json!({
        "schema": "bsb/tapscript-admission-vectors/v1",
        "adr": "ADR-015",
        "flags": "Bitcoin Core 26 consensus, VERIFY_ALL_PRE_TAPROOT | VERIFY_TAPROOT (spent outputs supplied)",
        "warning": "unfunded fabricated outpoints, public test keys; never broadcast",
        "cases": cases.iter().map(row).collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
