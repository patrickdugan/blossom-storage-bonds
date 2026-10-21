//! Deliberately incomplete input-binding designs, for isolated Core experiments only.
//! The inequality uses small script integers, not authenticated chain-work proofs.
use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::*;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{
    rand::thread_rng, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey,
};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::str::FromStr;

struct Leaf {
    script: ScriptBuf,
    spend: TaprootSpendInfo,
}
impl Leaf {
    fn new(script: ScriptBuf) -> Self {
        let nums = XOnlyPublicKey::from_str(
            "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
        )
        .unwrap();
        let spend = TaprootBuilder::new()
            .add_leaf(0, script.clone())
            .unwrap()
            .finalize(&Secp256k1::new(), nums)
            .unwrap();
        Self { script, spend }
    }
    fn output(&self, sats: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(self.spend.output_key()),
        }
    }
    fn sign(&self, tx: &mut Transaction, previous: &TxOut, key: &Keypair, mut data: Vec<Vec<u8>>) {
        let hash = SighashCache::new(&*tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[previous]),
                TapLeafHash::from_script(&self.script, LeafVersion::TapScript),
                TapSighashType::Default,
            )
            .unwrap();
        let sig = Secp256k1::new().sign_schnorr_with_rng(
            &Message::from_digest(hash.to_byte_array()),
            key,
            &mut thread_rng(),
        );
        data.push(sig.as_ref().to_vec());
        data.push(self.script.to_bytes());
        data.push(
            self.spend
                .control_block(&(self.script.clone(), LeafVersion::TapScript))
                .unwrap()
                .serialize(),
        );
        tx.input[0].witness = Witness::from_slice(&data);
    }
}
fn transaction(previous: OutPoint, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: previous,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs,
    }
}
fn record(tx: &Transaction) -> Value {
    json!({ "hex": serialize_hex(tx), "txid": tx.compute_txid().to_string(), "wtxid": tx.compute_wtxid().to_string(),
        "witness": tx.input[0].witness.iter().map(|v| v.iter().map(|b| format!("{b:02x}")).collect::<String>()).collect::<Vec<_>>() })
}
fn data_script(key: XOnlyPublicKey, bound: bool, compare: bool) -> ScriptBuf {
    let mut b = Builder::new()
        .push_x_only_key(&key)
        .push_opcode(OP_CHECKSIGVERIFY);
    b = if bound {
        b.push_slice([1u8; 32]).push_opcode(OP_EQUALVERIFY)
    } else {
        b.push_opcode(OP_SIZE)
            .push_int(32)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_DROP)
    };
    if bound && compare {
        b = b
            .push_opcode(OP_DUP)
            .push_int(468)
            .push_opcode(OP_EQUALVERIFY);
    }
    if compare {
        b.push_int(466).push_opcode(OP_GREATERTHAN).into_script()
    } else if bound {
        b.push_int(468).push_opcode(OP_EQUAL).into_script()
    } else {
        b.push_opcode(OP_DROP).push_int(1).into_script()
    }
}
fn main() {
    let secp = Secp256k1::new();
    let key = Keypair::from_secret_key(&secp, &SecretKey::new(&mut thread_rng()));
    let x = key.x_only_public_key().0;
    let root = Leaf::new(data_script(x, false, false));
    let mut output_script = data_script(x, false, false).into_bytes();
    output_script.push(OP_NOP.to_u8());
    let output_root = Leaf::new(ScriptBuf::from_bytes(output_script));
    let fixed = Leaf::new(data_script(x, true, false));
    let response = Leaf::new(data_script(x, false, true));
    let fixed_response = Leaf::new(data_script(x, true, true));
    let payout = Address::p2tr(&secp, x, None, Network::Regtest).script_pubkey();
    let address =
        |leaf: &Leaf| Address::p2tr_tweaked(leaf.spend.output_key(), Network::Regtest).to_string();
    println!(
        "BSB_BINDING {}",
        json!({ "ready": true, "network": "regtest", "funding": [address(&root),address(&fixed),address(&output_root)], "sats_each": 100_000_000 })
    );
    io::stdout().flush().unwrap();
    let line = io::stdin().lock().lines().next().unwrap().unwrap();
    let input: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(input["network"], "regtest");
    let txid = input["txid"].as_str().unwrap().parse().unwrap();
    let vouts: Vec<u32> = input["vouts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap().try_into().unwrap())
        .collect();
    assert_eq!(vouts.len(), 3);
    let zero_data = vec![vec![0u8], vec![0u8; 32]];
    let dummy = || {
        vec![TxOut {
            value: Amount::from_sat(99_994_000),
            script_pubkey: payout.clone(),
        }]
    };
    let mut exported = serde_json::Map::new();
    for (name, index, from, to) in [
        ("unbound", 0, &root, &response),
        ("fixed", 1, &fixed, &fixed_response),
    ] {
        let mut parent = transaction(
            OutPoint::new(txid, vouts[index]),
            vec![to.output(99_997_000)],
        );
        from.sign(
            &mut parent,
            &from.output(100_000_000),
            &key,
            zero_data.clone(),
        );
        let mut child = transaction(
            OutPoint::new(parent.compute_txid(), 0),
            vec![TxOut {
                value: Amount::from_sat(99_994_000),
                script_pubkey: payout.clone(),
            }],
        );
        to.sign(&mut child, &parent.output[0], &key, zero_data.clone());
        exported.insert(format!("{name}_parent"), record(&parent));
        exported.insert(format!("{name}_child"), record(&child));
    }
    // The output-commitment trial uses its own funding output so it can be mined independently.
    let body = |data: [u8; 32]| {
        vec![
            response.output(99_997_000),
            TxOut {
                value: Amount::ZERO,
                script_pubkey: Builder::new()
                    .push_opcode(OP_RETURN)
                    .push_slice(data)
                    .into_script(),
            },
        ]
    };
    let mut parent = transaction(OutPoint::new(txid, vouts[2]), body([0u8; 32]));
    output_root.sign(
        &mut parent,
        &output_root.output(100_000_000),
        &key,
        zero_data.clone(),
    );
    let mut child = transaction(OutPoint::new(parent.compute_txid(), 0), dummy());
    response.sign(&mut child, &parent.output[0], &key, zero_data.clone());
    let mut alternative = transaction(OutPoint::new(txid, vouts[2]), body([42u8; 32]));
    output_root.sign(
        &mut alternative,
        &output_root.output(100_000_000),
        &key,
        zero_data,
    );
    exported.insert("output_parent".into(), record(&parent));
    exported.insert("output_parent_alternative".into(), record(&alternative));
    exported.insert("output_child".into(), record(&child));
    println!(
        "BSB_BINDING {}",
        json!({ "complete":true,"transactions":exported,"scope":"Input-binding counterexamples with scalar inequality only. No header validation, proof verification, chain-work certificate or funded production graph." })
    );
}
