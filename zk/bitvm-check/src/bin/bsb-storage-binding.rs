//! Local regtest vectors for the storage binding leaf. No node access; no secret keys are exported.
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use bitcoin::{
    absolute,
    consensus::encode,
    secp256k1::{Secp256k1, XOnlyPublicKey},
    taproot::{LeafVersion, TaprootBuilder},
    transaction, Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};
use bitvm::signatures::{Wots, Wots32, Wots4};
use bsb_bitvm_check::storage_binding::{disprove_term_binding, BindingKeys};
use serde_json::{json, Value};
use std::{path::Path, str::FromStr};

fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn read(path: &str) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
fn write(path: &str, value: Value) {
    if Path::new(path).exists() {
        panic!("refusing to overwrite {path}");
    }
    std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("prepare") => {
            // prepare <phase6-results.json> <honest|wrong-public|wrong-tip|wrong-work|wrong-term> <out.json>
            let result = read(&args[2]);
            let kind = &args[3];
            assert!(["honest", "wrong-public", "wrong-tip", "wrong-work", "wrong-term"].contains(&kind.as_str()));
            let preimage = unhex(result["m2"]["term"]["preimage"].as_str().unwrap());
            assert_eq!(preimage.len(), 202);
            let mut prefix: [u8; 134] = preimage[..134].try_into().unwrap();
            let constants: [u8; 32] = unhex(result["m3"]["groth16"]["constants_digest"].as_str().unwrap()).try_into().unwrap();
            let tip: [u8; 4] = preimage[134..138].try_into().unwrap();
            let mut hash: [u8; 32] = preimage[138..170].try_into().unwrap();
            let mut work: [u8; 32] = preimage[170..202].try_into().unwrap();
            let mut public: [u8; 32] = Fr::from_str(result["m3"]["groth16"]["public_output_dec"].as_str().unwrap()).unwrap().into_bigint().to_bytes_be().into_iter().map(|b| b.rotate_left(4)).collect::<Vec<_>>().try_into().unwrap();
            match kind.as_str() { "wrong-public" => public[0] ^= 1, "wrong-tip" => hash[0] ^= 1,
                "wrong-work" => work[31] ^= 1, "wrong-term" => prefix[81] ^= 1, _ => {} }
            // Fresh one-time keys per case; signatures from different cases never share a key.
            let public_secret = Wots32::generate_secret_key();
            let tip_secret = Wots4::generate_secret_key();
            let hash_secret = Wots32::generate_secret_key();
            let work_secret = Wots32::generate_secret_key();
            let keys = BindingKeys {
                public_input: Wots32::generate_public_key(&public_secret),
                tip_height: Wots4::generate_public_key(&tip_secret),
                tip_hash: Wots32::generate_public_key(&hash_secret),
                total_work: Wots32::generate_public_key(&work_secret),
            };
            let leaf = disprove_term_binding(&prefix, &constants, &keys).compile();
            let mut witness = Vec::new();
            for signature in [
                Wots32::sign_to_raw_witness(&work_secret, &work),
                Wots32::sign_to_raw_witness(&hash_secret, &hash),
                Wots4::sign_to_raw_witness(&tip_secret, &tip),
                Wots32::sign_to_raw_witness(&public_secret, &public),
            ] { witness.extend(signature.iter().map(hex)); }
            let secp = Secp256k1::new();
            // Standard NUMS internal key: no known key-path spender.
            let nums = XOnlyPublicKey::from_str("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0").unwrap();
            let spend = TaprootBuilder::new().add_leaf(0, leaf.clone()).unwrap().finalize(&secp, nums).unwrap();
            let control = spend.control_block(&(leaf.clone(), LeafVersion::TapScript)).unwrap();
            let address = Address::p2tr_tweaked(spend.output_key(), Network::Regtest);
            let bytes = leaf.len();
            write(&args[4], json!({
                "network": "regtest", "kind": kind, "address": address.to_string(),
                "script_pubkey": hex(address.script_pubkey().as_bytes()), "script": hex(leaf.as_bytes()),
                "control": hex(&control.serialize()), "witness": witness,
                "scope": "isolated storage binding leaf, not a complete storage graph; fresh test keys only",
            }));
            println!("{}",json!({"kind": kind,"address": address.to_string(),"script_bytes": bytes}));
        }
        Some("spend") => {
            // spend <prepared.json> <txid> <vout> <input-sats> <regtest-destination> <out.json>
            let prepared = read(&args[2]);
            assert_eq!(prepared["network"], "regtest");
            let address = Address::from_str(&args[6]).unwrap().require_network(Network::Regtest).unwrap();
            let amount: u64 = args[5].parse().unwrap();
            let mut witness: Vec<Vec<u8>> = prepared["witness"].as_array().unwrap().iter().map(|v| unhex(v.as_str().unwrap())).collect();
            let script = unhex(prepared["script"].as_str().unwrap());
            let script_bytes = script.len();
            witness.push(script); witness.push(unhex(prepared["control"].as_str().unwrap()));
            let mut tx = Transaction {
                version: transaction::Version::TWO, lock_time: absolute::LockTime::ZERO,
                input: vec![TxIn { previous_output: OutPoint::new(args[3].parse().unwrap(),args[4].parse().unwrap()), script_sig: ScriptBuf::new(), sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, witness: Witness::from_slice(&witness) }],
                output: vec![TxOut { value: Amount::from_sat(amount), script_pubkey: address.script_pubkey() }],
            };
            let fee = tx.vsize() as u64 * 2;
            assert!(amount > fee + 10_000,"test funding cannot cover fee");
            tx.output[0].value = Amount::from_sat(amount - fee);
            let report = json!({ "kind": prepared["kind"], "network": "regtest", "hex": encode::serialize_hex(&tx), "txid": tx.compute_txid().to_string(), "vsize": tx.vsize(), "weight": tx.weight().to_wu(), "fee_sats": fee, "script_bytes": script_bytes });
            write(&args[7], report);
            println!("{}",json!({"kind":prepared["kind"],"vsize":tx.vsize(),"fee_sats":fee}));
        }
        _ => panic!("usage: bsb-storage-binding prepare <results> <kind> <out> | spend <prepared> <txid> <vout> <sats> <regtest-address> <out>"),
    }
}
