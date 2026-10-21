//! Isolated Core vectors for the genuine compact certificate binding. No node access or exported secrets.
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{
    absolute,
    consensus::encode,
    secp256k1::{Secp256k1, XOnlyPublicKey},
    taproot::{LeafVersion, TaprootBuilder},
    transaction, Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};
use bitvm::signatures::{Wots, Wots32, Wots4};
use bsb_bitvm_check::fork_binding::{disprove_compact_fork_binding, ForkBindingKeys};
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
            // prepare <compact-certificate.json> <case> <new-output.json>
            let result = read(&args[2]);
            let kind = args[3].as_str();
            assert_eq!(result["format"], "bsb/compact-cumulative-work-certificate/v1");
            assert_eq!(result["fork_image_id"], "b1766c1d9ebf071acd684ea744d83908181a60d313ccb385661e3fe76ff855b1");
            let statement = unhex(result["statement_preimage"].as_str().unwrap());
            assert_eq!(statement.len(), 214);
            assert_eq!(&statement[..14], b"bsb/r0-fork|v2");
            assert_eq!(hex(&sha256::Hash::hash(&statement).to_byte_array()),result["journal"]);
            let mut graph: [u8;32] = statement[14..46].try_into().unwrap();
            let mut constants: [u8;32] = unhex(result["groth16"]["constants_digest"].as_str().unwrap()).try_into().unwrap();
            let scalar = result["groth16"]["public_input"].as_str().unwrap();
            let public = Fr::from_str(scalar).unwrap();
            assert_eq!(public.to_string(),scalar);
            let digest = blake3::hash(&[constants.as_slice(),sha256::Hash::hash(&statement).as_byte_array()].concat());
            let mut expected = vec![0]; expected.extend_from_slice(&digest.as_bytes()[..31]);
            assert_eq!(public.into_bigint().to_bytes_be(),expected);
            let mut fields = vec![public.into_bigint().to_bytes_be().into_iter().map(|b|b.rotate_left(4)).collect::<Vec<_>>(),
                statement[46..78].to_vec(), statement[78..82].to_vec(), statement[82..114].to_vec(),statement[114..146].to_vec(),
                statement[146..150].to_vec(),statement[150..182].to_vec(),statement[182..214].to_vec()];
            let changed = match kind {
                "honest"|"wrong-key"|"wrong-graph"|"wrong-image"|"noncanonical-public"=>None,
                "wrong-public"=>Some(0),"wrong-term-journal"=>Some(1),"wrong-response-height"=>Some(2),
                "wrong-response-hash"=>Some(3),"wrong-response-work"=>Some(4),"wrong-candidate-height"=>Some(5),
                "wrong-candidate-hash"=>Some(6),"wrong-candidate-work"=>Some(7),_=>panic!("unknown compact binding case")};
            if let Some(i)=changed { let last=fields[i].len()-1;fields[i][last]^=1; }
            if kind=="wrong-graph" { graph[0]^=1; }
            if kind=="wrong-image" { constants[0]^=1; }
            if kind=="noncanonical-public" {
                let modulus=<Fr as PrimeField>::MODULUS.to_bytes_be(); let mut carry=0u16;
                for i in (0..32).rev() { let sum=fields[0][i].rotate_left(4) as u16+modulus[i] as u16+carry;fields[0][i]=(sum as u8).rotate_left(4);carry=sum>>8; }
                assert_eq!(carry,0);
            }
            // Each case generates eight fresh WOTS keys and signs each key exactly once.
            let secrets:Vec<Vec<u8>>=(0..8).map(|i|if i==2||i==5 {Wots4::generate_secret_key()} else {Wots32::generate_secret_key()}).collect();
            let mut keys=ForkBindingKeys {
                public_input:Wots32::generate_public_key(&secrets[0]),term_journal:Wots32::generate_public_key(&secrets[1]),
                response_height:Wots4::generate_public_key(&secrets[2]),response_hash:Wots32::generate_public_key(&secrets[3]),response_work:Wots32::generate_public_key(&secrets[4]),
                candidate_height:Wots4::generate_public_key(&secrets[5]),candidate_hash:Wots32::generate_public_key(&secrets[6]),candidate_work:Wots32::generate_public_key(&secrets[7]) };
            if kind=="wrong-key" { keys.public_input=Wots32::generate_public_key(&Wots32::generate_secret_key()); }
            let leaf=disprove_compact_fork_binding(&graph,&constants,&keys).compile();
            let mut witness=Vec::new();
            for i in (0..8).rev() {
                let signature=if i==2||i==5 {Wots4::sign_to_raw_witness(&secrets[i],fields[i].as_slice().try_into().unwrap())} else {Wots32::sign_to_raw_witness(&secrets[i],fields[i].as_slice().try_into().unwrap())};
                witness.extend(signature.iter().map(hex));
            }
            assert_eq!(witness.len(),844);
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
                "scope": "Isolated compact arithmetic binding to the genuine certificate public input; fresh test keys only. No fork-to-collateral graph or fixed payout enforcement.",
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
        _ => panic!("usage: bsb-fork-binding prepare <results> <kind> <out> | spend <prepared> <txid> <vout> <sats> <regtest-address> <out>"),
    }
}
