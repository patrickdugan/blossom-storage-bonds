//! Signature-boundary experiment only: no Binohash, ZK proof or chain-work verification.
use bitcoin::{
    absolute::LockTime,
    consensus::encode::{deserialize, serialize_hex},
    hashes::Hash,
    opcodes::all::*,
    script::Builder,
    secp256k1::{rand::thread_rng, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo},
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bsb_bitvm_check::graph_support::{bytes, read, write};
use serde_json::{json, Value};
use std::{
    io::{self, BufRead, Write},
    path::PathBuf,
    str::FromStr,
};
struct Leaf {
    script: ScriptBuf,
    spend: TaprootSpendInfo,
}
impl Leaf {
    fn new(x: XOnlyPublicKey) -> Self {
        let script = Builder::new()
            .push_x_only_key(&x)
            .push_opcode(OP_CHECKSIG)
            .into_script();
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
    fn output(&self, value: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(self.spend.output_key()),
        }
    }
    fn address(&self) -> String {
        Address::p2tr_tweaked(self.spend.output_key(), Network::Regtest).to_string()
    }
    fn sign(&self, tx: &mut Transaction, previous: &TxOut, key: &Keypair, kind: TapSighashType) {
        let hash = SighashCache::new(&*tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[previous.clone()]),
                TapLeafHash::from_script(&self.script, LeafVersion::TapScript),
                kind,
            )
            .unwrap();
        let mut signature = Secp256k1::new()
            .sign_schnorr_with_rng(
                &Message::from_digest(hash.to_byte_array()),
                key,
                &mut thread_rng(),
            )
            .as_ref()
            .to_vec();
        if kind != TapSighashType::Default {
            signature.push(kind as u8);
        }
        tx.input[0].witness = Witness::from_slice(&[
            signature,
            self.script.to_bytes(),
            self.spend
                .control_block(&(self.script.clone(), LeafVersion::TapScript))
                .unwrap()
                .serialize(),
        ]);
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
    json!({"hex":serialize_hex(tx),"txid":tx.compute_txid().to_string(),"wtxid":tx.compute_wtxid().to_string(),"weight":tx.weight().to_wu()})
}
fn emit(v: Value) {
    println!("BSB_LATE_PARENT {v}");
    io::stdout().flush().unwrap();
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args[1] == "mutate" || args[1] == "rewire" || args[1] == "redirect" {
        // Public-only tools: never generate a key or call a signing function.
        let v = read(&args[2]);
        let mut tx: Transaction = deserialize(&bytes(v["hex"].as_str().unwrap())).unwrap();
        let old_witness = tx.input[0].witness.clone();
        if args[1] == "mutate" {
            let tag: [u8; 32] = bytes(&args[3]).try_into().unwrap();
            tx.output[1].script_pubkey = Builder::new()
                .push_opcode(OP_RETURN)
                .push_slice(tag)
                .into_script();
        } else if args[1] == "rewire" {
            tx.input[0].previous_output.txid = args[3].parse().unwrap();
        } else {
            tx.output[0].script_pubkey = Address::from_str(&args[3])
                .unwrap()
                .require_network(Network::Regtest)
                .unwrap()
                .script_pubkey();
        }
        assert_eq!(tx.input[0].witness, old_witness);
        write(&args[4], record(&tx));
        return;
    }
    assert_eq!(args[1], "setup");
    assert_eq!(args.len(), 3);
    let dir = PathBuf::from(&args[2]);
    std::fs::create_dir(&dir).unwrap();
    let keys: [Keypair; 2] = std::array::from_fn(|_| {
        Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::new(&mut thread_rng()))
    });
    let leaves: Vec<_> = keys
        .iter()
        .map(|k| Leaf::new(k.x_only_public_key().0))
        .collect();
    let recipient = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::new(&mut thread_rng()));
    let destination = Address::p2tr(
        &Secp256k1::new(),
        recipient.x_only_public_key().0,
        None,
        Network::Regtest,
    );
    emit(
        json!({"ready":true,"network":"regtest","funding":leaves.iter().map(Leaf::address).collect::<Vec<_>>(),"recipient":destination.to_string()}),
    );
    let input: Value =
        serde_json::from_str(&io::stdin().lock().lines().next().unwrap().unwrap()).unwrap();
    let funding = input["txid"].as_str().unwrap().parse().unwrap();
    let modes = [
        ("default", TapSighashType::Default),
        ("all", TapSighashType::All),
        ("none", TapSighashType::None),
        ("single", TapSighashType::Single),
        ("all-acp", TapSighashType::AllPlusAnyoneCanPay),
        ("none-acp", TapSighashType::NonePlusAnyoneCanPay),
        ("single-acp", TapSighashType::SinglePlusAnyoneCanPay),
    ];
    for i in 0..2 {
        let mut parent = transaction(
            OutPoint::new(funding, input["vouts"][i].as_u64().unwrap() as u32),
            vec![
                leaves[i].output(99_997_000),
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: Builder::new()
                        .push_opcode(OP_RETURN)
                        .push_slice([0u8; 32])
                        .into_script(),
                },
            ],
        );
        leaves[i].sign(
            &mut parent,
            &leaves[i].output(100_000_000),
            &keys[i],
            TapSighashType::SinglePlusAnyoneCanPay,
        );
        write(dir.join(format!("parent-{i}.json")), record(&parent));
        for (name, kind) in modes {
            let mut child = transaction(
                OutPoint::new(parent.compute_txid(), 0),
                vec![TxOut {
                    value: Amount::from_sat(99_994_000),
                    script_pubkey: destination.script_pubkey(),
                }],
            );
            leaves[i].sign(&mut child, &parent.output[0], &keys[i], kind);
            write(dir.join(format!("child-{i}-{name}.json")), record(&child));
        }
    }
    write(
        dir.join("metadata.json"),
        json!({"network":"regtest","modes":modes.iter().map(|(n,_)|n).collect::<Vec<_>>(),"recipient":destination.to_string(),"scope":"Late output data is accepted by the parent SINGLE|ANYONECANPAY signature; changing the resulting parent outpoint must still invalidate every pre-existing child signature. No computation verifier or complete covenant."}),
    );
    emit(json!({"complete":true}));
}
