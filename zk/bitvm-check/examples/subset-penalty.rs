//! Standalone subset-overdisclosure penalty vectors; no Binohash grinding or fork game.
use bitcoin::{
    absolute::LockTime,
    consensus::encode::{deserialize, serialize_hex},
    hashes::{hash160, Hash},
    secp256k1::{
        rand::{thread_rng, RngCore},
        Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey,
    },
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo},
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitvm::treepp::script;
use bsb_bitvm_check::{
    graph_support::{bytes, hex, read, write},
    subset_equivocation::{prove_subset_overdisclosure, SubsetBanks, SUBSET_BANK_SIZE},
};
use serde_json::{json, Value};
use std::{
    io::{self, BufRead, Write},
    path::PathBuf,
    str::FromStr,
};
fn key() -> Keypair {
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::new(&mut thread_rng()))
}
fn emit(v: Value) {
    println!("BSB_SUBSET {v}");
    io::stdout().flush().unwrap();
}
fn record(tx: &Transaction) -> Value {
    json!({"hex":serialize_hex(tx),"txid":tx.compute_txid().to_string(),"wtxid":tx.compute_wtxid().to_string(),"weight":tx.weight().to_wu()})
}
fn pair_stack(entries: &[(i64, Vec<u8>)]) -> Vec<Vec<u8>> {
    entries
        .iter()
        .rev()
        .flat_map(|(i, p)| {
            assert!((-1..=120).contains(i));
            let encoded = if *i == -1 {
                vec![0x81]
            } else if *i == 0 {
                vec![]
            } else {
                vec![*i as u8]
            };
            [p.clone(), encoded]
        })
        .collect()
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args[1] == "redirect" {
        let v = read(&args[2]);
        let mut tx: Transaction = deserialize(&bytes(v["hex"].as_str().unwrap())).unwrap();
        tx.output[0].script_pubkey = Address::from_str(&args[3])
            .unwrap()
            .require_network(Network::Regtest)
            .unwrap()
            .script_pubkey();
        write(&args[4], record(&tx));
        return;
    }
    assert_eq!(args[1], "setup");
    assert_eq!(args.len(), 3);
    let dir = PathBuf::from(&args[2]);
    std::fs::create_dir(&dir).unwrap();
    let secrets: [[[u8; 32]; SUBSET_BANK_SIZE]; 2] = std::array::from_fn(|_| {
        std::array::from_fn(|_| {
            let mut s = [0; 32];
            thread_rng().fill_bytes(&mut s);
            s
        })
    });
    let banks: SubsetBanks = std::array::from_fn(|r| {
        std::array::from_fn(|i| hash160::Hash::hash(&secrets[r][i]).to_byte_array())
    });
    let committee = key();
    let destination = Address::p2tr(
        &Secp256k1::new(),
        key().x_only_public_key().0,
        None,
        Network::Regtest,
    );
    let nums = XOnlyPublicKey::from_str(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
    )
    .unwrap();
    let mut leaves = Vec::new();
    let mut spends: Vec<TaprootSpendInfo> = Vec::new();
    let mut measurements = Vec::new();
    for round in 0..2 {
        let penalty = prove_subset_overdisclosure(&banks, round);
        let leaf=script!{{committee.x_only_public_key().0.serialize().to_vec()} OP_CHECKSIGVERIFY {penalty}}.compile();
        let ops=leaf.instructions().filter(|i|matches!(i.as_ref().unwrap(),bitcoin::script::Instruction::Op(op) if op.to_u8()>0x60)).count();
        measurements.push(json!({"round":round,"scriptBytes":leaf.len(),"nonPushOpcodes":ops}));
        let spend = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .unwrap()
            .finalize(&Secp256k1::new(), nums)
            .unwrap();
        leaves.push(leaf);
        spends.push(spend);
    }
    emit(
        json!({"ready":true,"network":"regtest","funding":spends.iter().map(|s|Address::p2tr_tweaked(s.output_key(),Network::Regtest).to_string()).collect::<Vec<_>>(),"recipient":destination.to_string()}),
    );
    let input: Value =
        serde_json::from_str(&io::stdin().lock().lines().next().unwrap().unwrap()).unwrap();
    let funding = input["txid"].as_str().unwrap().parse().unwrap();
    for round in 0..2 {
        let prev = TxOut {
            value: Amount::from_sat(100_000_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(spends[round].output_key()),
        };
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(
                    funding,
                    input["vouts"][round].as_u64().unwrap() as u32,
                ),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(99_997_000),
                script_pubkey: destination.script_pubkey(),
            }],
        };
        let digest = SighashCache::new(&tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[prev]),
                TapLeafHash::from_script(&leaves[round], LeafVersion::TapScript),
                TapSighashType::Default,
            )
            .unwrap();
        let signature = Secp256k1::new()
            .sign_schnorr_with_rng(
                &Message::from_digest(digest.to_byte_array()),
                &committee,
                &mut thread_rng(),
            )
            .as_ref()
            .to_vec();
        for name in [
            "valid",
            "same-disclosure",
            "reordered-disclosure",
            "mixed-round",
            "negative-index",
            "out-of-range",
            "wrong-preimage",
        ] {
            let mut entries: Vec<_> = (0..9)
                .map(|i| (i as i64, secrets[round][i].to_vec()))
                .collect();
            match name {
                "valid" => {}
                "same-disclosure" => entries[8] = entries[7].clone(),
                "reordered-disclosure" => {
                    entries[8] = entries[7].clone();
                    entries.swap(0, 1);
                }
                "mixed-round" => entries[8].1 = secrets[1 - round][0].to_vec(),
                "negative-index" => entries[0].0 = -1,
                "out-of-range" => entries[8].0 = 120,
                "wrong-preimage" => entries[8].1[0] ^= 1,
                _ => unreachable!(),
            }
            let mut stack = pair_stack(&entries);
            stack.push(signature.clone());
            stack.push(leaves[round].to_bytes());
            stack.push(
                spends[round]
                    .control_block(&(leaves[round].clone(), LeafVersion::TapScript))
                    .unwrap()
                    .serialize(),
            );
            tx.input[0].witness = Witness::from_slice(&stack);
            write(dir.join(format!("round-{round}-{name}.json")), record(&tx));
        }
    }
    write(
        dir.join("metadata.json"),
        json!({"network":"regtest","bankSize":120,"honestRevealsPerBank":8,"penaltyDistinctReveals":9,"banks":banks.iter().map(|b|b.iter().map(|h|hex(h)).collect::<Vec<_>>()).collect::<Vec<_>>(),"disclosures":{"first":[0,1,2,3,4,5,6,7],"second":[1,2,3,4,5,6,7,8]},"measurements":measurements,"recipient":destination.to_string(),"scope":"A single fixed bank requires nine distinct preimages, exceeding one honest eight-preimage disclosure. Separate Taproot penalty, not Binohash or a complete escrow/fork protocol."}),
    );
    emit(json!({"complete":true}));
}
