//! Fixed-proof regtest graph setup. Committee and provider keys exit before funding.
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use bitcoin::{
    consensus::encode::serialize_hex,
    hashes::{sha256, Hash},
    Address, Network, OutPoint, ScriptBuf, Witness,
};
use bitvm::chunk::api::{
    type_conversion_utils::script_to_witness, validate_assertions, Assertions, NUM_HASH, NUM_TAPS,
};
use bsb_bitvm_check::{
    graph_support::{bytes, emit, hex, read, vk, write, Commitments, Scripts},
    storage_binding::disprove_term_binding,
    storage_graph::{
        Committee, GraphConfig, GraphTx, Party, ProofTree, State, StorageGraph, BINDING_LEAF,
    },
};
use serde_json::{json, Value};
use std::{
    io::{self, BufRead},
    path::PathBuf,
};

fn run() {
    let args = std::env::args().collect::<Vec<_>>();
    assert_eq!(
        args.len(),
        7,
        "<fixture> <proof-dir> <partials> <assertions> <scenario> <new-out-dir>"
    );
    let fixture = read(&args[1]);
    let proof_dir = PathBuf::from(&args[2]);
    let cache = PathBuf::from(&args[3]);
    let checked = read(&args[4]);
    let scenario = &args[5];
    let out = PathBuf::from(&args[6]);
    assert!([
        "honest",
        "wrong-term",
        "corrupt-proof",
        "silence",
        "no-challenge",
        "no-kickoff",
        "burn-marker"
    ]
    .contains(&scenario.as_str()));
    assert_eq!(checked["scripts_checked"], true);
    assert_eq!(checked["bitvm_rev"], "7d1ca36");
    let (key, _proof, public) = vk(&proof_dir);
    assert_eq!(checked["public_input"], public.to_string());
    let publics: Vec<[u8; 32]> = serde_json::from_value(checked["public"].clone()).unwrap();
    let fields: Vec<[u8; 32]> = serde_json::from_value(checked["fields"].clone()).unwrap();
    let hashes: Vec<[u8; 16]> = serde_json::from_value(checked["hashes"].clone()).unwrap();
    let mut assertions: Assertions = (
        publics.try_into().unwrap(),
        fields.try_into().unwrap(),
        hashes.try_into().unwrap(),
    );
    let encoded = public
        .into_bigint()
        .to_bytes_be()
        .into_iter()
        .map(|b| b.rotate_left(4))
        .collect::<Vec<_>>();
    assert_eq!(assertions.0[0].as_slice(), encoded);
    if scenario == "corrupt-proof" {
        assertions.2[NUM_HASH / 2][0] ^= 1;
    }
    let preimage = bytes(fixture["m2"]["term"]["preimage"].as_str().unwrap());
    assert_eq!(preimage.len(), 202);
    assert_eq!(&preimage[..14], b"bsb/r0-term|v1");
    let journal = sha256::Hash::hash(&preimage).to_byte_array();
    assert_eq!(hex(&journal), fixture["m3"]["groth16"]["journal"]);
    let wrapper = &fixture["m3"]["groth16"];
    let mut constant_bytes = bytes(wrapper["control_root"].as_str().unwrap())
        .into_iter()
        .map(|b| b.reverse_bits())
        .collect::<Vec<_>>();
    for field in ["pre_state", "post_state", "bn254_control_id"] {
        constant_bytes.extend(bytes(wrapper[field].as_str().unwrap()));
    }
    let digest = sha256::Hash::hash(&constant_bytes).to_byte_array();
    assert_eq!(hex(&digest), wrapper["constants_digest"]);
    let input = blake3::hash(&[digest.as_slice(), journal.as_slice()].concat());
    assert_eq!(
        Fr::from_be_bytes_mod_order(&input.as_bytes()[..31]),
        public,
        "proof public input must match fixture term"
    );
    let mut prefix: [u8; 134] = preimage[..134].try_into().unwrap();
    if scenario == "wrong-term" || scenario == "burn-marker" {
        prefix[81] ^= 1;
    }
    let constants: [u8; 32] = bytes(
        fixture["m3"]["groth16"]["constants_digest"]
            .as_str()
            .unwrap(),
    )
    .try_into()
    .unwrap();
    let committee = Committee::fresh();
    let client = Party::fresh();
    let provider = Party::fresh();
    let commitments = Commitments::fresh();
    let binding = disprove_term_binding(&prefix, &constants, &commitments.binding_keys()).compile();
    let mut config = GraphConfig {
        term_end: 220,
        kickoff_deadline: 240,
        final_deadline: 290,
        challenge_blocks: 6,
        assert_blocks: 12,
        dispute_blocks: 6,
        slot_value: 20_000,
        marker_value: 1_000_000,
    };
    let scripts = Scripts::new(cache, &proof_dir, commitments.pks);
    let tree = ProofTree::new(
        scripts.hashes(),
        &binding,
        provider.x,
        config.dispute_blocks,
    );
    emit(
        json!({"ready":true,"network":"regtest","funding_address":Address::from_script(&State::committee(committee.x).output,Network::Regtest).unwrap().to_string(),"client_address":Address::from_script(&client.output(0).script_pubkey,Network::Regtest).unwrap().to_string(),"provider_address":Address::from_script(&provider.output(0).script_pubkey,Network::Regtest).unwrap().to_string()}),
    );
    let line = io::stdin().lock().lines().next().unwrap().unwrap();
    let funding: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(funding["network"], "regtest");
    let point = OutPoint::new(
        funding["txid"].as_str().unwrap().parse().unwrap(),
        funding["vout"].as_u64().unwrap() as u32,
    );
    let amount = funding["sats"].as_u64().unwrap();
    config.term_end = 220u32.max(u32::try_from(funding["height"].as_u64().unwrap()).unwrap() + 4);
    config.kickoff_deadline = config.term_end + 20;
    config.final_deadline = config.term_end + 70;
    let word = |at: usize| u32::from_be_bytes(prefix[at..at + 4].try_into().unwrap()) as u64;
    assert!(word(78) > 0 && word(82) > 0 && word(122) > 0 && word(126) > 0 && word(130) > 0);
    assert!(
        word(118) + (word(126) - 1) * word(122) + word(130) <= config.term_end as u64,
        "term deadline precedes final confirmed seed"
    );
    let mut graph = StorageGraph::build(
        config,
        point,
        amount,
        &committee,
        &provider,
        &client,
        &commitments.keys(),
        tree,
    );
    let (signatures, witnesses, binding_witness) = commitments.sign(assertions, &preimage);
    graph.attach_assertions(&witnesses);
    let chosen = if scenario == "corrupt-proof" {
        let full: [ScriptBuf; NUM_TAPS] = (0..NUM_TAPS)
            .map(|i| scripts.full(i))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let (index, hint) = validate_assertions(&key, signatures, commitments.pks, &full)
            .expect("corrupt proof has a disprove");
        let raw = script_to_witness(hint);
        let script = full[index].clone();
        drop(full);
        graph.attach_disprove(index, &script, raw);
        index
    } else {
        graph.attach_disprove(BINDING_LEAF, &binding, binding_witness);
        BINDING_LEAF
    };
    let slash = &graph.transactions["slash"];
    let mut burn = slash.tx.clone();
    burn.input.remove(0);
    burn.output = vec![provider.output(slash.prevouts[1].value.to_sat() - 900_000)];
    let burn = GraphTx {
        tx: burn,
        prevouts: vec![slash.prevouts[1].clone()],
    };
    graph.transactions.insert("marker-burn".to_owned(), burn);
    std::fs::create_dir(&out).expect("output directory must be new");
    let mut txs = serde_json::Map::new();
    for (name, t) in &graph.transactions {
        let fee = t.prevouts.iter().map(|o| o.value.to_sat()).sum::<u64>()
            - t.tx.output.iter().map(|o| o.value.to_sat()).sum::<u64>();
        let path = out.join(format!("{name}.json"));
        write(
            &path,
            json!({"hex":serialize_hex(&t.tx),"txid":t.tx.compute_txid().to_string(),"vsize":t.tx.vsize(),"weight":t.tx.weight().to_wu(),"fee_sats":fee,"outputs":t.tx.output.iter().map(|o|json!({"sats":o.value.to_sat(),"script":hex(o.script_pubkey.as_bytes())})).collect::<Vec<_>>()}),
        );
        txs.insert(
            name.clone(),
            json!({"file":path,"txid":t.tx.compute_txid().to_string()}),
        );
    }
    let mut redirect = graph.transactions["slash"].tx.clone();
    redirect.output[0].script_pubkey = provider.output(0).script_pubkey;
    write(
        out.join("redirected-slash.json"),
        json!({"hex":serialize_hex(&redirect)}),
    );
    let mut skipped = graph.transactions["assert-commit-0"].tx.clone();
    let items = skipped.input[0]
        .witness
        .iter()
        .map(|x| x.to_vec())
        .collect::<Vec<_>>();
    skipped.input[0].witness = Witness::from_slice(&items[items.len() - 3..]);
    write(
        out.join("skipped-commitment.json"),
        json!({"hex":serialize_hex(&skipped)}),
    );
    write(
        out.join("slot-timeouts.json"),
        json!(graph
            .slot_timeouts
            .iter()
            .map(|t| serialize_hex(&t.tx))
            .collect::<Vec<_>>()),
    );
    let result = json!({"network":"regtest","scenario":scenario,"term_end":config.term_end,"kickoff_deadline":config.kickoff_deadline,"final_deadline":config.final_deadline,"challenge_blocks":config.challenge_blocks,"assert_blocks":config.assert_blocks,"dispute_blocks":config.dispute_blocks,"commitments":witnesses.len(),"groth16_leaves":NUM_TAPS,"disprove_leaf":chosen,"transactions":txs,"scope":"presigned storage graph with real Groth16 and binding leaves; fixed phase-6 proof, no heavier-chain challenge"});
    write(out.join("graph.json"), result.clone());
    emit(json!({"complete":true,"file":out.join("graph.json"),"disprove_leaf":chosen}));
    // All committee, party and one-time secrets remain in RAM and are dropped at process exit.
}
fn main() {
    std::thread::Builder::new()
        .name("storage-graph".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(run)
        .unwrap()
        .join()
        .unwrap();
}
