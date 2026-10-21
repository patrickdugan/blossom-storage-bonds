//! Separate committee setup and one-shot, term-end WOTS signing. Regtest only.
//! Provider secrets stay in its waiting process; committee secrets exit before funding.
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use bitcoin::{
    consensus::{deserialize, encode::serialize_hex},
    hashes::{sha256, Hash},
    secp256k1::XOnlyPublicKey,
    taproot::TapNodeHash,
    Address, Network, OutPoint, Transaction, Witness,
};
use bitvm::{
    chunk::api::{
        api_get_assertions_from_signature,
        type_conversion_utils::utils_signatures_from_raw_witnesses, Assertions, PublicKeys,
        NUM_PUBS, NUM_U256,
    },
    signatures::{Wots, Wots16, Wots32, Wots4},
    treepp::script,
};
use bsb_bitvm_check::{
    graph_support::{bytes, hex, read, vk, write, Commitments, Scripts},
    storage_binding::{disprove_term_binding, BindingKeys},
    storage_graph::{
        CommitmentKey, Committee, GraphConfig, GraphTx, Party, ProofTree, State, StorageGraph,
        BINDING_LEAF, SLOT_COUNT,
    },
};
use serde_json::{json, Value};
use std::{
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

const VK_HASH: &str = "2941dff0bd962ff8610773c9659c10d0dec561db1e2f6afecfbbe0d9cb457a7d";

fn event(value: Value) {
    println!("BSB_LIFECYCLE {value}");
    io::stdout().flush().unwrap();
}
fn message() -> Value {
    serde_json::from_str(
        &io::stdin()
            .lock()
            .lines()
            .next()
            .expect("coordinator message")
            .unwrap(),
    )
    .unwrap()
}
fn key_bytes<K: AsRef<[[u8; 20]]>>(key: &K) -> Vec<[u8; 20]> {
    key.as_ref().to_vec()
}
fn encode_keys(keys: &[CommitmentKey]) -> Value {
    json!(keys
        .iter()
        .map(|key| match key {
            CommitmentKey::Bytes32(k) => key_bytes(k),
            CommitmentKey::Bytes16(k) => key_bytes(k),
            CommitmentKey::Bytes4(k) => key_bytes(k),
        })
        .collect::<Vec<_>>())
}
struct PublicCommitments {
    proof: PublicKeys,
    binding: BindingKeys,
    slots: Vec<CommitmentKey>,
}
fn decode_keys(value: &Value) -> PublicCommitments {
    let raw: Vec<Vec<[u8; 20]>> = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(raw.len(), SLOT_COUNT, "exactly 381 commitment slots");
    let proof: PublicKeys = (
        std::array::from_fn(|i| raw[i].clone().try_into().unwrap()),
        std::array::from_fn(|i| raw[NUM_PUBS + i].clone().try_into().unwrap()),
        std::array::from_fn(|i| raw[NUM_PUBS + NUM_U256 + i].clone().try_into().unwrap()),
    );
    let binding = BindingKeys {
        public_input: proof.0[0],
        tip_height: raw[378].clone().try_into().unwrap(),
        tip_hash: raw[379].clone().try_into().unwrap(),
        total_work: raw[380].clone().try_into().unwrap(),
    };
    let mut slots = Vec::new();
    slots.extend(proof.0.iter().map(|k| CommitmentKey::Bytes32(*k)));
    slots.extend(proof.1.iter().map(|k| CommitmentKey::Bytes32(*k)));
    slots.extend(proof.2.iter().map(|k| CommitmentKey::Bytes16(*k)));
    slots.push(CommitmentKey::Bytes4(binding.tip_height));
    slots.push(CommitmentKey::Bytes32(binding.tip_hash));
    slots.push(CommitmentKey::Bytes32(binding.total_work));
    PublicCommitments {
        proof,
        binding,
        slots,
    }
}
fn check_setup(setup: &Value) -> ([u8; 134], [u8; 32], GraphConfig) {
    assert_eq!(setup["format"], "bsb/storage-setup/v1");
    assert_eq!(setup["network"], "regtest");
    assert_eq!(setup["vk_sha256"], VK_HASH);
    let prefix: [u8; 134] = bytes(setup["prefix"].as_str().unwrap()).try_into().unwrap();
    let constants = bytes(setup["constants_digest"].as_str().unwrap())
        .try_into()
        .unwrap();
    assert_eq!(&prefix[..14], b"bsb/r0-term|v1");
    let c = &setup["config"];
    let word = |name: &str| u32::try_from(c[name].as_u64().unwrap()).unwrap();
    let config = GraphConfig {
        term_end: word("term_end"),
        kickoff_deadline: word("kickoff_deadline"),
        final_deadline: word("final_deadline"),
        challenge_blocks: word("challenge_blocks").try_into().unwrap(),
        assert_blocks: word("assert_blocks").try_into().unwrap(),
        dispute_blocks: word("dispute_blocks").try_into().unwrap(),
        slot_value: c["slot_value"].as_u64().unwrap(),
        marker_value: c["marker_value"].as_u64().unwrap(),
    };
    let pword = |at| u32::from_be_bytes(prefix[at..at + 4].try_into().unwrap()) as u64;
    assert!(pword(78) > 0 && pword(82) > 0 && pword(122) > 0 && pword(126) > 0 && pword(130) > 0);
    assert!(
        pword(118) + (pword(126) - 1) * pword(122) + pword(130) <= config.term_end as u64,
        "deadline precedes final confirmed seed"
    );
    config.validate(100_000_000);
    (prefix, constants, config)
}
fn registration(setup: &Value, commitments: &Commitments) -> Value {
    json!({"format":"bsb/provider-public-keys/v1", "network":"regtest", "setup":setup, "keys":encode_keys(&commitments.keys())})
}
fn check_registration(setup: &Value, public: &Value) -> PublicCommitments {
    assert_eq!(public["format"], "bsb/provider-public-keys/v1");
    assert_eq!(public["network"], "regtest");
    assert_eq!(
        &public["setup"], setup,
        "provider and committee must pin identical setup terms"
    );
    decode_keys(&public["keys"])
}
fn fixture_binding(setup: &Value, fixture: &Value, proof_dir: &Path) -> (Vec<u8>, Fr) {
    let (prefix, constants, _) = check_setup(setup);
    assert_eq!(
        sha256::Hash::hash(&std::fs::read(proof_dir.join("vk.json")).unwrap()).to_string(),
        VK_HASH
    );
    let preimage = bytes(fixture["m2"]["term"]["preimage"].as_str().unwrap());
    assert_eq!(preimage.len(), 202);
    assert_eq!(
        &preimage[..134],
        &prefix,
        "term-end proof must use the setup-time term"
    );
    let wrapper = &fixture["m3"]["groth16"];
    let journal = sha256::Hash::hash(&preimage).to_byte_array();
    assert_eq!(hex(&journal), wrapper["journal"]);
    let mut constants_preimage = bytes(wrapper["control_root"].as_str().unwrap())
        .into_iter()
        .map(|b| b.reverse_bits())
        .collect::<Vec<_>>();
    for name in ["pre_state", "post_state", "bn254_control_id"] {
        constants_preimage.extend(bytes(wrapper[name].as_str().unwrap()));
    }
    assert_eq!(
        sha256::Hash::hash(&constants_preimage).to_byte_array(),
        constants,
        "term-end wrapper must use the setup-time image"
    );
    let expected = blake3::hash(&[constants.as_slice(), journal.as_slice()].concat());
    let (_, _, public) = vk(proof_dir); // verifies the actual Groth16 proof, rather than its metadata
    assert_eq!(
        Fr::from_be_bytes_mod_order(&expected.as_bytes()[..31]),
        public,
        "proof must bind the pinned storage term"
    );
    (preimage, public)
}
fn assertions(path: &Path, public: Fr) -> Assertions {
    let checked = read(path);
    assert_eq!(checked["bitvm_rev"], "7d1ca36");
    assert_eq!(checked["scripts_checked"], true);
    assert_eq!(checked["public_input"], public.to_string());
    let values: Vec<[u8; 32]> = serde_json::from_value(checked["public"].clone()).unwrap();
    let fields: Vec<[u8; 32]> = serde_json::from_value(checked["fields"].clone()).unwrap();
    let hashes: Vec<[u8; 16]> = serde_json::from_value(checked["hashes"].clone()).unwrap();
    let result: Assertions = (
        values.try_into().unwrap(),
        fields.try_into().unwrap(),
        hashes.try_into().unwrap(),
    );
    let expected = public
        .into_bigint()
        .to_bytes_be()
        .into_iter()
        .map(|b| b.rotate_left(4))
        .collect::<Vec<_>>();
    assert_eq!(result.0[0].as_slice(), expected);
    result
}
fn check_witnesses(keys: &[CommitmentKey], witnesses: &[Vec<Vec<u8>>]) {
    assert_eq!(witnesses.len(), SLOT_COUNT);
    for (i, (key, witness)) in keys.iter().zip(witnesses).enumerate() {
        let check = match key {
            CommitmentKey::Bytes32(k) => Wots32::checksig_verify_and_clear_stack(k),
            CommitmentKey::Bytes16(k) => Wots16::checksig_verify_and_clear_stack(k),
            CommitmentKey::Bytes4(k) => Wots4::checksig_verify_and_clear_stack(k),
        };
        assert!(
            bitvm::execute_script(
                script! { for item in witness { { item.clone() } } { check } OP_1 }
            )
            .success,
            "assertion slot {i}: invalid WOTS signature"
        );
    }
}
fn provider(setup_path: &Path) {
    let setup = read(setup_path);
    check_setup(&setup);
    let commitments = Commitments::fresh();
    let public_keys = registration(&setup, &commitments);
    event(json!({"provider_ready":true,"registration":public_keys}));
    // The coordinator supplies the fixture, proof and assertion paths only in this term-end request.
    let request = message();
    let fixture = read(request["fixture"].as_str().unwrap());
    let proof_dir = PathBuf::from(request["proof_dir"].as_str().unwrap());
    let (preimage, public) = fixture_binding(&setup, &fixture, &proof_dir);
    let checked = assertions(Path::new(request["assertions"].as_str().unwrap()), public);
    let (_, witnesses, _) = commitments.sign(checked, &preimage);
    let raw = witnesses
        .iter()
        .map(|w| w.iter().map(|i| i.to_vec()).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    check_witnesses(&commitments.keys(), &raw);
    let path = PathBuf::from(request["output"].as_str().unwrap());
    write(
        &path,
        json!({"format":"bsb/term-end-witnesses/v1","network":"regtest","registration":public_keys,"preimage":hex(&preimage),"public_input":public.to_string(),"witnesses":raw}),
    );
    event(json!({"provider_complete":true,"file":path}));
    // A single request is accepted. This process then exits, discarding the one-time secrets.
}
fn tx_record(tx: &GraphTx) -> Value {
    json!({"hex":serialize_hex(&tx.tx),"txid":tx.tx.compute_txid().to_string(),"vsize":tx.tx.vsize(),
        "fee_sats":tx.prevouts.iter().map(|o| o.value.to_sat()).sum::<u64>()-tx.tx.output.iter().map(|o| o.value.to_sat()).sum::<u64>()})
}
fn setup_graph(
    setup_path: &Path,
    registration_path: &Path,
    vk_dir: &Path,
    cache: &Path,
    output: &Path,
) {
    let setup = read(setup_path);
    let (prefix, constants, config) = check_setup(&setup);
    let registration = read(registration_path);
    let keys = check_registration(&setup, &registration);
    assert_eq!(
        sha256::Hash::hash(&std::fs::read(vk_dir.join("vk.json")).unwrap()).to_string(),
        VK_HASH
    );
    let committee = Committee::fresh();
    let provider = Party::fresh();
    let client = Party::fresh();
    let scripts = Scripts::new(cache.to_path_buf(), vk_dir, keys.proof);
    let hashes = scripts.hashes();
    let binding = disprove_term_binding(&prefix, &constants, &keys.binding).compile();
    let tree = ProofTree::new(hashes.clone(), &binding, provider.x, config.dispute_blocks);
    let funding_script = State::committee(committee.x).output;
    let address = |script: &bitcoin::Script| {
        Address::from_script(script, Network::Regtest)
            .unwrap()
            .to_string()
    };
    event(
        json!({"setup_ready":true,"network":"regtest","funding_address":address(&funding_script),"client_address":address(&client.output(0).script_pubkey),"provider_address":address(&provider.output(0).script_pubkey)}),
    );
    let funding = message();
    assert_eq!(funding["network"], "regtest");
    let first = u32::from_be_bytes(prefix[118..122].try_into().unwrap());
    assert!(
        funding["height"].as_u64().unwrap() + 1 < first as u64,
        "graph must be presigned before the first epoch"
    );
    assert_eq!(funding["sats"], 100_000_000);
    let point = OutPoint::new(
        funding["txid"].as_str().unwrap().parse().unwrap(),
        funding["vout"].as_u64().unwrap().try_into().unwrap(),
    );
    let graph = StorageGraph::build(
        config,
        point,
        100_000_000,
        &committee,
        &provider,
        &client,
        &keys.slots,
        tree,
    );
    let transactions = graph
        .transactions
        .iter()
        .map(|(name, tx)| (name.clone(), tx_record(tx)))
        .collect::<serde_json::Map<_, _>>();
    write(
        output,
        json!({"format":"bsb/presigned-storage-graph/v1","network":"regtest","setup":setup,"registration":registration,
        "provider_x":provider.x.to_string(),"client_address":address(&client.output(0).script_pubkey),"provider_address":address(&provider.output(0).script_pubkey),
        "proof_hashes":hashes.iter().map(|h|h.to_string()).collect::<Vec<_>>(),"transactions":transactions}),
    );
    event(json!({"setup_complete":true,"file":output}));
    // No WOTS secret or term-end proof ever enters this process. It must exit before funding.
}
fn tx(value: &Value) -> Transaction {
    deserialize(&bytes(value["hex"].as_str().unwrap())).unwrap()
}
fn attach(graph_path: &Path, witness_path: &Path, output: &Path) {
    let mut graph = read(graph_path);
    assert_eq!(graph["format"], "bsb/presigned-storage-graph/v1");
    assert_eq!(graph["network"], "regtest");
    let signed = read(witness_path);
    assert_eq!(signed["format"], "bsb/term-end-witnesses/v1");
    assert_eq!(signed["network"], "regtest");
    assert_eq!(
        signed["registration"], graph["registration"],
        "cannot swap setup-time one-time keys"
    );
    let (prefix, constants, config) = check_setup(&graph["setup"]);
    let keys = check_registration(&graph["setup"], &graph["registration"]);
    let raw: Vec<Vec<Vec<u8>>> = serde_json::from_value(signed["witnesses"].clone()).unwrap();
    check_witnesses(&keys.slots, &raw);
    let preimage = bytes(signed["preimage"].as_str().unwrap());
    assert_eq!(preimage.len(), 202);
    assert_eq!(&preimage[..134], &prefix);
    let journal = sha256::Hash::hash(&preimage).to_byte_array();
    let expected = blake3::hash(&[constants.as_slice(), journal.as_slice()].concat());
    let expected = Fr::from_be_bytes_mod_order(&expected.as_bytes()[..31]);
    assert_eq!(signed["public_input"], expected.to_string());
    let signature = utils_signatures_from_raw_witnesses(&raw[..378]);
    let decoded = api_get_assertions_from_signature(signature);
    assert_eq!(
        decoded.0[0].as_slice(),
        expected
            .into_bigint()
            .to_bytes_be()
            .into_iter()
            .map(|b| b.rotate_left(4))
            .collect::<Vec<_>>()
    );
    let binding = disprove_term_binding(&prefix, &constants, &keys.binding).compile();
    let hashes = graph["proof_hashes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| TapNodeHash::from_str(h.as_str().unwrap()).unwrap())
        .collect();
    let tree = ProofTree::new(
        hashes,
        &binding,
        XOnlyPublicKey::from_str(graph["provider_x"].as_str().unwrap()).unwrap(),
        config.dispute_blocks,
    );
    let final_tx = tx(&graph["transactions"]["assert-final"]);
    assert_eq!(
        final_tx.output[1].script_pubkey, tree.marker.output,
        "reconstructed tree differs from the presigned assertion"
    );
    for (group, range) in [0..300, 300..SLOT_COUNT].iter().enumerate() {
        let name = format!("assert-commit-{group}");
        let mut transaction = tx(&graph["transactions"][&name]);
        let txid = transaction.compute_txid();
        assert_eq!(graph["transactions"][&name]["txid"], txid.to_string());
        assert_eq!(transaction.input.len(), range.len());
        for (index, slot) in range.clone().enumerate() {
            let old = transaction.input[index]
                .witness
                .iter()
                .map(|b| b.to_vec())
                .collect::<Vec<_>>();
            assert_eq!(
                old.len(),
                3,
                "assertion already attached or incomplete presignature"
            );
            let mut witness = raw[slot].clone();
            witness.extend(old);
            transaction.input[index].witness = Witness::from_slice(&witness);
        }
        assert_eq!(
            transaction.compute_txid(),
            txid,
            "proof attachment must not change any presigned txid"
        );
        graph["transactions"][&name]["hex"] = json!(serialize_hex(&transaction));
        graph["transactions"][&name]["vsize"] = json!(transaction.vsize());
    }
    let mut binding_witness = Vec::new();
    for i in [380, 379, 378, 0] {
        binding_witness.extend(raw[i].iter().cloned());
    }
    let mut slash = tx(&graph["transactions"]["slash"]);
    assert_eq!(slash.input.len(), 2);
    slash.input[1].witness = tree.disprove_witness(BINDING_LEAF, &binding, binding_witness);
    assert_eq!(
        graph["transactions"]["slash"]["txid"],
        slash.compute_txid().to_string()
    );
    graph["transactions"]["slash"]["hex"] = json!(serialize_hex(&slash));
    graph["transactions"]["slash"]["vsize"] = json!(slash.vsize());
    graph["format"] = json!("bsb/asserted-storage-graph/v1");
    graph["term_preimage"] = signed["preimage"].clone();
    write(output, graph);
    event(json!({"attached":true,"file":output}));
}
fn run() {
    let args = std::env::args().collect::<Vec<_>>();
    match args.get(1).map(String::as_str) {
        Some("provider") if args.len()==3 => provider(Path::new(&args[2])),
        Some("setup") if args.len()==7 => setup_graph(Path::new(&args[2]),Path::new(&args[3]),Path::new(&args[4]),Path::new(&args[5]),Path::new(&args[6])),
        Some("attach") if args.len()==5 => attach(Path::new(&args[2]),Path::new(&args[3]),Path::new(&args[4])),
        _ => panic!("provider <setup.json> | setup <setup.json> <public-keys.json> <vk-dir> <partials> <new-graph.json> | attach <graph.json> <witnesses.json> <new-output.json>"),
    }
}
fn main() {
    std::thread::Builder::new()
        .name("storage-lifecycle".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(run)
        .unwrap()
        .join()
        .unwrap();
}
