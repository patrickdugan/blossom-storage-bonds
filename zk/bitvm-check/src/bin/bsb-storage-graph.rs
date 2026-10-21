//! Regtest graph setup process. Stdin/stdout handshake keeps keys in RAM until every graph edge
//! is presigned. The harness broadcasts the wallet funding transaction only after this exits.
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use bitcoin::{
    consensus::encode::serialize_hex,
    hashes::{sha256, Hash},
    taproot::{LeafVersion, TapNodeHash},
    Address, Network, OutPoint, ScriptBuf, Witness,
};
use bitvm::chunk::api::{
    api_generate_full_tapscripts, api_get_signature_from_assertion,
    type_conversion_utils::{script_to_witness, utils_raw_witnesses_from_signatures},
    validate_assertions, Assertions, PublicKeys, Signatures, NUM_HASH, NUM_PUBS, NUM_TAPS,
    NUM_U256,
};
use bitvm::signatures::{Wots, Wots16, Wots32, Wots4};
use bsb_bitvm_check::{
    storage_binding::{disprove_term_binding, BindingKeys},
    storage_graph::{
        CommitmentKey, Committee, GraphConfig, GraphTx, Party, ProofTree, State, StorageGraph,
        BINDING_LEAF,
    },
};
use serde_json::{json, Value};
use std::{
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

fn bytes(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}
fn read(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
fn emit(value: Value) {
    println!("BSB_GRAPH {}", value);
    io::stdout().flush().unwrap();
}
fn write(path: impl AsRef<Path>, value: Value) {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    f.write_all(&serde_json::to_vec(&value).unwrap()).unwrap();
}
fn vk(dir: &Path) -> (VerifyingKey<Bn254>, Proof<Bn254>, Fr) {
    let v = read(dir.join("vk.json"));
    let p = read(dir.join("proof.json"));
    let public = read(dir.join("public.json"));
    assert_eq!(v["nPublic"], 1);
    assert_eq!(v["IC"].as_array().unwrap().len(), 2);
    let f = |v: &Value| Fq::from_str(v.as_str().unwrap()).unwrap();
    let g1 = |v: &Value| G1Affine::new(f(&v[0]), f(&v[1]));
    let g2 = |v: &Value| {
        G2Affine::new(
            Fq2::new(f(&v[0][0]), f(&v[0][1])),
            Fq2::new(f(&v[1][0]), f(&v[1][1])),
        )
    };
    let key = VerifyingKey {
        alpha_g1: g1(&v["vk_alpha_1"]),
        beta_g2: g2(&v["vk_beta_2"]),
        gamma_g2: g2(&v["vk_gamma_2"]),
        delta_g2: g2(&v["vk_delta_2"]),
        gamma_abc_g1: v["IC"].as_array().unwrap().iter().map(g1).collect(),
    };
    let proof = Proof {
        a: g1(&p["pi_a"]),
        b: g2(&p["pi_b"]),
        c: g1(&p["pi_c"]),
    };
    let public = Fr::from_str(public[0].as_str().unwrap()).unwrap();
    assert!(Groth16::<Bn254>::verify_proof(
        &ark_groth16::prepare_verifying_key(&key),
        &proof,
        &[public]
    )
    .unwrap());
    (key, proof, public)
}

struct Commitments {
    secrets: Vec<String>,
    chain: [Vec<u8>; 3],
    pks: PublicKeys,
}
#[allow(deprecated)]
impl Commitments {
    fn fresh() -> Self {
        let secrets = (0..NUM_PUBS + NUM_U256 + NUM_HASH)
            .map(|_| hex(&Wots32::generate_secret_key()))
            .collect::<Vec<_>>();
        let pks = (
            std::array::from_fn(|i| {
                Wots32::generate_public_key(&Wots32::secret_from_str(&secrets[i]))
            }),
            std::array::from_fn(|i| {
                Wots32::generate_public_key(&Wots32::secret_from_str(&secrets[NUM_PUBS + i]))
            }),
            std::array::from_fn(|i| {
                Wots16::generate_public_key(&Wots16::secret_from_str(
                    &secrets[NUM_PUBS + NUM_U256 + i],
                ))
            }),
        );
        Self {
            secrets,
            chain: [
                Wots4::generate_secret_key(),
                Wots32::generate_secret_key(),
                Wots32::generate_secret_key(),
            ],
            pks,
        }
    }
    fn binding_keys(&self) -> BindingKeys {
        BindingKeys {
            public_input: self.pks.0[0],
            tip_height: Wots4::generate_public_key(&self.chain[0]),
            tip_hash: Wots32::generate_public_key(&self.chain[1]),
            total_work: Wots32::generate_public_key(&self.chain[2]),
        }
    }
    fn keys(&self) -> Vec<CommitmentKey> {
        let mut result = Vec::new();
        result.extend(self.pks.0.iter().map(|k| CommitmentKey::Bytes32(*k)));
        result.extend(self.pks.1.iter().map(|k| CommitmentKey::Bytes32(*k)));
        result.extend(self.pks.2.iter().map(|k| CommitmentKey::Bytes16(*k)));
        result.push(CommitmentKey::Bytes4(Wots4::generate_public_key(
            &self.chain[0],
        )));
        result.push(CommitmentKey::Bytes32(Wots32::generate_public_key(
            &self.chain[1],
        )));
        result.push(CommitmentKey::Bytes32(Wots32::generate_public_key(
            &self.chain[2],
        )));
        result
    }
    fn sign(
        &self,
        assertions: Assertions,
        preimage: &[u8],
    ) -> (Signatures, Vec<Witness>, Vec<Vec<u8>>) {
        let signatures = api_get_signature_from_assertion(assertions, self.secrets.clone());
        let mut witnesses = utils_raw_witnesses_from_signatures(&signatures)
            .into_iter()
            .map(|w| Witness::from_slice(&w))
            .collect::<Vec<_>>();
        let tip: [u8; 4] = preimage[134..138].try_into().unwrap();
        let hash: [u8; 32] = preimage[138..170].try_into().unwrap();
        let work: [u8; 32] = preimage[170..202].try_into().unwrap();
        let chain = [
            Wots4::sign_to_raw_witness(&self.chain[0], &tip),
            Wots32::sign_to_raw_witness(&self.chain[1], &hash),
            Wots32::sign_to_raw_witness(&self.chain[2], &work),
        ];
        witnesses.extend(chain.iter().cloned());
        let mut binding = Vec::new();
        for w in [&chain[2], &chain[1], &chain[0]] {
            binding.extend(w.iter().map(|x| x.to_vec()));
        }
        binding.extend(
            Wots32::signature_to_raw_witness(&signatures.0[0])
                .iter()
                .map(|x| x.to_vec()),
        );
        (signatures, witnesses, binding)
    }
}

struct Scripts {
    cache: PathBuf,
    manifest: Value,
    locks: Vec<ScriptBuf>,
}
impl Scripts {
    fn new(cache: PathBuf, proof_dir: &Path, pks: PublicKeys) -> Self {
        let manifest = read(cache.join("manifest.json"));
        assert_eq!(manifest["bitvm_rev"], "7d1ca36");
        assert_eq!(manifest["count"], NUM_TAPS);
        assert_eq!(
            manifest["vk_sha256"],
            sha256::Hash::hash(&std::fs::read(proof_dir.join("vk.json")).unwrap()).to_string()
        );
        let empty = vec![ScriptBuf::new(); NUM_TAPS];
        let locks = api_generate_full_tapscripts(pks, &empty);
        Self {
            cache,
            manifest,
            locks,
        }
    }
    fn full(&self, index: usize) -> ScriptBuf {
        let partial = std::fs::read(self.cache.join(format!("{index:03}.bin"))).unwrap();
        assert_eq!(
            self.manifest["script_sha256"][index],
            sha256::Hash::hash(&partial).to_string(),
            "cache script hash"
        );
        let mut result = self.locks[index].to_bytes();
        result.extend(partial);
        ScriptBuf::from_bytes(result)
    }
    fn hashes(&self) -> Vec<TapNodeHash> {
        (0..NUM_TAPS)
            .map(|index| TapNodeHash::from_script(&self.full(index), LeafVersion::TapScript))
            .collect()
    }
}

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
