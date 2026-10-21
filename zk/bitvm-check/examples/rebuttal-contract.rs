//! Bounded direct-header provider-response contract. Regtest only, no ZK proving.
use bitcoin::{
    consensus::encode::{deserialize, serialize_hex},
    hashes::{sha256d, Hash},
    secp256k1::XOnlyPublicKey,
    taproot::TaprootBuilder,
    Address, Network, OutPoint, ScriptBuf, Sequence, Transaction, Witness,
};
use bitvm::{
    signatures::{Wots, Wots32, Wots4},
    treepp::script,
};
use bsb_bitvm_check::{
    equivocation::prove_wots32_equivocation,
    graph_support::{bytes, hex, read, write},
    short_headers::{short_headers, HeaderMode, ShortHeaderContext},
    storage_graph::{Committee, GraphTx, Party, State},
};
use serde_json::{json, Value};
use std::{
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
    str::FromStr,
};
const WINDOW: u16 = 6;
struct Tree {
    state: State,
    leaves: Vec<ScriptBuf>,
}
impl Tree {
    fn new(mut leaves: Vec<ScriptBuf>) -> Self {
        let size = leaves.len().next_power_of_two();
        while leaves.len() < size {
            leaves.push(script! {0}.compile());
        }
        let mut b = TaprootBuilder::new();
        let depth = size.trailing_zeros() as u8;
        for leaf in &leaves {
            b = b.add_leaf(depth, leaf.clone()).unwrap();
        }
        let spend = b
            .finalize(
                &bitcoin::secp256k1::Secp256k1::new(),
                XOnlyPublicKey::from_str(
                    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
                )
                .unwrap(),
            )
            .unwrap();
        let state = State {
            output: ScriptBuf::new_p2tr_tweaked(spend.output_key()),
            script: leaves[0].clone(),
            spend,
        };
        Self { state, leaves }
    }
    fn at(&self, i: usize) -> State {
        let mut state = self.state.clone();
        state.script = self.leaves[i].clone();
        state
    }
}
fn emit(v: Value) {
    println!("BSB_REBUTTAL {v}");
    io::stdout().flush().unwrap();
}
fn record(tx: &Transaction) -> Value {
    json!({"hex":serialize_hex(tx),"txid":tx.compute_txid().to_string(),"wtxid":tx.compute_wtxid().to_string(),"weight":tx.weight().to_wu()})
}
fn line() -> Value {
    serde_json::from_str(&io::stdin().lock().lines().next().unwrap().unwrap()).unwrap()
}
fn raws(v: &Value) -> Vec<[u8; 80]> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|h| bytes(h.as_str().unwrap()).try_into().unwrap())
        .collect()
}
fn header_stack(headers: &[[u8; 80]]) -> Vec<Vec<u8>> {
    headers
        .iter()
        .rev()
        .flat_map(|h| {
            h.iter().rev().map(|b| {
                if *b == 0 {
                    vec![]
                } else if *b < 128 {
                    vec![*b]
                } else {
                    vec![*b, 0]
                }
            })
        })
        .collect()
}
fn decode_stack(v: &Value) -> Vec<Vec<u8>> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|s| bytes(s.as_str().unwrap()))
        .collect()
}
fn attach(tx: &mut Transaction, mut prefix: Vec<Vec<u8>>) {
    prefix.extend(tx.input[0].witness.to_vec());
    tx.input[0].witness = Witness::from_slice(&prefix);
}
fn proof_prefix(meta: &Value, headers: &[[u8; 80]], claim: bool, response: bool) -> Vec<Vec<u8>> {
    let mut p = if claim {
        vec![]
    } else {
        decode_stack(&meta["countSignature"])
    };
    p.extend(decode_stack(
        &meta[if response {
            "responseOriginalSignature"
        } else {
            "originalSignature"
        }],
    ));
    p.extend(header_stack(headers));
    p
}
fn public_tool(a: &[String]) {
    if a[1] == "replay-count" {
        let current = read(&a[2]);
        let old = read(&a[3]);
        let mut tx: Transaction = deserialize(&bytes(current["hex"].as_str().unwrap())).unwrap();
        let previous: Transaction = deserialize(&bytes(old["hex"].as_str().unwrap())).unwrap();
        let mut w = tx.input[0].witness.to_vec();
        let old_w = previous.input[0].witness.to_vec();
        let count = 2 * Wots4::TOTAL_DIGIT_LEN as usize;
        w[..count].clone_from_slice(&old_w[..count]);
        tx.input[0].witness = Witness::from_slice(&w);
        write(&a[4], record(&tx));
        return;
    }

    if a[1] == "redirect" || a[1] == "break-witness" {
        let v = read(&a[2]);
        let mut tx: Transaction = deserialize(&bytes(v["hex"].as_str().unwrap())).unwrap();
        if a[1] == "redirect" {
            tx.output[0].script_pubkey = Address::from_str(&a[3])
                .unwrap()
                .require_network(Network::Regtest)
                .unwrap()
                .script_pubkey();
        } else {
            let mut w = tx.input[0].witness.to_vec();
            let i: usize = a[3].parse().unwrap();
            assert_eq!(w[i].len(), 20);
            w[i][0] ^= 1;
            tx.input[0].witness = Witness::from_slice(&w);
        }
        write(&a[4], record(&tx));
        return;
    }
    let dir = Path::new(&a[2]);
    let meta = read(if dir.join("metadata.json").exists() {
        dir.join("metadata.json")
    } else {
        dir.join("claim-metadata.json")
    });
    let headers = raws(&read(&a[3]));
    assert!((1..=3).contains(&headers.len()));
    let kind = &a[1];
    assert!(kind == "counter" || kind == "response" || kind == "claim" || kind == "challenge");
    let file = if kind == "claim" {
        "claim-template.json".to_string()
    } else {
        format!("{kind}-{}-template.json", headers.len())
    };
    let v = read(dir.join(file));
    let mut tx: Transaction = deserialize(&bytes(v["hex"].as_str().unwrap())).unwrap();
    attach(
        &mut tx,
        proof_prefix(
            &meta,
            &headers,
            kind == "claim" || kind == "challenge",
            kind == "response",
        ),
    );
    write(&a[4], record(&tx));
}
fn make_tx(
    input: (OutPoint, bitcoin::TxOut),
    seq: Sequence,
    output: bitcoin::TxOut,
    lock: u32,
    state: &State,
    c: &Committee,
) -> GraphTx {
    let mut tx = GraphTx::new(vec![(input.0, input.1, seq)], vec![output], lock);
    tx.committee_input(0, state, c);
    tx
}
fn run() {
    let a: Vec<_> = std::env::args().collect();
    if a[1] != "serve" {
        public_tool(&a);
        return;
    }
    assert_eq!(a.len(), 4);
    let dir = PathBuf::from(&a[2]);
    std::fs::create_dir(&dir).unwrap();
    let anchor = read(&a[3]);
    assert_eq!(anchor["network"], "regtest");
    let anchor_height = anchor["height"].as_u64().unwrap() as u32;
    assert!(anchor_height >= 10);
    let original_secret = Wots32::generate_secret_key();
    let count_secret = Wots4::generate_secret_key();
    let context = ShortHeaderContext {
        anchor_hash: bytes(anchor["hashInternal"].as_str().unwrap())
            .try_into()
            .unwrap(),
        anchor_times: anchor["times"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u32)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        max_time: anchor["maxTime"].as_u64().unwrap() as u32,
        original_key: Wots32::generate_public_key(&original_secret),
        count_key: Wots4::generate_public_key(&count_secret),
    };
    let committee = Committee::fresh();
    let provider = Party::fresh();
    let client = Party::fresh();
    let x = committee.x;
    let guarded = |body: bitvm::treepp::Script| script! {{x}OP_CHECKSIGVERIFY{body}}.compile();
    let delayed = |n: u16| script! {{n as u32}OP_CSV OP_DROP{x}OP_CHECKSIG}.compile();
    let fund_deadline = anchor_height + 60;
    let funding = Tree::new(vec![
        guarded(short_headers(&context, 1, HeaderMode::Claim)),
        script! {{fund_deadline}OP_CLTV OP_DROP{x}OP_CHECKSIG}.compile(),
    ]);
    let claim = Tree::new(vec![
        guarded(short_headers(&context, 2, HeaderMode::Challenge)),
        guarded(short_headers(&context, 3, HeaderMode::Challenge)),
        delayed(WINDOW),
    ]);
    let mut response_leaves = Vec::new();
    for n in 1..=3 {
        response_leaves.push(guarded(short_headers(&context, n, HeaderMode::Response)));
    }
    response_leaves.push(delayed(WINDOW));
    let response = Tree::new(response_leaves);
    let mut settlement_leaves = Vec::new();
    for n in 1..=3 {
        settlement_leaves.push(guarded(short_headers(
            &context,
            n,
            HeaderMode::Counterexample,
        )));
    }
    settlement_leaves.push(guarded(prove_wots32_equivocation(&context.original_key)));
    settlement_leaves.push(delayed(WINDOW));
    let settlement = Tree::new(settlement_leaves);
    let address = |s: &State| {
        Address::from_script(&s.output, Network::Regtest)
            .unwrap()
            .to_string()
    };
    emit(
        json!({"ready":true,"network":"regtest","funding":address(&funding.state),"client":Address::from_script(&client.output(1).script_pubkey,Network::Regtest).unwrap().to_string(),"provider":Address::from_script(&provider.output(1).script_pubkey,Network::Regtest).unwrap().to_string(),"maxHeaders":3,"anchorHeight":anchor_height,"window":WINDOW}),
    );
    let input = line();
    let id = input["txid"].as_str().unwrap().parse().unwrap();
    let coin = OutPoint::new(id, input["vout"].as_u64().unwrap() as u32);
    let claim_tx = make_tx(
        (coin, funding.state.txout(100_000_000)),
        Sequence::ENABLE_LOCKTIME_NO_RBF,
        claim.state.txout(99_200_000),
        0,
        &funding.at(0),
        &committee,
    );
    let fund_timeout = make_tx(
        (coin, funding.state.txout(100_000_000)),
        Sequence::ENABLE_LOCKTIME_NO_RBF,
        client.output(99_997_000),
        fund_deadline,
        &funding.at(1),
        &committee,
    );
    let unchallenged = make_tx(
        claim_tx.output(0),
        Sequence::from_height(WINDOW),
        provider.output(99_197_000),
        0,
        &claim.at(2),
        &committee,
    );
    let challenge_tx = make_tx(
        claim_tx.output(0),
        Sequence::ZERO,
        response.state.txout(98_400_000),
        0,
        &claim.at(0),
        &committee,
    );
    let challenge_other = make_tx(
        claim_tx.output(0),
        Sequence::ZERO,
        response.state.txout(98_400_000),
        0,
        &claim.at(1),
        &committee,
    );
    assert_eq!(
        challenge_other.tx.compute_txid(),
        challenge_tx.tx.compute_txid()
    );
    let silence = make_tx(
        challenge_tx.output(0),
        Sequence::from_height(WINDOW),
        client.output(98_397_000),
        0,
        &response.at(3),
        &committee,
    );
    let mut responses = Vec::new();
    for n in 1..=3 {
        responses.push(make_tx(
            challenge_tx.output(0),
            Sequence::ZERO,
            settlement.state.txout(97_600_000),
            0,
            &response.at(n - 1),
            &committee,
        ));
    }
    assert!(responses
        .iter()
        .all(|t| t.tx.compute_txid() == responses[0].tx.compute_txid()));
    let refund = make_tx(
        responses[0].output(0),
        Sequence::from_height(WINDOW),
        provider.output(97_597_000),
        0,
        &settlement.at(4),
        &committee,
    );
    let mut counters = Vec::new();
    for n in 1..=3 {
        counters.push(make_tx(
            responses[0].output(0),
            Sequence::ZERO,
            client.output(95_600_000),
            0,
            &settlement.at(n - 1),
            &committee,
        ));
    }
    let equivocation = make_tx(
        responses[0].output(0),
        Sequence::ZERO,
        client.output(97_550_000),
        0,
        &settlement.at(3),
        &committee,
    );
    for (name, tx) in [
        ("claim-template", &claim_tx),
        ("fund-timeout", &fund_timeout),
        ("unchallenged", &unchallenged),
        ("challenge-2-template", &challenge_tx),
        ("challenge-3-template", &challenge_other),
        ("silence", &silence),
        ("refund", &refund),
        ("equivocation-template", &equivocation),
    ] {
        write(dir.join(format!("{name}.json")), record(&tx.tx));
    }
    for n in 1..=3 {
        write(
            dir.join(format!("response-{n}-template.json")),
            record(&responses[n - 1].tx),
        );
        write(
            dir.join(format!("counter-{n}-template.json")),
            record(&counters[n - 1].tx),
        );
    }
    // Private committee object is dropped before provider message selection. This
    // fixture is a co-located setup, not a distributed deletion ceremony.
    drop(committee);
    emit(json!({"presigned":true,"next":"provider headers"}));
    let claim_choice = line();
    if claim_choice["noClaim"] == true {
        write(
            dir.join("metadata.json"),
            json!({"network":"regtest","anchor":anchor,"maxHeaders":3,"window":WINDOW,"claimProduced":false,"providerResponseProduced":false,"responseCount":0,"leafBytes":{"claim":funding.leaves[0].len(),"response":response.leaves[..3].iter().map(|s|s.len()).collect::<Vec<_>>(),"counter":settlement.leaves[..3].iter().map(|s|s.len()).collect::<Vec<_>>()},"scope":"Provider stopped before signing any original header; only public committee transaction templates were exported."}),
        );
        emit(json!({"complete":true,"providerMessagesSigned":false}));
        return;
    }

    let claim_header: [u8; 80] = bytes(claim_choice["claimHeader"].as_str().unwrap())
        .try_into()
        .unwrap();
    let original_hash = sha256d::Hash::hash(&claim_header).to_byte_array();
    let original_signature = Wots32::sign_to_raw_witness(&original_secret, &original_hash);
    let encode = |w: &Witness| w.iter().map(hex).collect::<Vec<_>>();
    let mut meta = json!({"network":"regtest","anchor":anchor,"maxHeaders":3,"window":WINDOW,"originalSignature":encode(&original_signature),"responseOriginalSignature":encode(&original_signature),"countSignature":Vec::<String>::new(),"originalSignatureItems":original_signature.len(),"countSignatureItems":2*Wots4::TOTAL_DIGIT_LEN as usize,"responseCount":0,"originalHashInternal":hex(&original_hash),"responseOriginalHashInternal":hex(&original_hash),"countKey":context.count_key.iter().map(|b|hex(b)).collect::<Vec<_>>(),"originalKey":context.original_key.iter().map(|b|hex(b)).collect::<Vec<_>>(),"client":Address::from_script(&client.output(1).script_pubkey,Network::Regtest).unwrap().to_string(),"provider":Address::from_script(&provider.output(1).script_pubkey,Network::Regtest).unwrap().to_string(),"leafBytes":{"claim":funding.leaves[0].len(),"response":response.leaves[..3].iter().map(|s|s.len()).collect::<Vec<_>>(),"counter":settlement.leaves[..3].iter().map(|s|s.len()).collect::<Vec<_>>()},"scope":"Standalone bounded direct-header regtest dispute. Real headers and exact fixed-difficulty work, no unknown challenger keys or candidate allowlist. Not the long-chain Groth16 admission protocol or funded storage integration."});
    let mut signed_claim = claim_tx.tx.clone();
    attach(
        &mut signed_claim,
        proof_prefix(&meta, &[claim_header], true, false),
    );
    write(dir.join("claim.json"), record(&signed_claim));
    write(dir.join("claim-metadata.json"), meta.clone());
    emit(json!({"claimReady":true,"responseSigned":false}));
    let chosen = line();
    if chosen["noResponse"] == true {
        meta["providerResponseProduced"] = json!(false);
        write(dir.join("metadata.json"), meta);
        emit(json!({"complete":true,"providerMessagesSigned":"claim only"}));
        return;
    }
    let headers = raws(&chosen["responseHeaders"]);
    assert!((1..=3).contains(&headers.len()));
    let response_original_hash = sha256d::Hash::hash(&headers[0]).to_byte_array();
    let response_signature = if response_original_hash == original_hash {
        original_signature.clone()
    } else {
        assert_eq!(chosen["deliberateEquivocation"], true);
        Wots32::sign_to_raw_witness(&original_secret, &response_original_hash)
    };
    let count_signature =
        Wots4::sign_to_raw_witness(&count_secret, &(headers.len() as u32).to_be_bytes());
    meta["responseOriginalSignature"] = json!(encode(&response_signature));
    meta["countSignature"] = json!(encode(&count_signature));
    meta["responseCount"] = json!(headers.len());
    meta["responseOriginalHashInternal"] = json!(hex(&response_original_hash));
    meta["providerResponseProduced"] = json!(true);
    let mut signed_response = responses[headers.len() - 1].tx.clone();
    attach(
        &mut signed_response,
        proof_prefix(&meta, &headers, false, true),
    );
    write(dir.join("response.json"), record(&signed_response));
    let mut eq = equivocation.tx.clone();
    let mut pair = original_signature.to_vec();
    pair.extend(response_signature.to_vec());
    attach(&mut eq, pair);
    write(dir.join("equivocation.json"), record(&eq));
    write(dir.join("metadata.json"), meta);
    emit(json!({"complete":true,"providerMessagesSigned":true}));
}
fn main() {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(run)
        .unwrap()
        .join()
        .unwrap();
}
