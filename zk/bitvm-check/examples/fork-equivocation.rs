//! Isolated false-disprove / delayed-equivocation recovery experiment. Regtest only.
//! All secrets stay in RAM. Committee presigning exits before funding; no distributed ceremony.
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use bitcoin::{
    absolute,
    consensus::encode::serialize_hex,
    hashes::{sha256, Hash},
    secp256k1::{rand::thread_rng, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo},
    transaction, Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};
use bitvm::{
    signatures::{Wots, Wots32, Wots4},
    treepp::script,
};
use bsb_bitvm_check::{
    equivocation::prove_wots32_equivocation,
    fork_binding::{disprove_compact_fork_binding, ForkBindingKeys},
    graph_support::{bytes, hex, read, write},
};
use serde_json::{json, Value};
use std::{
    io::{self, BufRead, Write},
    path::PathBuf,
    str::FromStr,
};
const WINDOW: u16 = 6;
struct State {
    spend: TaprootSpendInfo,
    leaves: Vec<ScriptBuf>,
}
impl State {
    fn new(leaves: Vec<ScriptBuf>) -> Self {
        let mut builder = TaprootBuilder::new();
        for leaf in &leaves {
            builder = builder
                .add_leaf(if leaves.len() == 1 { 0 } else { 1 }, leaf.clone())
                .unwrap();
        }
        let nums = XOnlyPublicKey::from_str(
            "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
        )
        .unwrap();
        Self {
            spend: builder.finalize(&Secp256k1::new(), nums).unwrap(),
            leaves,
        }
    }
    fn output(&self, sats: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(self.spend.output_key()),
        }
    }
    fn address(&self) -> String {
        Address::p2tr_tweaked(self.spend.output_key(), Network::Regtest).to_string()
    }
    fn witness(&self, index: usize, mut stack: Vec<Vec<u8>>) -> Witness {
        let leaf = &self.leaves[index];
        stack.push(leaf.to_bytes());
        stack.push(
            self.spend
                .control_block(&(leaf.clone(), LeafVersion::TapScript))
                .unwrap()
                .serialize(),
        );
        Witness::from_slice(&stack)
    }
}
fn key() -> Keypair {
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::new(&mut thread_rng()))
}
fn sig(tx: &Transaction, prev: &[TxOut], index: usize, leaf: &ScriptBuf, key: &Keypair) -> Vec<u8> {
    let hash = SighashCache::new(tx)
        .taproot_script_spend_signature_hash(
            index,
            &Prevouts::All(prev),
            TapLeafHash::from_script(leaf, LeafVersion::TapScript),
            TapSighashType::Default,
        )
        .unwrap();
    Secp256k1::new()
        .sign_schnorr_with_rng(
            &Message::from_digest(hash.to_byte_array()),
            key,
            &mut thread_rng(),
        )
        .as_ref()
        .to_vec()
}
fn tx(inputs: Vec<(OutPoint, u16)>, output: TxOut) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: inputs
            .into_iter()
            .map(|(previous_output, sequence)| TxIn {
                previous_output,
                sequence: Sequence::from_height(sequence),
                script_sig: ScriptBuf::new(),
                witness: Witness::new(),
            })
            .collect(),
        output: vec![output],
    }
}
fn emit(v: Value) {
    println!("BSB_EQUIVOCATION {v}");
    io::stdout().flush().unwrap();
}
fn main() {
    let a: Vec<String> = std::env::args().collect();
    assert_eq!(a.len(), 3, "<compact-certificate.json> <new-output-dir>");
    let fixture = read(&a[1]);
    let dir = PathBuf::from(&a[2]);
    std::fs::create_dir(&dir).unwrap();
    assert_eq!(
        fixture["fork_image_id"],
        "b1766c1d9ebf071acd684ea744d83908181a60d313ccb385661e3fe76ff855b1"
    );
    let statement = bytes(fixture["statement_preimage"].as_str().unwrap());
    assert_eq!(statement.len(), 214);
    assert_eq!(&statement[..14], b"bsb/r0-fork|v2");
    let constants: [u8; 32] = bytes(fixture["groth16"]["constants_digest"].as_str().unwrap())
        .try_into()
        .unwrap();
    let public = Fr::from_str(fixture["groth16"]["public_input"].as_str().unwrap()).unwrap();
    let digest = blake3::hash(
        &[
            constants.as_slice(),
            sha256::Hash::hash(&statement).as_byte_array(),
        ]
        .concat(),
    );
    let mut expected = vec![0];
    expected.extend_from_slice(&digest.as_bytes()[..31]);
    assert_eq!(public.into_bigint().to_bytes_be(), expected);
    let fields = vec![
        public
            .into_bigint()
            .to_bytes_be()
            .into_iter()
            .map(|x| x.rotate_left(4))
            .collect::<Vec<_>>(),
        statement[46..78].to_vec(),
        statement[78..82].to_vec(),
        statement[82..114].to_vec(),
        statement[114..146].to_vec(),
        statement[146..150].to_vec(),
        statement[150..182].to_vec(),
        statement[182..214].to_vec(),
    ];
    let secrets: Vec<Vec<u8>> = (0..8)
        .map(|i| {
            if i == 2 || i == 5 {
                Wots4::generate_secret_key()
            } else {
                Wots32::generate_secret_key()
            }
        })
        .collect();
    let keys = ForkBindingKeys {
        public_input: Wots32::generate_public_key(&secrets[0]),
        term_journal: Wots32::generate_public_key(&secrets[1]),
        response_height: Wots4::generate_public_key(&secrets[2]),
        response_hash: Wots32::generate_public_key(&secrets[3]),
        response_work: Wots32::generate_public_key(&secrets[4]),
        candidate_height: Wots4::generate_public_key(&secrets[5]),
        candidate_hash: Wots32::generate_public_key(&secrets[6]),
        candidate_work: Wots32::generate_public_key(&secrets[7]),
    };
    let signatures: Vec<Witness> = (0..8)
        .map(|i| {
            if i == 2 || i == 5 {
                Wots4::sign_to_raw_witness(&secrets[i], fields[i].as_slice().try_into().unwrap())
            } else {
                Wots32::sign_to_raw_witness(&secrets[i], fields[i].as_slice().try_into().unwrap())
            }
        })
        .collect();
    let signatures: Vec<Vec<Vec<u8>>> = signatures.iter().map(Witness::to_vec).collect();
    // Deliberately malicious provider behavior: sign a second journal under its own key.
    let mut alternate: [u8; 32] = fields[1].as_slice().try_into().unwrap();
    alternate[0] ^= 1;
    let alternate_signature = Wots32::sign_to_raw_witness(&secrets[1], &alternate).to_vec();
    let unrelated =
        Wots32::sign_to_raw_witness(&Wots32::generate_secret_key(), &alternate).to_vec();
    let proof = State::new(vec![disprove_compact_fork_binding(
        statement[14..46].try_into().unwrap(),
        &constants,
        &keys,
    )
    .compile()]);
    let committee = [key(), key()];
    let ca = committee[0].x_only_public_key().0;
    let cb = committee[1].x_only_public_key().0;
    let control = State::new(vec![
        script! {{ca} OP_CHECKSIGVERIFY {cb} OP_CHECKSIG}.compile()
    ]);
    let provider = key();
    let provider_x = provider.x_only_public_key().0;
    let client = key();
    let destination = |who: &Keypair, sats: u64| TxOut {
        value: Amount::from_sat(sats),
        script_pubkey: Address::p2tr(
            &Secp256k1::new(),
            who.x_only_public_key().0,
            None,
            Network::Regtest,
        )
        .script_pubkey(),
    };
    let escrow=State::new(vec![script! {{ca} OP_CHECKSIGVERIFY {cb} OP_CHECKSIGVERIFY {prove_wots32_equivocation(&keys.term_journal)}}.compile(),script! {{WINDOW as u32} OP_CSV OP_DROP {provider_x} OP_CHECKSIG}.compile()]);
    emit(
        json!({"ready":true,"control":control.address(),"proof":proof.address(),"client":Address::from_script(&destination(&client,0).script_pubkey,Network::Regtest).unwrap().to_string(),"provider":Address::from_script(&destination(&provider,0).script_pubkey,Network::Regtest).unwrap().to_string()}),
    );
    let line = io::stdin().lock().lines().next().unwrap().unwrap();
    let funding: Value = serde_json::from_str(&line).unwrap();
    let id = funding["txid"].as_str().unwrap().parse().unwrap();
    let prev = vec![control.output(100_000_000), proof.output(1_000_000)];
    let mut dispute = tx(
        vec![
            (
                OutPoint::new(id, funding["control_vout"].as_u64().unwrap() as u32),
                0,
            ),
            (
                OutPoint::new(id, funding["proof_vout"].as_u64().unwrap() as u32),
                0,
            ),
        ],
        escrow.output(100_000_000),
    );
    dispute.input[0].witness = control.witness(
        0,
        vec![
            sig(&dispute, &prev, 0, &control.leaves[0], &committee[1]),
            sig(&dispute, &prev, 0, &control.leaves[0], &committee[0]),
        ],
    );
    let mut honest = dispute.clone();
    let honest_stack: Vec<_> = (0..8).rev().flat_map(|i| signatures[i].clone()).collect();
    honest.input[1].witness = proof.witness(0, honest_stack);
    let bad_stack: Vec<_> = (0..8)
        .rev()
        .flat_map(|i| {
            if i == 1 {
                alternate_signature.clone()
            } else {
                signatures[i].clone()
            }
        })
        .collect();
    dispute.input[1].witness = proof.witness(0, bad_stack);
    let coin = OutPoint::new(dispute.compute_txid(), 0);
    let ep = vec![escrow.output(100_000_000)];
    let mut penalty = tx(vec![(coin, 0)], destination(&client, 99_950_000));
    let ps = vec![
        sig(&penalty, &ep, 0, &escrow.leaves[0], &committee[1]),
        sig(&penalty, &ep, 0, &escrow.leaves[0], &committee[0]),
    ];
    let witness = |second: Vec<Vec<u8>>| {
        let mut w = signatures[1].clone();
        w.extend(second);
        w.extend(ps.clone());
        escrow.witness(0, w)
    };
    penalty.input[0].witness = witness(alternate_signature);
    let mut same = penalty.clone();
    same.input[0].witness = witness(signatures[1].clone());
    let mut wrong = penalty.clone();
    wrong.input[0].witness = witness(unrelated);
    let mut redirected = penalty.clone();
    redirected.output[0].script_pubkey = destination(&provider, 0).script_pubkey;
    let mut refund = tx(vec![(coin, WINDOW)], destination(&provider, 99_997_000));
    refund.input[0].witness =
        escrow.witness(1, vec![sig(&refund, &ep, 0, &escrow.leaves[1], &provider)]);
    let mut early = refund.clone();
    early.input[0].sequence = Sequence::from_height(0);
    for (name, tx) in [
        ("honest-binding", honest),
        ("false-disprove", dispute),
        ("equivocation-penalty", penalty),
        ("same-message", same),
        ("wrong-key", wrong),
        ("redirected-penalty", redirected),
        ("provider-refund", refund),
        ("shortened-refund", early),
    ] {
        write(
            dir.join(format!("{name}.json")),
            json!({"hex":serialize_hex(&tx),"txid":tx.compute_txid().to_string(),"weight":tx.weight().to_wu(),"vsize":tx.vsize()}),
        );
    }
    write(
        dir.join("metadata.json"),
        json!({"network":"regtest","window":WINDOW,"binding_bytes":proof.leaves[0].len(),"equivocation_bytes":escrow.leaves[0].len(),"original_journal":hex(&fields[1]),"alternate_journal":hex(&alternate),"scope":"Counterexample and delayed recovery with setup-fixed keys; no permissionless challenger admission or production fork graph."}),
    );
    emit(json!({"complete":true}));
}
