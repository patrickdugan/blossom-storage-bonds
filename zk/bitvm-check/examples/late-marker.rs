//! Deliberately incomplete late-marker attachment designs; isolated regtest only.
//! This tests signature/input authentication, not headers or Groth16 verification.
use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::{deserialize, serialize_hex};
use bitcoin::hashes::{sha256, Hash};
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

const POT: u64 = 100_000_000;
const MARKER: u64 = 100_000;
const PAYOUT: u64 = POT - 5_000;
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn bytes(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn key() -> Keypair {
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::new(&mut thread_rng()))
}
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
    fn address(&self) -> String {
        Address::p2tr_tweaked(self.spend.output_key(), Network::Regtest).to_string()
    }
    fn finish(&self, mut data: Vec<Vec<u8>>) -> Witness {
        data.push(self.script.to_bytes());
        data.push(
            self.spend
                .control_block(&(self.script.clone(), LeafVersion::TapScript))
                .unwrap()
                .serialize(),
        );
        Witness::from_slice(&data)
    }
    fn sign(
        &self,
        tx: &mut Transaction,
        index: usize,
        previous: &[TxOut],
        key: &Keypair,
        kind: TapSighashType,
        data: Vec<Vec<u8>>,
    ) {
        let hash = SighashCache::new(&*tx)
            .taproot_script_spend_signature_hash(
                index,
                &Prevouts::All(previous),
                TapLeafHash::from_script(&self.script, LeafVersion::TapScript),
                kind,
            )
            .unwrap();
        let sig = Secp256k1::new().sign_schnorr_with_rng(
            &Message::from_digest(hash.to_byte_array()),
            key,
            &mut thread_rng(),
        );
        let mut signature = sig.as_ref().to_vec();
        if kind != TapSighashType::Default {
            signature.push(kind as u8);
        }
        let mut data = data;
        data.push(signature);
        tx.input[index].witness = self.finish(data);
    }
}
fn input(previous_output: OutPoint) -> TxIn {
    TxIn {
        previous_output,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    }
}
fn transaction(previous: OutPoint, payout: ScriptBuf) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input(previous)],
        output: vec![TxOut {
            value: Amount::from_sat(PAYOUT),
            script_pubkey: payout,
        }],
    }
}
fn record(tx: &Transaction) -> Value {
    json!({"hex":serialize_hex(tx),"txid":tx.compute_txid().to_string(),"wtxid":tx.compute_wtxid().to_string(),"input_count":tx.input.len()})
}
fn number(n: u16) -> Vec<u8> {
    let b = n.to_le_bytes();
    assert!(n >= 128 && n < 32768);
    b.to_vec()
}
fn toy_marker(tag: [u8; 32], signer: Option<XOnlyPublicKey>) -> Leaf {
    let mut b = Builder::new();
    if let Some(x) = signer {
        b = b.push_x_only_key(&x).push_opcode(OP_CHECKSIGVERIFY);
    }
    Leaf::new(
        b.push_opcode(OP_SHA256)
            .push_slice(sha256::Hash::hash(&tag).to_byte_array())
            .push_opcode(OP_EQUALVERIFY)
            .push_int(466)
            .push_opcode(OP_GREATERTHAN)
            .into_script(),
    )
}
fn emit(v: Value) {
    println!("BSB_ATTACH {v}");
    io::stdout().flush().unwrap();
}
fn receive() -> Value {
    serde_json::from_str(&io::stdin().lock().lines().next().unwrap().unwrap()).unwrap()
}
fn outpoint(v: &Value, index: usize) -> OutPoint {
    OutPoint::new(
        v["txid"].as_str().unwrap().parse().unwrap(),
        v["vouts"][index].as_u64().unwrap().try_into().unwrap(),
    )
}
fn previous(v: &Value) -> TxOut {
    TxOut {
        value: Amount::from_sat(v["value_sats"].as_u64().unwrap()),
        script_pubkey: ScriptBuf::from_bytes(bytes(v["script_pubkey"].as_str().unwrap())),
    }
}
fn setup() {
    let keys = [key(), key(), key()];
    let leaves: Vec<Leaf> = keys
        .iter()
        .map(|k| {
            Leaf::new(
                Builder::new()
                    .push_x_only_key(&k.x_only_public_key().0)
                    .push_opcode(OP_CHECKSIG)
                    .into_script(),
            )
        })
        .collect();
    let client = key();
    let payout = Address::p2tr(
        &Secp256k1::new(),
        client.x_only_public_key().0,
        None,
        Network::Regtest,
    )
    .script_pubkey();
    let fixed = toy_marker([1; 32], None);
    let mut funding: Vec<Value> = leaves
        .iter()
        .map(|l| json!({"address":l.address(),"sats":POT}))
        .collect();
    funding.push(json!({"address":fixed.address(),"sats":MARKER}));
    emit(
        json!({"ready":true,"network":"regtest","funding":funding,"setup_public_keys":keys.iter().map(|k|k.x_only_public_key().0.to_string()).collect::<Vec<_>>()}),
    );
    let v = receive();
    assert_eq!(v["network"], "regtest");
    assert_eq!(v["vouts"].as_array().unwrap().len(), 4);
    let mut txs = serde_json::Map::new();
    let mut prevs = Vec::new();
    for (i, (name, kind)) in [
        ("single", TapSighashType::SinglePlusAnyoneCanPay),
        ("all", TapSighashType::AllPlusAnyoneCanPay),
        ("strict", TapSighashType::Default),
    ]
    .into_iter()
    .enumerate()
    {
        let root = leaves[i].output(POT);
        prevs.push(json!({"value_sats":POT,"script_pubkey":hex(root.script_pubkey.as_bytes())}));
        let mut tx = transaction(outpoint(&v, i), payout.clone());
        let mut prev = vec![root];
        if i == 2 {
            tx.input.push(input(outpoint(&v, 3)));
            prev.push(fixed.output(MARKER));
            tx.input[1].witness = fixed.finish(vec![number(468), vec![1; 32]]);
        }
        leaves[i].sign(&mut tx, 0, &prev, &keys[i], kind, vec![]);
        txs.insert(name.to_string(), record(&tx));
    }
    emit(
        json!({"complete":true,"network":"regtest","transactions":txs,"previous":prevs,"payout_script":hex(payout.as_bytes()),"marker_sats":MARKER,"scope":"Toy late-marker attachment counterexamples. No chain-work or Groth16 verification; existing storage graph unchanged. Single signing key stands in for committee authorization solely to test sighash semantics."}),
    );
}
fn late(tag: [u8; 32]) {
    let challenger = key();
    let x = challenger.x_only_public_key().0;
    let honest = toy_marker(tag, Some(x));
    let trivial = Leaf::new(Builder::new().push_int(1).into_script());
    emit(
        json!({"ready":true,"network":"regtest","late_public_key":x.to_string(),"funding":[{"address":honest.address(),"sats":MARKER},{"address":trivial.address(),"sats":MARKER}]}),
    );
    let v = receive();
    assert_eq!(v["network"], "regtest");
    let s = &v["setup"];
    let templates = &s["transactions"];
    let base = |name: &str| {
        deserialize::<Transaction>(&bytes(templates[name]["hex"].as_str().unwrap())).unwrap()
    };
    let attach = |mut tx: Transaction,
                  index: usize,
                  leaf: &Leaf,
                  point: OutPoint,
                  work: u16,
                  data: [u8; 32],
                  sign: bool| {
        tx.input.truncate(1);
        tx.input.push(input(point));
        if sign {
            leaf.sign(
                &mut tx,
                1,
                &[previous(&s["previous"][index]), leaf.output(MARKER)],
                &challenger,
                TapSighashType::Default,
                vec![number(work), data.to_vec()],
            );
        } else {
            tx.input[1].witness = leaf.finish(vec![]);
        }
        tx
    };
    let mut result = serde_json::Map::new();
    for (index, name) in ["single", "all"].into_iter().enumerate() {
        result.insert(format!("{name}_omitted"), record(&base(name)));
        let good = attach(base(name), index, &honest, outpoint(&v, 0), 468, tag, true);
        result.insert(format!("{name}_honest"), record(&good));
        result.insert(
            format!("{name}_equal_work"),
            record(&attach(
                base(name),
                index,
                &honest,
                outpoint(&v, 0),
                466,
                tag,
                true,
            )),
        );
        let mut wrong = tag;
        wrong[0] ^= 1;
        result.insert(
            format!("{name}_wrong_tag"),
            record(&attach(
                base(name),
                index,
                &honest,
                outpoint(&v, 0),
                468,
                wrong,
                true,
            )),
        );
        result.insert(
            format!("{name}_trivial"),
            record(&attach(
                base(name),
                index,
                &trivial,
                outpoint(&v, 1),
                0,
                [0; 32],
                false,
            )),
        );
        let mut redirect = base(name);
        let mut script = redirect.output[0].script_pubkey.to_bytes();
        *script.last_mut().unwrap() ^= 1;
        redirect.output[0].script_pubkey = ScriptBuf::from_bytes(script);
        result.insert(
            format!("{name}_redirected"),
            record(&attach(
                redirect,
                index,
                &honest,
                outpoint(&v, 0),
                468,
                tag,
                true,
            )),
        );
        let mut annex = good;
        let mut witness: Vec<Vec<u8>> = annex.input[0].witness.iter().map(|b| b.to_vec()).collect();
        witness.push([&[0x50][..], &tag].concat());
        annex.input[0].witness = Witness::from_slice(&witness);
        result.insert(format!("{name}_late_annex"), record(&annex));
    }
    result.insert("strict_original".into(), record(&base("strict")));
    let mut omitted = base("strict");
    omitted.input.pop();
    result.insert("strict_omitted".into(), record(&omitted));
    result.insert(
        "strict_honest_substitution".into(),
        record(&attach(
            base("strict"),
            2,
            &honest,
            outpoint(&v, 0),
            468,
            tag,
            true,
        )),
    );
    result.insert(
        "strict_trivial_substitution".into(),
        record(&attach(
            base("strict"),
            2,
            &trivial,
            outpoint(&v, 1),
            0,
            [0; 32],
            false,
        )),
    );
    let mut wrong = base("strict");
    let mut witness: Vec<Vec<u8>> = wrong.input[1].witness.iter().map(|b| b.to_vec()).collect();
    witness[0] = number(466);
    wrong.input[1].witness = Witness::from_slice(&witness);
    result.insert("strict_equal_work".into(), record(&wrong));
    emit(
        json!({"complete":true,"network":"regtest","late_public_key":x.to_string(),"transactions":result}),
    );
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("setup") => setup(),
        Some("late") => late(bytes(&args[2]).try_into().unwrap()),
        _ => panic!("usage: late-marker setup | late <32-byte-tag-hex>"),
    }
}
