//! Transaction-carrier falsification tool. It signs nothing and creates no proofs.
use bitcoin::{
    consensus::encode::{deserialize, serialize_hex},
    hashes::Hash,
    script::{Builder, PushBytesBuf},
    Amount, Transaction, TxOut, Witness,
};
use bsb_bitvm_check::graph_support::{bytes, read, write};
use serde_json::json;
use std::path::Path;

fn main() {
    let a: Vec<_> = std::env::args().collect();
    assert_eq!(a.len(), 4, "<tx.json> <32-byte commitment hex> <new-dir>");
    let payload = bytes(&a[2]);
    assert_eq!(payload.len(), 32);
    let v = read(&a[1]);
    let tx: Transaction = deserialize(&bytes(v["hex"].as_str().unwrap())).unwrap();
    let dir = Path::new(&a[3]);
    std::fs::create_dir(dir).unwrap();
    for kind in ["output", "annex", "stack"] {
        let mut changed = tx.clone();
        match kind {
            "output" => changed.output.push(TxOut {
                value: Amount::ZERO,
                script_pubkey: Builder::new()
                    .push_opcode(bitcoin::opcodes::all::OP_RETURN)
                    .push_slice(PushBytesBuf::try_from(payload.clone()).unwrap())
                    .into_script(),
            }),
            "annex" => {
                let mut w = changed.input[0].witness.to_vec();
                w.push([vec![0x50], payload.clone()].concat());
                changed.input[0].witness = Witness::from_slice(&w);
            }
            "stack" => {
                let w = [vec![payload.clone()], changed.input[0].witness.to_vec()].concat();
                changed.input[0].witness = Witness::from_slice(&w);
            }
            _ => unreachable!(),
        }
        assert_ne!(changed.compute_wtxid(), tx.compute_wtxid());
        assert_eq!(
            changed.compute_txid() == tx.compute_txid(),
            kind != "output"
        );
        write(
            dir.join(format!("{kind}.json")),
            json!({
                "hex":serialize_hex(&changed),"txid":changed.compute_txid().to_string(),
                "wtxid":changed.compute_wtxid().to_string(),"baseTxid":tx.compute_txid().to_string(),
                "baseWtxid":tx.compute_wtxid().to_string(),"carrier":kind,
                "commitment":a[2],"txidUnchanged":changed.compute_txid()==tx.compute_txid()
            }),
        );
    }
    // Record canonical serialization as a separate guard against a caller's stale txid field.
    write(
        dir.join("base.json"),
        json!({"hex":serialize_hex(&tx),
        "txid":tx.compute_txid().to_string(),"wtxid":tx.compute_wtxid().to_string(),
        "witnessHashBytes":tx.compute_wtxid().to_byte_array()}),
    );
}
