//! ADR-015 checker: Bitcoin Core 26 libbitcoinconsensus with Taproot enabled, for any number of inputs.
//!
//! `bitcoinconsensus::verify` enables VERIFY_TAPROOT only when the spent outputs are supplied, so every
//! case carries all of its spent outputs. Each case asserts Core's verdict (`core_valid`), then reports
//! the cases where consensus accepts a spend the design meant to forbid (`counterexample`).
//! This checks Script for supplied UTXOs only: not UTXO existence, chain, relay policy or mining.
use serde_json::Value;
use std::io::{self, Read};

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 { return Err("odd-length hex".into()); }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid hex".into())).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let v: Value = serde_json::from_str(&input)?;
    if v["schema"].as_str() != Some("bsb/tapscript-admission-vectors/v1") {
        return Err("wrong vector schema".into());
    }
    let cases = v["cases"].as_array().ok_or("missing cases")?;
    let (mut failed, mut counter) = (0usize, 0usize);
    for c in cases {
        let name = c["name"].as_str().ok_or("missing name")?;
        let raw = decode_hex(c["raw_hex"].as_str().ok_or("missing raw_hex")?)?;
        let idx = c["input_index"].as_u64().ok_or("missing input_index")? as usize;
        let spent = c["spent_outputs"].as_array().ok_or("missing spent_outputs")?;
        let scripts: Vec<Vec<u8>> = spent.iter()
            .map(|o| decode_hex(o["script_pub_key"].as_str().unwrap_or("")))
            .collect::<Result<_, _>>()?;
        let values: Vec<u64> = spent.iter().map(|o| o["value"].as_u64().unwrap_or(0)).collect();
        let utxos: Vec<bitcoinconsensus::Utxo> = scripts.iter().zip(&values).map(|(s, val)| bitcoinconsensus::Utxo {
            script_pubkey: s.as_ptr(), script_pubkey_len: s.len() as u32, value: *val as i64,
        }).collect();
        let res = bitcoinconsensus::verify(&scripts[idx], values[idx], &raw, Some(&utxos), idx);
        let ok = res.is_ok();
        let expect = c["core_valid"].as_bool().ok_or("missing core_valid")?;
        let cx = c["counterexample"].as_bool() == Some(true);
        if ok != expect { failed += 1; }
        if ok && cx { counter += 1; }
        println!("{}  {:<36} core={} design_ok={} {}{:?}",
            if ok == expect { "ok" } else { "FAIL" }, name, ok,
            c["design_ok"].as_bool().unwrap_or(false),
            if ok && cx { "COUNTEREXAMPLE " } else { "" }, res.err());
    }
    println!("ADR-015 Bitcoin Core 26 Taproot cases: {}, mismatches: {}, consensus-valid counterexamples: {}",
        cases.len(), failed, counter);
    if failed > 0 { return Err(format!("{failed} consensus mismatches").into()); }
    Ok(())
}
