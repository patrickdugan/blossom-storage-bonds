// Shared Taproot checker for ADR-015 and ADR-016 vectors. Every case carries all of its spent
// outputs, because bitcoinconsensus::verify enables VERIFY_TAPROOT only when they are supplied.
// `field` names the expected verdict for the linked library: "core_valid" for stock Bitcoin Core 26,
// "bip347_valid" for Core 26 with research/bip347-check/bip347.patch. Each case is asserted against it,
// and the run reports consensus-valid counterexamples (valid here, forbidden by the design).
// This checks Script for supplied UTXOs only: not UTXO existence, chain, relay policy or mining.
use serde_json::Value;
use std::io::{self, Read};

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 { return Err("odd-length hex".into()); }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid hex".into())).collect()
}

pub fn run(field: &str, label: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let v: Value = serde_json::from_str(&input)?;
    match v["schema"].as_str() {
        Some("bsb/tapscript-admission-vectors/v1") | Some("bsb/cat-verifier-vectors/v1") => {}
        _ => return Err("wrong vector schema".into()),
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
        let expect = c[field].as_bool().ok_or_else(|| format!("case {name} has no {field}"))?;
        let design = c["design_ok"].as_bool().unwrap_or(false);
        let cx = ok && !design;
        if ok != expect { failed += 1; }
        if cx { counter += 1; }
        println!("{}  {:<36} {}={} design_ok={} {}{:?}",
            if ok == expect { "ok" } else { "FAIL" }, name, field, ok, design,
            if cx { "COUNTEREXAMPLE " } else { "" }, res.err());
    }
    println!("{label}: {} cases, mismatches: {}, consensus-valid counterexamples: {}", cases.len(), failed, counter);
    if failed > 0 { return Err(format!("{failed} consensus mismatches").into()); }
    Ok(())
}
