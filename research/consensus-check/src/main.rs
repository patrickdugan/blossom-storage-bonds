//! Offline per-input Script verification against Bitcoin Core's vendored 26.0
//! libbitcoinconsensus. No Bitcoin node, mempool, miner or chain is involved.
//! This checks caller-supplied legacy Script inputs only. It is not a full Bitcoin transaction
//! or Binohash security audit.
use std::io::{self, Read};
use serde_json::Value;

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 { return Err("odd-length hex".to_string()); }
    let mut b = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        b.push(u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid hex".to_string())?);
    }
    Ok(b)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input=String::new();
    io::stdin().read_to_string(&mut input)?;
    let vectors:Value=serde_json::from_str(&input)?;
    let schema=vectors["schema"].as_str().ok_or("missing schema")?;
    let checks: Vec<(usize,Vec<u8>,u64)> = match schema {
        "bsb/unfunded-script-vectors/v1" => vec![(
            vectors["input_index"].as_u64().ok_or("missing input index")? as usize,
            decode_hex(vectors["script_pub_key"].as_str().ok_or("missing script_pub_key")?)?,
            vectors["spent_output_amount_sats"].as_u64().ok_or("missing amount")?
        )],
        "bsb/unfunded-multi-script-vectors/v1" => vectors["checks"]
            .as_array().ok_or("missing checks")?
            .iter().map(|v| -> Result<(usize,Vec<u8>,u64),String> {
                Ok((v["input_index"].as_u64().ok_or("missing check index")? as usize,
                    decode_hex(v["script_pub_key"].as_str().ok_or("missing check script")?)?,
                    v["spent_output_amount_sats"].as_u64().ok_or("missing check amount")?))
            }).collect::<Result<Vec<_>,String>>()?,
        _ => return Err("wrong vector schema".into())
    };
    if checks.is_empty() {return Err("empty per-input checks".into());}
    let cases=vectors["cases"].as_array().ok_or("missing cases")?;
    let mut failed=0;
    for case in cases {
        let name=case["name"].as_str().ok_or("missing name")?;
        let expected=case["expected_valid"].as_bool().ok_or("missing expected validity")?;
        let raw=decode_hex(case["tx_hex"].as_str().ok_or("missing tx bytes")?)?;
        let mut actual=true;
        let mut results=Vec::new();
        for (index,script,amount) in &checks {
            let verified=bitcoinconsensus::verify(script,*amount,&raw,None,*index);
            let ok=verified.is_ok();
            if let Some(exp)=case["expected_inputs"].as_array() {
                let entry=exp.iter().find(|row| row["input_index"].as_u64()==Some(*index as u64))
                    .ok_or("missing expected input check")?;
                if entry["expected_valid"].as_bool()!=Some(ok){failed+=1;}
            }
            results.push(format!("input {}: {} {:?}", index, ok,verified.err()));
            actual &= ok;
        }
        println!("{}  {:<44} expected={} actual={} checks={}",
            if expected==actual{"ok"}else{"FAIL"},name,expected,actual,results.join("; "));
        if actual!=expected{failed+=1;}
    }
    println!("offline Bitcoin Core 26 input Script verification: {} cases, {} failures",cases.len(),failed);
    if failed>0{return Err(format!("{} consensus mismatches",failed).into());}
    Ok(())
}
