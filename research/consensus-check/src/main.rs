//! Offline per-input Script verification against Bitcoin Core's vendored 26.0
//! libbitcoinconsensus. No Bitcoin node, mempool, miner or chain is involved.
//! This checks one legacy Script input only. It is not a full Bitcoin transaction
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
    if vectors["schema"]!="bsb/unfunded-script-vectors/v1" {return Err("wrong vector schema".into());}
    let script=decode_hex(vectors["script_pub_key"].as_str().ok_or("missing script_pub_key")?)?;
    let amount=vectors["spent_output_amount_sats"].as_u64().ok_or("bad amount")?;
    let index=vectors["input_index"].as_u64().ok_or("bad input index")? as usize;
    let cases=vectors["cases"].as_array().ok_or("missing cases")?;
    let mut failed=0;
    for case in cases {
        let name=case["name"].as_str().ok_or("missing name")?;
        let expected=case["expected_valid"].as_bool().ok_or("missing expected validity")?;
        let raw=decode_hex(case["tx_hex"].as_str().ok_or("missing tx bytes")?)?;
        let result=bitcoinconsensus::verify(&script,amount,&raw,None,index);
        let actual=result.is_ok();
        println!("{}  {:<44} expected={} actual={} err={:?}",
            if expected==actual{"ok"}else{"FAIL"},name,expected,actual,result.err());
        if actual!=expected{failed+=1;}
    }
    println!("offline Bitcoin Core 26 Script verification: {} cases, {} failures",cases.len(),failed);
    if failed>0{return Err(format!("{} consensus mismatches",failed).into());}
    Ok(())
}
