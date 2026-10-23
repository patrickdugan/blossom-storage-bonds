//! Offline Bitcoin Core 26 libbitcoinconsensus verification for the
//! real rust-bitcoin Taproot sentinel transaction evidence.
 //!
 //! Both legitimate witnesses and adversarial mutations are verified against
 //! the actual P2TR scriptPubKey from the synthetic spent output.
 //!
 //! This checks Script validity for a supplied UTXO and amount. It does NOT
 //! verify UTXO membership, real confirmations, BIP68 relative age in the
 //! active chain, canonical chainwork, miner inclusion or mempool policy.
use serde_json::Value;
use std::io::{self,Read};

fn decode_hex(hex:&str)->Result<Vec<u8>,String>{
    if hex.len()%2!=0{return Err("odd hex byte count".into());}
    (0..hex.len()).step_by(2)
      .map(|i|u8::from_str_radix(&hex[i..i+2],16)
           .map_err(|_|"invalid hex".to_string())).collect()
}
fn check(name:&str,raw:&str,spent_script:&str,spent_value:u64,should_accept:bool)->Result<bool,String>{
    let raw=decode_hex(raw)?;
    let script=decode_hex(spent_script)?;
    let result=bitcoinconsensus::verify(&script,spent_value,&raw,None,0);
    let accepted=result.is_ok();
    println!("{}  {:<48} expected={} actual={} {:?}",
        if accepted==should_accept{"ok"}else{"FAIL"},
        name,should_accept,accepted,result.err());
    Ok(accepted==should_accept)
}
fn field<'a>(v:&'a Value,name:&str)->Result<&'a str,String>{
    v[name].as_str().ok_or_else(||format!("missing field {name}"))
}
fn amount(v:&Value)->Result<u64,String>{
    v["spent_value"].as_u64().ok_or_else(||"missing spent_value".to_string())
}
fn main()->Result<(),Box<dyn std::error::Error>>{
    let mut input=String::new();
    io::stdin().read_to_string(&mut input)?;
    let v:Value=serde_json::from_str(&input)?;
    if field(&v,"schema")?!="bsb/taproot-real-serialization-evidence/v1"{
        return Err("unknown evidence schema".into());
    }
    if field(&v,"internal_key")?!="NUMS"{
        return Err("expected NUMS operational bond mode".into());
    }
    let mut checked=0usize;
    let mut failures=0usize;
    for row in v["transactions"].as_array().ok_or("missing transactions")?{
        let name=field(row,"name")?;
        let script=field(row,"spent_script")?;
        let value=amount(row)?;
        checked+=1;
        if !check(name,field(row,"raw_hex")?,script,value,true)?{failures+=1;}
        let attacks=row["adversarial_raw_hex"].as_object()
            .ok_or("missing adversarial raw transaction evidence")?;
        for (label,raw) in attacks {
            let raw=raw.as_str().ok_or("attack missing raw bytes")?;
            checked+=1;
            if !check(&format!("{name}/{label}"),raw,script,value,false)?{failures+=1;}
        }
    }
    for label in ["forfeit","refund"] {
        let row=&v[label];
        checked+=1;
        if !check(label,field(row,"raw_hex")?,field(row,"spent_script")?,
                  amount(row)?,true)?{failures+=1;}
    }
    println!("offline Bitcoin Core Taproot witness Script checks: {checked} cases, {failures} failures");
    if failures>0{return Err(format!("{failures} Taproot consensus Script mismatches").into());}
    Ok(())
}
