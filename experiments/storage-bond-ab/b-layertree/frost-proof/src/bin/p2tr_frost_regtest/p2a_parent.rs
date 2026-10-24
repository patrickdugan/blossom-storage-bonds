//! One-input, zero-fee v3 FROST parent and separately funded v3 P2A child.
use super::*;
pub(super) const FEE:u64=3000;
pub(super) fn anchor()->ScriptBuf{
    ScriptBuf::from_bytes(vec![0x51,0x02,0x4e,0x73])
}
pub(super) fn output(value:u64,script:&ScriptBuf)->TxOut{
    TxOut{value:Amount::from_sat(value),script_pubkey:script.clone()}
}
pub(super) fn parent(prev:OutPoint,mut outputs:Vec<TxOut>)->Transaction{
    outputs.push(output(0,&anchor()));
    Transaction{
        version:Version(3),lock_time:LockTime::ZERO,
        input:vec![TxIn{previous_output:prev,script_sig:ScriptBuf::new(),
            sequence:Sequence::ENABLE_RBF_NO_LOCKTIME,witness:Witness::new()}],
        output:outputs
    }
}
pub(super) fn signed_parent(
    keys:&Packages,public:&frost::keys::PublicKeyPackage,
    ids:&[frost::Identifier],raw:Transaction,prev:&TxOut,
    p2tr_key:XOnlyPublicKey,rng:&mut OsRng
)->ResultX<Transaction>{
    let (tx,needed)=sign_frost_keypath(
        public,keys,ids,[0,2],&raw,&[prev.clone()],p2tr_key,rng)?;
    require(needed&&tx.version==Version(3)&&tx.input.len()==1 &&
        tx.input[0].witness.len()==1,
        "single-input v3 parent lacks FROST 2-of-3 BIP341 signature")?;
    require(tx.output.iter().map(|o|o.value.to_sat()).sum::<u64>()==
        prev.value.to_sat()&&tx.output.last().unwrap().script_pubkey==anchor(),
        "signed v3 parent lost collateral or P2A anchor")?;
    Ok(tx)
}
pub(super) fn record(tx:&Transaction,point:OutPoint)->Value{
    json!({
        "signedHex":serialize_hex(tx),
        "txid":tx.compute_txid().to_string(),
        "wtxid":tx.compute_wtxid().to_string(),
        "vsize":tx.vsize(),
        "version":tx.version.0,
        "carrierBefore":point.to_string(),
        "carrierPrincipalSats":tx.output.iter().map(|o|o.value.to_sat()).sum::<u64>(),
        "anchorOutIndex":tx.output.len()-1,
        "noSponsorInput":true,
        "feePaidByParentSats":0,
        "outputs":tx.output.iter().enumerate().map(|(i,o)|json!({
            "vout":i,"sats":o.value.to_sat(),
            "script_pubkey_hex":hex(o.script_pubkey.as_bytes())
        })).collect::<Vec<_>>()
    })
}
pub(super) fn fund_child(
    rpc:&Rpc,parent:&Transaction,fee_point:OutPoint,fee_coin:&TxOut,
    fee_change_script:&ScriptBuf,wallet:&str
)->ResultX<Transaction>{
    require(parent.version==Version(3)&&
        parent.output.last().unwrap().script_pubkey==anchor()&&
        fee_coin.value.to_sat()>FEE,"invalid TRUC P2A package funding")?;
    let anchor_out=OutPoint::new(parent.compute_txid(),(parent.output.len()-1) as u32);
    let unsigned=Transaction{
        version:Version(3),lock_time:LockTime::ZERO,
        input:vec![
            TxIn{previous_output:anchor_out,script_sig:ScriptBuf::new(),
                sequence:Sequence::ENABLE_RBF_NO_LOCKTIME,witness:Witness::new()},
            TxIn{previous_output:fee_point,script_sig:ScriptBuf::new(),
                sequence:Sequence::ENABLE_RBF_NO_LOCKTIME,witness:Witness::new()},
        ],
        output:vec![output(fee_coin.value.to_sat()-FEE,fee_change_script)]
    };
    let prevs=json!([{
        "txid":anchor_out.txid.to_string(),"vout":anchor_out.vout,
        "scriptPubKey":hex(anchor().as_bytes()),"amount":0.0
    }]);
    let signed=rpc.call("signrawtransactionwithwallet",
        &[json!(serialize_hex(&unsigned)),prevs],Some(wallet))?;
    let tx:Transaction=deserialize(&unhex(signed["hex"].as_str()
        .ok_or("fee payer did not sign P2A child")?)?)?;
    require(tx.compute_txid()==unsigned.compute_txid()&&
        tx.input[0].previous_output==anchor_out&&
        tx.input[1].previous_output==fee_point&&
        tx.input[0].witness.is_empty()&&!tx.input[1].witness.is_empty(),
        "fee payer changed signed TRUC child input ancestry")?;
    Ok(tx)
}
pub(super) fn submit(rpc:&Rpc,parent:&Transaction,child:&Transaction)->ResultX<()>{
    let x=rpc.call("submitpackage",
        &[json!([serialize_hex(parent),serialize_hex(child)])],None)?;
    require(x["package_msg"]=="success",
        "Bitcoin Core did not accept signed FROST P2A 1p1c package")
}
