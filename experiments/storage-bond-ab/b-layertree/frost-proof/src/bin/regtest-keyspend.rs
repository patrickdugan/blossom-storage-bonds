//! Disposable Bitcoin Core regtest BIP341 P2TR key-spend with real
//! Zcash Foundation FROST-secp256k1-tr 3.0.0, 2-of-3 signing shares.
//! This is neither LayerTree MID enforcement nor a storage validity proof.
//! Both legitimate and fraudulent messages can be threshold signed.
//! Never use mainnet funds or reuse the generated shares.
use bitcoin::{
    absolute::LockTime, address::NetworkUnchecked, consensus::encode::serialize_hex,
    hashes::Hash, key::TapTweak, sighash::{Prevouts,SighashCache,TapSighashType},
    transaction::Version, Amount, Network, OutPoint, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness, Address,
};
use frost_secp256k1_tr as frost;
use rand_core::OsRng;
use secp256k1::{Message, PublicKey, Secp256k1, XOnlyPublicKey, schnorr};
use serde_json::{Value,json};
use std::{collections::BTreeMap,env,error::Error,process::Command,str::FromStr};
type E=Box<dyn Error>;
fn require(ok:bool, reason:&str)->Result<(),E>{if ok{Ok(())}else{Err(reason.into())}}
fn call(binary:&str,data:&str,wallet:Option<&str>,method:&str,args:&[String])->Result<Value,E>{
    let mut cmd=Command::new(binary);
    cmd.arg("-regtest").arg(format!("-datadir={data}"));
    if let Some(w)=wallet{cmd.arg(format!("-rpcwallet={w}"));}
    cmd.arg(method).args(args);
    let result=cmd.output()?;
    require(result.status.success(),&format!("bitcoin-cli {method}: {}",String::from_utf8_lossy(&result.stderr)))?;
    let s=String::from_utf8(result.stdout)?;
    Ok(serde_json::from_str(&s).unwrap_or_else(|_|Value::String(s.trim().into())))
}
fn arg(v:&Value)->String{match v{Value::String(s)=>s.clone(),_=>v.to_string()}}
fn cli(b:&str,d:&str,w:Option<&str>,m:&str,args:&[Value])->Result<Value,E>{
    call(b,d,w,m,&args.iter().map(arg).collect::<Vec<_>>())
}
fn strval<'a>(v:&'a Value)->Result<&'a str,E>{v.as_str().ok_or_else(||"expected Bitcoin Core string".into())}
fn btc_json_sats(v:&Value)->Result<u64,E>{
    let s=v.to_string();let s=s.trim_matches('"');
    let mut split=s.split('.');
    let major:u64=split.next().unwrap_or("0").parse()?;
    let decimals=split.next().unwrap_or("");
    require(decimals.len()<=8 && split.next().is_none(),"Bitcoin amount has excessive decimals")?;
    let minor:u64=format!("{decimals:0<8}").parse()?;
    Ok(major*100_000_000+minor)
}
fn group_key(p:&frost::keys::PublicKeyPackage)->Result<XOnlyPublicKey,E>{
    let raw=p.verifying_key().serialize()?;
    match raw.len(){33=>Ok(PublicKey::from_slice(&raw)?.x_only_public_key().0),
        32=>Ok(XOnlyPublicKey::from_slice(&raw)?),_=>Err("unknown key size".into())}
}
fn threshold_sign(
    ids:&[frost::Identifier],keys:&BTreeMap<frost::Identifier,frost::keys::KeyPackage>,
    public:&frost::keys::PublicKeyPackage,msg:&[u8;32],
)->Result<(Vec<u8>,bool),E>{
    require(ids.len()==2 && ids[0]!=ids[1],"2 distinct signer IDs required")?;
    let mut rng=OsRng;
    let mut nonce_map=BTreeMap::new();let mut commitments=BTreeMap::new();
    for id in ids{
        let key=keys.get(id).ok_or("unknown FROST key")?;
        let (nonce,com)=frost::round1::commit(key.signing_share(),&mut rng);
        nonce_map.insert(*id,nonce);commitments.insert(*id,com);
    }
    let pkg=frost::SigningPackage::new(commitments,msg);
    let mut sigshares=BTreeMap::new();
    for id in ids{
        let share=frost::round2::sign_with_tweak(&pkg,nonce_map.get(id).unwrap(),
            keys.get(id).unwrap(),None)?;
        sigshares.insert(*id,share);
    }
    let signature=frost::aggregate_with_tweak(&pkg,&sigshares,public,None)?;
    sigshares.remove(&ids[1]);
    let incomplete=frost::aggregate_with_tweak(&pkg,&sigshares,public,None).is_err();
    require(incomplete,"single FROST share falsely accepted")?;
    Ok((signature.serialize()?,incomplete))
}
fn tx_for(outpoint:OutPoint,to:ScriptBuf,value:u64)->Transaction{
    Transaction{version:Version(2),lock_time:LockTime::ZERO,
        input:vec![TxIn{previous_output:outpoint,script_sig:ScriptBuf::new(),
            sequence:Sequence::ENABLE_RBF_NO_LOCKTIME,witness:Witness::new()}],
        output:vec![TxOut{value:Amount::from_sat(value),script_pubkey:to}]}
}
fn signed(mut tx:Transaction,sig:&[u8])->Transaction{
    tx.input[0].witness=Witness::from_slice(&[sig]);tx
}
fn intent_sighash(tx:&Transaction,prev:&TxOut)->Result<[u8;32],E>{
    let digest=SighashCache::new(tx).taproot_key_spend_signature_hash(
        0,&Prevouts::All(&[prev.clone()]),TapSighashType::Default)?;
    Ok(digest.to_byte_array())
}
fn main_run()->Result<Value,E>{
    let args=env::args().skip(1).collect::<Vec<_>>();
    require(args.len()==3,"usage: bsb-frost-bip341-regtest BITCOIN_CLI DATADIR ALICE_FAULT_EVIDENCE_SHA256")?;
    let cli_bin=&args[0];let dir=&args[1];let evidence=&args[2];
    require(evidence.len()==64 && evidence.bytes().all(|x|x.is_ascii_hexdigit()),"invalid source PDP hash")?;
    let network=cli(cli_bin,dir,None,"getblockchaininfo",&[])?;
    require(network["chain"]=="regtest","Bitcoin Core must be disposable regtest")?;
    let mut rng=OsRng;
    let (shares,public)=frost::keys::generate_with_dealer(
        3,2,frost::keys::IdentifierList::Default,&mut rng)?;
    let mut packages=BTreeMap::new();
    for (id,share) in shares{packages.insert(id,frost::keys::KeyPackage::try_from(share)?);}
    let ids=packages.keys().copied().collect::<Vec<_>>();
    let secp=Secp256k1::new();let internal=group_key(&public)?;
    let p2tr=Address::p2tr(&secp,internal,None,Network::Regtest);
    let tweaked=internal.tap_tweak(&secp,None).0;
    require(p2tr.script_pubkey()==Address::p2tr_tweaked(tweaked,Network::Regtest).script_pubkey(),
        "FROST tweaked key mismatches native Bitcoin Taproot key")?;
    cli(cli_bin,dir,None,"createwallet",&[json!("frost-miner")])?;
    let miner=strval(&cli(cli_bin,dir,Some("frost-miner"),"getnewaddress",&[])? )?.to_owned();
    cli(cli_bin,dir,None,"generatetoaddress",&[json!(101),json!(miner)])?;
    let funding=strval(&cli(cli_bin,dir,Some("frost-miner"),"sendtoaddress",&[
        json!(p2tr.to_string()),json!(0.001)])?)?.to_owned();
    cli(cli_bin,dir,None,"generatetoaddress",&[json!(6),json!(miner)])?;
    let funded=cli(cli_bin,dir,None,"getrawtransaction",&[json!(funding),json!(true)])?;
    let outputs=funded["vout"].as_array().ok_or("no actual funding outputs")?;
    let choices=outputs.iter().filter(|o|
       o["scriptPubKey"]["hex"]==format!("{:x}",p2tr.script_pubkey().as_script()) &&
       btc_json_sats(&o["value"]).ok()==Some(100_000)).collect::<Vec<_>>();
    require(choices.len()==1,"actual P2TR 100k funding not found")?;
    let index=choices[0]["n"].as_u64().ok_or("missing P2TR index")? as u32;
    let outpoint=OutPoint{txid:Txid::from_str(&funding)?,vout:index};
    let prev=TxOut{value:Amount::from_sat(100_000),script_pubkey:p2tr.script_pubkey()};
    let alice=strval(&cli(cli_bin,dir,Some("frost-miner"),"getnewaddress",&[])?)?.to_owned();
    let alice_address=Address::<NetworkUnchecked>::from_str(&alice)?.require_network(Network::Regtest)?;
    let unsigned=tx_for(outpoint,alice_address.script_pubkey(),99_000);
    let sighash=intent_sighash(&unsigned,&prev)?;
    let (signature,one_rejected)=threshold_sign(&ids[..2],&packages,&public,&sighash)?;
    require(signature.len()==64,"invalid BIP340 FROST signature length")?;
    secp.verify_schnorr(&schnorr::Signature::from_slice(&signature)?,
       &Message::from_digest(sighash),&tweaked.to_x_only_public_key())?;
    let valid=signed(unsigned.clone(),&signature);
    let raw=serialize_hex(&valid);
    let checked=cli(cli_bin,dir,None,"testmempoolaccept",&[json!([raw.clone()])])?;
    require(checked[0]["allowed"]==true,"Bitcoin rejected actual FROST BIP341 keyspend")?;

    let destination=strval(&cli(cli_bin,dir,Some("frost-miner"),"getnewaddress",&[])?)?.to_owned();
    let theft_addr=Address::<NetworkUnchecked>::from_str(&destination)?.require_network(Network::Regtest)?;
    let theft_unsigned=tx_for(outpoint,theft_addr.script_pubkey(),99_000);
    let malicious_msg=intent_sighash(&theft_unsigned,&prev)?;
    let (bad_sig,_)=threshold_sign(&ids[..2],&packages,&public,&malicious_msg)?;
    let forged=signed(theft_unsigned,&bad_sig);
    let bad_accept=cli(cli_bin,dir,None,"testmempoolaccept",&[json!([serialize_hex(&forged)])])?;
    require(bad_accept[0]["allowed"]==true,"two malicious FROST shares did not authorize theft")?;
    require(secp.verify_schnorr(&schnorr::Signature::from_slice(&bad_sig)?,
       &Message::from_digest(sighash),&tweaked.to_x_only_public_key()).is_err(),
       "malicious redirected signature validated honest sighash")?;

    let txid=strval(&cli(cli_bin,dir,None,"sendrawtransaction",&[json!(raw)])?)?.to_owned();
    cli(cli_bin,dir,None,"generatetoaddress",&[json!(6),json!(miner)])?;
    let confirmed=cli(cli_bin,dir,None,"getrawtransaction",&[json!(txid),json!(true)])?;
    require(confirmed["confirmations"].as_u64().unwrap_or(0)>=6 &&
      confirmed["hash"]==valid.compute_wtxid().to_string(),
      "Bitcoin confirmed unexpected wtxid")?;
    let block=strval(&confirmed["blockhash"])?;
    let header=cli(cli_bin,dir,None,"getblockheader",&[json!(block),json!(true)])?;
    let height=header["height"].as_u64().ok_or("no confirmation height")?;
    require(cli(cli_bin,dir,None,"getblockhash",&[json!(height)])?==block,
        "Bitcoin Core reports stale branch")?;
    let actual_fee=100_000-99_000;
    Ok(json!({"schema":"bsb-frost-bip341-funded-regtest-v1",
      "network":"regtest","realBip341P2trKeySpendConfirmed":true,
      "frostThreshold":"2-of-3","sourceEvidenceHash":evidence,
      "signingMaterial":"ephemeral dealer in one process, not DKG",
      "p2trScriptPubKey":format!("{:x}",p2tr.script_pubkey().as_script()),
      "keypathSignatureBytes":64,"tapTweakApplied":true,
      "oneSignerAggregateRejected":one_rejected,
      "maliciousQuorumRedirectAllowedByBitcoinMempool":true,
      "maliciousTransactionBroadcast":false,
      "sourcePdpVerdictEnforcedByBitcoin":false,
      "sapioMidEnforced":false,"filecoinFaultVerified":false,
      "txid":txid,"wtxid":confirmed["hash"],
      "confirmationDepth":confirmed["confirmations"],"confirmationHeight":height,
      "measuredVbytes":confirmed["vsize"],"feeSats":actual_fee,
      "recipientPaidSats":99_000,
      "entitlement60k40kSplitPerformed":false}))
}
fn main(){
    match main_run(){
      Ok(receipt)=>println!("{}",serde_json::to_string_pretty(&receipt).unwrap()),
      Err(e)=>{eprintln!("BIP341 FROST regtest: {e}");std::process::exit(1)}
    }
}
