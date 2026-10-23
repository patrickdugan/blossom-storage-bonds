//! Funded Bitcoin Core regtest P2TR with a REAL two-of-three FROST BIP340 keypath.
//! This is a single-process trusted-dealer TEST. It is NOT Sapio MID, a
//! federation that can survive a process crash, or Filecoin adjudication.
//!
//! The FROST signature signs a real BIP341 key-spend sighash; no private
//! FROST shares or nonce secrets are written to disk, printed or exported.
//! Bitcoin Core verifies the transaction and refuses corrupted witnesses.
//! A dishonest 2/3 quorum also has sufficient power to sign a 100% theft.
//!
//! Caller must launch its own disposable Bitcoin Core REGTEST node with
//! txindex=1 and wallets enabled. This binary refuses all other networks.

use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::{deserialize, serialize_hex};
use bitcoin::hashes::Hash as _;
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, XOnlyPublicKey, schnorr};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use frost_secp256k1_tr as frost;
use rand_core::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, env, error::Error, fs, io::Write, path::PathBuf, process::Command, str::FromStr};

type ResultX<T> = Result<T, Box<dyn Error>>;
type Packages = BTreeMap<frost::Identifier, frost::keys::KeyPackage>;

const PRINCIPAL: u64 = 100_000;
const SPONSOR_INITIAL: u64 = 50_000;
const EXTERNAL_FEE: u64 = 3_000;

fn require(value: bool, reason: &'static str) -> ResultX<()> {
    if value { Ok(()) } else { Err(reason.into()) }
}
fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(src: &str) -> ResultX<Vec<u8>> {
    require(src.len() % 2 == 0 && src.bytes().all(|b| b.is_ascii_hexdigit()), "non-hex Bitcoin transaction")?;
    let mut out = Vec::with_capacity(src.len()/2);
    for x in src.as_bytes().chunks_exact(2) {
        out.push(u8::from_str_radix(std::str::from_utf8(x)?,16)?);
    }
    Ok(out)
}
fn sha(bytes: &[u8]) -> [u8;32] {
    Sha256::digest(bytes).into()
}
fn sats_to_btc(sats: u64) -> String {
    format!("{}.{:08}", sats/100_000_000, sats%100_000_000)
}
fn rpc_string(value: Value) -> ResultX<String> {
    Ok(value.as_str().ok_or("Bitcoin Core omitted expected string")?.to_owned())
}
struct Rpc {
    binary: PathBuf,
    datadir: PathBuf,
}
impl Rpc {
    fn call(&self, method: &str, args: &[Value], wallet: Option<&str>) -> ResultX<Value> {
        let mut command = Command::new(&self.binary);
        command.arg("-regtest").arg(format!("-datadir={}",self.datadir.display()));
        if let Some(wallet) = wallet {command.arg(format!("-rpcwallet={wallet}"));}
        command.arg(method);
        for arg in args {
            command.arg(match arg {
                Value::String(x) => x.clone(),
                value => value.to_string(),
            });
        }
        let output = command.output()?;
        if !output.status.success() {
            return Err(format!("{method} failed: {}",
                String::from_utf8_lossy(&output.stderr).chars().take(550).collect::<String>()).into());
        }
        let text = String::from_utf8(output.stdout)?;
        match serde_json::from_str::<Value>(text.trim()) {
            Ok(value) => Ok(value),
            Err(_) => Ok(Value::String(text.trim().to_owned())),
        }
    }
    fn text(&self, method:&str, args:&[Value], wallet: Option<&str>)->ResultX<String>{
        rpc_string(self.call(method,args,wallet)?)
    }
    fn chain(&self) -> ResultX<()> {
        let info = self.call("getblockchaininfo",&[],None)?;
        require(info["chain"]=="regtest","refusing Bitcoin network other than regtest")?;
        // A brand-new PRIVATE regtest node is in IBD at height zero, even
        // though it is the only authority over this throwaway chain.
        let blocks=info["blocks"].as_u64().unwrap_or(0);
        require(info["initialblockdownload"]==false || blocks==0,
            "refusing a populated but unsynced regtest node")
    }
    fn mine(&self, n:u32, address:&str)->ResultX<()>{
        self.call("generatetoaddress",&[json!(n),json!(address)],None)?;
        Ok(())
    }
    fn address(&self, wallet:&str)->ResultX<(String, ScriptBuf)>{
        let raw = self.text("getnewaddress",&[],Some(wallet))?;
        let script = Address::from_str(&raw)?.require_network(Network::Regtest)?.script_pubkey();
        Ok((raw,script))
    }
    fn coin(&self,txid:&str,script:&ScriptBuf,value:u64)->ResultX<(OutPoint,TxOut)> {
        let data = self.call("getrawtransaction",&[json!(txid),json!(true)],None)?;
        let tx:Transaction=deserialize(&unhex(data["hex"].as_str().ok_or("missing funded raw tx")?)?)?;
        require(tx.compute_txid().to_string()==txid,"Bitcoin Core returned wrong funding txid")?;
        let found=tx.output.iter().enumerate().filter(|(_,o)|{
            o.script_pubkey==*script && o.value.to_sat()==value
        }).collect::<Vec<_>>();
        require(found.len()==1,"ambiguous Bitcoin bond/fee funding output")?;
        let vout=found[0].0 as u32;
        let point=OutPoint::new(tx.compute_txid(),vout);
        require(!self.call("gettxout",&[json!(txid),json!(vout)],None)?.is_null(),
            "expected confirmed regtest UTXO is unavailable")?;
        Ok((point,found[0].1.clone()))
    }
    fn witness_authorization(&self,tx:&Transaction)->ResultX<bool>{
        let verdict = self.call("testmempoolaccept",&[json!([serialize_hex(tx)])],None)?;
        Ok(verdict.as_array().and_then(|a|a.first())
            .and_then(|v|v["allowed"].as_bool())==Some(true))
    }
    fn sign_sponsor(&self,tx:&Transaction)->ResultX<Transaction>{
        let signed=self.call("signrawtransactionwithwallet",
            &[json!(serialize_hex(tx))],Some("sponsor"))?;
        require(signed["complete"]==true,"sponsor failed to sign external fee input")?;
        let raw=signed["hex"].as_str().ok_or("missing externally sponsored Bitcoin witness")?;
        let result:Transaction=deserialize(&unhex(raw)?)?;
        require(result.compute_txid()==tx.compute_txid(),
            "sponsor changed the originally committed transaction")?;
        require(result.input[0].witness==tx.input[0].witness,
            "Bitcoin wallet substituted the threshold FROST signature")?;
        Ok(result)
    }
    fn confirmed(&self,id:&str,min:u64)->ResultX<Value>{
        let data=self.call("getrawtransaction",&[json!(id),json!(true)],None)?;
        require(data["confirmations"].as_u64().unwrap_or(0)>=min,
            "signed Taproot carrier is not sufficiently confirmed")?;
        let block=data["blockhash"].as_str().ok_or("confirmed transaction missing blockhash")?;
        let header=self.call("getblockheader",&[json!(block),json!(true)],None)?;
        let height=header["height"].as_u64().ok_or("block header height unavailable")?;
        require(self.text("getblockhash",&[json!(height)],None)?==block,
            "transaction belongs to a stale regtest fork")?;
        Ok(data)
    }
}

fn bitcoin_group_internal_key(public:&frost::keys::PublicKeyPackage)->ResultX<XOnlyPublicKey>{
    let serialized=public.verifying_key().serialize()?;
    Ok(match serialized.len(){
        33 => PublicKey::from_slice(&serialized)?.x_only_public_key().0,
        32 => XOnlyPublicKey::from_slice(&serialized)?,
        _ => return Err("FROST group public key is not a secp256k1 point".into()),
    })
}
fn sign_frost_keypath(
    public:&frost::keys::PublicKeyPackage,
    packages:&Packages,
    identifiers:&[frost::Identifier],
    selected:[usize;2],
    unsigned:&Transaction,
    prevouts:&[TxOut;2],
    taproot_key:XOnlyPublicKey,
    rng:&mut OsRng,
)->ResultX<(Transaction,bool)>{
    require(selected[0]!=selected[1]&&selected.iter().all(|i|*i<identifiers.len()),
        "invalid 2-of-3 signing pair")?;
    let message=SighashCache::new(unsigned).taproot_key_spend_signature_hash(
        0,&Prevouts::All(prevouts),TapSighashType::Default)?.to_byte_array();
    let mut nonces=BTreeMap::new();
    let mut commitments=BTreeMap::new();
    for index in selected {
        let identifier=identifiers[index];
        let package=packages.get(&identifier).ok_or("FROST signer missing share")?;
        let (private_nonces,published_commitments)=frost::round1::commit(
            package.signing_share(),rng);
        nonces.insert(identifier,private_nonces);
        commitments.insert(identifier,published_commitments);
    }
    let signing=frost::SigningPackage::new(commitments,&message);
    let mut signed_shares=BTreeMap::new();
    for index in selected {
        let identifier=identifiers[index];
        let share=frost::round2::sign(&signing,
            nonces.get(&identifier).ok_or("missing FROST secret nonce")?,
            packages.get(&identifier).ok_or("missing verified FROST share")?)?;
        signed_shares.insert(identifier,share);
    }
    let signature=frost::aggregate_with_tweak(&signing,&signed_shares,public,None)?;
    let mut incomplete=signed_shares.clone();
    incomplete.remove(&identifiers[selected[1]]);
    let missing_second_rejected=
        frost::aggregate_with_tweak(&signing,&incomplete,public,None).is_err();
    require(missing_second_rejected,"one share unexpectedly completed FROST threshold")?;
    let signature_bytes=signature.serialize()?;
    require(signature_bytes.len()==64,"FROST P2TR signature not a 64-byte BIP340 witness")?;
    let sig=schnorr::Signature::from_slice(&signature_bytes)?;
    let msg=Message::from_digest(message);
    Secp256k1::verification_only().verify_schnorr(&sig,&msg,&taproot_key)?;
    let wrong_message=Message::from_digest(sha(b"wrong-BIP341-prevouts"));
    require(Secp256k1::verification_only().verify_schnorr(&sig,
        &wrong_message,&taproot_key).is_err(),"FROST signature verifies an unrelated digest")?;
    let mut signed=unsigned.clone();
    signed.input[0].witness=Witness::from_slice(&[signature_bytes]);
    Ok((signed,missing_second_rejected))
}
fn build(
    bond:OutPoint, sponsor:OutPoint,
    recipient_outputs: Vec<TxOut>, sponsor_script:&ScriptBuf,
    new_sponsor_amount:u64,commitment:[u8;32]
)->Transaction{
    let mut outputs=recipient_outputs;
    outputs.push(TxOut{value:Amount::from_sat(new_sponsor_amount),
        script_pubkey:sponsor_script.clone()});
    outputs.push(TxOut{value:Amount::ZERO,script_pubkey:Builder::new()
        .push_opcode(OP_RETURN).push_slice(commitment).into_script()});
    Transaction {
        version:Version(2),lock_time:LockTime::ZERO,
        input:vec![
            TxIn{previous_output:bond,script_sig:ScriptBuf::new(),
                sequence:Sequence::ENABLE_RBF_NO_LOCKTIME,witness:Witness::new()},
            TxIn{previous_output:sponsor,script_sig:ScriptBuf::new(),
                sequence:Sequence::ENABLE_RBF_NO_LOCKTIME,witness:Witness::new()},
        ], output:outputs
    }
}
fn commit(tag:&str,evidence:&str,prev:&OutPoint)->[u8;32]{
    sha(format!("BSB/FROST/P2TR/{tag}|{evidence}|{prev}|alice60000|bob40000").as_bytes())
}
fn inspect_outputs(tx:&Transaction,expected:&[(ScriptBuf,u64)])->ResultX<()>{
    require(tx.output.len()==expected.len(),"P2TR outputs contain unexpected extras")?;
    for (actual,(script,value)) in tx.output.iter().zip(expected){
        require(actual.value.to_sat()==*value && actual.script_pubkey==*script,
            "threshold transaction redirected or shaved a payout")?;
    }
    Ok(())
}
fn output_summary(tx:&Value)->ResultX<Value>{
    let raw=tx["hex"].as_str().ok_or("missing confirmed signed transaction bytes")?;
    let decoded:Transaction=deserialize(&unhex(raw)?)?;
    Ok(json!({
        "txid":decoded.compute_txid().to_string(),
        "wtxid":decoded.compute_wtxid().to_string(),
        "vsize":decoded.vsize(),
        "outputs": decoded.output.iter().enumerate().map(|(index,o)|json!({
            "vout":index,"sats":o.value.to_sat(),
            "script_pubkey_hex":hex(o.script_pubkey.as_bytes())
        })).collect::<Vec<_>>(),
        "confirmations":tx["confirmations"],
        "blockhash":tx["blockhash"]
    }))
}
fn run(args:Vec<String>)->ResultX<()>{
    let mut cli=None;let mut dir=None;let mut evidence=None;let mut out=None;
    let mut items=args.into_iter();
    while let Some(flag)=items.next(){
        let value=items.next().ok_or("argument option has no value")?;
        match flag.as_str(){
            "--bitcoin-cli"=>cli=Some(value),
            "--datadir"=>dir=Some(value),
            "--evidence-hash"=>evidence=Some(value),
            "--out"=>out=Some(value),
            _=>return Err(format!("unknown option {flag}").into()),
        }
    }
    let cli=cli.ok_or("provide --bitcoin-cli")?;
    let dir=dir.ok_or("provide --datadir")?;
    let evidence=evidence.ok_or("provide --evidence-hash")?;
    require(evidence.len()==64&&evidence.bytes().all(|c|c.is_ascii_hexdigit()),
        "storage evidence hash must be a 64-character SHA256 hex digest")?;
    let rpc=Rpc{binary:PathBuf::from(cli),datadir:PathBuf::from(dir)};
    rpc.chain()?;
    let (shares,public)=frost::keys::generate_with_dealer(
        3,2,frost::keys::IdentifierList::Default,&mut OsRng)?;
    let mut packages=Packages::new();
    for (id,share) in shares {packages.insert(id,frost::keys::KeyPackage::try_from(share)?);}
    require(packages.len()==3,"failed to create three ephemeral FROST key packages")?;
    let identifiers=packages.keys().copied().collect::<Vec<_>>();
    let internal_key=bitcoin_group_internal_key(&public)?;
    let secp=Secp256k1::new();
    let vault=Address::p2tr(&secp,internal_key,None,Network::Regtest);
    let vault_script=vault.script_pubkey();
    let taproot_key=XOnlyPublicKey::from_slice(
        vault_script.as_bytes().get(2..34).ok_or("P2TR vault script has wrong size")?)?;
    let wallet_names=["miner","sponsor","alice","bob"];
    for wallet in wallet_names {rpc.call("createwallet",&[json!(wallet)],None)?;}
    let (miner_addr,_)=rpc.address("miner")?;
    // Newly generated regtest chains have no mempool fee history. The miner
    // wallet alone gets an explicit deterministic fee before bootstrapping
    // the bond and independent recovery-fee sponsor.
    require(rpc.call("settxfee",&[json!(0.00002000)],Some("miner"))?==true,
        "Bitcoin Core miner did not accept fixed funding fee")?;
    rpc.mine(101,&miner_addr)?;
    let (sponsor_addr,sponsor_script)=rpc.address("sponsor")?;
    let (_alice_addr,alice_script)=rpc.address("alice")?;
    let (_bob_addr,bob_script)=rpc.address("bob")?;
    require(alice_script!=bob_script,"two beneficiary wallets got the same script")?;
    let thief_script=rpc.address("miner")?.1;
    let fund_id=rpc.text("sendtoaddress",
        &[json!(vault.to_string()),json!(sats_to_btc(PRINCIPAL))],Some("miner"))?;
    let sponsor_id=rpc.text("sendtoaddress",
        &[json!(sponsor_addr),json!(sats_to_btc(SPONSOR_INITIAL))],Some("miner"))?;
    rpc.mine(6,&miner_addr)?;
    let (mut carrier_point,mut carrier_output)=rpc.coin(&fund_id,&vault_script,PRINCIPAL)?;
    let (mut fee_point,mut fee_output)=rpc.coin(&sponsor_id,&sponsor_script,SPONSOR_INITIAL)?;
    let mut rng=OsRng;
    let refresh_commit=commit("refresh",&evidence,&carrier_point);
    let refresh_base=build(carrier_point,fee_point,
        vec![TxOut{value:Amount::from_sat(PRINCIPAL),script_pubkey:vault_script.clone()}],
        &sponsor_script,SPONSOR_INITIAL-EXTERNAL_FEE,refresh_commit);
    let (refresh_frost,one_share_rejected)=sign_frost_keypath(
        &public,&packages,&identifiers,[0,1],&refresh_base,
        &[carrier_output.clone(),fee_output.clone()],taproot_key,&mut rng)?;
    let refresh=rpc.sign_sponsor(&refresh_frost)?;
    require(rpc.witness_authorization(&refresh)?,"2-of-3 Taproot refresh rejected by Bitcoin Core")?;
    inspect_outputs(&refresh,&[
        (vault_script.clone(),PRINCIPAL),
        (sponsor_script.clone(),SPONSOR_INITIAL-EXTERNAL_FEE),
        (Builder::new().push_opcode(OP_RETURN).push_slice(refresh_commit).into_script(),0)])?;
    let refresh_id=rpc.text("sendrawtransaction",&[json!(serialize_hex(&refresh))],None)?;
    require(refresh_id==refresh.compute_txid().to_string(),"regtest changed signed FROST refresh")?;
    rpc.mine(1,&miner_addr)?;
    let confirmed_refresh=rpc.confirmed(&refresh_id,1)?;
    (carrier_point,carrier_output)=rpc.coin(&refresh_id,&vault_script,PRINCIPAL)?;
    (fee_point,fee_output)=rpc.coin(&refresh_id,&sponsor_script,
        SPONSOR_INITIAL-EXTERNAL_FEE)?;

    // The malicious quorum may re-sign a different BIP341 transaction,
    // including a changed beneficiary, without consulting PDP validity.
    let stolen_commit=commit("malicious-2of3-fault",&evidence,&carrier_point);
    let stolen_base=build(carrier_point,fee_point,
        vec![TxOut{value:Amount::from_sat(PRINCIPAL),script_pubkey:thief_script.clone()}],
        &sponsor_script,SPONSOR_INITIAL-2*EXTERNAL_FEE,stolen_commit);
    let (evil_frost,evil_quorum)=sign_frost_keypath(
        &public,&packages,&identifiers,[0,1],&stolen_base,
        &[carrier_output.clone(),fee_output.clone()],taproot_key,&mut rng)?;
    let evil=rpc.sign_sponsor(&evil_frost)?;
    require(rpc.witness_authorization(&evil)?,
        "malicious 2-of-3 FROST settlement not valid under Bitcoin")?;
    inspect_outputs(&evil,&[
        (thief_script.clone(),PRINCIPAL),
        (sponsor_script.clone(),SPONSOR_INITIAL-2*EXTERNAL_FEE),
        (Builder::new().push_opcode(OP_RETURN).push_slice(stolen_commit).into_script(),0)])?;

    // Defend only against *unauthorized transaction mutation*, not
    // against a quorum that creates a FRESH malicious signature.
    let mut corrupt=evil.clone();
    let mut first=corrupt.input[0].witness.iter().next().ok_or("empty FROST witness")?.to_vec();
    first[3]^=1;
    corrupt.input[0].witness=Witness::from_slice(&[first]);
    require(corrupt.compute_txid()==evil.compute_txid()&&
        corrupt.compute_wtxid()!=evil.compute_wtxid(),
        "witness-only mutation did not preserve its txid")?;
    require(!rpc.witness_authorization(&corrupt)?,
        "Bitcoin accepted a modified FROST signature under unchanged txid")?;

    let honest_commit=commit("honest-split",&evidence,&carrier_point);
    let honest_base=build(carrier_point,fee_point,
        vec![
            TxOut{value:Amount::from_sat(60_000),script_pubkey:alice_script.clone()},
            TxOut{value:Amount::from_sat(40_000),script_pubkey:bob_script.clone()},
        ],
        &sponsor_script,SPONSOR_INITIAL-2*EXTERNAL_FEE,honest_commit);
    let (honest_frost,honest_quorum)=sign_frost_keypath(
        &public,&packages,&identifiers,[0,2],&honest_base,
        &[carrier_output.clone(),fee_output.clone()],taproot_key,&mut rng)?;
    let honest=rpc.sign_sponsor(&honest_frost)?;
    require(rpc.witness_authorization(&honest)?,"honest FROST P2TR spend invalid to Core")?;
    inspect_outputs(&honest,&[
        (alice_script.clone(),60_000),(bob_script.clone(),40_000),
        (sponsor_script.clone(),SPONSOR_INITIAL-2*EXTERNAL_FEE),
        (Builder::new().push_opcode(OP_RETURN).push_slice(honest_commit).into_script(),0)])?;

    let mut redirected=honest.clone();
    redirected.output[0].script_pubkey=thief_script.clone();
    require(!rpc.witness_authorization(&redirected)?,
        "Bitcoin permitted post-signature payout redirection without a new quorum")?;
    let settlement_id=rpc.text("sendrawtransaction",
        &[json!(serialize_hex(&honest))],None)?;
    require(settlement_id==honest.compute_txid().to_string(),"Bitcoin Core changed FROST payout")?;
    rpc.mine(6,&miner_addr)?;
    let confirmed_settlement=rpc.confirmed(&settlement_id,6)?;
    let (alice_point,_)=rpc.coin(&settlement_id,&alice_script,60_000)?;
    let (bob_point,_)=rpc.coin(&settlement_id,&bob_script,40_000)?;
    let report=json!({
        "schema":"bsb-ab-p2tr-real-frost-regtest-v1",
        "chain":"regtest",
        "cryptography":"frost-secp256k1-tr 3.0.0",
        "signatures":"real-BIP341-sighash-P2TR-TapTweak",
        "capitalSats":PRINCIPAL,
        "aliceSats":60_000,"bobSats":40_000,
        "independentFeeSponsorSats":SPONSOR_INITIAL,
        "sponsorTotalFeesSats":EXTERNAL_FEE*2,
        "p2trGroupKey":hex(internal_key.serialize()),
        "p2trTweakedOutputKey":hex(taproot_key.serialize()),
        "sharedPdpEvidenceHash":evidence,
        "separateSignerSharesInDifferentProcesses":false,
        "trustedDealerSimulated":true,
        "allKeySharesEphemeral":true,
        "missingSecondShareRejected":one_share_rejected&&evil_quorum&&honest_quorum,
        "maliciousTwoShareRedirect":{
            "validBitcoinMempoolSpend":true,
            "broadcast":false,
            "redirectedPrincipalSats":PRINCIPAL,
            "txid":evil.compute_txid().to_string(),
            "wtxid":evil.compute_wtxid().to_string(),
            "sameTxidWitnessMutationRejected":true,
            "sourceBlossomStorageEvidenceHash":evidence
        },
        "honestTwoSharePayout":{
            "confirmed":true,
            "txid":honest.compute_txid().to_string(),
            "wtxid":honest.compute_wtxid().to_string(),
            "aliceOutpoint":alice_point.to_string(),
            "bobOutpoint":bob_point.to_string(),
            "sixConfirmations":true,
            "postSignatureOutputTamperRejected":true
        },
        "refresh":output_summary(&confirmed_refresh)?,
        "payout":output_summary(&confirmed_settlement)?,
        "limits":{
            "filecoinFaultVerifiedByBitcoin":false,
            "blossomPdpVerifiedByBitcoin":false,
            "realSapioMidCovenant":false,
            "realLayerTreeRefresh":false,
            "realFrostAcrossNetworkPeers":false,
            "independentHolderExitWithoutFederation":false,
            "publicTestnetSpend":false,
            "bitcoinCoreBip341AndP2TRKeyPathAccepted":true
        }
    });
    let encoded=serde_json::to_string_pretty(&report)?+"\n";
    if let Some(out)=out {
        let mut opts=fs::OpenOptions::new();opts.write(true).create_new(true);
        #[cfg(unix)]{
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file=opts.open(out)?;
        file.write_all(encoded.as_bytes())?;
        file.sync_all()?;
    }
    println!("{encoded}");
    Ok(())
}
fn main(){
    let args=env::args().skip(1).collect::<Vec<_>>();
    if let Err(err)=run(args){
        eprintln!("B FROST P2TR real-regtest integration failed: {err}");
        std::process::exit(1);
    }
}
