//! A frozen v3 P2TR FROST parent uses ONE carrier input, exact owner
//! outputs and a zero-value P2A anchor. It never commits to a fee UTXO.
 //!
 //! The signer only prepares immutable two-branch/second-owner parents.
 //! A SEPARATE later Node process creates a new v3 CPFP child and proves
 //! Bitcoin Core submitpackage accepts parent+child without signer access.
 //!
 //! These presigned parents cannot defeat a malicious ACTIVE two-share
 //! quorum, a missing frozen package or lack of any available fee payer.
use super::*;
use std::{fs::OpenOptions,io::Write,path::Path};
const FEE_COIN_SATS:u64=10_000;
fn anchor()->ScriptBuf{
    ScriptBuf::from_bytes(vec![0x51,0x02,0x4e,0x73])
}
fn parent(prev:OutPoint,payouts:Vec<TxOut>)->Transaction {
    let mut outputs=payouts;
    outputs.push(TxOut{value:Amount::ZERO,script_pubkey:anchor()});
    Transaction{
        version:Version(3),lock_time:LockTime::ZERO,
        input:vec![TxIn{previous_output:prev,script_sig:ScriptBuf::new(),
            sequence:Sequence::ENABLE_RBF_NO_LOCKTIME,witness:Witness::new()}],
        output:outputs,
    }
}
fn signed_parent(
    public:&frost::keys::PublicKeyPackage,
    keys:&Packages,ids:&[frost::Identifier],tap:XOnlyPublicKey,
    tx:Transaction,prev:&TxOut,rng:&mut OsRng,
)->ResultX<Transaction>{
    let principal=prev.value.to_sat();
    require(tx.version==Version(3)&&tx.input.len()==1,
        "FROST fee-independent parent must be single-input TRUC v3")?;
    require(tx.output.last().map(|o|o.value==Amount::ZERO&&o.script_pubkey==anchor())
        ==Some(true),"parent must commit the exact zero-value P2A anchor")?;
    let total:u64=tx.output.iter().map(|o|o.value.to_sat()).sum();
    require(total==principal,"frozen parent must preserve entire carrier principal")?;
    let (signed,incomplete)=sign_frost_keypath(
        public,keys,ids,[0,2],&tx,&[prev.clone()],tap,rng)?;
    require(incomplete&&signed.input[0].witness.len()==1,
        "presigned parent requires exact real two-share BIP341 keypath witness")?;
    require(signed.compute_txid()==tx.compute_txid(),
        "FROST witness changed presigned Bitcoin parent txid")?;
    Ok(signed)
}
fn record(tx:&Transaction,expected:&[(ScriptBuf,u64)],ancestor:OutPoint,
    owner:&str,generation:u32,kind:&str)->ResultX<Value>{
    inspect_outputs(tx,expected)?;
    require(tx.version==Version(3)&&tx.input.len()==1&&
        tx.input[0].previous_output==ancestor &&
        tx.input[0].witness.len()==1,
        "stored FROST P2A parent has substituted input or missing signature")?;
    let anchor_output=tx.output.len()-1;
    require(tx.output[anchor_output].value==Amount::ZERO&&
        tx.output[anchor_output].script_pubkey==anchor(),
        "missing exact P2A parent output")?;
    Ok(json!({
        "generation":generation,"ownerOrder":owner,"step":kind,
        "txid":tx.compute_txid().to_string(),
        "wtxid":tx.compute_wtxid().to_string(),
        "signedHex":serialize_hex(tx),
        "vsize":tx.vsize(),
        "version":3,
        "carrierInput":ancestor.to_string(),
        "carrierOutputSats":expected.iter().map(|(_,v)|*v).sum::<u64>(),
        "anchorIndex":anchor_output,"anchorScript":"51024e73",
        "parentMinerFeeSats":0,
        "feeInputsSignedByFrost":false,
        "sighashType":"BIP341-SIGHASH_DEFAULT",
        "outputAgreement":expected.iter().enumerate().map(|(i,(script,value))|
            json!({"vout":i,"sats":value,"script":hex(script.as_bytes())})
        ).collect::<Vec<_>>(),
    }))
}
fn freeze_file(path:&Path,bytes:&[u8])->ResultX<()>{
    let mut options=OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]{
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file=options.open(path)?;
    file.write_all(bytes)?;file.sync_all()?;
    Ok(())
}
pub(super) fn prepare(args:Vec<String>)->ResultX<()> {
    let mut cli=None;let mut dir=None;let mut evidence=None;let mut out=None;
    let mut args=args.into_iter();
    while let Some(flag)=args.next(){
        let val=args.next().ok_or("missing P2A preparation argument value")?;
        match flag.as_str(){
            "--bitcoin-cli"=>cli=Some(val),
            "--datadir"=>dir=Some(val),
            "--evidence-hash"=>evidence=Some(val),
            "--out-dir"=>out=Some(val),
            _=>return Err(format!("unknown offline P2A argument {flag}").into()),
        }
    }
    let rpc=Rpc{
        binary:PathBuf::from(cli.ok_or("provide trusted absolute bitcoin-cli path")?),
        datadir:PathBuf::from(dir.ok_or("provide private disposable datadir")?),
    };
    rpc.chain()?;
    let evidence:String=evidence.ok_or("Blossom source evidence SHA256 missing")?;
    require(evidence.len()==64&&evidence.bytes().all(|b|b.is_ascii_hexdigit()),
        "PDP hash must be 64 hexadecimal characters")?;
    let outdir=PathBuf::from(out.ok_or("missing exclusive output directory")?);
    require(!outdir.join("p2a-frozen.json").exists(),
        "previous signed P2A parent exports must not be overwritten")?;
    let (shares,public)=frost::keys::generate_with_dealer(
        3,2,frost::keys::IdentifierList::Default,&mut OsRng)?;
    let mut packages=Packages::new();
    for (id,share) in shares{
        packages.insert(id,frost::keys::KeyPackage::try_from(share)?);
    }
    require(packages.len()==3,"real FROST dealer did not create exactly three shares")?;
    let ids=packages.keys().copied().collect::<Vec<_>>();
    let secp=Secp256k1::new();
    let internal=bitcoin_group_internal_key(&public)?;
    let vault=Address::p2tr(&secp,internal,None,Network::Regtest);
    let vault_script=vault.script_pubkey();
    let tap=XOnlyPublicKey::from_slice(
        vault_script.as_bytes().get(2..34).ok_or("invalid native Taproot output")?)?;
    for name in ["miner","sponsor","alice","bob"]{
        rpc.call("createwallet",&[json!(name)],None)?;
    }
    let (miner,_)=rpc.address("miner")?;
    rpc.mine(101,&miner)?;
    let (fee_addr,fee_script)=rpc.address("sponsor")?;
    let (_,alice_script)=rpc.address("alice")?;
    let (_,bob_script)=rpc.address("bob")?;
    require(alice_script!=bob_script,"P2A beneficiary payout scripts must be different")?;
    let (_,attacker_script)=rpc.address("miner")?;
    let initial_id=rpc.text("sendtoaddress",&[
        json!(vault.to_string()),json!(sats_to_btc(PRINCIPAL))],Some("miner"))?;
    // These three *fixed* UTXOs fund ONLY the two already-broadcast
    // preparation refreshes and the unbroadcast malicious-quorum control.
    // No recovery parent refers to any sponsor or fee coin.
    let mut sponsor_ids=Vec::new();
    for _ in 0..3{
        sponsor_ids.push(rpc.text("sendtoaddress",&[
            json!(fee_addr),json!(sats_to_btc(FEE_COIN_SATS))],Some("miner"))?);
    }
    rpc.mine(6,&miner)?;
    let (mut carrier_point,mut carrier_output)=rpc.coin(&initial_id,&vault_script,PRINCIPAL)?;
    let mut fixed_coins=Vec::new();
    for txid in &sponsor_ids{
        fixed_coins.push(rpc.coin(txid,&fee_script,FEE_COIN_SATS)?);
    }
    let mut rng=OsRng;
    let mut generations=Vec::new();
    for generation in 0..3u32{
        let mut branch_rows=serde_json::Map::new();
        for (first_name,second_name,first_sats,second_sats,
             first_script,second_script) in [
            ("alice","bob",60_000u64,40_000u64,
                alice_script.clone(),bob_script.clone()),
            ("bob","alice",40_000u64,60_000u64,
                bob_script.clone(),alice_script.clone()),
        ]{
            let first=parent(carrier_point,vec![
                TxOut{value:Amount::from_sat(second_sats),
                    script_pubkey:vault_script.clone()},
                TxOut{value:Amount::from_sat(first_sats),
                    script_pubkey:first_script.clone()},
            ]);
            let signed_first=signed_parent(&public,&packages,&ids,tap,
                first,&carrier_output,&mut rng)?;
            let first_agreement=[
                (vault_script.clone(),second_sats),
                (first_script,first_sats),
                (anchor(),0),
            ];
            let first_record=record(&signed_first,&first_agreement,
                carrier_point,first_name,generation,"first")?;
            let descendant=OutPoint::new(signed_first.compute_txid(),0);
            let remaining=TxOut{
                value:Amount::from_sat(second_sats),
                script_pubkey:vault_script.clone(),
            };
            let second=parent(descendant,vec![TxOut{
                value:Amount::from_sat(second_sats),
                script_pubkey:second_script.clone(),
            }]);
            let signed_second=signed_parent(&public,&packages,&ids,tap,
                second,&remaining,&mut rng)?;
            let second_agreement=[
                (second_script,second_sats),
                (anchor(),0),
            ];
            let second_record=record(&signed_second,&second_agreement,
                descendant,second_name,generation,"second")?;
            branch_rows.insert(first_name.into(),json!({
                "first":first_record,
                "second":second_record,
                "firstReceivesSats":first_sats,
                "secondReceivesSats":second_sats,
                "otherOwner":second_name,
                "descendantOutpoint":descendant.to_string(),
                "noFeeInputsInEitherFrostSignature":true,
            }));
        }
        let refresh=if generation<2{
            // These are completed before signer disappearance, so the
            // static sponsor does not endanger post-outage owner exits.
            // Unattended refresh still requires future separate proof.
            let (fee_point,fee_output)=fixed_coins[generation as usize].clone();
            let state=commit(&format!("p2a-preoutage-gen{generation}-refresh"),
                &evidence,&carrier_point);
            let base=build(carrier_point,fee_point,
                vec![TxOut{value:Amount::from_sat(PRINCIPAL),
                    script_pubkey:vault_script.clone()}],
                &fee_script,FEE_COIN_SATS-EXTERNAL_FEE,state);
            let (frost,complete)=sign_frost_keypath(&public,&packages,&ids,
                [0,1],&base,&[carrier_output.clone(),fee_output],tap,&mut rng)?;
            require(complete,"one FROST share falsely authorized preoutage refresh")?;
            let signed=rpc.sign_sponsor(&frost)?;
            require(rpc.witness_authorization(&signed)?,
                "completed preoutage refresh was not a real Bitcoin-valid spend")?;
            let txid=rpc.text("sendrawtransaction",&[json!(serialize_hex(&signed))],None)?;
            require(txid==signed.compute_txid().to_string(),"Bitcoin published wrong refresh")?;
            rpc.mine(1,&miner)?;
            rpc.confirmed(&txid,1)?;
            Some(json!({
                "txid":txid,
                "wtxid":signed.compute_wtxid().to_string(),
                "signedHex":serialize_hex(&signed),
                "staticSponsorInputBeforeOutage":fee_point.to_string(),
                "feeSats":EXTERNAL_FEE,
                "principalNextSats":PRINCIPAL,
            }))
        }else{None};
        generations.push(json!({
            "generation":generation,
            "carrierBefore":carrier_point.to_string(),
            "carrierScriptPubkeyHex":hex(vault_script.as_bytes()),
            "branches":branch_rows,
            "refreshBroadcast":refresh,
        }));
        if generation<2 {
            let id=generations.last().unwrap()["refreshBroadcast"]["txid"]
                .as_str().ok_or("missing real preoutage refresh transaction")?;
            (carrier_point,carrier_output)=rpc.coin(id,&vault_script,PRINCIPAL)?;
        }
    }
    // A malicious live quorum still signs and Bitcoin accepts a different
    // keypath theft. This negative control NEVER broadcasts.
    let (attack_fee,attack_prev)=fixed_coins[2].clone();
    let root=commit("p2a-does-not-prevent-quorum-theft",&evidence,&carrier_point);
    let evil=build(carrier_point,attack_fee,vec![TxOut{
        value:Amount::from_sat(PRINCIPAL),script_pubkey:attacker_script,
    }],&fee_script,FEE_COIN_SATS-EXTERNAL_FEE,root);
    let (signed_evil,_)=sign_frost_keypath(&public,&packages,&ids,[0,1],
        &evil,&[carrier_output,attack_prev],tap,&mut rng)?;
    let malicious=rpc.sign_sponsor(&signed_evil)?;
    require(rpc.witness_authorization(&malicious)?,
        "active malicious two-share quorum did not recreate unrestricted Bitcoin theft")?;
    let manifest=json!({
        "schema":"bsb-frost-v3-p2a-frozen-v1",
        "network":"disposable-regtest-only",
        "sourceBlossomReferencePdpHash":evidence,
        "realFrostThreshold":"2-of-3-secp256k1-tr-3.0.0",
        "bitcoinTransactionVersion":3,
        "feeIndependentSignedParents":true,
        "frostWitnessCommittedToExternalFeeUtxo":false,
        "allPreSignedParentsZeroMinerFee":true,
        "zeroValueAnchorScriptPubkeyHex":"51024e73",
        "principalSats":PRINCIPAL,
        "aliceSats":60_000,"bobSats":40_000,
        "beneficiaryScripts":{
            "alice":hex(alice_script.as_bytes()),
            "bob":hex(bob_script.as_bytes()),
        },
        "currentGeneration":2,
        "minerAddress":miner,
        "generations":generations,
        "signerProcessMustTerminateBeforeP2aChildCreated":true,
        "originalFrostPrivateSharesSerialized":false,
        "onlineSapioOracleRequiredForRelay":false,
        "maliciousActiveQuorumControl":{
            "bitcoinMempoolAcceptsCompetingTheft":true,
            "broadcast":false,
            "feeIndependenceDoesNotPreventByzantineQuorumTheft":true,
            "txid":malicious.compute_txid().to_string(),
        },
        "scopeLimits":{
            "futureUnattendedRefreshWithDynamicSponsorProven":false,
            "p2aParentPackageAcceptedBeforeActualRelay":false,
            "recipientExclusiveCarrierSigning":false,
            "infiniteFeeSponsorsGuaranteed":false,
            "midCovenantEnforcedByBitcoin":false,
            "actualFilecoinFaultVerifiedByBitcoin":false,
        }
    });
    let data=serde_json::to_vec_pretty(&manifest)?;
    let root=Path::new(&outdir);
    std::fs::create_dir_all(root)?;
    #[cfg(unix)]{
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root,std::fs::Permissions::from_mode(0o700))?;
    }
    freeze_file(&root.join("p2a-frozen.json"),&data)?;
    freeze_file(&root.join("p2a-frozen.sha256"),
        format!("{}\n",hex(sha(&data))).as_bytes())?;
    println!("{}",serde_json::to_string_pretty(&json!({
        "status":"P2A_FROST_PARENTS_FROZEN_BEFORE_SIGNER_EXIT",
        "gen":3,"alternativeFirstBranchesPerGen":2,
        "signedSecondOwnersPerGen":2,
        "eachFrostParentHasOnlyOneInput":true,
        "allPrincipalFullyPreserved":true,
        "noFeeInputInFrostSignature":true,
        "maliciousQuorumMayStillSteal":true,
        "manifestSha256":hex(sha(&data))
    }))?);
    Ok(())
}
