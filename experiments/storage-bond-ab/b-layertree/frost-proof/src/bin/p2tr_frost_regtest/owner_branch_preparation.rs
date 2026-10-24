//! FROST-signed owner-first branch recovery DAG, three carrier generations.
 //!
 //! Pre-sign alternative Alice-first and Bob-first transactions for each
 //! generation, plus a beneficiary recovery from either branch's successor.
 //! All 14 fee inputs are independent, confirmed sponsor UTXOs, signed
 //! before this process terminates. No key shares or nonce secrets exported.
 //!
 //! These branches are publishable by anyone holding frozen raw bytes.
 //! Owner-specific outputs do NOT imply owner-only relay authentication,
 //! nor protection from an ACTIVE colluding FROST quorum.
use super::*;
use std::{fs::OpenOptions,io::Write,path::Path};

const SPONSOR_COIN:u64=10_000;

fn checked_sponsor(
    rpc:&Rpc, signed_frost:&Transaction, prev:&TxOut,
)->ResultX<Transaction>{
    // For the second branch spend, its parent has NOT been published
    // during pre-signing. Explicit prevout metadata lets Core check
    // BIP341 witnesses while signing only the independent sponsor coin.
    let spent=signed_frost.input[0].previous_output;
    let prevs=json!([{
        "txid":spent.txid.to_string(),"vout":spent.vout,
        "scriptPubKey":hex(prev.script_pubkey.as_bytes()),
        "amount":sats_to_btc(prev.value.to_sat())
    }]);
    let r=rpc.call("signrawtransactionwithwallet",
        &[json!(serialize_hex(signed_frost)),prevs],Some("sponsor"))?;
    let text=r["hex"].as_str().ok_or("sponsor did not return signed Bitcoin raw bytes")?;
    let tx:Transaction=deserialize(&unhex(text)?)?;
    require(tx.compute_txid()==signed_frost.compute_txid(),
        "external fee sponsor altered the frozen unsigned transaction")?;
    require(tx.input.len()==2&&tx.input[0].witness==signed_frost.input[0].witness,
        "fee sponsor replaced the FROST keypath signature")?;
    require(!tx.input[1].witness.is_empty(),
        "separately confirmed sponsor UTXO was not actually signed")?;
    Ok(tx)
}
fn exact_signed(
    rpc:&Rpc,packages:&Packages,public:&frost::keys::PublicKeyPackage,
    ids:&[frost::Identifier],taproot_key:XOnlyPublicKey,
    unsigned:Transaction,principal:&TxOut,sponsor:&TxOut,
    rng:&mut OsRng,
)->ResultX<Transaction>{
    let (frost_signed,second_required)=sign_frost_keypath(public,packages,ids,
        [0,2],&unsigned,&[principal.clone(),sponsor.clone()],taproot_key,rng)?;
    require(second_required,"one share authorized presigned exit")?;
    let complete=checked_sponsor(rpc,&frost_signed,principal)?;
    let inputs=principal.value.to_sat()+sponsor.value.to_sat();
    let outputs:u64=complete.output.iter().map(|v|v.value.to_sat()).sum();
    require(inputs>=outputs&&inputs-outputs==EXTERNAL_FEE,
        "pre-signed recovery fee consumed owner entitlement")?;
    Ok(complete)
}
fn amount_script(value:u64,script:&ScriptBuf)->TxOut{
    TxOut{value:Amount::from_sat(value),script_pubkey:script.clone()}
}
fn signed_record(tx:&Transaction,principal:OutPoint,sponsor:OutPoint,
    outputs:&[(ScriptBuf,u64)],index:u32)->ResultX<Value>{
    inspect_outputs(tx,outputs)?;
    require(tx.input.len()==2&&
        tx.input[0].previous_output==principal&&
        tx.input[1].previous_output==sponsor,
        "signed recovery branch uses different parent/sponsor inputs")?;
    require(tx.input[0].witness.len()==1&&!tx.input[1].witness.is_empty(),
        "signed recovery branch lacks complete Bitcoin witness")?;
    Ok(json!({
        "exitNumber":index,
        "signedHex":serialize_hex(tx),
        "txid":tx.compute_txid().to_string(),
        "wtxid":tx.compute_wtxid().to_string(),
        "vsize":tx.vsize(),
        "principalInput":principal.to_string(),
        "sponsorInput":sponsor.to_string(),
        "exactOutputs":outputs.iter().enumerate().map(|(vout,(script,sats))|json!({
            "vout":vout,"script":hex(script.as_bytes()),"sats":sats
        })).collect::<Vec<_>>(),
        "externalSponsorFeeSats":EXTERNAL_FEE
    }))
}
fn parse_opts(args:Vec<String>)->ResultX<(Rpc,String,String)>{
    let mut cli=None;let mut datadir=None;let mut evidence=None;let mut out=None;
    let mut args=args.into_iter();
    while let Some(flag)=args.next(){
        let value=args.next().ok_or("owner branch option omitted a value")?;
        match flag.as_str(){
            "--bitcoin-cli"=>cli=Some(value),
            "--datadir"=>datadir=Some(value),
            "--evidence-hash"=>evidence=Some(value),
            "--out-dir"=>out=Some(value),
            _=>return Err(format!("unrecognized owner branch flag {flag}").into())
        }
    }
    let evidence:String=evidence.ok_or("missing --evidence-hash")?;
    require(evidence.len()==64&&evidence.bytes().all(|b|b.is_ascii_hexdigit()),
        "source Blossom fault must be a SHA256 hex digest")?;
    Ok((Rpc{
        binary:PathBuf::from(cli.ok_or("missing --bitcoin-cli")?),
        datadir:PathBuf::from(datadir.ok_or("missing --datadir")?)
    },evidence,out.ok_or("missing --out-dir")?))
}
pub(super) fn prepare(args:Vec<String>)->ResultX<()>{
    let (rpc,evidence,outdir)=parse_opts(args)?;
    rpc.chain()?;
    require(!Path::new(&outdir).join("owner-frozen.json").exists(),
        "refusing to overwrite previously saved owner branch witness set")?;
    let (shares,public)=frost::keys::generate_with_dealer(
        3,2,frost::keys::IdentifierList::Default,&mut OsRng)?;
    let mut packages=Packages::new();
    for(id,share)in shares{
        packages.insert(id,frost::keys::KeyPackage::try_from(share)?);
    }
    require(packages.len()==3,"wrong 2-of-3 FROST dealer output")?;
    let ids=packages.keys().copied().collect::<Vec<_>>();
    let internal=bitcoin_group_internal_key(&public)?;
    let secp=Secp256k1::new();
    let vault=Address::p2tr(&secp,internal,None,Network::Regtest);
    let carrier_script=vault.script_pubkey();
    let taproot_key=XOnlyPublicKey::from_slice(
        carrier_script.as_bytes().get(2..34).ok_or("bad Taproot carrier output key")?)?;
    for name in ["miner","sponsor","alice","bob"]{
        rpc.call("createwallet",&[json!(name)],None)?;
    }
    let (miner,_)=rpc.address("miner")?;
    rpc.mine(101,&miner)?;
    let (fee_address,fee_script)=rpc.address("sponsor")?;
    let (_,alice_script)=rpc.address("alice")?;
    let (_,bob_script)=rpc.address("bob")?;
    require(alice_script!=bob_script,"Alice/Bob beneficiary scripts collided")?;
    let theft_script=rpc.address("miner")?.1;
    let bond_id=rpc.text("sendtoaddress", &[
        json!(vault.to_string()),json!(sats_to_btc(PRINCIPAL))],Some("miner"))?;
    // Each unbroadcast alternative must have its own already-confirmed
    // sponsor UTXO: no missing-parent wallet signing at relay time.
    // 3 generations * 4 recovery coins + 2 refresh coins = 14.
    let mut sponsor_ids=Vec::new();
    for _ in 0..14{
        sponsor_ids.push(rpc.text("sendtoaddress",
            &[json!(fee_address),json!(sats_to_btc(SPONSOR_COIN))],Some("miner"))?);
    }
    rpc.mine(6,&miner)?;
    let (mut carrier_point,mut carrier_output)=rpc.coin(&bond_id,&carrier_script,PRINCIPAL)?;
    let mut fee_coins=Vec::new();
    for id in &sponsor_ids{
        fee_coins.push(rpc.coin(id,&fee_script,SPONSOR_COIN)?);
    }
    require(fee_coins.len()==14,"missing distinct sponsor fee UTXOs")?;
    let mut consumed=std::collections::BTreeSet::new();
    let mut generations=Vec::new();
    let mut rng=OsRng;
    for generation in 0..3u32{
        let mut branches=serde_json::Map::new();
        for (branch_index,first_is_alice) in [(0usize,true),(1,false)] {
            let first_name=if first_is_alice{"alice"}else{"bob"};
            let second_name=if first_is_alice{"bob"}else{"alice"};
            let first_value=if first_is_alice{60_000}else{40_000};
            let remainder=PRINCIPAL-first_value;
            let first_script=if first_is_alice{alice_script.clone()}else{bob_script.clone()};
            let second_script=if first_is_alice{bob_script.clone()}else{alice_script.clone()};
            let fee_slot=generation as usize*4+branch_index*2;
            let (sponsor_first,sponsor_first_txout)=fee_coins[fee_slot].clone();
            let (sponsor_second,sponsor_second_txout)=fee_coins[fee_slot+1].clone();
            require(consumed.insert(sponsor_first)&&consumed.insert(sponsor_second),
                "fee sponsorship double-counted a confirmed Bitcoin UTXO")?;
            let first_commit=commit(&format!("gen{generation}-{first_name}-first"),
                &evidence,&carrier_point);
            let first_base=build(carrier_point,sponsor_first,
                vec![
                    amount_script(remainder,&carrier_script),
                    amount_script(first_value,&first_script)
                ],&fee_script,SPONSOR_COIN-EXTERNAL_FEE,first_commit);
            let first=exact_signed(&rpc,&packages,&public,&ids,taproot_key,
                first_base,&carrier_output,&sponsor_first_txout,&mut rng)?;
            require(rpc.witness_authorization(&first)?,
                "first owner branch is not Bitcoin Core mempool valid")?;
            let first_outputs=vec![
                (carrier_script.clone(),remainder),
                (first_script.clone(),first_value),
                (fee_script.clone(),SPONSOR_COIN-EXTERNAL_FEE),
                (Builder::new().push_opcode(OP_RETURN)
                    .push_slice(first_commit).into_script(),0)
            ];
            let descendant=OutPoint::new(first.compute_txid(),0);
            let descendant_coin=amount_script(remainder,&carrier_script);
            let second_commit=commit(&format!("gen{generation}-{second_name}-second-after-{first_name}"),
                &evidence,&descendant);
            let second_base=build(descendant,sponsor_second,
                vec![amount_script(remainder,&second_script)],
                &fee_script,SPONSOR_COIN-EXTERNAL_FEE,second_commit);
            let second=exact_signed(&rpc,&packages,&public,&ids,taproot_key,
                second_base,&descendant_coin,&sponsor_second_txout,&mut rng)?;
            let second_outputs=vec![
                (second_script.clone(),remainder),
                (fee_script.clone(),SPONSOR_COIN-EXTERNAL_FEE),
                (Builder::new().push_opcode(OP_RETURN)
                    .push_slice(second_commit).into_script(),0)
            ];
            branches.insert(first_name.into(),json!({
                "first":signed_record(&first,carrier_point,sponsor_first,
                    &first_outputs,0)?,
                "second":signed_record(&second,descendant,sponsor_second,
                    &second_outputs,1)?,
                "firstPaysOwner":first_name,
                "secondPaysOther":second_name,
                "remainderAfterFirstSats":remainder,
                "ownerGetsSats":first_value,
                "otherGetsSats":remainder,
                "sameOriginalCarrier":carrier_point.to_string(),
                "descendantCarrier":descendant.to_string(),
                "descendantScriptPubkeyHex":hex(carrier_script.as_bytes()),
                "independentSecondExternalFeeAlreadySigned":true,
            }));
        }
        let refresh=if generation<2 {
            let (fee_point,fee_txout)=fee_coins[12+generation as usize].clone();
            require(consumed.insert(fee_point),"refresh sponsor coin reused")?;
            let state=commit(&format!("gen{generation}-refresh"),&evidence,&carrier_point);
            let unsigned=build(carrier_point,fee_point,
                vec![amount_script(PRINCIPAL,&carrier_script)],
                &fee_script,SPONSOR_COIN-EXTERNAL_FEE,state);
            let tx=exact_signed(&rpc,&packages,&public,&ids,taproot_key,unsigned,
                &carrier_output,&fee_txout,&mut rng)?;
            require(rpc.witness_authorization(&tx)?,
                "pre-signed generation refresh rejected by Bitcoin Core")?;
            let expected=vec![
                (carrier_script.clone(),PRINCIPAL),
                (fee_script.clone(),SPONSOR_COIN-EXTERNAL_FEE),
                (Builder::new().push_opcode(OP_RETURN).push_slice(state).into_script(),0)
            ];
            let rec=signed_record(&tx,carrier_point,fee_point,&expected,0)?;
            let txid=rpc.text("sendrawtransaction",&[json!(serialize_hex(&tx))],None)?;
            require(txid==tx.compute_txid().to_string(),"Bitcoin changed frozen refresh")?;
            rpc.mine(1,&miner)?;
            rpc.confirmed(&txid,1)?;
            Some(rec)
        }else{None};
        generations.push(json!({
            "generation":generation,
            "carrierBefore":carrier_point.to_string(),
            "carrierScriptPubkeyHex":hex(carrier_script.as_bytes()),
            "branches":branches,
            "refreshBroadcast":refresh
        }));
        if generation<2 {
            let ref_id=generations.last().unwrap()["refreshBroadcast"]["txid"]
                .as_str().ok_or("missing generation refresh txid")?;
            (carrier_point,carrier_output)=rpc.coin(ref_id,&carrier_script,PRINCIPAL)?;
        }
    }
    // A malicious 2-share FROST quorum may spend the current full 100k
    // instead of respecting any of the pre-signed first/second exit paths.
    let (sponsor_thief,sponsor_thief_out)=fee_coins[8].clone();
    let theft_root=commit("malicious-coordinator-ignores-presigned-exits",
        &evidence,&carrier_point);
    let bad=build(carrier_point,sponsor_thief,
        vec![amount_script(PRINCIPAL,&theft_script)],
        &fee_script,SPONSOR_COIN-EXTERNAL_FEE,theft_root);
    let (malicious_sig,_)=sign_frost_keypath(&public,&packages,&ids,[0,1],
        &bad,&[carrier_output.clone(),sponsor_thief_out],taproot_key,&mut rng)?;
    let malicious_tx=checked_sponsor(&rpc,&malicious_sig,&carrier_output)?;
    require(rpc.witness_authorization(&malicious_tx)?,
        "missing live quorum theft counterexample");
    for old in generations.iter().take(2) {
        let original=old["carrierBefore"].as_str().ok_or("missing old carrier")?;
        let mut fields=original.split(':');
        let parent=fields.next().ok_or("missing old parent")?;
        let vout:u32=fields.next().ok_or("missing old vout")?.parse()?;
        require(rpc.call("gettxout",&[json!(parent),json!(vout)],None)?.is_null(),
            "old carrier generation stayed in active chain")?;
    }
    let payload=json!({
        "schema":"bsb-frost-owner-branch-prepared-v1",
        "network":"disposable-regtest-only",
        "sourcePdpEvidenceHash":evidence,
        "real2of3TaprootThresholdSignatures":true,
        "signerProcessMustDieBeforeRelay":true,
        "threeIndependentGenerationStates":true,
        "allSponsoredInputsIndependentlyConfirmed":true,
        "allSignatureBytesFrozenBeforeBroadcast":true,
        "signingSharesSavedToDisk":false,
        "fundedPrincipalSats":100_000,
        "aliceSats":60_000,"bobSats":40_000,
        "minerAddress":miner,
        "latestGeneration":2,
        "sponsorInputValueSats":SPONSOR_COIN,
        "sponsorFeePerTransactionSats":EXTERNAL_FEE,
        "holderPayoutScripts":{
            "alice":hex(alice_script.as_bytes()),
            "bob":hex(bob_script.as_bytes())
        },
        "generations":generations,
        "maliciousQuorumControl":{
            "bitcoinMempoolAcceptsConflictingTheft":true,
            "broadcast":false,
            "liveQuorumCanBeatOwnerFirstExit":true,
            "txid":malicious_tx.compute_txid().to_string(),
            "wtxid":malicious_tx.compute_wtxid().to_string()
        },
        "caveats":{
            "firstExitNeedsNoOtherHolderOnlineAfterFreeze":true,
            "secondExitPreSignedForBothPossibleFirstExits":true,
            "anyRelayerCanBroadcastFrozenExits":true,
            "holderExclusiveCarrierSignature":false,
            "opposingFirstExitsConflictAndOnlyOneCanWin":true,
            "maliciousQuorumCanSignTheftOrWrongRoot":true,
            "futureRefreshWithoutNewSignaturesUnsafe":true,
            "sapioMidEnforcedOnBitcoin":false,
            "filecoinFaultEnforcedOnBitcoin":false
        }
    });
    let bytes=serde_json::to_vec_pretty(&payload)?;
    let hash=hex(sha(&bytes));
    let p=Path::new(&outdir);
    std::fs::create_dir_all(p)?;
    #[cfg(unix)]{
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p,std::fs::Permissions::from_mode(0o700))?;
    }
    fn fresh(path:&Path,data:&[u8])->ResultX<()>{
        let mut cfg=OpenOptions::new();cfg.write(true).create_new(true);
        #[cfg(unix)]{
            use std::os::unix::fs::OpenOptionsExt;
            cfg.mode(0o600);
        }
        let mut file=cfg.open(path)?;
        file.write_all(data)?;file.sync_all()?;
        Ok(())
    }
    fresh(&p.join("owner-frozen.json"),&bytes)?;
    fresh(&p.join("owner-frozen.sha256"),format!("{hash}\n").as_bytes())?;
    println!("{}",serde_json::to_string_pretty(&json!({
        "status":"ALL_OWNER_BRANCHES_SIGNED_AND_FROZEN",
        "generationCount":3,
        "firstExitOptionsPerGeneration":2,
        "subsequentOtherOwnerExitsPerGeneration":2,
        "savedBytesSha256":hash,
        "privateFrostSharesPresent":false,
        "maliciousLiveQuorumTheftBitcoinValid":true,
        "latestPrincipalSats":100_000,
        "signerProcessMustTerminateBeforeAnyOwnerExit":true
    }))?);
    Ok(())
}
