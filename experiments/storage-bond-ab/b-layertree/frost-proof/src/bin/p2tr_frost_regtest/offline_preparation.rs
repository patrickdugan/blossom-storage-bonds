//! Two-phase, durable, signed, three-generation Bitcoin regtest carrier.
 //!
 //! PREP only: generation of ephemeral trusted-dealer 2-of-3 FROST shares
 //! and sponsor-wallet Bitcoin signatures. Pre-signed full-split exits for
 //! generations 0/1/2 are frozen with hashes before the process exits.
 //!
 //! Later a separate Node executable broadcasts current signed bytes with
 //! no FROST crates, no sponsor wallet, no owner wallets and no oracle.
 //! This is liveness against ABSENT signers, not anti-theft protection
 //! against a malicious quorum signing another conflicting transaction.
use super::*;
use std::{fs::OpenOptions,io::Write,path::Path};
pub(super) fn prepare(args:Vec<String>)->ResultX<()> {
    let mut cli=None;let mut datadir=None;let mut evidence=None;let mut out=None;
    let mut args=args.into_iter();
    while let Some(flag)=args.next(){
        let value=args.next().ok_or("missing value for offline preparation argument")?;
        match flag.as_str(){
            "--bitcoin-cli"=>cli=Some(value),
            "--datadir"=>datadir=Some(value),
            "--evidence-hash"=>evidence=Some(value),
            "--out-dir"=>out=Some(value),
            _=>return Err(format!("unknown offline prep option {flag}").into()),
        }
    }
    let cli=cli.ok_or("missing --bitcoin-cli")?;
    let datadir=datadir.ok_or("missing --datadir")?;
    let evidence=evidence.ok_or("missing --evidence-hash")?;
    let out=out.ok_or("missing --out-dir")?;
    require(evidence.len()==64&&evidence.bytes().all(|x|x.is_ascii_hexdigit()),
        "Alice storage evidence must be exactly 32-byte SHA256 hex")?;
    let rpc=Rpc{binary:PathBuf::from(cli),datadir:PathBuf::from(datadir)};
    rpc.chain()?;
    require(!Path::new(&out).join("sealed-exits.json").exists(),
        "refusing to replace signed recovery evidence")?;
    let (shares,public)=frost::keys::generate_with_dealer(
        3,2,frost::keys::IdentifierList::Default,&mut OsRng)?;
    let mut packages=Packages::new();
    for (id,share) in shares {
        packages.insert(id,frost::keys::KeyPackage::try_from(share)?);
    }
    require(packages.len()==3,"ephemeral FROST share count !=3")?;
    let identifiers=packages.keys().copied().collect::<Vec<_>>();
    let internal=bitcoin_group_internal_key(&public)?;
    let secp=Secp256k1::new();
    let carrier_addr=Address::p2tr(&secp,internal,None,Network::Regtest);
    let carrier_script=carrier_addr.script_pubkey();
    let taproot_key=XOnlyPublicKey::from_slice(
        carrier_script.as_bytes().get(2..34).ok_or("P2TR commitment malformed")?)?;
    require(carrier_script.as_bytes().starts_with(&[0x51,0x20]),
        "carrier must be native BIP341 Taproot")?;
    for wallet in ["miner","sponsor","alice","bob"]{
        rpc.call("createwallet",&[json!(wallet)],None)?;
    }
    let (mining_address,_)=rpc.address("miner")?;
    rpc.mine(101,&mining_address)?;
    let (sponsor_addr,sponsor_script)=rpc.address("sponsor")?;
    let (alice_addr,alice_script)=rpc.address("alice")?;
    let (bob_addr,bob_script)=rpc.address("bob")?;
    require(alice_script!=bob_script,"two beneficiaries share an exit script")?;
    let theft_script=rpc.address("miner")?.1;
    let bond_funding=rpc.text("sendtoaddress", &[
        json!(carrier_addr.to_string()),json!(sats_to_btc(PRINCIPAL))],Some("miner"))?;
    let fee_funding=rpc.text("sendtoaddress",&[
        json!(sponsor_addr),json!(sats_to_btc(SPONSOR_INITIAL))],Some("miner"))?;
    rpc.mine(6,&mining_address)?;
    let (mut carrier_point,mut carrier_output)=rpc.coin(&bond_funding,&carrier_script,PRINCIPAL)?;
    let (mut sponsor_point,mut sponsor_output)=rpc.coin(&fee_funding,&sponsor_script,SPONSOR_INITIAL)?;
    let mut snapshots=Vec::new();
    let mut rng=OsRng;
    let mut malicious_quorum_valid=false;
    let mut malicious_txid=String::new();
    for generation in 0..=2u32 {
        let sponsor_input_sats=sponsor_output.value.to_sat();
        require(sponsor_input_sats>=EXTERNAL_FEE+1,
            "external sponsor ran out of spendable fee funds")?;
        let to_sponsor=sponsor_input_sats-EXTERNAL_FEE;
        let exit_commit=commit(&format!("frozen-full-split-gen-{generation}"),
            &evidence,&carrier_point);
        let exit_base=build(carrier_point,sponsor_point,
            vec![TxOut{value:Amount::from_sat(60_000),script_pubkey:alice_script.clone()},
                TxOut{value:Amount::from_sat(40_000),script_pubkey:bob_script.clone()}],
            &sponsor_script,to_sponsor,exit_commit);
        let (exit_frost,two_shares_only)=sign_frost_keypath(
            &public,&packages,&identifiers,[0,2],&exit_base,
            &[carrier_output.clone(),sponsor_output.clone()],taproot_key,&mut rng)?;
        require(two_shares_only,"exit unexpectedly signed with fewer than 2 FROST shares")?;
        let exit=rpc.sign_sponsor(&exit_frost)?;
        inspect_outputs(&exit,&[
            (alice_script.clone(),60_000),(bob_script.clone(),40_000),
            (sponsor_script.clone(),to_sponsor),
            (Builder::new().push_opcode(OP_RETURN).push_slice(exit_commit).into_script(),0)])?;
        require(rpc.witness_authorization(&exit)?,
            "frozen 60/40 exit did not pass Bitcoin Core mempool policy")?;
        let input_sum=carrier_output.value.to_sat()+sponsor_input_sats;
        let output_sum:u64=exit.output.iter().map(|o|o.value.to_sat()).sum();
        require(input_sum-output_sum==EXTERNAL_FEE &&
            exit.output[0].value.to_sat()+exit.output[1].value.to_sat()==PRINCIPAL,
            "frozen exit consumed principal for fees or leaked funds");
        let refresh_broadcast=if generation<2 {
            let refresh_commit=commit(&format!("advance-generation-{generation}"),
                &evidence,&carrier_point);
            let refresh_base=build(carrier_point,sponsor_point,
                vec![TxOut{value:Amount::from_sat(PRINCIPAL),
                    script_pubkey:carrier_script.clone()}],
                &sponsor_script,to_sponsor,refresh_commit);
            let (refresh_frost,_) =sign_frost_keypath(
                &public,&packages,&identifiers,[0,1],&refresh_base,
                &[carrier_output.clone(),sponsor_output.clone()],taproot_key,&mut rng)?;
            let signed=rpc.sign_sponsor(&refresh_frost)?;
            require(rpc.witness_authorization(&signed)?,
                "generation refresh failed Bitcoin Core signature checks")?;
            inspect_outputs(&signed,&[
                (carrier_script.clone(),PRINCIPAL),(sponsor_script.clone(),to_sponsor),
                (Builder::new().push_opcode(OP_RETURN).push_slice(refresh_commit).into_script(),0)])?;
            let id=rpc.text("sendrawtransaction",&[json!(serialize_hex(&signed))],None)?;
            require(id==signed.compute_txid().to_string(),
                "Bitcoin Core broadcast another generation")?;
            rpc.mine(1,&mining_address)?;
            rpc.confirmed(&id,1)?;
            Some(json!({
                "txid":id,
                "wtxid":signed.compute_wtxid().to_string(),
                "signedHex":serialize_hex(&signed),
                "sponsorFeeSats":EXTERNAL_FEE,
                "successorPrincipalSats":PRINCIPAL,
                "successorOutputIndex":0
            }))
        }else{None};
        snapshots.push(json!({
            "generation":generation,
            "carrierBefore":carrier_point.to_string(),
            "carrierScriptPubkeyHex":hex(carrier_script.as_bytes()),
            "sponsorBefore":sponsor_point.to_string(),
            "sponsorScriptPubkeyHex":hex(sponsor_script.as_bytes()),
            "sponsorInputSats":sponsor_input_sats,
            "independentSponsorFeeSats":EXTERNAL_FEE,
            "sponsorChangeSats":to_sponsor,
            "applicationCommitment":hex(exit_commit),
            "exitSignedHex":serialize_hex(&exit),
            "exitTxid":exit.compute_txid().to_string(),
            "exitWtxid":exit.compute_wtxid().to_string(),
            "exitVsize":exit.vsize(),
            "exitOutputs":[
                {"vout":0,"script":hex(alice_script.as_bytes()),"sats":60_000},
                {"vout":1,"script":hex(bob_script.as_bytes()),"sats":40_000},
                {"vout":2,"script":hex(sponsor_script.as_bytes()),"sats":to_sponsor},
                {"vout":3,"script":hex(
                    Builder::new().push_opcode(OP_RETURN)
                    .push_slice(exit_commit).into_script().as_bytes()),"sats":0}
            ],
            "refreshBroadcast":refresh_broadcast
        }));
        if generation<2 {
            let refresh=snapshots.last().unwrap()["refreshBroadcast"]["txid"]
                .as_str().ok_or("signed refresh txid missing")?;
            (carrier_point,carrier_output)=rpc.coin(refresh,&carrier_script,PRINCIPAL)?;
            (sponsor_point,sponsor_output)=rpc.coin(refresh,&sponsor_script,to_sponsor)?;
        }
    }
    // A living/malicious quorum can preempt the current signed exit.
    // Its Bitcoin validity is a *negative* security result, never broadcast.
    let sponsor_new=sponsor_output.value.to_sat()-EXTERNAL_FEE;
    let fake_root=commit("malicious-late-quorum-theft",&evidence,&carrier_point);
    let evil_base=build(carrier_point,sponsor_point,
        vec![TxOut{value:Amount::from_sat(PRINCIPAL),script_pubkey:theft_script}],
        &sponsor_script,sponsor_new,fake_root);
    let (evil_frost,_)=sign_frost_keypath(
        &public,&packages,&identifiers,[0,1],&evil_base,
        &[carrier_output,sponsor_output],taproot_key,&mut rng)?;
    let evil=rpc.sign_sponsor(&evil_frost)?;
    malicious_quorum_valid=rpc.witness_authorization(&evil)?;
    require(malicious_quorum_valid,
        "malicious 2-share quorum failed to demonstrate the honest-exit race")?;
    malicious_txid=evil.compute_txid().to_string();
    require(!rpc.call("gettxout",&[
        json!(snapshots[0]["carrierBefore"].as_str().unwrap().split(':').next().unwrap()),
        json!(0)],None)?.is_object(),
        "earliest fully spent P2TR carrier remained in active UTXO set")?;
    let root=Path::new(&out);
    std::fs::create_dir_all(root)?;
    #[cfg(unix)]{
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root,std::fs::Permissions::from_mode(0o700))?;
    }
    let payload=json!({
        "schema":"bsb-frost-frozen-offline-exit-v1",
        "chain":"regtest",
        "networkUse":"disposable-signing-fixture-only",
        "sighashType":"BIP341-SIGHASH_DEFAULT",
        "threshold":"2-of-3-real-ZF-FROST-secp256k1-tr-3.0.0",
        "dealerProcessMustDisappearBeforeBroadcast":true,
        "signerPrivateSharesInThisExport":false,
        "sapioOracleRequiredForPublication":false,
        "allWalletSignaturesAlreadyFrozen":true,
        "principalSats":PRINCIPAL,
        "aliceEntitlementSats":60_000,
        "bobEntitlementSats":40_000,
        "referenceBlossomPdpEvidenceHash":evidence,
        "minerAddress":mining_address,
        "requiredFinalGeneration":2,
        "snapshots":snapshots,
        "maliciousQuorumNegativeControl":{
            "bitcoinMempoolWouldAcceptConflictingSpend":malicious_quorum_valid,
            "broadcast":false,
            "txid":malicious_txid,
            "activeQuorumCouldDefeatPreSignedExit":true
        },
        "limits":{
            "jointPreSignedFullSplitRatherThanSeparateClaims":true,
            "aliceOrBobMayRelayEntireSplit":true,
            "eachHolderHasUnilateralClaimingScriptPath":false,
            "bitcoinMidCovenantEnforced":false,
            "allSignersUnavailableDuringRecoveryToBeTestedSeparately":true,
            "activeMaliciousQuorumTheftResistance":false,
            "separateFeeWalletRequiredAtRecovery":false,
            "filecoinAbsenceProofBitcoinVerifiable":false
        }
    });
    let encoded=serde_json::to_vec_pretty(&payload)?;
    let content_sha=hex(sha(&encoded));
    fn write_new(path:&Path,bytes:&[u8])->ResultX<()>{
        let mut opts=OpenOptions::new();opts.write(true).create_new(true);
        #[cfg(unix)]{
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file=opts.open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }
    write_new(&root.join("sealed-exits.json"),&encoded)?;
    write_new(&root.join("sealed-exits.sha256"),format!("{content_sha}\n").as_bytes())?;
    println!("{}",serde_json::to_string_pretty(&json!({
        "status":"PRE_SIGNER_SHUTDOWN_FREEZE_COMPLETE",
        "signedGenerationCount":3,
        "currentGeneration":2,
        "storedFileSha256":content_sha,
        "privateSharesInSavedEvidence":false,
        "presignedExitWtxids":payload["snapshots"].as_array().unwrap()
            .iter().map(|x|x["exitWtxid"].clone()).collect::<Vec<_>>(),
        "maliciousQuorumCompetingSpendWouldBeAccepted":malicious_quorum_valid,
        "bitcoinCarrierStillLockedSats":100_000,
        "broadcastAfterThisProcessExitsOnly":true
    }))?);
    Ok(())
}
