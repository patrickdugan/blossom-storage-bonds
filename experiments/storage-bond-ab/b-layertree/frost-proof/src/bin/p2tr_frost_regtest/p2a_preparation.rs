//! Real FROST one-input v3 parent freeze; two actual P2A refresh packages.
use super::*;
use super::p2a_parent as p;
use std::{fs::OpenOptions,io::Write,path::Path};

pub(super) fn prepare(args:Vec<String>)->ResultX<()>{
    let mut cli=None;let mut datadir=None;let mut evidence=None;let mut dir=None;
    let mut iter=args.into_iter();
    while let Some(k)=iter.next(){
        let v=iter.next().ok_or("v3 preparation option omitted a value")?;
        match k.as_str(){
            "--bitcoin-cli"=>cli=Some(v),
            "--datadir"=>datadir=Some(v),
            "--evidence-hash"=>evidence=Some(v),
            "--out-dir"=>dir=Some(v),
            _=>return Err(format!("unrecognized FROST P2A option {k}").into())
        }
    }
    let evidence:String=evidence.ok_or("missing source Merkle proof hash")?;
    require(evidence.len()==64&&evidence.bytes().all(|b|b.is_ascii_hexdigit()),
        "P2A preparation requires 64 hex source evidence bytes")?;
    let dest:String=dir.ok_or("missing frozen directory")?;
    require(!Path::new(&dest).join("p2a-frozen.json").exists(),
        "previous signed v3 recovery package cannot be overwritten")?;
    let rpc=Rpc{binary:PathBuf::from(cli.ok_or("missing bitcoin-cli")?),
        datadir:PathBuf::from(datadir.ok_or("missing datadir")?)};
    rpc.chain()?;
    let (shares,public)=frost::keys::generate_with_dealer(
        3,2,frost::keys::IdentifierList::Default,&mut OsRng)?;
    let mut keys=Packages::new();
    for(id,share)in shares{keys.insert(id,frost::keys::KeyPackage::try_from(share)?);}
    require(keys.len()==3,"incorrect three-party FROST dealer key count")?;
    let ids=keys.keys().copied().collect::<Vec<_>>();
    let secp=Secp256k1::new();
    let internal=bitcoin_group_internal_key(&public)?;
    let vault=Address::p2tr(&secp,internal,None,Network::Regtest);
    let spk=vault.script_pubkey();
    let output_key=XOnlyPublicKey::from_slice(
        spk.as_bytes().get(2..34).ok_or("malformed P2TR FROST key")?)?;
    for wallet in ["miner","refreshfee","relayfee","legacyfee","alice","bob"]{
        rpc.call("createwallet",&[json!(wallet)],None)?;
    }
    let (miner,_)=rpc.address("miner")?;
    rpc.mine(101,&miner)?;
    let (refresh_addr,refresh_script)=rpc.address("refreshfee")?;
    let (relay_addr,relay_script)=rpc.address("relayfee")?;
    let (legacy_addr,legacy_script)=rpc.address("legacyfee")?;
    let (_,alice_script)=rpc.address("alice")?;
    let (_,bob_script)=rpc.address("bob")?;
    require(alice_script!=bob_script&&relay_script!=legacy_script,
        "different regtest participants got identical Bitcoin payout scripts")?;
    let fund=rpc.text("sendtoaddress",
        &[json!(vault.to_string()),json!(sats_to_btc(PRINCIPAL))],Some("miner"))?;
    let refresh_fund=rpc.text("sendtoaddress",
        &[json!(refresh_addr),json!(sats_to_btc(50_000))],Some("miner"))?;
    let relay_fund=rpc.text("sendtoaddress",
        &[json!(relay_addr),json!(sats_to_btc(50_000))],Some("miner"))?;
    let legacy_fund=rpc.text("sendtoaddress",
        &[json!(legacy_addr),json!(sats_to_btc(10_000))],Some("miner"))?;
    rpc.mine(6,&miner)?;
    let (mut carrier,mut prev)=rpc.coin(&fund,&spk,PRINCIPAL)?;
    let (mut refresh_fee,mut refresh_prev)=rpc.coin(&refresh_fund,&refresh_script,50_000)?;
    let (relay_coin,_)=rpc.coin(&relay_fund,&relay_script,50_000)?;
    let (legacy_coin,_)=rpc.coin(&legacy_fund,&legacy_script,10_000)?;
    let mut generations=Vec::new();
    let mut rng=OsRng;
    for index in 0..3u32 {
        let mut branches=serde_json::Map::new();
        for(name,other,value,remainder,first_script,second_script)in [
            ("alice","bob",60_000,40_000,&alice_script,&bob_script),
            ("bob","alice",40_000,60_000,&bob_script,&alice_script)
        ]{
            let first=p::parent(carrier,vec![
                p::output(remainder,&spk),p::output(value,first_script)
            ]);
            let signed_first=p::signed_parent(&keys,&public,&ids,first,
                &prev,output_key,&mut rng)?;
            let descendant=OutPoint::new(signed_first.compute_txid(),0);
            let signed_second=p::signed_parent(&keys,&public,&ids,
                p::parent(descendant,vec![p::output(remainder,second_script)]),
                &p::output(remainder,&spk),output_key,&mut rng)?;
            branches.insert(name.into(),json!({
                "firstOwner":name,"otherOwner":other,
                "firstSats":value,"otherSats":remainder,
                "first":p::record(&signed_first,carrier),
                "second":p::record(&signed_second,descendant),
                "otherOwnerPreSignedDescendant":descendant.to_string(),
                "feeInputsBoundIntoParent":false
            }));
        }
        let refresh=if index<2 {
            let signed=p::signed_parent(&keys,&public,&ids,
                p::parent(carrier,vec![p::output(PRINCIPAL,&spk)]),
                &prev,output_key,&mut rng)?;
            let fee_child=p::fund_child(&rpc,&signed,refresh_fee,&refresh_prev,
                &refresh_script,"refreshfee")?;
            p::submit(&rpc,&signed,&fee_child)?;
            rpc.mine(1,&miner)?;
            let pid=signed.compute_txid().to_string();
            let cid=fee_child.compute_txid().to_string();
            rpc.confirmed(&pid,1)?;
            rpc.confirmed(&cid,1)?;
            (refresh_fee,refresh_prev)=rpc.coin(&cid,&refresh_script,
                refresh_prev.value.to_sat()-p::FEE)?;
            Some(json!({
                "parent":p::record(&signed,carrier),
                "childTxid":cid,
                "childWtxid":fee_child.compute_wtxid().to_string(),
                "childVbytes":fee_child.vsize(),
                "childFeeSats":p::FEE,
                "actualBitcoinCoreSubmitpackageSuccess":true
            }))
        }else{None};
        generations.push(json!({
            "generation":index,"carrierBefore":carrier.to_string(),
            "carrierScriptPubkeyHex":hex(spk.as_bytes()),
            "principalSats":PRINCIPAL,"branches":branches,
            "refreshBroadcast":refresh
        }));
        if index<2 {
            let pid=generations.last().unwrap()["refreshBroadcast"]["parent"]["txid"]
                .as_str().ok_or("refresh parent id absent")?;
            (carrier,prev)=rpc.coin(pid,&spk,PRINCIPAL)?;
        }
    }
    for old in generations.iter().take(2) {
        let op=old["carrierBefore"].as_str().ok_or("old outpoint absent")?;
        let mut it=op.split(':');
        let txid=it.next().ok_or("old txid missing")?;
        let vout:u32=it.next().ok_or("old vout missing")?.parse()?;
        require(rpc.call("gettxout",&[json!(txid),json!(vout)],None)?.is_null(),
            "Bitcoin still sees previous generation's spent P2TR carrier")?;
    }
    let report=json!({
        "schema":"bsb-frost-truc-p2a-presigned-dag-v1",
        "network":"regtest",
        "sourceBlossomPdpEvidenceHash":evidence,
        "realFrostBip341TaprootKeypath":true,
        "onlyOneInputPerPresignedParent":true,
        "zeroParentFeeSats":0,
        "zeroValueAnchorScriptHex":hex(p::anchor().as_bytes()),
        "generationCount":3,
        "latestGeneration":2,
        "originalPrincipalSats":PRINCIPAL,
        "entitlementsSats":{"alice":60_000,"bob":40_000},
        "beneficiaryScripts":{
            "alice":hex(alice_script.as_bytes()),"bob":hex(bob_script.as_bytes())
        },
        "principalCarrierScript":hex(spk.as_bytes()),
        "minerAddress":miner,
        "relayFeePayerScript":hex(relay_script.as_bytes()),
        "relayFeePayerConfirmedOutpoint":relay_coin.to_string(),
        "legacyCandidateScript":hex(legacy_script.as_bytes()),
        "legacyCandidateConfirmedOutpoint":legacy_coin.to_string(),
        "childFeeSats":p::FEE,"snapshots":generations,
        "allFrostSharesRemainInSignerProcess":true,
        "onlineSapioOracleRequiredToRelay":false,
        "holderWalletSignaturesRequiredToRelay":false,
        "v3ParentSignerKeysRequiredToFundChild":false,
        "activeMaliciousTwoShareQuorumCouldRedirect":true,
        "experimentalMidRulesBitcoinEnforced":false,
        "differentFeePayerCanFundSameParent":true,
        "relayMustProvideFreshValidChild":true,
        "unboundedRefreshCoverageProven":false
    });
    let bytes=serde_json::to_vec_pretty(&report)?;
    let hash=hex(sha(&bytes));
    let root=Path::new(&dest);
    std::fs::create_dir_all(root)?;
    #[cfg(unix)]{
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root,std::fs::Permissions::from_mode(0o700))?;
    }
    fn write(path:&Path,bytes:&[u8])->ResultX<()>{
        let mut f=OpenOptions::new();
        f.write(true).create_new(true);
        #[cfg(unix)]{
            use std::os::unix::fs::OpenOptionsExt;
            f.mode(0o600);
        }
        let mut out=f.open(path)?;
        out.write_all(bytes)?;out.sync_all()?;Ok(())
    }
    write(&root.join("p2a-frozen.json"),&bytes)?;
    write(&root.join("p2a-frozen.sha256"),format!("{hash}\n").as_bytes())?;
    println!("{}",serde_json::to_string_pretty(&json!({
        "status":"BIP341_V3_FROST_P2A_PARENT_FREEZE_COMPLETE",
        "generationCount":3,
        "twoRefreshesConfirmedWithSubmitpackage":true,
        "originalFrozenSha256":hash,
        "privateFrostSharesExported":false
    }))?);
    Ok(())
}
