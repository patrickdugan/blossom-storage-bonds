//! Disposable regtest holder-custody checks for the real FROST P2TR demo.
//! A Bitcoin-confirmed payout can be independently spent by its beneficiary.
//! THIS DOES NOT prove unilateral spending of the pooled carrier before the
//! FROST federation authorizes settlement.
use super::*;
use bitcoin::consensus::encode::serialize_hex;

pub(super) fn assert_no_unilateral_carrier_exit(rpc:&Rpc,unsigned:&Transaction)->ResultX<Value> {
    // Funded, independently sponsored fees do not confer control over the
    // Taproot carrier. Attempted bearer exits are not authorization proofs.
    let sponsor=rpc.call("signrawtransactionwithwallet",
        &[json!(serialize_hex(unsigned))],Some("sponsor"))?;
    require(sponsor["complete"]!=true,
        "separate fee wallet unexpectedly controls threshold carrier")?;
    let partially_funded=sponsor["hex"].as_str()
        .ok_or("Bitcoin Core fee signer omitted a partially signed transaction")?;
    let mut checks=serde_json::Map::new();
    for holder in ["alice","bob"] {
        let checked=rpc.call("signrawtransactionwithwallet",
            &[json!(partially_funded)],Some(holder));
        let rejected=match checked {
            Err(_) => true,
            Ok(value) => {
                require(value["complete"]!=true,
                    "beneficiary wallet unexpectedly signed pooled FROST carrier")?;
                let hex=value["hex"].as_str().ok_or("missing unsigned carrier attempt")?;
                let attempted:Transaction=deserialize(&unhex(hex)?)?;
                !rpc.witness_authorization(&attempted)?
            }
        };
        require(rejected,"user wallet authorized pooled P2TR carrier without threshold")?;
        checks.insert(holder.to_owned(),json!(rejected));
    }
    Ok(json!({
        "payoutsNotYetReleased":true,
        "sponsorAlreadySignedItsOnlyInput":true,
        "noBip341FrostSignature":true,
        "ownerOnlyCarrierSpendRejected":checks,
        "unilateralCarrierRecoveryProven":false
    }))
}

fn owner_psbt(
    rpc:&Rpc,holder:&str,counterparty:&str,
    payout:OutPoint,original_sats:u64,
)->ResultX<(String,ScriptBuf,u64)>{
    require(original_sats>1000,"holder's individual payout cannot pay the regtest fee")?;
    let (destination,script)=rpc.address(holder)?;
    let reduced=original_sats-1_000;
    let mut obj=serde_json::Map::new();
    obj.insert(destination,json!(reduced as f64/100_000_000.0));
    let unsigned=rpc.text("createpsbt",&[
        json!([{"txid":payout.txid.to_string(),"vout":payout.vout}]),
        Value::Object(obj),json!(0),json!(true),
    ],None)?;
    let cross=rpc.call("walletprocesspsbt",
        &[json!(unsigned.clone()),json!(true)],Some(counterparty));
    let cross_rejected=match cross {
        Err(_)=>true,
        Ok(partial)=>partial["complete"]!=true,
    };
    require(cross_rejected,"other holder wallet completed the beneficiary's PSBT")?;
    let own=rpc.call("walletprocesspsbt",
        &[json!(unsigned),json!(true)],Some(holder))?;
    require(own["complete"]==true,
        "holder wallet did not sign/finalize its own regtest P2WPKH payout")?;
    let final_psbt=rpc.call("finalizepsbt",&[own["psbt"].clone()],None)?;
    require(final_psbt["complete"]==true,"failed to finalize beneficiary-only PSBT")?;
    let hex=final_psbt["hex"].as_str().ok_or("finalized PSBT missing raw Bitcoin witness")?;
    let signed:Transaction=deserialize(&unhex(hex)?)?;
    require(signed.input.len()==1&&signed.input[0].previous_output==payout,
        "owner PSBT improperly drew any other funds")?;
    require(signed.output.len()==1&&
        signed.output[0].value.to_sat()==reduced&&
        signed.output[0].script_pubkey==script,
        "owner PSBT redirected or altered its redemption")?;
    require(rpc.witness_authorization(&signed)?,
        "owner-controlled Bitcoin redemption was rejected by Core")?;
    let txid=rpc.text("sendrawtransaction",&[json!(serialize_hex(&signed))],None)?;
    require(txid==signed.compute_txid().to_string(),
        "Bitcoin Core broadcast an unexpected beneficiary redemption")?;
    Ok((txid,script,reduced))
}

pub(super) fn redeem_distinct_wallets(
    rpc:&Rpc, miner:&str,alice:OutPoint,bob:OutPoint
)->ResultX<Value>{
    // Neither call invokes FROST, invokes the sponsor wallet or accesses the
    // original threshold share packages. This only proves post-payout rights.
    let (alice_id,alice_script,alice_amount)=owner_psbt(rpc,"alice","bob",alice,60_000)?;
    let (bob_id,bob_script,bob_amount)=owner_psbt(rpc,"bob","alice",bob,40_000)?;
    require(alice_id!=bob_id&&alice_script!=bob_script,
        "two payouts were not independently signed to different wallet scripts")?;
    rpc.mine(6,miner)?;
    let alice_chain=rpc.confirmed(&alice_id,6)?;
    let bob_chain=rpc.confirmed(&bob_id,6)?;
    require(rpc.call("gettxout",
        &[json!(alice.txid.to_string()),json!(alice.vout)],None)?.is_null()
        && rpc.call("gettxout",
        &[json!(bob.txid.to_string()),json!(bob.vout)],None)?.is_null(),
        "holder payout remains unspent despite confirmed redemption")?;
    rpc.coin(&alice_id,&alice_script,alice_amount)?;
    rpc.coin(&bob_id,&bob_script,bob_amount)?;
    Ok(json!({
        "actualBitcoinCoreConfirmed":true,
        "noFrostSigningRoundNeededAfterSplit":true,
        "walletsSeparatelyKeyed":true,
        "crossSigningBlocked":true,
        "noSponsorInputUsed":true,
        "alice":{
            "originalPayoutOutpoint":alice.to_string(),
            "originalValueSats":60_000,
            "reclaimedSats":alice_amount,
            "ownerWalletFeeSats":1_000,
            "rawTransaction":output_summary(&alice_chain)?
        },
        "bob":{
            "originalPayoutOutpoint":bob.to_string(),
            "originalValueSats":40_000,
            "reclaimedSats":bob_amount,
            "ownerWalletFeeSats":1_000,
            "rawTransaction":output_summary(&bob_chain)?
        },
        "combinedBeneficiaryWalletFeesSats":2_000,
        "provesPreSplitFederationFreeExit":false
    }))
}
