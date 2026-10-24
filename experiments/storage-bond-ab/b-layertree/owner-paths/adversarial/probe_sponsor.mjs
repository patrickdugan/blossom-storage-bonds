#!/usr/bin/env node
/**
 * Recovery only: real Bitcoin Core observation with FROST signer,
 * sponsor wallet, and beneficiary wallets all unavailable.
 *
 * ONE-FIRST sponsor loss: alternate Bob-first branch still publishes
 * BOTH owner payments through presigned successor.
 * BOTH-FIRST loss: neither available owner-first transaction can enter mempool.
 * BOB-SECOND loss: Alice-first confirms but Bob's remainder is stuck in P2TR.
 *
 * No new signatures or access to signer private shares.
 */
import {readFile,open} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {bitcoinCli,run as relayOwner} from '../relay_owner_branch.mjs';
const expect=(x,s)=>{if(!x)throw Error(s);};
const sha=x=>createHash('sha256').update(x).digest('hex');
const sats=n=>Math.round(Number(n)*100_000_000);
const point=s=>{const match=/^([a-f0-9]{64}):(\d+)$/i.exec(s);expect(match,'invalid outpoint');return {txid:match[1],vout:Number(match[2])};};
async function saved(dir,pin,attackFile){
  const raw=await readFile(resolve(dir,'owner-frozen.json'));
  const local=(await readFile(resolve(dir,'owner-frozen.sha256'),'utf8')).trim();
  expect(sha(raw)===pin&&local===pin,'frozen material rolled back or rewritten');
  const p=JSON.parse(raw.toString('utf8'));
  expect(p.schema==='bsb-frost-owner-branch-prepared-v1' &&
    p.generations.length===3&&p.latestGeneration===2,
    'not exact three-generation signed Bitcoin recovery set');
  const attack=JSON.parse(await readFile(resolve(attackFile),'utf8'));
  expect(attack.schema==='bsb-frost-sponsored-outpoint-sabotage-regtest-v1' &&
    attack.frozenManifestSha256===pin &&
    attack.maliciousSpendSignedBySponsorWalletOnly===true &&
    attack.signerProcessAlreadyExited===true,
    'malicious fee input evidence was not independently preserved');
  return {p,attack};
}
function status(node,spent){
  const a=node('testmempoolaccept',[[spent]]);
  expect(a?.length===1,'Bitcoin Core missing candidate acceptance status');
  return a[0].allowed===true;
}
export async function prove({binary,datadir,dir,expectedSha,attackFile,mode,out}) {
  expect(/^[a-f0-9]{64}$/i.test(expectedSha),'bad externally pinned SHA256');
  const {p,attack}=await saved(dir,expectedSha,attackFile);
  expect(mode===attack.mode,'conflicting attack and independent relay mode');
  const node=bitcoinCli(binary,datadir);
  expect(node('getblockchaininfo').chain==='regtest',
    'refusing to submit adversarial Bitcoin transactions outside disposable regtest');
  const wallets=node('listwallets');
  expect(JSON.stringify(wallets)===JSON.stringify(['miner']),
    'FROST sponsor/owner signing wallets still online during outage test');
  const current=p.generations[2],alice=current.branches.alice,
    bob=current.branches.bob;
  expect(p.fundedPrincipalSats===100000&&
    alice.first.exactOutputs[1].sats===60000&&
    bob.first.exactOutputs[1].sats===40000,
    'frozen beneficiary entitlements changed from reviewed setup');
  const carrier=point(current.carrierBefore);
  const coin=node('gettxout',[carrier.txid,carrier.vout]);
  expect(coin&&sats(coin.value)===100000,
    'recovery principal was already consumed before attacked sponsor coin checks');
  const expectedTargets=mode==='alice-first'?
    [alice.first.sponsorInput]:
    mode==='both-first'?[alice.first.sponsorInput,bob.first.sponsorInput]:
    mode==='bob-second'?[alice.second.sponsorInput]:null;
  expect(expectedTargets&&
    JSON.stringify(expectedTargets.sort())===
      JSON.stringify(attack.onchainConflicts.map(x=>x.sabotagedOutpoint).sort()),
    'actual attacked sponsor UTXOs differ from the committed branch inputs');
  for(const a of attack.onchainConflicts){
    const input=point(a.sabotagedOutpoint);
    expect(node('gettxout',[input.txid,input.vout])===null,
      'hostile sponsor input was not spent on Bitcoin before signing was unavailable');
    const transaction=node('getrawtransaction',[a.sabotageTxid,true]);
    expect(transaction.confirmations>=1 &&
      transaction.vin.length===1 &&
      transaction.vin[0].txid===input.txid &&
      transaction.vin[0].vout===input.vout,
      'sponsor sabotage did not confirm on the active Bitcoin history');
  }
  const aliceAllowed=status(node,alice.first.signedHex),
    bobAllowed=status(node,bob.first.signedHex);
  let result={
    schema:'bsb-frost-sponsor-liveness-counterexample-v1',
    network:'regtest',mode,frozenManifestSha256:expectedSha,
    preSignedGeneration:2,
    sponsorInputsSpentBeforeOwnerPublication:attack.onchainConflicts.length,
    activeFrostOrSapioSigningServiceAvailable:false,
    principalSatsBeforeAttack:100000,
    sponsorSabotageDoesNotSpendCarrier:true,
    aliceFirstInitiallyMempoolValid:aliceAllowed,
    bobFirstInitiallyMempoolValid:bobAllowed,
    noNativeMidEnforcement:true,
    maliciousThresholdCanStillSteal:true
  };
  if(mode==='alice-first'){
    expect(!aliceAllowed&&bobAllowed,
      'single sponsorship loss must invalidate Alice-first but preserve Bob-first');
    // The intact alternative can publish without ANY fresh signing.
    const fallbackPath=out+'.fallback.json';
    const relay=await relayOwner({
      binary,datadir,dir,sha256:expectedSha,first:'bob',out:fallbackPath,
      degradedSponsor:true,
    });
    expect(relay.firstExit.confirmations>=6&&relay.secondExit.confirmations>=6 &&
      relay.independentlyConfirmedOutputs.alice.sats===60000 &&
      relay.independentlyConfirmedOutputs.bob.sats===40000 &&
      relay.alternativeSponsorSpentFallback===true &&
      relay.securityBoundaries.activeMaliciousQuorumCanStillSteal===true,
      'healthy other-branch signed recovery failed after sponsor sabotage');
    result={...result,
      fallbackPresignedOtherFirstConfirmed:true,
      fallbackPublishedAs:'bob-first-then-alice',
      firstPayoutSats:40000,secondPayoutSats:60000,
      totalExternalSponsorFeesOfFallbackSats:6000,
      bothOwnersReceivedFullCollateral:true,
      independentOwnerSignatureForFirstOrSecondNotRequired:true,
      recipientExclusivityProven:false,
      fallbackReceiptTxids:[relay.firstExit.txid,relay.secondExit.txid],
      serviceDeadLivenessWithSingleSponsorAttack:true
    };
  }else if(mode==='both-first'){
    expect(!aliceAllowed&&!bobAllowed,
      'both first-branch sponsor spends must invalidate all frozen first exits');
    const still=node('gettxout',[carrier.txid,carrier.vout]);
    expect(still&&sats(still.value)===100000,
      'malicious sponsor was able to steal the underlying pledged collateral');
    result={...result,
      noFrozenOwnerFirstExitAvailable:true,
      bondedPrincipalStillLockedSats:100000,
      signerFreeRecoveryPossibleFromThisSignedDAG:false,
      wouldNeedFreshQuorumOrNewFeeAuthorization:true,
      noCurrentFirstBranchBroadcast:true,
      failureClass:'dual-sponsor-outpoint-liveness-denial'
    };
  }else if(mode==='bob-second'){
    expect(aliceAllowed&&bobAllowed,
      'second-claim sponsor sabotage must leave first exits valid');
    // Following presigned first step cannot be safely completed for Bob.
    const txid=node('sendrawtransaction',[alice.first.signedHex]);
    expect(txid===alice.first.txid,'wrong first owner signed transaction was sent');
    node('generatetoaddress',[6,p.minerAddress]);
    const first=node('getrawtransaction',[txid,true]);
    expect(first.confirmations>=6&&first.hash===alice.first.wtxid,
      'Alice valid first claim did not confirm against Bitcoin');
    const bobSecondAllowed=status(node,alice.second.signedHex);
    expect(!bobSecondAllowed,
      'Bob second exit unexpectedly remained spendable despite consumed sponsor input');
    const remainder=point(alice.second.principalInput);
    const remaining=node('gettxout',[remainder.txid,remainder.vout]);
    expect(remaining&&sats(remaining.value)===40000 &&
      remaining.scriptPubKey.hex===current.carrierScriptPubkeyHex,
      'Bob successor funds not held in locked real P2TR output');
    const bobAlternative=status(node,bob.first.signedHex);
    expect(!bobAlternative,'Bob conflicting first exit still spendable after Alice paid');
    const alicePayout=node('gettxout',[txid,1]);
    expect(alicePayout&&sats(alicePayout.value)===60000,
      'Alice original full entitlement was shaved by sponsor sabotage');
    result={...result,
      aliceFirstConfirmed:true,bobSecondSponsorCoinConsumed:true,
      bitcoinRefusedPreviouslySignedBobSecondExit:true,
      bobRemainderLockedSats:40000,
      aliceUnspentPayoutSats:60000,
      bobOwnerCouldNotRedeemAfterSignerShutdown:true,
      alternativeBobFirstAlreadyInvalidAfterAliceConfirmed:true,
      currentFirstTransaction:txid,
      failureClass:'descendant-sponsor-outpoint-liveness-denial'
    };
  }
  const fd=await open(out,'wx',0o600);
  try{await fd.writeFile(JSON.stringify(result,null,2)+'\n');await fd.sync();}
  finally{await fd.close();}
  return result;
}
async function main(args) {
  const o={};
  for(let i=0;i<args.length;i++){
    const name=args[i],value=args[++i];expect(value,'missing argument value for '+name);
    if(name==='--bitcoin-cli')o.binary=resolve(value);
    else if(name==='--datadir')o.datadir=resolve(value);
    else if(name==='--frozen-dir')o.dir=resolve(value);
    else if(name==='--sha256')o.expectedSha=value;
    else if(name==='--attack')o.attackFile=resolve(value);
    else if(name==='--mode')o.mode=value;
    else if(name==='--out')o.out=resolve(value);
    else throw Error('unsupported sponsor liveness argument '+name);
  }
  expect(o.binary&&o.datadir&&o.dir&&o.expectedSha&&o.attackFile&&o.mode&&o.out,
    'missing required signer-dead sponsor-liveness options');
  console.log(JSON.stringify(await prove(o),null,2));
}
if(process.argv[1]&&import.meta.url===new URL('file://'+resolve(process.argv[1])).href){
  main(process.argv.slice(2)).catch(e=>{console.error('Signer-dead sponsor probe:',e.message);process.exitCode=1;});
}
