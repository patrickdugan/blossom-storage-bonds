#!/usr/bin/env node
/**
 * Independently audit exported signed Sapio oracle/MID guest transaction
 * vectors, their two original member balances, and linked successor roots.
 *
 * These are synthetic Sapio fixture outpoints. Never call these funded
 * Bitcoin spends, or confuse a valid oracle wrapper with a Bitcoin-native
 * state covenant or the funded FROST keypath.
 */
import {createHash} from 'node:crypto';
import {readFile,open} from 'node:fs/promises';
import {resolve} from 'node:path';
const SHA='34363851a11d0f2b3ddb27c050537c1a2e5b7e9b';
const fail=(m)=>{throw Error(m);};
const check=(x,m)=>{if(!x)fail(m);};
const h64=x=>typeof x==='string'&&/^[0-9a-f]{64}$/i.test(x);
const h=x=>createHash('sha256').update(x).digest();
const doubleHash=hex=>{
  check(typeof hex==='string'&&/^(?:[a-f0-9]{2})+$/i.test(hex),'invalid signed MID hex');
  return Buffer.from(h(h(Buffer.from(hex,'hex')))).reverse().toString('hex');
};
function checkRoot(r,amount){
  check(r&&h64(r.merkleSumHash)&&r.satoshis===amount &&
    typeof r.canonicalNodeBytesHex==='string'&&
    /^[0-9a-f]{82}$/i.test(r.canonicalNodeBytesHex),
    'wrong MID Merkle-sum state or missing canonical root bytes');
  const bytes=Buffer.from(r.canonicalNodeBytesHex,'hex');
  check(bytes.subarray(0,32).toString('hex')===r.merkleSumHash.toLowerCase() &&
    Number(bytes.readBigUInt64LE(32))===amount && bytes[40]===1,
    'MID root sum encoding is not canonical');
}
function checkTx(t,expectedSum,ownerScript){
  check(t&&h64(t.txid)&&h64(t.wtxid)&&
    Number.isInteger(t.vbytes)&&t.vbytes>0 &&
    Array.isArray(t.inputOutpoints)&&t.inputOutpoints.length===2 &&
    t.inputOutpoints.every(o=>/^[a-f0-9]{64}:[0-9]+$/i.test(o)) &&
    t.allWitnessInputsNonempty===true,
    'missing two-input oracle+fee signed MID witness');
  check(t.wtxid.toLowerCase()===doubleHash(t.hex),
    'real signed MID witness was substituted or mislabeled');
  check(Array.isArray(t.outputs)&&t.outputs.length===2 &&
    t.outputs[0].index===0&&t.outputs[0].sats===expectedSum &&
    t.outputs[1].index===1&&
    t.outputs[1].scriptPubkeyHex===ownerScript,
    'oracle MID successor or exact beneficiary script changed');
  check(t.outputs.every((o,i)=>o.index===i&&
    Number.isSafeInteger(o.sats)&&o.sats>=0 &&
    typeof o.scriptPubkeyHex==='string'&&
    /^(?:[a-f0-9]{2})+$/i.test(o.scriptPubkeyHex)),
    'MID signed transaction has invalid output encoding');
}
export function verifyVectors(v){
  check(v&&v.schema==='bsb-sapio-pinned-mid-two-exits-v1'&&
    v.pinnedSource===SHA&&
    v.network==='synthetic-Sapio-fixture-outpoints-NOT-chain'&&
    v.initialPrincipalSats===100_000&&
    v.otherMemberSignatureRequired===false&&
    v.onlineSapioEmulationOracleRequired===true&&
    v.bitcoinConsensusRecognizesMidGuest===false&&
    v.sameScriptAsFundedFrostCarrier===false&&
    v.sourceBlossomPdpHashCryptographicallyBound===false&&
    v.allMidOracleGuestWitnessesSigned===true&&
    v.allLineageValuesConserved===true&&v.feeSatsPerExit===2_000,
    'MID oracle vector is stale or misclassified');
  const root=v.principalRoots;
  checkRoot(root?.initial,100_000);
  checkRoot(root?.afterAlice,40_000);
  checkRoot(root?.afterBob,0);
  check(root.initial.merkleSumHash!==root.afterAlice.merkleSumHash&&
    root.afterAlice.merkleSumHash!==root.afterBob.merkleSumHash,
    'MID root was replayed or not advanced');
  check(/^5120[0-9a-f]{64}$/i.test(v.initialMidScriptPubkeyHex),
    'pinned MID carrier output does not use a native P2TR covenant wrapper');
  const scripts=v.payoutScripts;
  check(/^5120[a-f0-9]{64}$/i.test(scripts?.alice)&&
    /^5120[a-f0-9]{64}$/i.test(scripts?.bob)&&
    scripts.alice!==scripts.bob,
    'MID holder payout scripts are not two distinct x-only keys');
  checkTx(v.aliceExit,40_000,scripts.alice);
  checkTx(v.bobExit,0,scripts.bob);
  check(v.aliceExit.outputs[1].sats===60_000&&
    v.bobExit.outputs[1].sats===40_000,
    'MID signed owner entitlement amounts changed');
  check(v.bobExit.inputOutpoints[0]===v.aliceExit.txid+':0',
    'MID Bob exit failed to spend Alice exit successor');
  check(v.aliceExit.txid!==v.bobExit.txid&&
    v.aliceExit.wtxid!==v.bobExit.wtxid,
    'MID signed exits share transaction identity');
  return {
    schema:'bsb-sapio-pinned-mid-exit-verified-v1',
    sapioRevision:SHA,
    actualCompiledOracleGuestTransitions:2,
    syntheticPayoutSats:{alice:60_000,bob:40_000},
    merkleSumSequenceSats:[100_000,40_000,0],
    canonicalRootHashes:[
      root.initial.merkleSumHash,root.afterAlice.merkleSumHash,
      root.afterBob.merkleSumHash,
    ],
    signedMidExitTxids:{alice:v.aliceExit.txid,bob:v.bobExit.txid},
    witnessTransactionIdsRehashed:true,
    syntheticSeparateSponsorFeesSats:4_000,
    physicalMidCarrierScriptPubkeyHex:v.initialMidScriptPubkeyHex,
    bitcoinCoreConfirmed:false,
    bitcoinConsensusEnforcedMid:false,
    onlineOracleRequired:true,
    unilateralExitDuringTotalOracleOutageProven:false,
    sameBitcoinCarrierAsFundedFrost:false,
    storagePdpEvidenceBoundToMidRoot:false,
  };
}
async function main(args){
  check(args.length===1||args.length===2,
    'usage: node verify_mid_vectors.mjs PINNED-REAL-INPUT.json [NEW-VERIFIED-OUTPUT.json]');
  const data=JSON.parse(await readFile(resolve(args[0]),'utf8'));
  const result=verifyVectors(data);
  const json=JSON.stringify(result,null,2)+'\n';
  if(args[1]){
    const fd=await open(resolve(args[1]),'wx',0o600);
    try{await fd.writeFile(json);await fd.sync();}
    finally{await fd.close();}
  } else process.stdout.write(json);
}
if(process.argv[1]&&import.meta.url===new URL('file://'+resolve(process.argv[1])).href){
  main(process.argv.slice(2)).catch(e=>{console.error(e.message);process.exitCode=1;});
}
