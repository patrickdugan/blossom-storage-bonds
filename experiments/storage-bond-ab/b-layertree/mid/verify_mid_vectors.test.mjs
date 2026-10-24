import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {verifyVectors} from './verify_mid_vectors.mjs';

const H=x=>x.repeat(64), sha=b=>createHash('sha256').update(b).digest();
const doubleHex=raw=>Buffer.from(sha(sha(Buffer.from(raw,'hex')))).reverse().toString('hex');
const root=(digest,sats)=>{
  const b=Buffer.alloc(41);
  Buffer.from(digest,'hex').copy(b);
  b.writeBigUInt64LE(BigInt(sats),32);
  b[40]=1;
  return {merkleSumHash:digest,satoshis:sats,
    canonicalNodeBytesHex:b.toString('hex')};
};
const tx=(raw,id,value,script,parent)=>({
  txid:id,wtxid:doubleHex(raw),hex:raw,vbytes:210,
  inputOutpoints:[parent,H('9')+':0'],allWitnessInputsNonempty:true,
  outputs:[
    {index:0,sats:value,scriptPubkeyHex:'51'},
    {index:1,sats:100_000-value- (value===0?60_000:0),scriptPubkeyHex:script}
  ]
});
function fixture(){
  const aliceScript='5120'+'11'.repeat(32),
    bobScript='5120'+'22'.repeat(32);
  const first=tx('02000111',H('a'),40_000,aliceScript,H('f')+':0');
  first.outputs[1].sats=60_000;
  const second=tx('02000112',H('b'),0,bobScript,H('a')+':0');
  second.outputs[1].sats=40_000;
  return {
    schema:'bsb-sapio-pinned-mid-two-exits-v1',
    pinnedSource:'34363851a11d0f2b3ddb27c050537c1a2e5b7e9b',
    network:'synthetic-Sapio-fixture-outpoints-NOT-chain',
    initialPrincipalSats:100_000,
    otherMemberSignatureRequired:false,
    onlineSapioEmulationOracleRequired:true,
    bitcoinConsensusRecognizesMidGuest:false,
    sameScriptAsFundedFrostCarrier:false,
    sourceBlossomPdpHashCryptographicallyBound:false,
    allMidOracleGuestWitnessesSigned:true,allLineageValuesConserved:true,
    feeSatsPerExit:2_000,
    principalRoots:{initial:root(H('a'),100_000),afterAlice:root(H('b'),40_000),
      afterBob:root(H('c'),0)},
    payoutScripts:{alice:aliceScript,bob:bobScript},
    aliceExit:first,bobExit:second
  };
}
test('strictly verify signed oracle MID vectors and classify non-chain scope',()=>{
  const r=verifyVectors(fixture());
  assert.equal(r.actualCompiledOracleGuestTransitions,2);
  assert.deepEqual(r.merkleSumSequenceSats,[100_000,40_000,0]);
  assert.deepEqual(r.syntheticPayoutSats,{alice:60_000,bob:40_000});
  assert.equal(r.bitcoinCoreConfirmed,false);
  assert.equal(r.bitcoinConsensusEnforcedMid,false);
  assert.equal(r.sameBitcoinCarrierAsFundedFrost,false);
  assert.equal(r.unilateralExitDuringTotalOracleOutageProven,false);
});
test('changed output, wrong exit owner and missing MID owner scripts are rejected',()=>{
  const a=fixture();a.aliceExit.outputs[1].sats=59_999;
  assert.throws(()=>verifyVectors(a),/entitlement amounts/);
  const b=fixture();b.bobExit.outputs[1].scriptPubkeyHex=b.payoutScripts.alice;
  assert.throws(()=>verifyVectors(b),/successor or exact beneficiary/);
  const c=fixture();c.payoutScripts.bob=c.payoutScripts.alice;
  assert.throws(()=>verifyVectors(c),/not two distinct/);
});
test('reject phantom Merkle-sum balance and root byte substitutions',()=>{
  const a=fixture();a.principalRoots.afterAlice.satoshis=39_999;
  assert.throws(()=>verifyVectors(a),/wrong MID Merkle-sum/);
  const b=fixture();b.principalRoots.afterAlice.canonicalNodeBytesHex='00'.repeat(41);
  assert.throws(()=>verifyVectors(b),/not canonical/);
});
test('reject false success of oracle-free or native Bitcoin MID enforcement',()=>{
  const a=fixture();a.onlineSapioEmulationOracleRequired=false;
  assert.throws(()=>verifyVectors(a),/misclassified/);
  const b=fixture();b.bitcoinConsensusRecognizesMidGuest=true;
  assert.throws(()=>verifyVectors(b),/misclassified/);
  const c=fixture();c.sameScriptAsFundedFrostCarrier=true;
  assert.throws(()=>verifyVectors(c),/misclassified/);
});
test('reject MID transaction witness forgery and loss of lineage',()=>{
  const a=fixture();a.aliceExit.hex+='00';
  assert.throws(()=>verifyVectors(a),/substituted or mislabeled/);
  const b=fixture();b.bobExit.inputOutpoints[0]=H('0')+':1';
  assert.throws(()=>verifyVectors(b),/failed to spend Alice/);
  const c=fixture();c.aliceExit.allWitnessInputsNonempty=false;
  assert.throws(()=>verifyVectors(c),/oracle\+fee signed/);
});
