import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {serializeStatelessClaimInput,statelessJournalDigest,riscZeroJournalBytes,assertPreconditions,MAX_WORK} from './stateless_public_input.mjs';
const fields={
  networkGenesis:'00'.repeat(31)+'01',
  claimCommitment:'11'.repeat(32),certificateDigest:'22'.repeat(32),certificateTip:'33'.repeat(32),
  providerWork:120n,challengerWork:151n,anchorBlockHash:'44'.repeat(32),anchorHeight:20,cutoff:20,
  disputeDeadline:30,collateralOutpoint:'55'.repeat(32)+':7',payoutScript:'5120'+'66'.repeat(32),
};
const journal=(patch={})=>statelessJournalDigest({...fields,...patch}).toString('hex');
test('J01: proof journal has exactly 32 bytes for existing RISC0/Groth16 adapter',()=>{
  assert.equal(riscZeroJournalBytes(fields).length,32);
});
test('J02: deterministic canonical digest for identical data',()=>{
  assert.equal(journal(),journal());
});
test('J03: schema hash depends on provider assertion',()=>{
  assert.notEqual(journal(),journal({claimCommitment:'aa'.repeat(32)}));
});
test('J04: schema hash depends on exact 256-bit challenger work',()=>{
  assert.notEqual(journal(),journal({challengerWork:152n}));
  assert.notEqual(journal(),journal({challengerWork:(1n<<200n)+151n}));
});
test('J05: certificate digest, tip and anchor block each bind independently',()=>{
  for(const key of ['certificateDigest','certificateTip','anchorBlockHash'])
    assert.notEqual(journal(),journal({[key]:'aa'.repeat(32)}));
});
test('J06: payout script and collateral input are bound to proof journal',()=>{
  assert.notEqual(journal(),journal({payoutScript:'51'}));
  assert.notEqual(journal(),journal({collateralOutpoint:'55'.repeat(32)+':8'}));
});
test('J07: network genesis prevents cross-network reuse',()=>{
  assert.notEqual(journal(),journal({networkGenesis:'fe'.repeat(32)}));
});
test('J08: anchor height cutoff and deadline are independent fields',()=>{
  for(const patch of [{anchorHeight:19},{cutoff:21},{disputeDeadline:31}])
    assert.notEqual(journal(),journal(patch));
});
test('J09: unsigned BigInt work retains 256-bit upper boundary exactly',()=>{
  assert.equal(assertPreconditions({...fields,challengerWork:MAX_WORK}),true);
  assert.throws(()=>journal({challengerWork:MAX_WORK+1n}),RangeError);
});
test('J10: included after cutoff and weak challenge fail preconditions',()=>{
  assert.throws(()=>assertPreconditions({...fields,anchorHeight:21}),/after cutoff/);
  assert.throws(()=>assertPreconditions({...fields,challengerWork:120n}),/not strictly stronger/);
  assert.throws(()=>assertPreconditions({...fields,disputeDeadline:20}),/duration/);
});
test('J11: rejects malformed hashes, scripts and outpoint indexes',()=>{
  assert.throws(()=>journal({networkGenesis:'abcd'}),TypeError);
  assert.throws(()=>journal({payoutScript:'xyz'}),TypeError);
  assert.throws(()=>journal({collateralOutpoint:'55'.repeat(32)+':4294967296'}),RangeError);
});
test('J12: txid/vout bytes and work are in documented Bitcoin/circuit endianness',()=>{
  const b=serializeStatelessClaimInput(fields);
  const outpointSuffix=Buffer.concat([Buffer.from('55'.repeat(32),'hex'),Buffer.from('07000000','hex')]);
  const pos=b.indexOf(outpointSuffix);
  assert.ok(pos>=0);
  assert.ok(b.includes(Buffer.from((151n).toString(16).padStart(64,'0'),'hex')));
});
test('J13: schema output matches sha256 of complete deterministic preimage',()=>{
  const b=serializeStatelessClaimInput(fields);
  assert.deepEqual(createHash('sha256').update(b).digest(),riscZeroJournalBytes(fields));
});
