import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {prepareFixtures,emit} from './export_sentinels.mjs';
import {challenge,scenario} from './scenario.mjs';

const hash=b=>createHash('sha256').update(b).digest('hex');
test('real A source witnesses bind exact shared PDP root and each Merkle-derived sentinel',async()=>{
  const fixtures=await prepareFixtures();
  assert.deepEqual(fixtures.map(f=>f.holder),['alice','bob']);
  for(const {holder,fixture,evidence} of fixtures) {
    assert.equal(fixture.fixtureClass,'SHARED_BLOSSOM_PDP_WITH_PUBLIC_COUNTERFACTUAL_PREIMAGES');
    assert.equal(fixture.n,8);
    assert.equal(fixture.sentinels.length,3);
    assert.equal(fixture.independentMerkleEvidence.length,3);
    for(const [i,s] of fixture.sentinels.entries()) {
      const e=evidence[i],src=challenge({kind:'proof',id:holder,epoch:i+1,
        storage:holder==='alice'&&i===1?'deleted':'intact'});
      assert.equal(e.sourceEvidenceHash,src.evidenceHash);
      assert.equal(e.sourceProofRoot,src.root);
      assert.equal(e.sourceProofRoot,fixture.root);
      assert.equal(s.r,src.witness.sentinel.r.toString('hex'));
      assert.equal(s.s,hash(Buffer.from(s.r,'hex')));
      assert.equal(s.h,hash(Buffer.from(s.preimage,'hex')));
      assert.equal(s.wrong_preimage.length,160);
      assert.notEqual(s.h,hash(Buffer.from(s.wrong_preimage,'hex')));
    }
  }
});
test('deleted Alice epoch 2 is an actual missed Merkle sample, not a federation self-report',async()=>{
  const {fixture,evidence}= (await prepareFixtures())[0];
  assert.equal(evidence[1].sourceVerdict,'fault');
  assert(evidence[1].selectedChunks.includes(evidence[1].sentinelChunk));
  assert.equal(evidence[1].storageCase,'deleted');
  assert.equal(evidence[1].publicCounterfactualOpeningIncluded,true);
  assert.equal(evidence[0].sourceVerdict,'pass');
  assert.equal(evidence[2].hypotheticalEpoch,true);
  const counter=challenge({kind:'proof',id:'alice',epoch:2,storage:'intact'});
  assert.equal(hash(Buffer.from(fixture.sentinels[1].preimage,'hex')),
    counter.witness.sentinel.h.toString('hex'));
  assert.equal(counter.verified,true);
});
test('Bob reference never loses a chunk, and the public preimage is not nonavailability proof',async()=>{
  const b=(await prepareFixtures())[1];
  assert(b.evidence.every(e=>e.sourceVerdict==='pass'));
  assert(b.evidence.every(e=>e.storageCase==='intact'));
  assert(b.fixture.sentinels.every(s=>s.preimage.length===160));
  assert.equal(b.fixture.wide.preimage.length,1040);
  assert.equal(scenario('false-fault').events[3].assertedVerdict,'fault');
});
test('written fixture manifest binds exact file hashes; reruns refuse overwrite',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'ab-pdp-taproot-'));
  try{
    const manifest=await emit(dir);
    assert.equal(manifest.files.length,2);
    assert.equal(manifest.demonstratesCryptographicStorageNonavailability,false);
    assert.equal(manifest.publicCounterfactualDeletedPreimageIncluded,true);
    for(const f of manifest.files) {
      const bytes=await readFile(join(dir,f.file));
      assert.equal(hash(bytes),f.sha256);
      assert.equal(bytes.length,f.bytes);
      assert.equal(JSON.parse(bytes).root,f.sourceRoot);
    }
    await assert.rejects(emit(dir),/EEXIST/);
  }finally{await rm(dir,{recursive:true,force:true});}
});
