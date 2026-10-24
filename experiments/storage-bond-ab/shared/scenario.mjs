// Common deterministic stimulus for both experimental BTC storage-bond backends.
// This module produces real Blossom SHA256/Merkle challenge material through
// the repository's reference implementation, but NO Bitcoin transactions.
import { createHash } from 'node:crypto';
import { keyFromSeed } from '../../../model/schnorr.ts';
import {
  chunk, buildTree, encryptReplica, replicaKey, makeSentinel, sentinelResponse,
  epochIndices, proveEpoch, verifyEpoch,
} from '../../../model/storage_bonds.ts';

export const sha = (value) => createHash('sha256').update(String(value)).digest('hex');
export const carrier = (value) => sha('bond/ab/carrier|' + value) + ':0';
export const QUORUM = Object.freeze(['f1', 'f2']);
export const FEDERATION = Object.freeze(['f1', 'f2', 'f3']);
export const NETWORK = 'model-only';
const REPLICA_SECRET = Buffer.alloc(32, 0x46);
const SENTINEL_SEED = Buffer.alloc(32, 0xb2);
const Q = 4;

export function terms() {
  return [
    ['alice', 60_000],
    ['bob', 40_000],
  ].map(([id, stake]) => ({
    id,
    provider: 'miner-' + id,
    client: id,
    deal: 'blossom-deal-' + id,
    sector: 'test-sector-' + id,
    nonce: id + '-lineage-0',
    proofKind: 'blossom-pdp',
    stake,
    clientScript: '5120' + keyFromSeed('ab-client-' + id).x,
    providerScript: '5120' + keyFromSeed('ab-provider-' + id).x,
    startEpoch: 1,
    endEpoch: 3,
    refundHeight: 100,
    challengeBlocks: 6,
  }));
}

function bytes(id) {
  const idSeed = Buffer.from(sha('pdp-data|' + id), 'hex');
  return Buffer.from(Array.from({ length: 8 * 4096 }, (_, i) =>
    (idSeed[i % idSeed.length] ^ (i * 31) ^ (i >>> 4)) & 0xff));
}
const replicas = new Map();
function replica(id) {
  if (!replicas.has(id)) {
    const plain = bytes(id);
    const chunks = chunk(encryptReplica(
      plain, replicaKey(REPLICA_SECRET, 'ab-blob-' + id, 'miner-' + id),
    ));
    replicas.set(id, { chunks, tree: buildTree(chunks) });
  }
  return replicas.get(id);
}
function nonceFor(id, epoch, n, targetChunk) {
  for (let index = 0; index < 4096; index++) {
    const nonce = Buffer.from(sha('ab/nonce|' + id + '|' + epoch + '|' + index), 'hex');
    if (targetChunk === null || epochIndices(nonce, n, Q).includes(targetChunk)) {
      return nonce;
    }
  }
  throw new Error('could not select an independently reproducible PDP sample');
}

export function challenge(event) {
  if (event.kind !== 'proof') throw new TypeError('PDP challenge needs a proof event');
  const { chunks, tree } = replica(event.id);
  const sen = makeSentinel(SENTINEL_SEED, tree, chunks, event.epoch);
  const held = new Map(chunks.map((value, index) => [index, value]));
  const missingChunk = Math.floor(sen.idx / 64);
  if (event.storage === 'deleted') held.delete(missingChunk);
  const nonce = nonceFor(event.id, event.epoch, tree.n,
    event.storage === 'deleted' ? missingChunk : null);
  const sampled = epochIndices(nonce, tree.n, Q);
  const proof = proveEpoch(held, tree, nonce, Q);
  const verified = verifyEpoch(tree.root, tree.n, nonce, Q, proof);
  // Explicitly distinguish the actual reference-code result from an oracle claim.
  const assertedVerdict = event.assertedVerdict ?? (verified ? 'pass' : 'fault');
  if (!['pass', 'fault'].includes(assertedVerdict)) {
    throw new Error('invalid claimed storage outcome');
  }
  const response = sentinelResponse(sen.r, tree.n, held);
  const neighbor = chunks[(missingChunk + 1) % chunks.length];
  const offset = (sen.idx % 64) * 64;
  const wrong = Buffer.concat([sen.r, neighbor.subarray(offset, offset + 64)]);
  const evidenceHash = sha(JSON.stringify({
    id: event.id, epoch: event.epoch, root: tree.root.toString('hex'),
    nonce: nonce.toString('hex'), selected: sampled,
    present: proof.chunks.map(c => c.length),
    verdict: verified ? 'pass' : 'fault',
  }));
  return {
    id: event.id, epoch: event.epoch, root: tree.root.toString('hex'),
    proofKind: 'blossom-pdp', verified, assertedVerdict,
    evidenceHash, checkpoint: sha('ab/pdp-checkpoint|' + event.epoch),
    finalizedEpoch: event.epoch, nonce: nonce.toString('hex'), selected: sampled,
    deletedChunk: event.storage === 'deleted' ? missingChunk : null,
    witness: { sentinel: sen, response, wrong },
    // Bitcoin node and consensus verification remain independent stages.
    evidenceClass: 'real-sha256-merkle-reference-proof-model',
  };
}

const expectedEvents = [
  {kind:'refresh',height:40,externalFee:500},
  {kind:'proof',id:'alice',epoch:1,height:42,storage:'intact'},
  {kind:'proof',id:'bob',epoch:1,height:43,storage:'intact'},
  {kind:'proof',id:'alice',epoch:2,height:50,storage:'deleted'},
  {kind:'proof',id:'bob',epoch:2,height:51,storage:'intact'},
  {kind:'settle',id:'alice',winner:'client',height:56},
  {kind:'proof',id:'bob',epoch:3,height:57,storage:'intact'},
  {kind:'settle',id:'bob',winner:'provider',height:101},
];

export function scenario(name='storage-fault') {
  const events = structuredClone(expectedEvents);
  if (name === 'healthy') {
    events[3].storage = 'intact';
    events[5] = {kind:'proof',id:'alice',epoch:3,height:57,storage:'intact'};
    events.splice(7,0,{kind:'settle',id:'alice',winner:'provider',height:101});
  } else if (name === 'false-fault') {
    events[3].storage = 'intact';
    events[3].assertedVerdict = 'fault';
  } else if (name === 'quorum-outage') {
    events.forEach(event => {event.voters=['f1'];});
  } else if (name === 'storage-fault') {
    // Original common loss scenario.
  } else throw new Error('unknown A/B scenario: ' + name);
  return { version:1, name, network:NETWORK, terms:terms(),
    initialCarrier:carrier('genesis'), federation:[...FEDERATION],
    threshold:2, voters:[...QUORUM], events };
}

export const SCENARIOS = Object.freeze([
  'storage-fault', 'healthy', 'false-fault', 'quorum-outage',
]);
