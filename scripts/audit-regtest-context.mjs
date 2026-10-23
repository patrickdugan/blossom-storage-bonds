/**
 * Core-31.1 REGTEST active-chain contextual audit for the existing sentinel
 * harness. This queries a locally running, fully validating bitcoind by RPC.
 *
 * It does not construct a trustless light-client proof. The block and UTXO
 * inclusion claims are authenticated by the node's consensus validation
 * and active-chain index. We independently reparse each returned raw tx.
 *
 * Usage:
 *   node --experimental-strip-types scripts/audit-regtest-context.mjs results/regtest.json
 */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {parseTx} from '../layer1/onchain.ts';
import {forfeitContextOk,refundContextOk} from '../model/contextual_finality.mjs';
import {parseBitcoinTxOutProof,proofIncludesTxid} from '../model/bitcoin_merkleblock.mjs';
import {createWitnessCommitmentEvidence,verifyWitnessCommitmentEvidence}
  from '../model/bitcoin_witness_commitment.mjs';

const BOND=100_000_000n, DELTA=144, CLOSE_FEE=1000n;
const hashInput=b=>createHash('sha256').update(b).digest('hex');
const sha256d=b=>createHash('sha256').update(
  createHash('sha256').update(b).digest()).digest();
const wtxidOfRaw=b=>Buffer.from(sha256d(b)).reverse().toString('hex');
const sats=x=>{const n=Math.round(x*100_000_000);assert.ok(Number.isSafeInteger(n));return BigInt(n);};
const isP2TR=x=>/^5120[0-9a-f]{64}$/i.test(x);
const fail=(label,message)=>{throw Error(label+': '+message);};

export async function rpc(method,params=[]) {
  const endpoint=process.env.BSB_RPC??'http://127.0.0.1:18543';
  const user=process.env.BSB_RPC_USER??'bsb';
  const pass=process.env.BSB_RPC_PASSWORD??'bsb-regtest-only';
  if(!/^http:\/\/127\.0\.0\.1:\d{1,5}$/.test(endpoint))
    throw Error('regtest audit RPC endpoint must be local loopback');
  const response=await fetch(endpoint,{
    method:'POST',
    headers:{'content-type':'application/json',
      authorization:'Basic '+Buffer.from(user+':'+pass).toString('base64')},
    body:JSON.stringify({jsonrpc:'1.0',id:'bsb-context',method,params})
  });
  if(!response.ok)throw Error('bitcoind RPC HTTP '+response.status+' for '+method);
  const payload=await response.json();
  if(payload.error)throw Error('bitcoind RPC '+method+': '+payload.error.message);
  return payload.result;
}

export async function auditContext(report,call=rpc) {
  assert.equal(report.failed,0,'harness cannot report any failed Core checks');
  assert.ok(Array.isArray(report.checks)&&report.checks.length>=14);
  for(const check of report.checks)
    assert.equal(check.pass,true,'Core rejected an expected test outcome: '+check.check);
  const chain=await call('getblockchaininfo',[]);
  assert.equal(chain.chain,'regtest');
  const version=(await call('getnetworkinfo',[])).subversion;
  const sizes=new Map();
  for(const entry of report.sizes??[]){
    if(!entry.txid||!entry.tx)fail('report','bad size entry');
    if(sizes.has(entry.tx))fail('report','duplicate transaction category '+entry.tx);
    sizes.set(entry.tx,entry);
  }
  const byId=new Map();
  async function confirmed(txid) {
    if(byId.has(txid))return byId.get(txid);
    if(typeof txid!=='string'||!/^[0-9a-f]{64}$/i.test(txid))
      fail('receipt','bad transaction ID');
    const t=await call('getrawtransaction',[txid,true]);
    assert.equal(t.txid,txid,'queried txid must match confirmed bytes');
    assert.ok(Number.isInteger(t.confirmations)&&t.confirmations>0,
      'transaction is not confirmed in the active chain: '+txid);
    assert.ok(typeof t.blockhash==='string');
    const header=await call('getblockheader',[t.blockhash,true]);
    assert.ok(Number.isInteger(header.height)&&header.height>=1);
    assert.equal(await call('getblockhash',[header.height]),t.blockhash,
      'tx belongs to non-active branch or forged height');
    const block=await call('getblock',[t.blockhash,2]);
    assert.equal(block.hash,t.blockhash);
    assert.equal(block.height,header.height);
    assert.ok(block.tx.some(x=>x.txid===txid),'transaction absent from containing block');
    assert.ok(typeof t.hex==='string'&&/^[0-9a-f]+$/i.test(t.hex));
    const bytes=Buffer.from(t.hex,'hex');
    const parsed=parseTx(bytes);
    assert.equal(parsed.txid,txid,'independently parsed txid mismatch');
    assert.equal(parsed.version,t.version);
    assert.equal(parsed.locktime,t.locktime);
    assert.equal(parsed.inputs.length,t.vin.length);
    assert.equal(parsed.outputs.length,t.vout.length);
    for(let i=0;i<parsed.inputs.length;i++){
      assert.equal(parsed.inputs[i].txid,t.vin[i].txid);
      assert.equal(parsed.inputs[i].vout,t.vin[i].vout);
      assert.equal(parsed.inputs[i].sequence,t.vin[i].sequence);
    }
    for(let i=0;i<parsed.outputs.length;i++){
      assert.equal(parsed.outputs[i].value,sats(t.vout[i].value));
      assert.equal(parsed.outputs[i].script.toString('hex'),t.vout[i].scriptPubKey.hex);
    }
    // Bitcoin Core can produce a BIP37 partial Merkle proof tied to the
    // confirmed transaction's block header. Independently decode the
    // serialized proof, then ask Core to cross-check it against its active
    // chain. The header's active-chain status still comes from trusted RPC.
    const txoutproof=await call('gettxoutproof',[[txid],t.blockhash]);
    assert.ok(typeof txoutproof==='string' && /^[0-9a-f]+$/i.test(txoutproof));
    const verified=proofIncludesTxid(txoutproof,txid,t.blockhash);
    assert.equal(verified.matches.length,1,
      'single-transaction partial Merkle proof must match exactly one leaf');
    assert.equal(await call('getblockheader',[t.blockhash,false]),verified.headerHex,
      'partial Merkle proof must embed exact active-chain block header');
    assert.deepEqual(await call('verifytxoutproof',[txoutproof]),[txid],
      'Bitcoin Core must independently verify the inclusion proof');
    // A BIP37 txid inclusion proof does not commit to the witness. For
    // the *actual* witnessed tx, derive wtxid from the raw serialization
    // and verify it against the BIP141 witness commitment in the coinbase.
    const txIndex=block.tx.findIndex(item=>item.txid===txid);
    assert.ok(txIndex>=1,'audited bond tx must be a non-coinbase transaction');
    const computedWtxid=wtxidOfRaw(bytes);
    assert.equal(t.hash,computedWtxid,'Core wtxid must match raw witness bytes');
    assert.equal(block.tx[txIndex].hash,computedWtxid);
    const coinbaseId=block.tx[0].txid;
    const cb=await call('getrawtransaction',[coinbaseId,true]);
    assert.equal(cb.txid,coinbaseId);
    assert.ok(typeof cb.hex==='string'&&typeof cb.vin?.[0]?.coinbase==='string');
    const coinbaseParsed=parseTx(Buffer.from(cb.hex,'hex'));
    assert.equal(coinbaseParsed.txid,coinbaseId,
      'Bitcoin coinbase inclusion must be bound to independently parsed raw bytes');
    assert.equal(coinbaseParsed.inputs[0].txid,'00'.repeat(32));
    const reservedHex=cb.vin[0].txinwitness?.[0];
    assert.ok(typeof reservedHex==='string'&&/^[0-9a-f]{64}$/i.test(reservedHex),
      'SegWit block coinbase must carry a 32-byte witness reserved value');
    const coinbaseRaw=Buffer.from(cb.hex,'hex');
    assert.ok(coinbaseRaw.includes(Buffer.from(reservedHex,'hex')),
      'reported reserved value must occur in raw coinbase witness bytes');
    const candidateOutputs=coinbaseParsed.outputs
      .map(output=>output.script.toString('hex'))
      .filter(script=>script.startsWith('6a24aa21a9ed') && script.length>=76);
    assert.ok(candidateOutputs.length>=1,'coinbase missing BIP141 witness commitment');
    // BIP141 explicitly selects the highest matching coinbase output index.
    const coinbaseCommitmentScript=candidateOutputs.at(-1);
    const witnessEvidence=createWitnessCommitmentEvidence({
      txids:block.tx.map(x=>x.txid),
      wtxids:block.tx.map((x,i)=>i===0?'00'.repeat(32):x.hash),
      targetIndex:txIndex,blockHeaderHex:verified.headerHex,
      reservedHex,coinbaseCommitmentScript
    });
    assert.equal(witnessEvidence.blockhash,t.blockhash);
    assert.equal(witnessEvidence.txid,txid);
    assert.equal(witnessEvidence.wtxid,computedWtxid);
    assert.equal(verifyWitnessCommitmentEvidence(witnessEvidence),true);
    const out={txid,height:header.height,blockhash:t.blockhash,
      tx:t,parsed,rawSha256:hashInput(bytes),
      inclusion:{
        txid,blockhash:t.blockhash,height:header.height,
        index:verified.matches[0].index,
        headerHex:verified.headerHex,proofHex:txoutproof,
        merkleRoot:verified.merkleRoot,
        witness:{
          ...witnessEvidence,
          coinbaseRawHex:cb.hex,
          witnessedRawHex:t.hex
        }
      }};
    byId.set(txid,out);
    return out;
  }
  async function named(name) {
    const v=sizes.get(name);
    if(!v)fail('report','missing confirmed transaction '+name);
    const proof=await confirmed(v.txid);
    assert.equal(proof.tx.vsize,v.vsize,'Core vsize must agree with harness measurement');
    return proof;
  }
  async function inputParent(proof) {
    assert.equal(proof.tx.vin.length,1);
    const inp=proof.tx.vin[0];
    const parent=await confirmed(inp.txid);
    assert.ok(inp.vout>=0&&inp.vout<parent.tx.vout.length);
    const source=parent.tx.vout[inp.vout];
    assert.ok(isP2TR(source.scriptPubKey.hex),'spent bond output is not P2TR');
    assert.equal(sats(source.value),BOND);
    // This is a post-settlement UTXO check. It cannot independently prove
    // the original funding without trusting the active-chain node.
    assert.equal(await call('gettxout',[inp.txid,inp.vout,false]),null,
      'spent bond outpoint must not remain unspent at audited tip');
    return {parent,height:parent.height,output:source,vout:inp.vout};
  }
  const fund=await named('fund');
  const challenge0=await named('Challenge_i');
  const response0=await named('Respond_i');
  const forfeit=await named('Forfeit_i');
  const refund=await named('Refund');
  const cooperative=await named('Cooperative close');
  assert.equal(challenge0.tx.vin[0].txid,fund.txid,
    'first challenge must spend confirmed funding output');
  // A BIP37 proof only commits to the legacy txid. Modify a real confirmed
  // challenge's witness without altering its input prevouts/outputs; the
  // same partial Merkle proof still matches the forged variant's txid.
  // This does NOT demonstrate consensus validity of the forged witness.
  const witnessBytes=Buffer.from(challenge0.tx.vin[0].txinwitness[0],'hex');
  assert.ok(witnessBytes.length>=16);
  const actualRaw=Buffer.from(challenge0.tx.hex,'hex');
  const byteOffset=actualRaw.indexOf(witnessBytes);
  assert.ok(byteOffset>0,'opening bytes must be present in raw transaction witness');
  const alteredWitnessRaw=Buffer.from(actualRaw);
  alteredWitnessRaw[byteOffset]^=1;
  const substituted=parseTx(alteredWitnessRaw);
  assert.equal(substituted.txid,challenge0.txid,
    'witness-only substitution preserves txid');
  assert.notEqual(hashInput(alteredWitnessRaw),hashInput(actualRaw));
  assert.equal(proofIncludesTxid(challenge0.inclusion.proofHex,
    substituted.txid,challenge0.blockhash).matches[0].txid,challenge0.txid,
    'txid Merkle proof cannot distinguish a substituted SegWit witness');
  const corruptedWtxid=wtxidOfRaw(alteredWitnessRaw);
  assert.notEqual(corruptedWtxid,challenge0.inclusion.witness.wtxid);
  assert.equal(verifyWitnessCommitmentEvidence({
    ...challenge0.inclusion.witness,wtxid:corruptedWtxid
  }),false,'BIP141 coinbase witness commitment rejects the forged witness variant');
  assert.equal(response0.tx.vin[0].txid,challenge0.txid,
    'response must spend first challenged state');
  const challenge1=await confirmed(forfeit.tx.vin[0].txid);
  assert.equal(challenge1.tx.vin[0].txid,response0.txid,
    'second challenge must spend confirmed successor');
  const allParents=[challenge0,response0,challenge1];
  for(const spend of allParents) {
    const spent=await inputParent(spend);
    assert.equal(spend.tx.version,3);
    assert.equal(spend.tx.locktime,0);
    assert.equal(spend.tx.vin.length,1);
    assert.equal(spend.tx.vout.length,2);
    assert.equal(sats(spend.tx.vout[0].value),BOND,'parent preserves full bond');
    assert.ok(isP2TR(spend.tx.vout[0].scriptPubKey.hex));
    assert.equal(sats(spend.tx.vout[1].value),0n);
    assert.equal(spend.tx.vout[1].scriptPubKey.hex,'51024e73',
      'v3 parent must have a zero-value P2A anchor');
    assert.ok(spend.tx.vin[0].txinwitness.length>=4,
      'challenge/response witness missing expected items');
    assert.ok(spend.height>=spent.height);
  }
  const forfeitSource=await inputParent(forfeit);
  assert.equal(forfeitSource.parent.txid,challenge1.txid);
  const refSource=await inputParent(refund);
  const coopSource=await inputParent(cooperative);
  for(const spend of [forfeit,refund,cooperative]) {
    assert.equal(spend.tx.vin.length,1);
    assert.ok(spend.tx.vout.length>=1);
    assert.equal(spend.tx.vout.reduce((n,o)=>n+sats(o.value),0n),BOND-CLOSE_FEE,
      'terminal bond payout plus fee must equal bond value');
  }
  assert.equal(forfeit.tx.vout.length,1);
  assert.equal(refund.tx.vout.length,1);
  assert.ok(isP2TR(forfeit.tx.vout[0].scriptPubKey.hex));
  assert.ok(isP2TR(refund.tx.vout[0].scriptPubKey.hex));
  assert.equal(forfeit.tx.vin[0].sequence,DELTA);
  assert.equal(refund.tx.vin[0].sequence,0xfffffffe);
  assert.equal(refund.tx.version,2);
  assert.equal(forfeit.tx.version,2);
  assert.ok(forfeitContextOk({version:forfeit.tx.version,
    sequence:forfeit.tx.vin[0].sequence,delay:DELTA,
    outpointHeight:forfeitSource.height,candidateHeight:forfeit.height}),
    'confirmed forfeit fails contextual BIP68/112 height check');
  assert.ok(!forfeitContextOk({version:forfeit.tx.version,
    sequence:forfeit.tx.vin[0].sequence,delay:DELTA,
    outpointHeight:forfeitSource.height,candidateHeight:forfeit.height-1}),
    'one-block-earlier forfeiture must be contextually invalid');
  assert.ok(refundContextOk({contractEndHeight:refund.tx.locktime,
    nLockTime:refund.tx.locktime,sequence:refund.tx.vin[0].sequence,
    candidateHeight:refund.height}),
    'confirmed refund is not BIP65/absolute-height final');
  assert.ok(!refundContextOk({contractEndHeight:refund.tx.locktime,
    nLockTime:refund.tx.locktime,sequence:refund.tx.vin[0].sequence,
    candidateHeight:refund.tx.locktime}),
    'refund must be invalid in same-height block as locktime');
  assert.ok(cooperative.tx.vout.length===2);
  assert.ok(cooperative.tx.vin[0].txinwitness.length===1,
    'cooperative test must be MuSig2 keypath witness');
  assert.equal(cooperative.tx.vin[0].txinwitness[0].length,128,
    'MuSig2 keypath test requires a 64-byte signature');
  const tip=await call('getblockcount',[]);
  for(const entry of byId.values())assert.ok(entry.height<=tip);
  return {
    schema:'bsb/core-active-chain-context/v1',
    scope:'Fully validating Bitcoin Core 31.1 REGTEST node, trusted local RPC',
    consensusAssumption:'Core-valid active chain and UTXO set; not a trustless inclusion proof',
    coreVersion:version,network:'regtest',tip,
    confirmedTransactions:byId.size,
    inclusionProofs:[...byId.values()].map(x=>x.inclusion),
    parents:[
      {path:'challenge-0',txid:challenge0.txid,confirmedHeight:challenge0.height,sourceHeight:fund.height},
      {path:'response-0',txid:response0.txid,confirmedHeight:response0.height,sourceHeight:challenge0.height},
      {path:'challenge-1',txid:challenge1.txid,confirmedHeight:challenge1.height,sourceHeight:response0.height}
    ],
    forfeit:{txid:forfeit.txid,spentTxid:challenge1.txid,
      spendingHeight:forfeit.height,spentOutputHeight:forfeitSource.height,
      signedSequence:forfeit.tx.vin[0].sequence,minimumHeight:forfeitSource.height+DELTA,
      inputSats:BOND.toString(),paidSats:(BOND-CLOSE_FEE).toString(),feeSats:CLOSE_FEE.toString()},
    refund:{txid:refund.txid,spentTxid:refSource.parent.txid,
      spendingHeight:refund.height,spentOutputHeight:refSource.height,
      signedLockTime:refund.tx.locktime,minimumHeight:refund.tx.locktime+1,
      inputSats:BOND.toString(),paidSats:(BOND-CLOSE_FEE).toString(),feeSats:CLOSE_FEE.toString()},
    cooperative:{txid:cooperative.txid,sourceHeight:coopSource.height,
      spendingHeight:cooperative.height,providerAndClientOutputs:2,feeSats:CLOSE_FEE.toString()},
    reportChecks:report.checks.length,
    nodeAssertsActiveChain:true,
    txidProofDoesNotAuthenticateWitness:true,
    witnessCommitmentRejectsAlteredWitness:true,
    substitutionCounterexample:{
      confirmedTxid:challenge0.txid,
      confirmedRawSha256:hashInput(actualRaw),
      unconfirmedAlteredWitnessRawSha256:hashInput(alteredWitnessRaw),
      unchangedTxid:substituted.txid,
      alteredWitnessIsConfirmed:false
    }
  };
}
if(process.argv[1]&&import.meta.url===new URL('file://'+process.argv[1]).href){
  const path=process.argv[2]??'results/regtest.json';
  const report=JSON.parse(readFileSync(path,'utf8'));
  const result=await auditContext(report);
  // Fault injection, not a successful proof: reject an RPC that falsifies an
  // active-chain block-hash lookup for a confirmed transaction.
  let changed=false;
  const wrongChain=async(method,params)=>{
    const answer=await rpc(method,params);
    if(method==='getblockhash'&&!changed){changed=true;return 'ff'.repeat(32);}
    return answer;
  };
  await assert.rejects(auditContext(report,wrongChain),/non-active branch|forged height/);
  assert.equal(changed,true,'active chain must be consulted');
  const corrupted=Buffer.from(result.inclusionProofs[0].proofHex,'hex');
  corrupted[36]^=1; // mutate the header's Merkle commitment
  assert.throws(()=>parseBitcoinTxOutProof(corrupted.toString('hex')),
    /merkle root does not match/);
  console.log(JSON.stringify({...result,adversarialWrongActiveChainRejected:true,
    adversarialMerkleProofTamperRejected:true},null,2));
}
