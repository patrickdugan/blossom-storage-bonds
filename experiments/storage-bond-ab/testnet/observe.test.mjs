import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { observe } from './observe.mjs';

const prev='22'.repeat(32);
const block='33'.repeat(32);
const script='0014'+'11'.repeat(20);
function little64(value) {
  const x=Buffer.alloc(8);x.writeBigUInt64LE(BigInt(value));return x.toString('hex');
}
function serialized() {
  return '02000000'+'01'+prev+'00000000'+'00'+'ffffffff'+'02'+
    little64(60_000)+'16'+script+little64(0)+'04'+'51024e73'+'00000000';
}
function hash256(raw) {
  let h=createHash('sha256').update(Buffer.from(raw,'hex')).digest();
  h=createHash('sha256').update(h).digest();
  return Buffer.from(h).reverse().toString('hex');
}
const raw=serialized(),txid=hash256(raw);
function good() {
  const manifest={
    schema:'bsb-ab-testnet-receipt-v1',
    network:'signet',backend:'A-sentinel',minimum_confirmations:6,
    transactions:[{
      role:'payout',txid,wtxid:txid,
      inputs:[prev+':0'],exact_inputs:true,
      outputs:[
        {vout:0,script_pubkey_hex:script,sats:60_000},
        {vout:1,script_pubkey_hex:'51024e73',sats:0},
      ],exact_outputs:true,
    }],
  };
  const transaction={
    txid,hash:txid,hex:raw,confirmations:6,blockhash:block,
    vsize:raw.length/2,
    vin:[{txid:prev,vout:0}],
    vout:[
      {n:0,value:0.0006,scriptPubKey:{hex:script}},
      {n:1,value:0,scriptPubKey:{hex:'51024e73'}},
    ],
  };
  const parent={
    txid:prev,vout:[{n:0,value:0.00061,scriptPubKey:{hex:script}}],
  };
  const confirmations={hash:block,height:500,confirmations:6};
  const source={
    rpc(method,args){
      switch(method){
        case 'getblockchaininfo':return {chain:'signet',initialblockdownload:false};
        case 'getrawtransaction':return args[0]===txid?transaction:parent;
        case 'getblockheader':return confirmations;
        case 'getblockhash':return block;
        default:throw new Error('unexpected RPC '+method);
      }
    },
  };
  return {manifest,source,transaction,parent,confirmations};
}
test('signed exact witness and BTC fee observed from trusted signet chain',async()=>{
  const {manifest,source}=good();
  const result=await observe(manifest,source);
  assert.equal(result.backend,'A-sentinel');
  assert.equal(result.network,'signet');
  assert.equal(result.transactionCount,1);
  assert.equal(result.transactions[0].wtxid,txid);
  assert.equal(result.transactions[0].fee_sats,1000);
  assert.equal(result.transactions[0].outputs[0].sats,60_000);
  assert.equal(result.claimAuthorizationVerified,false);
  assert.equal(result.storageFaultValidityVerified,false);
  assert.equal(result.realFrostAuthorizationChecked,false);
});
test('reject substituted witness bytes retaining a claimed txid',async()=>{
  const {manifest,source,transaction}=good();
  transaction.hex=raw.slice(0,-2)+(raw.endsWith('00')?'01':'00');
  await assert.rejects(observe(manifest,source),/signed witness differs/);
});
test('reject one satoshi redirected or shaved from recipient',async()=>{
  const {manifest,source,transaction}=good();
  transaction.vout[0].value=0.00059999;
  await assert.rejects(observe(manifest,source),/script or satoshi/);
});
test('reject extra output and changed parent outpoint',async()=>{
  const {manifest,source,transaction}=good();
  transaction.vout.push({n:2,value:0,scriptPubKey:{hex:'6a'}});
  await assert.rejects(observe(manifest,source),/output count/);
  const x=good();x.transaction.vin[0].txid='44'.repeat(32);
  await assert.rejects(observe(x.manifest,x.source),/input set/);
});
test('reject stale branch, unconfirmed claims and network substitution',async()=>{
  const x=good();x.transaction.confirmations=0;
  await assert.rejects(observe(x.manifest,x.source),/confirmations/);
  const y=good();y.source.rpc=(method,args)=>{
    if(method==='getblockhash')return '55'.repeat(32);
    return good().source.rpc(method,args);
  };
  await assert.rejects(observe(y.manifest,y.source),/stale Bitcoin branch/);
  const z=good();z.manifest.network='testnet4';
  await assert.rejects(observe(z.manifest,z.source),/network differs/);
});
test('reject unsupported mainnet/regtest or missing independent signed wtxid',async()=>{
  for(const chain of ['main','regtest','bitcoin','testnet']) {
    const x=good();x.manifest.network=chain;
    await assert.rejects(observe(x.manifest,x.source),/signet and testnet4/);
  }
  const y=good();delete y.manifest.transactions[0].wtxid;
  await assert.rejects(observe(y.manifest,y.source),/signed wtxid/);
});
test('reject weak manifests with optional input or output escapes',async()=>{
  const {manifest,source}=good();
  manifest.transactions[0].exact_inputs=false;
  await assert.rejects(observe(manifest,source),/input set must/);
  const x=good();x.manifest.transactions[0].exact_outputs=false;
  await assert.rejects(observe(x.manifest,x.source),/output must/);
  const y=good();y.manifest.transactions[0].inputs.push(y.manifest.transactions[0].inputs[0]);
  await assert.rejects(observe(y.manifest,y.source),/repeated input/);
});
test('reject value creation or unavailable transaction provenance',async()=>{
  const x=good();x.parent.vout[0].value=0.00059999;
  await assert.rejects(observe(x.manifest,x.source),/value creation/);
  const y=good();y.parent.vout=[];
  await assert.rejects(observe(y.manifest,y.source),/missing Bitcoin output/);
});
