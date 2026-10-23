import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {ChannelPayee,ChannelPayer,decodeChannelInvoice,type ChannelFile} from './channel.ts';
import type {BondTool} from './bondtool.ts';

const provider='ab'.repeat(32),client='cd'.repeat(32);
const payee='bsbch:'+provider,clientX=client;
const expiry=()=>Math.floor(Date.now()/1000)+300;
const preimage='a2'.repeat(32);
const hash=createHash('sha256').update(Buffer.from(preimage,'hex')).digest('hex');
const encoded=(overrides:Record<string,unknown>={})=>'bsbch1'+Buffer.from(JSON.stringify({
  h:hash,a:3000,p:payee,m:'epoch-7',x:expiry(),u:'http://127.0.0.1:1234/channel/pay',
  ...overrides
})).toString('base64url');

test('CI01: valid channel invoice retains positive whole-satoshi amount',()=>{
  const decoded=decodeChannelInvoice(encoded());
  assert.equal(decoded.amountMsat,3000);
  assert.equal(decoded.paymentHash,hash);
  assert.equal(decoded.payee,payee);
  assert.equal(decoded.memo,'epoch-7');
});
test('CI02: zero, negative, fractional and sub-satoshi amounts are rejected',()=>{
  for(const amount of [0,-1000,1,999,1500,1000.5,Number.MAX_SAFE_INTEGER+1]){
    assert.throws(()=>decodeChannelInvoice(encoded({a:amount})),/malformed invoice/);
  }
});
test('CI03: reject wrong hash, payee, expiry and URL fields before signing',()=>{
  const bad=[
    {h:'ff'},{h:'zz'.repeat(32)},{p:'bsbch:fake'}, {p:'other'},
    {x:-1},{x:'tomorrow'},{x:1.2},{u:'javascript:alert(1)'},{u:7}
  ];
  for(const b of bad)assert.throws(()=>decodeChannelInvoice(encoded(b)),/malformed invoice/);
});
test('CI04: payee refuses nonpositive and invalid invoice TTL',async()=>{
  const tool={run:async()=>({})} as unknown as BondTool;
  const p=new ChannelPayee(provider,tool,'/tmp');
  p.setBaseUrl('http://127.0.0.1:1234');
  await assert.rejects(p.createInvoice(0,'bad'),/whole sats/);
  await assert.rejects(p.createInvoice(500,'bad'),/whole sats/);
  await assert.rejects(p.createInvoice(1000,'bad',0),/TTL/);
  await assert.rejects(p.createInvoice(1000,'bad',-3),/TTL/);
  const inv=await p.createInvoice(4000,'epoch-10',90);
  assert.equal(decodeChannelInvoice(inv.paymentRequest).amountMsat,4000);
});
test('CI05: payer rejects expired invoice before channel signing or HTTP',async()=>{
  let calls=0;
  const tool={run:async()=>{calls++;throw Error('should not be called');}} as unknown as BondTool;
  const p=new ChannelPayer(clientX,tool);
  await assert.rejects(p.pay(encoded({x:Math.floor(Date.now()/1000)-1}),9000),/invoice expired/);
  assert.equal(calls,0);
});
test('CI06: signed channel payments increase monotonically and cannot replay invoice hash',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'bsb-chan-sanity-'));
  const origFetch=globalThis.fetch;
  const signed:number[]=[];
  const tool={run:async(cmd:string,...args:string[])=>{
    if(cmd==='chan-open')return {provider_x:provider,client_x:client,capacity_sats:2000,t_refund:990000};
    if(cmd==='chan-sign'){signed.push(Number(args[1]));return {sig:'deadbeef'};}
    throw Error('unexpected command '+cmd);
  }} as unknown as BondTool;
  try{
    const p=new ChannelPayer(clientX,tool);
    const c:ChannelFile={provider_x:provider,client_x:client,capacity_sats:2000,t_refund:990000};
    await p.open(join(dir,'channel.json'),c);
    const receiptRequests:number[]=[];
    globalThis.fetch=async (_url,init)=>{
      const body=JSON.parse(String(init?.body));
      receiptRequests.push(body.paid);
      return new Response(JSON.stringify({preimage}),{status:200});
    };
    const first=encoded({a:3000,h:hash});
    assert.equal((await p.pay(first,4000)).preimage,preimage);
    assert.equal(p.paidTo(payee),3);
    await assert.rejects(p.pay(first,4000),/invoice already paid/);
    const different='be'.repeat(32);
    const secondPreimage='b3'.repeat(32);
    const secondHash=createHash('sha256').update(Buffer.from(secondPreimage,'hex')).digest('hex');
    globalThis.fetch=async(_url,init)=>{
      const body=JSON.parse(String(init?.body));receiptRequests.push(body.paid);
      return new Response(JSON.stringify({preimage:secondPreimage}),{status:200});
    };
    assert.equal((await p.pay(encoded({a:5000,h:secondHash}),7000)).preimage,secondPreimage);
    assert.equal(p.paidTo(payee),8);
    assert.deepEqual(signed,[3,8]);
    assert.deepEqual(receiptRequests,[3,8]);
    void different;
  }finally{
    globalThis.fetch=origFetch;
    rmSync(dir,{recursive:true,force:true});
  }
});
test('CI07: concurrent payment on same channel fails before duplicate signing',async()=>{
  const dir=mkdtempSync(join(tmpdir(),'bsb-chan-race-'));
  const origFetch=globalThis.fetch;
  const signed:number[]=[];
  const tool={run:async(cmd:string,...args:string[])=>{
    if(cmd==='chan-open')return {provider_x:provider,client_x:client,capacity_sats:2000,t_refund:990000};
    if(cmd==='chan-sign'){signed.push(Number(args[1]));return {sig:'beef'};}
    throw Error('unexpected '+cmd);
  }} as unknown as BondTool;
  try{
    const p=new ChannelPayer(clientX,tool);
    await p.open(join(dir,'channel.json'),{provider_x:provider,client_x:client,capacity_sats:2000,t_refund:990000});
    let completeFetch:(r:Response)=>void=()=>{};
    globalThis.fetch=async()=>new Promise<Response>(resolve=>{completeFetch=resolve;});
    const inv=encoded();
    const first=p.pay(inv,10000);
    await assert.rejects(p.pay(encoded({a:4000,h:'88'.repeat(32)}),10000),/already in flight/);
    completeFetch(new Response(JSON.stringify({preimage}),{status:200}));
    await first;
    assert.deepEqual(signed,[3]);
    assert.equal(p.paidTo(payee),3);
  }finally{
    globalThis.fetch=origFetch;
    rmSync(dir,{recursive:true,force:true});
  }
});
