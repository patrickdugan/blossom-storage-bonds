import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import type {AddressInfo} from 'node:net';
import {ChannelPayee} from './channel.ts';
import type {BondTool} from './bondtool.ts';

const provider='ab'.repeat(32);
const client='cd'.repeat(32);

test('CR01: concurrent channel payments cannot overwrite a higher cumulative state',async()=>{
  let releaseFirst:()=>void=()=>{};
  let signalEntered:()=>void=()=>{};
  const firstGate=new Promise<void>(resolve=>{releaseFirst=resolve;});
  const firstEntered=new Promise<void>(resolve=>{signalEntered=resolve;});
  let checks=0;
  const verifiedPaid:number[]=[];
  const tool={run:async(cmd:string,_path:string,paid:string)=>{
    assert.equal(cmd,'chan-verify');
    checks++;
    verifiedPaid.push(Number(paid));
    if(checks===1){signalEntered();await firstGate;}
    return {ok:true};
  }} as unknown as BondTool;
  const payee=new ChannelPayee(provider,tool,'/tmp');
  payee.channels.set(client,{path:'test-channel.json',paid:0});
  const server=createServer((req,res)=>{
    const url=new URL(req.url??'/', 'http://'+req.headers.host);
    void payee.route(req,res,url).then(handled=>{
      if(!handled){res.writeHead(404);res.end();}
    }).catch(e=>{
      res.writeHead(500);res.end(String(e));
    });
  });
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
  const {port}=server.address() as AddressInfo;
  const base='http://127.0.0.1:'+port;
  payee.setBaseUrl(base);
  const send=async(pr:string,paid:number)=>{
    const response=await fetch(base+'/channel/pay',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({paymentRequest:pr,client_x:client,paid,sig:'fixture-client-sig'})
    });
    return {status:response.status,body:await response.text()};
  };
  try{
    const a=await payee.createInvoice(3000,'epoch-1');
    const b=await payee.createInvoice(5000,'epoch-2');
    const first=send(a.paymentRequest,3);
    await firstEntered;
    const second=await send(b.paymentRequest,5);
    assert.equal(second.status,402);
    assert.equal(checks,1,'second request must fail before signature verification');
    assert.equal(payee.channels.get(client)?.paid,0,'unconfirmed verification cannot update state');
    releaseFirst();
    assert.equal((await first).status,200);
    assert.equal(payee.channels.get(client)?.paid,3);
    const retry=await send(b.paymentRequest,8);
    assert.equal(retry.status,200);
    assert.equal(payee.channels.get(client)?.paid,8);
    assert.deepEqual(verifiedPaid,[3,8]);
    const duplicate=await send(a.paymentRequest,11);
    assert.equal(duplicate.status,402);
    assert.equal(payee.channels.get(client)?.paid,8);
  } finally {
    releaseFirst();
    await new Promise<void>((resolve,reject)=>server.close(err=>err?reject(err):resolve()));
  }
});
