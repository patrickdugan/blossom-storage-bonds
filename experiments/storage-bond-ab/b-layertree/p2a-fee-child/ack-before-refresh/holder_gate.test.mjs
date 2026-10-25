import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtemp,writeFile,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
const hash=x=>createHash('sha256').update(x).digest('hex');
const script={alice:'0014'+'aa'.repeat(20),bob:'0014'+'bb'.repeat(20)},vault='5120'+'cd'.repeat(32);
const refresh={0:hash('refresh0'),1:hash('refresh1')};
function record(g,first,step,input,amounts){const txid=hash(g+':'+first+':'+step);const owner=step==='first'?first:(first==='alice'?'bob':'alice');return {generation:g,ownerOrder:owner,step,txid,wtxid:hash(txid),signedHex:'030000000001'+('bb'.repeat(120)),version:3,vsize:200,carrierInput:input,carrierOutputSats:step==='first'?100000:(first==='alice'?40000:60000),anchorIndex:amounts.length-1,anchorScript:'51024e73',parentMinerFeeSats:0,feeInputsSignedByFrost:false,sighashType:'BIP341-SIGHASH_DEFAULT',outputAgreement:amounts.map(([sats,script],vout)=>({sats,script,vout}))};}
function manifest(gen){const rows=[];for(let i=0;i<=gen;i++){const before=(i===0?hash('genesis'):refresh[i-1])+':0';const branches={};for(const first of ['alice','bob']){const other=first==='alice'?'bob':'alice',a=first==='alice'?60000:40000,b=100000-a;const p=record(i,first,'first',before,[[b,vault],[a,script[first]],[0,'51024e73']]);branches[first]={first:p,second:record(i,first,'second',p.txid+':0',[[b,script[other]],[0,'51024e73']]),firstReceivesSats:a,secondReceivesSats:b,otherOwner:other,descendantOutpoint:p.txid+':0',noFeeInputsInEitherFrostSignature:true};}rows.push({generation:i,carrierBefore:before,carrierScriptPubkeyHex:vault,branches,refreshBroadcast:i<gen?{txid:refresh[i]}:null});}return Buffer.from(JSON.stringify({schema:'bsb-frost-v3-p2a-frozen-v1',network:'disposable-regtest-only',principalSats:100000,aliceSats:60000,bobSats:40000,feeIndependentSignedParents:true,zeroValueAnchorScriptPubkeyHex:'51024e73',beneficiaryScripts:script,currentGeneration:gen,generations:rows}));}
async function runGate(t,scenario){const root=await mkdtemp(join(tmpdir(),'holder-gate-test-'));t.after(()=>rm(root,{recursive:true,force:true}));const store=join(root,'vault');for(const g of [1,2]){const bytes=manifest(g),file=join(root,'gen'+g+'.json'),out=join(root,'gen'+g+'.receipt.json');await writeFile(file,bytes);const status=spawnSync(process.execPath,[resolve(import.meta.dirname,'holder_gate.mjs'),'--candidate',file,'--sha256',hash(bytes),'--refresh-txid',refresh[g-1],'--generation',String(g),'--store',store,'--scenario',scenario,'--out',out],{encoding:'utf8'});if(status.status!==0){assert.match(status.stderr,/REFRESH_BLOCKED/);return {blockedAt:g,receipt:JSON.parse(await readFile(out,'utf8'))};}assert.equal(JSON.parse(await readFile(out)).status,'approved');}return {blockedAt:null};}
test('two separate holder processes ACK before both prospective carrier refreshes',async t=>{assert.deepEqual(await runGate(t,'success'),{blockedAt:null});});
for(const [scenario,at] of [['missing-alice',1],['missing-bob',1],['tampered-envelope',1],['forged-ack',1],['partial-before-ack',1],['stale-ack-second',2],['rollback-second',2]]){
 test('ACK gate denies '+scenario,async t=>{const x=await runGate(t,scenario);assert.equal(x.blockedAt,at);assert.equal(x.receipt.status,'blocked');});
}
