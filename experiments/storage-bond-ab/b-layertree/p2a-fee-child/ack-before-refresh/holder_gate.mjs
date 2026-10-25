#!/usr/bin/env node
// Honest-coordinator application gate, verified BEFORE Core refresh broadcast.
// Node holder processes and private key directories are separate but co-hosted.
import {generateKeyPairSync,createHash,sign} from 'node:crypto';
import {readFile,mkdir,open,stat} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,resolve,dirname} from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {issueDelivery,refreshAcknowledged} from '../delivery/holder_vault.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const ok=(v,msg)=>{if(!v)throw Error(msg);};
const h64=x=>typeof x==='string'&&/^[0-9a-f]{64}$/.test(x);
const secureWrite=async(file,content)=>{const f=await open(file,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY|constants.O_NOFOLLOW,0o600);try{await f.writeFile(content);await f.sync();}finally{await f.close();}};
const readJson=async x=>JSON.parse(await readFile(x,'utf8'));
const serialize=x=>JSON.stringify(x)+'\n';
const args=argv=>{let out={};for(let i=0;i<argv.length;i+=2){ok(argv[i]?.startsWith('--')&&argv[i+1]!=null,'incomplete argument');ok(!Object.hasOwn(out,argv[i]),'duplicate parameter');out[argv[i]]=argv[i+1];}return out;};
function actor(action,root,extra=[]){
 const cmd=spawnSync(process.execPath,[resolve(dirname(fileURLToPath(import.meta.url)),'holder_actor.mjs'),action,'--root',root,...extra],{encoding:'utf8',timeout:15_000,maxBuffer:8_000_000});
 ok(!cmd.error&&cmd.status===0,'holder '+action+' failed: '+(cmd.stderr||cmd.error||'nonzero').slice(0,380));
 return JSON.parse(cmd.stdout.trim());
}
async function begin(p){
 const dir=resolve(p['--store']);const gen=Number(p['--generation']);const scenario=p['--scenario'];
 ok(p['--candidate']&&p['--sha256']&&p['--refresh-txid']&&p['--out']&&
   Number.isSafeInteger(gen)&&(gen===1||gen===2)&&h64(p['--sha256'])&&h64(p['--refresh-txid']), 'invalid signer prospective generation or digest');
 ok(['success','missing-alice','missing-bob','tampered-envelope','forged-ack',
    'rollback-second','stale-ack-second','partial-before-ack'].includes(scenario),'unsupported gate scenario');
 const bytes=await readFile(p['--candidate']);const digest=sha(bytes);
 ok(digest===p['--sha256'],'candidate digest not equal signer source');
 const m=JSON.parse(bytes);const row=m.generations?.at(-1);
 ok(m.schema==='bsb-frost-v3-p2a-frozen-v1'&&m.network==='disposable-regtest-only'&&
   m.currentGeneration===gen&&m.generations?.length===gen+1&&
   row?.carrierBefore&&m.generations.at(-2).refreshBroadcast?.txid===p['--refresh-txid']&&
   row.carrierBefore===p['--refresh-txid']+':0'&&
   row.branches?.alice?.first?.carrierInput===row.carrierBefore&&
   row.branches?.bob?.first?.carrierInput===row.carrierBefore,'candidate does not bind presigned next carrier');
 await mkdir(dir,{recursive:true,mode:0o700});
 const sourceFile=join(dir,'delivery_signer.key');const sourcePub=join(dir,'delivery_signer.pub');
 let signer;
 if(gen===1){
   const pair=generateKeyPairSync('ed25519');signer=pair.privateKey;
   await secureWrite(sourceFile,pair.privateKey.export({type:'pkcs8',format:'pem'}));
   await secureWrite(sourcePub,pair.publicKey.export({type:'spki',format:'pem'}));
   for(const holder of ['alice','bob']){
     const pin={holder,script:m.beneficiaryScripts[holder],generation:gen,manifestSha256:digest,carrierBefore:row.carrierBefore};
     const pinFile=join(dir,'initial-'+holder+'.json');await secureWrite(pinFile,serialize(pin));
     actor('init',join(dir,'holder-'+holder),['--holder',holder,'--sender-pub',sourcePub,'--pin',pinFile]);
   }
 }else{
   signer=await readFile(sourceFile,'utf8');
   ok((await stat(sourcePub)).isFile(),'prior provisioned sender identity missing');
 }
 const acks={},actorPids=[];
 for(const holder of ['alice','bob']){
   if(scenario==='missing-'+holder)continue;
   const root=join(dir,'holder-'+holder);
   const prior=gen===2?actor('state',root).state:null;
   ok(gen===1||prior?.generation===1,'missing previous durable generation ACK');
   const envelope=issueDelivery({holder,manifestBytes:bytes,
     signingKey:signer,pinnedScript:m.beneficiaryScripts[holder],
     previousDeliveryDigest:prior?.deliveryDigest??null});
   if(scenario==='tampered-envelope'&&holder==='alice')envelope.payload.manifestSha256=sha('attacker changes message');
   const envelopeFile=join(dir,'envelope-'+gen+'-'+holder+'.json');
   await secureWrite(envelopeFile,serialize(envelope));
   if(scenario==='partial-before-ack'&&holder==='alice')actor('corrupt',root,['--mode','partial','--generation',String(gen)]);
   const accepted=actor('accept',root,['--envelope',envelopeFile]);
   actorPids.push(accepted.pid);acks[holder]=accepted.ack;
 }
 if(scenario==='forged-ack'&&acks.alice)acks.alice.signature=sign(null,Buffer.from('not-an-ACK'),generateKeyPairSync('ed25519').privateKey).toString('base64');
 if(scenario==='stale-ack-second'&&gen===2)
   acks.bob=await readJson(join(dir,'accepted-gen1-bob.json'));
 if(scenario==='rollback-second'&&gen===2)
   actor('corrupt',join(dir,'holder-alice'),['--mode','remove']);
 const expected={generation:gen,manifestSha256:digest,carrierBefore:row.carrierBefore};
 ok(actorPids.length===2&&actorPids[0]!==actorPids[1]&&actorPids.every(x=>x!==process.pid),'holders did not acknowledge from distinct processes');
 const holderPub={alice:await readFile(join(dir,'holder-alice','holder.pub'),'utf8'),bob:await readFile(join(dir,'holder-bob','holder.pub'),'utf8')};
 ok(refreshAcknowledged(acks,holderPub,expected),'holder ACK verification denied');
 for(const holder of ['alice','bob']){
   const checked=actor('state',join(dir,'holder-'+holder)).state;
   ok(checked?.generation===gen&&checked.manifestSha256===digest&&
     checked.carrierBefore===row.carrierBefore&&
     checked.deliveryDigest===acks[holder].payload.deliveryDigest,'holder checkpoint rollback after acknowledgement');
 }
 if(gen===1)for(const holder of ['alice','bob'])
   await secureWrite(join(dir,'accepted-gen1-'+holder+'.json'),serialize(acks[holder]));
 const out={schema:'bsb-frost-p2a-pre-refresh-ack-gate-v1',status:'approved',scenario,generation:gen,
   prospectiveCarrier:row.carrierBefore,approvedRefreshTxid:p['--refresh-txid'],
   candidateManifestSha256:digest,distinctHolderProcesses:2,
   signedAcksVerifiedByCoordinator:2,durablePerHolderCheckpointsReread:true,
   separateHolderKeyFilesInOneCiHost:true,bitcoinConsensusEnforcesAcknowledgement:false,
   maliciousFrostQuorumStillControlsKeypath:true};
 await secureWrite(p['--out'],serialize(out));
 console.log(JSON.stringify(out));
}
const p=args(process.argv.slice(2));begin(p).catch(async e=>{
 console.error('REFRESH_BLOCKED',e.message);
 if(p['--out']){
  try{await secureWrite(p['--out'],serialize({schema:'bsb-frost-p2a-pre-refresh-ack-gate-v1',status:'blocked',scenario:p['--scenario'],generation:Number(p['--generation']),reason:e.message.slice(0,240)}));}catch{}
 }
 process.exitCode=7;
});
