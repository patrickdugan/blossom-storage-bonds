#!/usr/bin/env node
// Isolated process owning one disposable holder ACK key and recovery vault.
import {generateKeyPairSync} from 'node:crypto';
import {readFile,mkdir,open,readdir,unlink} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {constants} from 'node:fs';
import {receiveDelivery,readHolderState} from '../delivery/holder_vault.mjs';
const fail=(ok,msg)=>{if(!ok)throw Error(msg);};
async function exclusive(p,data){const f=await open(p,constants.O_EXCL|constants.O_CREAT|constants.O_WRONLY|constants.O_NOFOLLOW,0o600);try{await f.writeFile(data);await f.sync();}finally{await f.close();}}
const json=async path=>JSON.parse(await readFile(path,'utf8'));
function options(args){const obj={};for(let i=0;i<args.length;i+=2){fail(args[i]?.startsWith('--')&&args[i+1]!==undefined,'bad argument');fail(!Object.hasOwn(obj,args[i]),'duplicate argument');obj[args[i]]=args[i+1];}return obj;}
async function setup(root){const pin=await json(join(root,'pin.json'));const publicKey=await readFile(join(root,'sender.pub'),'utf8');return {holder:pin.holder,signerPublicKey:publicKey,pinnedScript:pin.script,packageDir:join(root,'packages'),anchorDir:join(root,'checkpoint'),holderPrivateKey:await readFile(join(root,'holder.key'),'utf8')};}
async function main([action,...argv]){
  const p=options(argv);fail(p['--root']&&p['--root'].startsWith('/'),'absolute private vault required');const root=resolve(p['--root']);
  if(action==='init'){
    fail(['alice','bob'].includes(p['--holder']),'holder invalid');
    const sender=await readFile(p['--sender-pub'],'utf8');const pin=await json(p['--pin']);
    fail(pin.holder===p['--holder']&&pin.generation===1&&typeof pin.script==='string', 'invalid first generation holder pin');
    await mkdir(root,{recursive:false,mode:0o700});
    const kp=generateKeyPairSync('ed25519');
    await exclusive(join(root,'holder.key'),kp.privateKey.export({type:'pkcs8',format:'pem'}));
    await exclusive(join(root,'holder.pub'),kp.publicKey.export({type:'spki',format:'pem'}));
    await exclusive(join(root,'sender.pub'),sender);await exclusive(join(root,'pin.json'),JSON.stringify(pin)+'\n');
    console.log(JSON.stringify({holder:pin.holder,pid:process.pid,publicKey:kp.publicKey.export({type:'spki',format:'pem'})}));
    return;
  }
  const o=await setup(root);const pin=await json(join(root,'pin.json'));
  if(action==='state'){
    const state=await readHolderState(o);
    console.log(JSON.stringify({holder:o.holder,pid:process.pid,state}));return;
  }
  if(action==='accept'){
    const e=await json(p['--envelope']);
    const ack=await receiveDelivery({...o,envelope:e,
      bootstrapPin:{generation:pin.generation,manifestSha256:pin.manifestSha256,carrierBefore:pin.carrierBefore}});
    const state=await readHolderState(o);
    fail(ack.payload.manifestSha256===state.manifestSha256&&ack.payload.deliveryDigest===state.deliveryDigest,'failed durable holder reread');
    console.log(JSON.stringify({holder:o.holder,pid:process.pid,ack,checkpoint:{generation:state.generation,manifestSha256:state.manifestSha256,deliveryDigest:state.deliveryDigest}}));return;
  }
  if(action==='corrupt'){
    fail(['remove','partial'].includes(p['--mode']),'corruption mode invalid');
    if(p['--mode']==='remove'){
      const files=(await readdir(o.packageDir)).filter(f=>/^g-[0-9]{8}\.json$/.test(f)).sort();
      fail(files.length>0,'missing existing package for rollback attack');await unlink(join(o.packageDir,files.at(-1)));
    }else{
      await mkdir(o.packageDir,{recursive:true,mode:0o700});
      await exclusive(join(o.packageDir,'g-'+p['--generation'].padStart(8,'0')+'.json'),'{"truncated":true}\n');
    }
    console.log(JSON.stringify({holder:o.holder,pid:process.pid,corrupted:true}));return;
  }
  throw Error('unknown holder action');
}
main(process.argv.slice(2)).catch(e=>{console.error('HOLDER_DENIED',e.message);process.exitCode=2;});
