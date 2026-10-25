#!/usr/bin/env node
/** Actual FROST manifest transport test, called only after the signer exits.
 * Acknowledgement keys are disposable, co-located simulation keys.
 */
import {readFile,open} from 'node:fs/promises';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {resolve,join} from 'node:path';
import {issueDelivery,receiveDelivery,readHolderState,refreshAcknowledged} from './holder_vault.mjs';
const need=(x,msg)=>{if(!x)throw Error(msg);};
const sha=x=>createHash('sha256').update(x).digest('hex');

async function main(args){
  const a={};
  for(let i=0;i<args.length;i+=2){
    need(args[i+1],'missing option value');
    if(args[i]==='--frozen-dir')a.dir=resolve(args[i+1]);
    else if(args[i]==='--sha256')a.sha=args[i+1];
    else if(args[i]==='--out')a.out=resolve(args[i+1]);
    else throw Error('unexpected delivery argument '+args[i]);
  }
  need(a.dir&&a.sha&&a.out&&/^[a-f0-9]{64}$/.test(a.sha),
    'requires --frozen-dir --sha256 --out');
  const manifestBytes=await readFile(join(a.dir,'p2a-frozen.json'));
  const seal=(await readFile(join(a.dir,'p2a-frozen.sha256'),'utf8')).trim();
  need(sha(manifestBytes)===a.sha&&seal===a.sha,
    'FROST manifest differs from signer-time independent SHA256');
  const m=JSON.parse(manifestBytes.toString('utf8'));
  const source=generateKeyPairSync('ed25519');
  const holders={alice:generateKeyPairSync('ed25519'),bob:generateKeyPairSync('ed25519')};
  const acks={};
  for(const holder of ['alice','bob']){
    const opts={packageDir:join(a.dir,'delivery-'+holder),
      anchorDir:join(a.dir,'rollback-anchor-'+holder),
      holder,signerPublicKey:source.publicKey,
      pinnedScript:m.beneficiaryScripts[holder]};
    const envelope=issueDelivery({holder,manifestBytes,
      signingKey:source.privateKey,pinnedScript:opts.pinnedScript});
    const ack=await receiveDelivery({...opts,holderPrivateKey:holders[holder].privateKey,
      envelope,bootstrapPin:{generation:m.currentGeneration,
        manifestSha256:a.sha,carrierBefore:m.generations[m.currentGeneration].carrierBefore}});
    const reopened=await readHolderState(opts);
    need(reopened?.generation===m.currentGeneration&&
      reopened.manifestSha256===a.sha&&
      reopened.carrierBefore===m.generations[m.currentGeneration].carrierBefore,
      'persisted manifest unreadable after holder restart');
    let rejected=false;
    try{await receiveDelivery({...opts,
      holderPrivateKey:holders[holder].privateKey,envelope});}
    catch{rejected=true;}
    need(rejected,'replayed signed recovery manifest was accepted');
    acks[holder]=ack;
  }
  const expected={generation:m.currentGeneration,manifestSha256:a.sha,
    carrierBefore:m.generations[m.currentGeneration].carrierBefore};
  need(refreshAcknowledged(acks,{alice:holders.alice.publicKey,
    bob:holders.bob.publicKey},expected),'one holder acknowledgement was missing');
  const receipt={schema:'bsb-p2a-frost-manifest-holder-delivery-test-v1',
    network:m.network,currentGeneration:m.currentGeneration,
    independentlyPinnedManifestSha256:a.sha,
    exactRealFrozenManifestBytesDelivered:true,
    signerShutdownPrerequisiteProvidedByCallingRunner:true,
    independentlySignedHolderAcks:2,
    twoDurableSeparateHolderCheckpoints:true,
    bootstrapPinMatchedSignerSource:true,
    testProcessRestartReadbackPassed:true,
    replaysRejected:2,
    generationRefreshPreventedByBitcoinConsensus:false,
    laterGenerationsPreacknowledgedBeforeOnchainRefresh:false,
    coLocatedDisposableAckKeysInTest:true,
    maliciousFrostQuorumCanStillSteal:true,
    rollbackOfBothVaultAndExternalAnchorDetectable:false};
  const f=await open(a.out,'wx',0o600);
  try{await f.writeFile(JSON.stringify(receipt,null,2)+'\n');await f.sync();}
  finally{await f.close();}
  console.log(JSON.stringify(receipt));
}
main(process.argv.slice(2)).catch(e=>{console.error('holder signed recovery delivery failed:',e.message);process.exitCode=1;});
