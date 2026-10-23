// Deterministic A/B transcript. This DOES NOT broadcast Bitcoin transactions.
// Both backends consume identical source-data/nonce/Merkle witness material.
import { scenario, challenge, SCENARIOS } from './shared/scenario.mjs';
import { makeSentinelBackend } from './a-sentinel/adapter.mjs';
import { makeLayerTreeBackend } from './b-layertree/adapter.mjs';
import { mkdir, open } from 'node:fs/promises';
import { resolve, join } from 'node:path';

const safeApply=(adapter,event,evidence)=>{
  try {
    return {ok:true,receipt:adapter.step(event,evidence)};
  } catch(error) {
    if(!(error instanceof Error))throw error;
    return {ok:false,error:error.message};
  }
};
export function runScenario(name='storage-fault') {
  const config=scenario(name);
  const A=makeSentinelBackend(config);
  const B=makeLayerTreeBackend(config);
  const trace=[];
  for(const [step,event] of config.events.entries()) {
    const witness=event.kind==='proof'?challenge(event):null;
    trace.push({
      step,event:structuredClone(event),
      sharedEvidence:witness?{
        evidenceClass:witness.evidenceClass,sourceRoot:witness.root,
        sha256:witness.evidenceHash,nonce:witness.nonce,selected:witness.selected,
        actualPdpVerdict:witness.verified?'pass':'fault',
        claimedVerdict:witness.assertedVerdict,
        missingChunk:witness.deletedChunk,
      }:null,
      A:safeApply(A,event,witness),
      B:safeApply(B,event,witness),
    });
  }
  const a=A.report(),b=B.report();
  const accepted=(key)=>trace.filter(t=>t[key].ok).length;
  const rejected=(key)=>trace.filter(t=>!t[key].ok).length;
  const byName=(r)=>Object.fromEntries(r.settlements.map(s=>[s.holder,s.winner]));
  return {
    schema:'bsb-storage-ab-v1',scenario:name,network:'model-only',
    bitcoinTransactionsBroadcast:0,
    scriptInterpreterIsConsensus:false,
    realFrostSignatures:0,
    filecoinConsensusProofs:0,
    source:'blossom-reference-SHA256-PDP-model',
    terms:config.terms.map(t=>({
      id:t.id,stake:t.stake,provider:t.provider,client:t.client,
      sector:t.sector,deal:t.deal,proofKind:t.proofKind,
      startEpoch:t.startEpoch,endEpoch:t.endEpoch,
    })),
    trace,backends:[a,b],
    comparison:{
      sameStimulus:true,
      A:{accepted:accepted('A'),rejected:rejected('A'),
        unresolvedSats:a.unresolvedSats,settlements:byName(a),
        estimatedVbytes:a.metrics.estimatedVbytes,
        illustrativeFeesSats:a.metrics.illustrativeFeesSats},
      B:{accepted:accepted('B'),rejected:rejected('B'),
        unresolvedSats:b.unresolvedSats,settlements:byName(b),
        estimatedVbytes:null,illustrativeFeesSats:null,
        physicallyModeledRefreshes:b.metrics.physicalCarrierRefreshesModeled,
        falseFaultsAccepted:b.metrics.acceptedFalseFaults},
      testnetComparable:false,
      criterion:'BTC-consensus paths, availability and actual fee measurements must be independently proven per backend',
    },
  };
}
export const runAll = () => SCENARIOS.map(runScenario);
function csvQuote(value) {
  return '"'+String(value??'').replaceAll('"','""')+'"';
}
export function summarizeCSV(reports) {
  const keys=[
    'scenario','backend','accepted','rejected','unresolved_sats',
    'sentinel_estimated_vbytes','sentinel_illustrative_fee_sats',
    'federation_refresh_count','false_fault_accepted',
    'actual_testnet_confirmations',
  ];
  const rows=[keys.join(',')];
  for(const r of reports) {
    for(const key of ['A','B']) {
      const x=r.comparison[key];
      const values=[r.scenario,key,x.accepted,x.rejected,x.unresolvedSats,
        key==='A'?x.estimatedVbytes:null,
        key==='A'?x.illustrativeFeesSats:null,
        key==='B'?x.physicallyModeledRefreshes:null,
        key==='B'?x.falseFaultsAccepted:null,null];
      rows.push(values.map(csvQuote).join(','));
    }
  }
  return rows.join('\n')+'\n';
}
async function saveNew(path,value) {
  const file=await open(path,'wx',0o600);
  try {await file.writeFile(value,'utf8'); await file.sync();}
  finally {await file.close();}
}
async function cli() {
  const args=process.argv.slice(2);
  let target=null,chosen=null;
  for(let i=0;i<args.length;i++){
    if(args[i]==='--out' && i+1<args.length){target=args[++i];continue;}
    if(args[i]==='--scenario' && i+1<args.length){chosen=args[++i];continue;}
    throw new Error('usage: node experiments/storage-bond-ab/run.mjs [--scenario NAME] [--out DIR]');
  }
  const reports=chosen?[runScenario(chosen)]:runAll();
  if(!target) {process.stdout.write(JSON.stringify(reports.length===1?reports[0]:reports,null,2)+'\n');return;}
  const out=resolve(target);
  await mkdir(out,{recursive:true,mode:0o700});
  for(const r of reports) {
    await saveNew(join(out,r.scenario+'.json'),JSON.stringify(r,null,2)+'\n');
  }
  await saveNew(join(out,'comparison.csv'),summarizeCSV(reports));
  process.stdout.write(JSON.stringify({written:reports.map(r=>r.scenario),
    directory:out,testnetComparable:false},null,2)+'\n');
}
if(process.argv[1] && import.meta.url===new URL('file://'+resolve(process.argv[1])).href) {
  cli().catch(e=>{console.error(e.message);process.exitCode=1;});
}
