import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
const [repo,destination]=process.argv.slice(2);
mkdirSync(destination);
const evidence=JSON.parse(readFileSync(join(repo,'results/bitvm-cumulative-work-forks.json'),'utf8'));
const fixture=JSON.parse(readFileSync(join(repo,'results/bitvm2-spike.json'),'utf8'));
const files={};
function write(name,bytes){writeFileSync(join(destination,name),bytes,{flag:'wx'});files[name]=createHash('sha256').update(bytes).digest('hex');}
for(const [name,headers,end] of [['common',evidence.headers.honest,170],['original',evidence.headers.honest,221],['response',evidence.headers.honest,233],['candidate',evidence.headers.alternative,234]]){
  assert.ok(headers.length>=end);write(`${name}.bin`,Buffer.from(headers.slice(0,end).join(''),'hex'));
}
const height=Buffer.alloc(4);height.writeUInt32BE(evidence.claim.height);
const p=Buffer.concat([Buffer.from(fixture.m2.term.preimage,'hex').subarray(0,134),height,Buffer.from(evidence.claim.hash,'hex').reverse(),Buffer.from(BigInt(evidence.claim.work).toString(16).padStart(64,'0'),'hex')]);
assert.equal(p.length,202);write('term-preimage.bin',p);
// A synthetic research graph identifier, explicitly not a funded graph outpoint.
const graphId=createHash('sha256').update('bsb/cumulative-work-research/v1\0').update(JSON.stringify(evidence.claim)).digest('hex');
writeFileSync(join(destination,'manifest.json'),JSON.stringify({format:'bsb/fork-proof-research-inputs/v1',network:'regtest',graph_id:graphId,graph_id_is_synthetic:true,term_preimage:p.toString('hex'),term_journal:createHash('sha256').update(p).digest('hex'),original:evidence.claim,response:evidence.honestExtension,candidate:evidence.cases[2].alternative,divergent_height:170,epoch_index:0,files},null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({graph_id:graphId,files}));
