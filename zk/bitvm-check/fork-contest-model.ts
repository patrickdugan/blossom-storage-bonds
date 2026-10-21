// Protocol counterexample, not Bitcoin enforcement. Header validity is checked locally;
// delivering and authenticating these candidates to a contract remains an assumption.
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {readFileSync,writeFileSync} from "node:fs";
import {fileURLToPath} from "node:url";
import {HeaderChain,REGTEST} from "../../layer1/headerchain.ts";

const opt=(name:string)=>{const i=process.argv.indexOf(`--${name}`);assert.ok(i>=0&&process.argv[i+1],`--${name} required`);return process.argv[i+1];};
const fixturePath=opt("forks"),out=opt("out");
const fixtureBytes=readFileSync(fixturePath),fixture=JSON.parse(fixtureBytes.toString());
const sha=(v:Buffer)=>createHash("sha256").update(v).digest("hex");
function replay(headers:string[],height:number,expected:any){
  const chain=new HeaderChain(REGTEST);
  chain.ingest(0,Buffer.from(headers.slice(0,height+1).join(""),"hex"),Math.floor(Date.now()/1000));
  assert.equal(chain.height,expected.height);assert.equal(chain.tip,expected.hash);
  assert.equal(chain.totalWork,BigInt(expected.work));return chain;
}
const original=replay(fixture.headers.honest,fixture.claim.height,fixture.claim);
const response=replay(fixture.headers.honest,fixture.honestExtension.height,fixture.honestExtension);
const weak=replay(fixture.headers.alternative,fixture.cases[0].alternative.height,fixture.cases[0].alternative);
const tie=replay(fixture.headers.alternative,fixture.cases[1].alternative.height,fixture.cases[1].alternative);
const strong=replay(fixture.headers.alternative,fixture.cases[2].alternative.height,fixture.cases[2].alternative);
assert.equal(response.hashAt(original.height),original.tip);
for(const candidate of [weak,tie,strong]){
  assert.notEqual(candidate.hashAt(fixture.firstSeedHeight),original.hashAt(fixture.firstSeedHeight));
  assert.equal(candidate.hashAt(fixture.commonAncestorHeight),original.hashAt(fixture.commonAncestorHeight));
  assert.ok(candidate.totalWork>original.totalWork);
}
assert.ok(weak.totalWork<response.totalWork);assert.equal(tie.totalWork,response.totalWork);assert.ok(strong.totalWork>response.totalWork);

type Event="weak-candidate"|"strong-candidate"|"provider-extension";
type Rule="first-candidate"|"strongest-candidate";
type TraceItem={event:string;action:string;candidateWork:string|null;responseWork:string|null};
function run(rule:Rule,events:Event[],candidates:Record<string,HeaderChain>={"weak-candidate":weak,"strong-candidate":strong}){
  let selected:HeaderChain|undefined,reply:HeaderChain|undefined;
  const trace:TraceItem[]=[];
  for(const event of events){
    let action:string;
    if(event==="provider-extension"){
      reply=response;action="record valid original-branch extension";
    }else{
      const candidate=candidates[event];assert.ok(candidate.totalWork>original.totalWork);
      if(!selected){selected=candidate;action="admit candidate";}
      else if(rule==="strongest-candidate"&&candidate.totalWork>selected.totalWork){selected=candidate;action="supersede with greater-work candidate";}
      else action=rule==="first-candidate"?"reject: public challenge slot already consumed":"retain candidate with at least as much work";
    }
    trace.push({event,action,candidateWork:selected?.totalWork.toString()??null,responseWork:reply?.totalWork.toString()??null});
  }
  // Both rules defer every payout until the submission window has closed.
  const winner=!selected||reply&&reply.totalWork>=selected.totalWork?"provider":"challenger";
  trace.push({event:"close submission window and finish response window",action:`fixed ${winner} payout`,candidateWork:selected?.totalWork.toString()??null,responseWork:reply?.totalWork.toString()??null});
  return {winner,trace};
}
function permutations<T>(items:T[]):T[][]{
  return items.length===0?[[]]:items.flatMap((v,i)=>permutations(items.filter((_,j)=>i!==j)).map(rest=>[v,...rest]));
}
const orders=permutations<Event>(["weak-candidate","strong-candidate","provider-extension"]);
let unsafeFirst=0,unsafeStrongest=0;
const schedules=orders.map(order=>{
  const first=run("first-candidate",order),frontier=run("strongest-candidate",order);
  // All submissions and the response are delivered before either deadline.
  // The already validated strong branch outweighs the only provider extension.
  if(first.winner==="provider")unsafeFirst++;
  if(frontier.winner==="provider")unsafeStrongest++;
  return {order,firstCandidateWinner:first.winner,strongestCandidateWinner:frontier.winner};
});
assert.equal(orders.length,6);assert.equal(unsafeFirst,3);assert.equal(unsafeStrongest,0);
const attack=run("first-candidate",["weak-candidate","provider-extension","strong-candidate"]);
assert.equal(attack.winner,"provider");
assert.equal(run("strongest-candidate",["weak-candidate","provider-extension","strong-candidate"]).winner,"challenger");
const controls={
  weakOnly:run("strongest-candidate",["weak-candidate","provider-extension"]).winner,
  equalWork:run("strongest-candidate",["weak-candidate","provider-extension"],{"weak-candidate":tie}).winner,
  silence:run("strongest-candidate",["strong-candidate"]).winner,
  noChallenge:run("strongest-candidate",["provider-extension"]).winner,
};
assert.deepEqual(controls,{weakOnly:"provider",equalWork:"provider",silence:"challenger",noChallenge:"provider"});
const result={
  format:"bsb/fork-contest-model/v1",generated:new Date().toISOString(),network:"regtest",
  scope:"Finite abstract state-machine counterexample for hypothetical first-candidate contest rules. Replays saved Core headers locally; performs no new Core transaction, ZK proof, signature admission, payout enforcement or miner test. This is not an exploit of the existing storage graph, which has no fork contest.",
  assumptions:["All compared branch headers pass the existing local HeaderChain validator.","Every candidate is assumed delivered and authenticated to the hypothetical contract before the submission deadline; that contract mechanism is still absent.","The provider may respond with the validated extension of its original tip before the response deadline.","Payouts occur only after both windows; no censorship or early payout is needed for the counterexample."],
  provenance:{fixture:"results/bitvm-cumulative-work-forks.json",fixtureSha256:sha(fixtureBytes),model:"zk/bitvm-check/fork-contest-model.ts",modelSha256:sha(readFileSync(fileURLToPath(import.meta.url)))},
  branches:Object.fromEntries(Object.entries({original,response,weak,tie,strong}).map(([name,c])=>[name,{height:c.height,hash:c.tip,work:c.totalWork.toString()}])),
  schedules,summary:{enumeratedSchedules:orders.length,firstCandidateUnsafeSchedules:unsafeFirst,strongestCandidateUnsafeSchedules:unsafeStrongest},
  counterexample:attack.trace,controls,
  requiredInvariant:"An earlier weaker or rebutted candidate must not permanently exclude a timely stronger candidate; merely delaying the final payout is insufficient.",
  missing:["Bitcoin-authenticated candidate admission and supersession","Provider response linked to the actual frozen candidate set","A bounded transaction graph supporting the required adversarial update order","Fixed payout, replay binding, fee and timeout enforcement"],
  strongestCandidateAbstraction:"A finite comparison oracle illustrates the missing invariant only. It is not a proposed implemented max-register, does not establish safety for arbitrary schedules or branches, and does not solve the presigned-parent or unknown-input binding problems.",
};
writeFileSync(out,JSON.stringify(result,null,2)+"\n",{flag:"wx"});
console.log(JSON.stringify(result.summary));
