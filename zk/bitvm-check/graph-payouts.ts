// Independent decoder check of payouts in the graph transactions whose txids Core mined.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseTx, taprootAddress } from "../../layer1/onchain.ts";

const beneficiary:Record<string,"client"|"provider">={"kickoff-timeout":"client","unchallenged-refund":"provider","assert-timeout":"client","slots-timeout":"client","refund":"provider","slash":"client","final-timeout":"client","marker-burn":"provider"};
const terminal:Record<string,string>={"no-kickoff":"kickoff-timeout","no-challenge":"unchallenged-refund","silence":"assert-timeout","honest":"refund","wrong-term":"slash","corrupt-proof":"slash","burn-marker":"final-timeout"};
export function verifyGraphPayouts(cases:any[],datadir:string):void{
  for(const scenario of cases){
    scenario.payouts=[];
    for(const mined of scenario.mined){
      const role=beneficiary[mined.name];if(!role)continue;
      const recorded=JSON.parse(readFileSync(join(datadir,`graph-${scenario.scenario}`,`${mined.name}.json`),"utf8"));
      const tx=parseTx(Buffer.from(recorded.hex,"hex"));assert.equal(tx.txid,mined.txid,"decoded bytes must be the transaction Core mined");
      assert.equal(tx.outputs.length,1);const output=tx.outputs[0];assert.equal(output.script.length,34);assert.equal(output.script.subarray(0,2).toString("hex"),"5120");
      const address=taprootAddress(output.script.subarray(2).toString("hex"),"regtest");assert.equal(address,scenario[role],`${scenario.scenario}: ${mined.name} must pay ${role}`);
      assert.ok(output.value>0n);if(mined.name===terminal[scenario.scenario])assert.ok(output.value>90_000_000n,"terminal path must recover the main collateral");
      scenario.payouts.push({name:mined.name,beneficiary:role,address,sats:Number(output.value),txid:tx.txid});
    }
    assert.ok(scenario.payouts.some((p:any)=>p.name===terminal[scenario.scenario]),"scenario needs its terminal payout");
  }
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const [reportPath,datadir]=process.argv.slice(2);assert.ok(reportPath&&datadir,"<report.json> <test datadir>");
  const report=JSON.parse(readFileSync(reportPath,"utf8"));assert.equal(report.network,"regtest");verifyGraphPayouts(report.cases,datadir);
  report.payoutVerification="independent transaction decoder; exact txids accepted and mined by Core";
  writeFileSync(reportPath,JSON.stringify(report,null,2)+"\n");console.log(`verified payouts for ${report.cases.length} graph scenarios`);
}
