// Independent public-input binding for the research fork certificate's Groth16 wrap.
// This does not perform pairings or authorize a Bitcoin collateral spend.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { blake3Block } from "../../model/bitvm_term.ts";

const compact=process.argv.includes("--compact"), version=compact?"v2":"v1";
const FORK_ID = compact ? "b1766c1d9ebf071acd684ea744d83908181a60d313ccb385661e3fe76ff855b1" : "8cf297b91e31b0ee52b57c876888f120416950ab3e7169d26c7315751da39457";
const constants = {
  control_root: "539032186827b06719244873b17b2d4c122e2d02cfb1994fe958b2523b844576",
  post_state: "a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2",
  bn254_control_id: "c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404",
};
const image = "ozancw/risc0-to-bitvm2-groth16-prover@sha256:840b833190a86c87eb71473cd72bcaa3e3b90cefa9bf4ae785ab2de61bc9d262";
const option = (name: string) => { const i=process.argv.indexOf(`--${name}`); return i<0?undefined:process.argv[i+1]; };
const required = (name: string) => { const v=option(name);assert.ok(v,`--${name} is required`);return resolve(v); };
const directory=required("g16"),readback=JSON.parse(readFileSync(required("readback"),"utf8"));
assert.equal(readback.format,`bsb/fork-proof-readback/${version}`);
assert.equal(readback.fork_image_id,FORK_ID);
assert.equal(readback.statement_checked,true);assert.equal(readback.header_chains_checked,true);
assert.match(readback.journal,/^[0-9a-f]{64}$/);
const wrap=JSON.parse(readFileSync(join(directory,"groth16.json"),"utf8"));
assert.equal(wrap.cmd,compact?"groth16-fork-compact":"groth16-fork");assert.equal(wrap.image,image);
assert.equal(wrap.pre_state,FORK_ID);assert.equal(wrap.journal,readback.journal);
for(const [name,value] of Object.entries(constants))assert.equal(wrap[name],value,name);
const root=Buffer.from(constants.control_root,"hex").map(byte=>{
  let result=0;for(let bit=0;bit<8;bit++)result|=((byte>>>bit)&1)<<(7-bit);return result;
});
const digest=createHash("sha256").update(Buffer.concat([root,Buffer.from(FORK_ID,"hex"),Buffer.from(constants.post_state,"hex"),Buffer.from(constants.bn254_control_id,"hex")])).digest();
assert.equal(digest.toString("hex"),wrap.constants_digest);
const publicBytes=blake3Block(Buffer.concat([digest,Buffer.from(readback.journal,"hex")])).subarray(0,31);
const scalar=BigInt("0x"+publicBytes.toString("hex")).toString();
const supplied=JSON.parse(readFileSync(join(directory,"public.json"),"utf8"));
assert.deepEqual(supplied,[scalar]);assert.equal(wrap.public_output_dec,scalar);
assert.equal(wrap.public_output_hex,publicBytes.toString("hex"));
assert.equal(wrap.expected_output_hex,publicBytes.toString("hex"));assert.equal(wrap.output_matches,true);
const vk=readFileSync(join(directory,"vk.json"));
assert.equal(createHash("sha256").update(vk).digest("hex"),"2941dff0bd962ff8610773c9659c10d0dec561db1e2f6afecfbbe0d9cb457a7d");
const result={format:`bsb/fork-public-input-readback/${version}`,fork_image_id:FORK_ID,journal:readback.journal,constants_digest:digest.toString("hex"),public_input:scalar,
  scope:"Independent public-input binding only. Pairing verification and Bitcoin fork-dispute enforcement are separate checks."};
if(option("out"))writeFileSync(resolve(option("out")!),JSON.stringify(result,null,2)+"\n",{flag:"wx"});
console.log(JSON.stringify(result));
