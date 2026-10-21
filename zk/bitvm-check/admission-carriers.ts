// Negative integration experiment on the actual storage graph, never an admission verifier.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { HeaderChain, REGTEST, parseHeader } from "../../layer1/headerchain.ts";
import { parseTx } from "../../layer1/onchain.ts";

type RPC = (method: string, params?: any[], wallet?: boolean) => Promise<any>;
const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
const json = (p: string) => JSON.parse(readFileSync(p, "utf8"));

export async function prepareAdmissionCarriers(o: {
  rpc: RPC; mine: (n: number) => Promise<void>; graphDir: string;
  graph: any; record: any; checker: string; fundingTxid: string; fundingVout: number;
}) {
  const { rpc, mine, graph, graphDir, record } = o;
  const dir = join(graphDir, "admission-carriers"); mkdirSync(dir);
  assert.equal(graph.journal_binding, true);
  assert.equal(graph.term_end, 220, "use a new node and the fixed-proof regression graph");
  assert.equal(await rpc("getblockcount"), 220);
  const checkpointHeight = 169, originalTipHeight = 232, candidateTipHeight = 320;
  const checkpointHash = await rpc("getblockhash", [checkpointHeight]);
  const originalSeed = await rpc("getblockhash", [170]);
  await mine(originalTipHeight - await rpc("getblockcount"));
  const originalTip = await rpc("getbestblockhash");
  const originalWork = BigInt("0x" + (await rpc("getblockheader", [originalTip])).chainwork);
  const originalHeaders: string[] = [];
  for (let h = 0; h <= originalTipHeight; h++) originalHeaders.push(await rpc("getblockheader", [await rpc("getblockhash", [h]), false]));

  // Funding is below the fork. Branch generation changes only this fresh, isolated node.
  const fundHeight = (await rpc("getblockheader", [(await rpc("getrawtransaction", [o.fundingTxid, true])).blockhash])).height;
  assert.ok(fundHeight < checkpointHeight);
  const clock = (await rpc("getblockheader", [originalTip])).time;
  await rpc("invalidateblock", [originalSeed]);
  assert.equal(await rpc("getbestblockhash"), checkpointHash);
  await rpc("setmocktime", [clock + 1]);
  await mine(candidateTipHeight - checkpointHeight);
  const candidateTip = await rpc("getbestblockhash");
  const candidateWork = BigInt("0x" + (await rpc("getblockheader", [candidateTip])).chainwork);
  const candidateHeaders = originalHeaders.slice(0, checkpointHeight + 1);
  for (let h = 170; h <= candidateTipHeight; h++) candidateHeaders.push(await rpc("getblockheader", [await rpc("getblockhash", [h]), false]));
  const candidateSeed = parseHeader(Buffer.from(candidateHeaders[170], "hex")).hash;
  assert.notEqual(originalSeed, candidateSeed);
  const upperTime = clock + 7200;
  const replay = (headers: string[]) => {
    const c = new HeaderChain(REGTEST); c.ingest(0, Buffer.from(headers.join(""), "hex"), upperTime); return c;
  };
  assert.equal(replay(originalHeaders).totalWork, originalWork);
  assert.equal(replay(candidateHeaders).totalWork, candidateWork);
  assert.ok(candidateWork > originalWork);
  const broken = [...candidateHeaders]; const raw = Buffer.from(broken[200], "hex"); raw[4] ^= 1; broken[200] = raw.toString("hex");
  assert.throws(() => replay(broken), /prev|link|connect|chain|hash/i);
  await rpc("invalidateblock", [candidateSeed]);
  await rpc("reconsiderblock", [originalSeed]);
  assert.equal(await rpc("getbestblockhash"), originalTip);
  await rpc("setmocktime", [clock + 30]);
  assert.ok((await rpc("getrawtransaction", [o.fundingTxid, true])).confirmations > 0);
  const intent = {
    format: "bsb/long-chain-admission-intent/v1", network: "regtest",
    funding: { txid: o.fundingTxid, vout: o.fundingVout },
    storageChallengeTxid: json(graph.transactions.challenge.file).txid,
    storageTermJournal: graph.claimed_term_journal,
    checkpointHeight, checkpointHash, firstSeedHeight: 170,
    provider: { height: originalTipHeight, hash: originalTip, work: originalWork.toString() },
    candidate: { height: candidateTipHeight, hash: candidateTip, work: candidateWork.toString(), headersSha256: sha(Buffer.from(candidateHeaders.join(""), "hex")) },
    outsiderNonce: randomBytes(32).toString("hex"),
  };
  const encoded = Buffer.from(JSON.stringify(intent)), commitment = sha(encoded);
  writeFileSync(join(dir, "intent.json"), encoded);
  writeFileSync(join(dir, "headers.json"), JSON.stringify({ originalHeaders, candidateHeaders }));
  // Separate runtime publication has no setup role, committee key or provider signature.
  const psbt = await rpc("walletcreatefundedpsbt", [[], [{ data: commitment }], 0, { replaceable: false }, true], true);
  const signed = await rpc("walletprocesspsbt", [psbt.psbt], true);
  const publication = await rpc("finalizepsbt", [signed.psbt]); assert.equal(publication.complete, true);
  const publicationTx = parseTx(Buffer.from(publication.hex, "hex"));
  assert.ok(publicationTx.outputs.some(v => v.value === 0n && v.script.equals(Buffer.from("6a20" + commitment, "hex"))));
  const publishedTxid = await rpc("sendrawtransaction", [publication.hex]); await mine(1);
  const published = await rpc("getrawtransaction", [publishedTxid, true]);
  assert.ok(published.confirmations >= 1); assert.equal(published.hex, publication.hex);
  writeFileSync(join(dir, "publication.json"), JSON.stringify({ hex: publication.hex, txid: publishedTxid, blockhash: published.blockhash, commitment }));
  record.admission = {
    classification: "negative integration regression; admission remains unimplemented",
    fixedProofReused: true, sameFundedChainStorageProof: false,
    scope: "Authentic current storage v2 transaction graph and verifier leaves; its phase-6 storage proof is a regression fixture. Generated header branches and public intent are fresh. This is an admission-carrier test, not a private-fork storage attack or completed long-chain contract.",
    candidateHeadersAfterCheckpoint: candidateTipHeight - checkpointHeight,
    intent, commitment, publication: { txid: publishedTxid, blockhash: published.blockhash },
    nativeExactWorkValidated: true, brokenHeaderLinkRejected: true,
    outsideSetup: true, carrierRejections: [] as any[],
    proofGate: "closed", authenticatedOnchainAdmission: false,
  };

  return {
    async rejectAt(stage: "challenge" | "assert-final" | "refund") {
      const target = graph.transactions[stage].file, variants = join(dir, stage);
      execFileSync(o.checker, [target, commitment, variants], { windowsHide: true, timeout: 30_000, stdio: "pipe" });
      for (const kind of ["output", "annex", "stack"]) {
        const v = json(join(variants, `${kind}.json`));
        assert.equal(v.baseTxid, json(target).txid);
        const check = (await rpc("testmempoolaccept", [[v.hex]]))[0];
        assert.equal(check.allowed, false, `unexpected admission of ${stage}/${kind}`);
        assert.match(check["reject-reason"], /script/i);
        record.admission.carrierRejections.push({ stage, carrier: kind, txid: v.txid, wtxid: v.wtxid, txidUnchanged: v.txidUnchanged, reason: check["reject-reason"] });
      }
    },
    async finish(refundTxid: string) {
      const refund = await rpc("getrawtransaction", [refundTxid, true]); assert.ok(refund.confirmations > 0);
      const tip = await rpc("getbestblockhash"), tipWork = BigInt("0x" + (await rpc("getblockheader", [tip])).chainwork);
      assert.ok(candidateWork > tipWork, "candidate must still outweigh the observed chain at withdrawal");
      const withdrawalHeaders:string[]=[];
      for(let h=0;h<=await rpc("getblockcount");h++)withdrawalHeaders.push(await rpc("getblockheader",[await rpc("getblockhash",[h]),false]));
      const withdrawalChain=replay(withdrawalHeaders);
      assert.equal(withdrawalChain.tip,tip);assert.equal(withdrawalChain.totalWork,tipWork);
      writeFileSync(join(dir,"withdrawal-headers.json"),JSON.stringify(withdrawalHeaders));
      assert.ok((await rpc("getrawtransaction", [publishedTxid, true])).confirmations > 0);
      assert.equal(await rpc("getconnectioncount"), 0);
      record.admission.observed = { providerRefundMined: true, txid: refundTxid, observedTip: tip, observedWork: tipWork.toString(), candidateStillStronger: true, publicationStillConfirmed: true };
      writeFileSync(join(dir, "admission.json"), JSON.stringify(record.admission, null, 2) + "\n");
    },
  };
}
