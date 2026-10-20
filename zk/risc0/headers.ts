// Exports a regtest node's headers for the header-chain guest (chainwayxyz/risc0-to-bitvm2), whose
// CircuitBlockHeader borsh encoding is exactly the 80-byte consensus header.
//
//   node zk/risc0/headers.ts --out DIR [--to HEIGHT]        (BSB_RPC, default 127.0.0.1:18543)
//
// Writes DIR/headers.bin (heights 0..HEIGHT, 80 bytes each) and DIR/hashes.json, the RPC's
// display-order hash per height: what layer1/zk-provider.ts uses as an epoch seed.

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { rpc } from "../../layer1/bondtool.ts";
import { sha256d, toDisplay } from "../../layer1/headerchain.ts";

const argv = process.argv.slice(2);
const opt = (k: string): string | undefined => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : undefined; };
const out = opt("--out") ?? (() => { throw new Error("--out DIR") })();
const to = Number(opt("--to") ?? (await rpc("getblockcount")));

const raws: Buffer[] = [];
const hashes: string[] = [];
for (let h = 0; h <= to; h++) {
  const hash: string = await rpc("getblockhash", [h]);
  const raw = Buffer.from(await rpc("getblockheader", [hash, false]), "hex");
  if (toDisplay(sha256d(raw)) !== hash) throw new Error(`header ${h} does not hash to ${hash}`);
  if (h > 0 && !raw.subarray(4, 36).equals(sha256d(raws[h - 1]))) throw new Error(`header ${h} does not link`);
  raws.push(raw);
  hashes.push(hash);
}
mkdirSync(out, { recursive: true });
writeFileSync(join(out, "headers.bin"), Buffer.concat(raws));
writeFileSync(join(out, "hashes.json"), JSON.stringify({ chain: await rpc("getblockchaininfo").then((i: any) => i.chain), hashes }, null, 1) + "\n");
console.log(JSON.stringify({ out, headers: raws.length, tip: hashes[to], genesis: hashes[0] }));
