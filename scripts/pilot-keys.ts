// Signet/testnet4 pilot step 3 helper: make (or reuse) each party's fresh key in its pilot directory and print
// the fee address to fund. It starts no party and sends nothing. The seeds land in <dir>/party.seed,
// exactly where provider.ts and full-stack.ts look for them later.
//   BSB_NETWORK=signet (or testnet4) BSB_RPC_COOKIE=... node scripts/pilot-keys.ts <pilot root>
import { join } from "node:path";
import { BondTool } from "../layer1/bondtool.ts";
import { currentNet, partySeed } from "../layer1/net.ts";
import { keyFromSeed } from "../model/schnorr.ts";

const root = process.argv[2];
if (!root) { console.error("usage: node scripts/pilot-keys.ts <pilot root>"); process.exit(2); }
const NET = currentNet();
if (NET.canMine) throw new Error("pilot keys require signet or testnet4");
const parties = [
  { name: "client", dir: join(root, "client", "client"), label: "bsb/client/full-stack" },
  { name: "honest", dir: join(root, "honest"), label: "" },
  { name: "deletes10", dir: join(root, "deletes10"), label: "" },
  { name: "outsources", dir: join(root, "outsources"), label: "" },
];
const out = [];
for (const p of parties) {
  const seed = partySeed(NET, p.dir, p.label);
  const info = await new BondTool(seed).run("info");
  out.push({ party: p.name, dir: p.dir, nostr: keyFromSeed(`nostr|${seed}`).x, bond_x: info.x, fee_address: info.fee_address });
}
console.log(JSON.stringify({ network: NET.name, parties: out }, null, 2));
