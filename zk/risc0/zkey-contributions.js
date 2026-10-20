// Lists the phase-2 contributions recorded in a snarkjs Groth16 zkey (section 10, mpcParams), to
// see how a proving key was made. Plain CommonJS, so it runs on the prover image's own node:
//
//   docker run --rm --entrypoint node -v "$PWD/zk/risc0:/s:ro" <prover image> \
//     /s/zkey-contributions.js /app/verify_for_guest_final.zkey
//
// Layout (snarkjs zkey_utils.js): "zkey", u32 version, u32 section count, then sections of
// u32 type, u64 size. mpcParams: 64-byte circuit hash, u32 count, then per contribution
// deltaAfter, g1_s, g1_sx (G1, 64 bytes each), g2_spx (G2, 128), transcript (64), u32 type
// (0 contribution, 1 beacon), u32 parameter length, parameters (1 name, 2 iterations exp, 3 beacon hash).

const fs = require("fs");
const fd = fs.openSync(process.argv[2], "r");
const read = (pos, n) => { const b = Buffer.alloc(n); fs.readSync(fd, b, 0, n, pos); return b; };
if (read(0, 4).toString() !== "zkey") throw new Error("not a zkey");
const nSections = read(8, 4).readUInt32LE(0);
let pos = 12, mpc = null, protocol = null;
for (let i = 0; i < nSections; i++) {
  const h = read(pos, 12);
  const type = h.readUInt32LE(0), size = h.readUInt32LE(4) + h.readUInt32LE(8) * 2 ** 32;
  if (type === 1) protocol = read(pos + 12, 4).readUInt32LE(0);
  if (type === 10) mpc = { pos: pos + 12, size };
  pos += 12 + size;
}
if (!mpc) throw new Error("no mpcParams section");
const m = read(mpc.pos, mpc.size);
let o = 64;
const n = m.readUInt32LE(o); o += 4;
const contributions = [];
for (let i = 0; i < n; i++) {
  o += 64 * 3 + 128;
  const transcript = m.slice(o, o + 64).toString("hex"); o += 64;
  const type = m.readUInt32LE(o); o += 4;
  const len = m.readUInt32LE(o); o += 4;
  const end = o + len, c = { type: type === 1 ? "beacon" : "contribution", transcript };
  while (o < end) {
    const t = m[o++];
    if (t === 1) { const l = m[o++]; c.name = m.slice(o, o + l).toString(); o += l; }
    else if (t === 2) c.numIterationsExp = m[o++];
    else if (t === 3) { const l = m[o++]; c.beaconHash = m.slice(o, o + l).toString("hex"); o += l; }
    else throw new Error("unknown parameter " + t);
  }
  contributions.push(c);
}
console.log(JSON.stringify({ protocol: protocol === 1 ? "groth16" : protocol, csHash: m.slice(0, 64).toString("hex"), contributions }, null, 1));
