// Phase 7C, nova-bitvm3 brief 4: a deal's term settled against a Nova header-chain proof, in place of
// phase 6's RISC Zero term guest.
//
// Phase 6 bound three epochs' seeds to chainwayxyz/risc0-to-bitvm2's regtest header-chain proof, pinning
// the header-chain image and genesis. This module consumes the statements of
// garbled-snark-verifier/nova-bitvm3 instead:
//   guest A (1,164 bytes): magic "NHC1"|"NHT4" | u32 k | u32 steps | z0 (17 × 32) | zn (17 × 32)
//                          | sha256(compressed Nova vk) | proofs digest
//   M16 adds 128 bytes:    "PAY1" | u32 segments | u32 height_B | hash_B | u32 confirmations | txid
//                          | u32 vout | u64 value | u32 script length | sha256(scriptPubKey)
// Hashes are in internal byte order; integers little-endian; z holds Pallas scalars, little-endian.
// zn[0] is the tip height, zn[1..2] the tip hash (low, high 128 bits), zn[3] the chainwork.
//
// A term is accepted only if:
// - the statement's network magic and k are the pinned ones, its z0 is that network's genesis state,
//   and its Nova key digest is the pinned key (both pins, as the brief asks);
// - every epoch seed is the hash of the block at its height, shown by headers that link by previous-block
//   hash to the proven tip (the tip's hash is in zn, so these headers are fixed by it);
// - with a PAY1 record: the proven output is one of the term's payments (txid, vout, value, script) with at
//   least minConfs confirmations, and its height is consistent with the tip;
// - with a wrap proof: m13-verify accepts it for a statement whose committed-values digest is
//   sha256(statement bytes) and whose program key is pinned for that statement's shape.
//
// The proof shows a valid proof-of-work chain from genesis, not the heaviest one: a caller that knows the
// chain compares chainwork (knownChainwork) before trusting the tip.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sha256d, toDisplay } from "./headerchain.ts";

const sha256 = (b: Uint8Array): Buffer => createHash("sha256").update(b).digest();
const ZB = 17 * 32;
export const GUEST_A_BYTES = 12 + 2 * ZB + 64;   // 1,164
export const PAY1_BYTES = 128;

/** testnet4's genesis state, z0 of every NHT4 statement (from guest A's proven testnet4 statement). */
const T4_Z0 = (() => {
  const z = Buffer.alloc(ZB);
  const put = (i: number, v: bigint) => { for (let j = 0; j < 32; j++) z[32 * i + j] = Number((v >> BigInt(8 * j)) & 0xffn); };
  const g = Buffer.from("00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043", "hex").reverse();
  put(1, BigInt("0x" + Buffer.from(g.subarray(0, 16)).reverse().toString("hex")));
  put(2, BigInt("0x" + Buffer.from(g.subarray(16, 32)).reverse().toString("hex")));
  put(3, 0x100010001n);                 // work of one block at bits 0x1d00ffff
  put(4, 0x1d00ffffn);
  for (let i = 6; i < 16; i += 2) put(i + 1, 0xffffffffn);
  put(5, 1714777860n); put(16, 1714777860n);
  return z;
})();

/** Per network: the k = 1 Nova key digest (compressed encoding) and the genesis state. Mainnet's z0 is
 *  pinned when nova-bitvm3 publishes the mainnet statement; until then an NHC1 statement is refused. */
export const NOVA_PINS: Record<string, { magic: string; k: number; vkSha: string; z0?: Buffer }> = {
  testnet4: { magic: "NHT4", k: 1, vkSha: "6894f4903a9ff9713111bb1076b61663ac3592ad3d51b697d58125403fc5c12a", z0: T4_Z0 },
  mainnet: { magic: "NHC1", k: 1, vkSha: "6aa50d09397c51d0b89d78b3a918d3fe0962251225c8b6ca91e83199a4e6da1d" },
};

/** The M13 final layer (nova-bitvm3/m13/pins.json) and the SP1 program key of each statement shape.
 *  The M16 key is pinned when its first proof is published; until then a PAY1 proof is refused. */
export const WRAP_PINS = {
  wrapVkSha256: "d42c63e3c873b35576b4c95fa8c41770a8c6b8a9f16ba74732c5b52a43b0b0d7",
  recursionVkRoot: "7487c2175bd3256619ca0118094b8150d6df0246a1b41979a081642e5253f257",
  programs: { guestA: "5df3760fed1620671151183a73c9407d528b2239a5cd243b14cf5c7b4d4af46b", m16: undefined as string | undefined },
};

export interface Pay1 { segments: number; heightB: number; hashB: string; confirmations: number; txid: string; vout: number; value: bigint; scriptLen: number; scriptSha: string }
export interface NovaStatement {
  magic: string; k: number; steps: number; z0: Buffer; zn: Buffer[];
  tipHeight: number; tipHash: string; chainwork: bigint; vkSha: string; proofsSha: string; pay?: Pay1;
}

export class NovaRefused extends Error {}
const refuse = (why: string): never => { throw new NovaRefused(why); };

const le = (b: Buffer): bigint => BigInt("0x" + (Buffer.from(b).reverse().toString("hex") || "0"));

export function decodeStatement(b: Buffer): NovaStatement {
  if (b.length !== GUEST_A_BYTES && b.length !== GUEST_A_BYTES + PAY1_BYTES) refuse(`statement is ${b.length} bytes, not ${GUEST_A_BYTES} or ${GUEST_A_BYTES + PAY1_BYTES}`);
  const magic = b.subarray(0, 4).toString("latin1");
  const zn = Array.from({ length: 17 }, (_, i) => b.subarray(12 + ZB + 32 * i, 12 + ZB + 32 * i + 32));
  const small = (f: Buffer, what: string) => { if (f.subarray(4).some((x) => x !== 0)) refuse(`${what} exceeds 32 bits`); return f.readUInt32LE(0); };
  for (const half of [zn[1], zn[2]]) if (half.subarray(16).some((x) => x !== 0)) refuse("tip hash half exceeds 128 bits");
  const tip = Buffer.concat([zn[1].subarray(0, 16), zn[2].subarray(0, 16)]);
  const s: NovaStatement = {
    magic, k: b.readUInt32LE(4), steps: b.readUInt32LE(8), z0: b.subarray(12, 12 + ZB), zn,
    tipHeight: small(zn[0], "tip height"), tipHash: toDisplay(tip), chainwork: le(zn[3]),
    vkSha: b.subarray(12 + 2 * ZB, 44 + 2 * ZB).toString("hex"), proofsSha: b.subarray(44 + 2 * ZB, GUEST_A_BYTES).toString("hex"),
  };
  if (b.length > GUEST_A_BYTES) {
    const p = b.subarray(GUEST_A_BYTES);
    if (p.subarray(0, 4).toString("latin1") !== "PAY1") refuse("payment record lacks the PAY1 tag");
    s.pay = {
      segments: p.readUInt32LE(4), heightB: p.readUInt32LE(8), hashB: toDisplay(p.subarray(12, 44)), confirmations: p.readUInt32LE(44),
      txid: toDisplay(p.subarray(48, 80)), vout: p.readUInt32LE(80), value: p.readBigUInt64LE(84), scriptLen: p.readUInt32LE(92), scriptSha: p.subarray(96, 128).toString("hex"),
    };
  }
  return s;
}

/** Network, k, genesis and key pins. Returns the network name. */
export function checkPins(s: NovaStatement, network: string): void {
  const pin = NOVA_PINS[network] ?? refuse(`no Nova pins for network ${network}`);
  if (s.magic !== pin.magic) refuse(`statement is for ${s.magic}, not ${network} (${pin.magic})`);
  if (s.k !== pin.k) refuse(`fold width ${s.k} is not the pinned ${pin.k}`);
  if (!pin.z0) refuse(`no genesis state pinned for ${network} yet`);
  if (!s.z0.equals(pin.z0!)) refuse(`z0 is not ${network}'s genesis state`);
  if (s.vkSha !== pin.vkSha) refuse(`Nova key digest ${s.vkSha.slice(0, 8)}… is not the pinned ${pin.vkSha.slice(0, 8)}…`);
  if (s.steps !== s.tipHeight) refuse(`steps ${s.steps} differ from the tip height ${s.tipHeight} (k = 1 folds one header per step from genesis)`);
}

export interface Seed { height: number; hash: string }   // hash in display order, as getblockhash returns it

/** Each seed is the block at its height on the proven chain. `headers` are 80-byte headers ending at the
 *  proven tip (any start at or below the lowest seed). Returns the seeds bound. */
export function bindSeeds(s: NovaStatement, headers: Buffer[], seeds: Seed[]): number {
  if (!seeds.length) return 0;
  if (!headers.length) refuse("no headers to bind the seeds to the proven tip");
  for (const h of headers) if (h.length !== 80) refuse("a header is not 80 bytes");
  const hashes = headers.map((h) => sha256d(h));
  for (let i = 1; i < headers.length; i++) if (!headers[i].subarray(4, 36).equals(hashes[i - 1])) refuse(`headers do not link at position ${i}`);
  if (toDisplay(hashes[hashes.length - 1]) !== s.tipHash) refuse("last header is not the proven tip");
  const first = s.tipHeight - (headers.length - 1);
  if (first < 0) refuse("more headers than the proven chain holds");
  for (const seed of seeds) {
    if (seed.height > s.tipHeight) refuse(`seed at ${seed.height} is above the proven tip ${s.tipHeight}`);
    if (seed.height < first) refuse(`seed at ${seed.height} is below the headers given (from ${first})`);
    if (toDisplay(hashes[seed.height - first]) !== seed.hash) refuse(`seed at ${seed.height} is not the proven chain's block`);
  }
  return seeds.length;
}

export interface TermPayment { txid: string; vout: number; sats: number | string; script: string }   // script hex

/** The PAY1 record proves one of the term's payments, at least minConfs deep under the proven tip. */
export function matchPayment(s: NovaStatement, payments: TermPayment[], minConfs: number): TermPayment {
  const p = s.pay ?? refuse("statement has no payment record (guest A, not M16)");
  if (p.segments < 1) refuse("payment record has no segments");
  if (p.confirmations < 1 || p.heightB + p.confirmations - 1 !== s.tipHeight) refuse("payment height and confirmations do not end at the proven tip");
  if (p.confirmations < minConfs) refuse(`payment has ${p.confirmations} confirmations, fewer than ${minConfs}`);
  const m = payments.find((t) => t.txid === p.txid && t.vout === p.vout);
  if (!m) refuse(`proven output ${p.txid.slice(0, 16)}…:${p.vout} is not one of the term's payments`);
  const script = Buffer.from(m!.script, "hex");
  if (BigInt(m!.sats) !== p.value) refuse(`proven value ${p.value} differs from the term's ${m!.sats}`);
  if (script.length !== p.scriptLen || sha256(script).toString("hex") !== p.scriptSha) refuse("proven scriptPubKey differs from the payee's");
  return m!;
}

/** m13-verify on an SP1 wrap proof of `statementBytes`. The expectation file it checks is rebuilt from the
 *  pins and the statement, so a caller cannot pass a looser one. `cmd` is the verifier command line
 *  (BSB_M13_VERIFY); a command starting with "wsl" gets /mnt/ paths. */
export function verifyWrap(statementBytes: Buffer, wrapPath: string, cmd: string): { status: "verified"; programKey: string } {
  const s = decodeStatement(statementBytes);
  const programKey = s.pay ? WRAP_PINS.programs.m16 : WRAP_PINS.programs.guestA;
  if (!programKey) refuse("no M16 program key pinned yet, so no PAY1 proof can be checked");
  const expect = {
    committed_values_sha256: sha256(statementBytes).toString("hex"), exit_code: 0, is_complete: 1,
    program_vk_digest: programKey, recursion_vk_root: WRAP_PINS.recursionVkRoot, wrap_vk_sha256: WRAP_PINS.wrapVkSha256,
  };
  const dir = mkdtempSync(join(tmpdir(), "bsb-nova-"));
  const expectPath = join(dir, "expect.json");
  writeFileSync(expectPath, JSON.stringify(expect, null, 2) + "\n");
  const parts = cmd.split(/\s+/).filter(Boolean);
  const wsl = /^wsl(\.exe)?$/i.test(parts[0] ?? "");
  const path = (p: string) => wsl ? p.replace(/^([A-Za-z]):[\\/]/, (_, d: string) => `/mnt/${d.toLowerCase()}/`).replace(/\\/g, "/") : p;
  const r = spawnSync(parts[0], [...parts.slice(1), "verify-v2", path(wrapPath), path(expectPath)], { encoding: "utf8", env: { ...process.env, MSYS_NO_PATHCONV: "1" } });
  if (r.error) refuse(`m13-verify did not start: ${r.error.message}`);
  if (r.status !== 0) refuse(`m13-verify refused: ${(r.stderr || r.stdout).trim().split("\n").pop()}`);
  if (!/"status":\s*"verified"/.test(r.stdout)) refuse("m13-verify exited 0 without reporting verified");
  return { status: "verified", programKey: programKey! };
}

export interface Term { network: string; seeds: Seed[]; payments: TermPayment[]; minConfs: number }
export interface NovaTermResult {
  term: "fixture" | "run"; network: string; statement: string; tip: { height: number; hash: string; chainwork: string };
  chainwork: "equal to the node's" | "not compared"; seedsBound: number;
  payment: { txid: string; vout: number; confirmations: number } | "no PAY1 record";
  proof: "verified" | `not checked: ${string}`;
}

/** Everything above, from a directory: statement.bin (required), headers.hex (one header per line, ending
 *  at the proven tip), wrap.bin (or BSB_NOVA_WRAP), and term.json, which replaces the caller's own term
 *  when present (a fixture shaped like a run's term). Throws NovaRefused on the first failed check. */
export function checkNovaTermDir(dir: string, own: Term, opts: { verifier?: string; knownChainwork?: (tipHash: string) => bigint | undefined } = {}): NovaTermResult {
  const bytes = readFileSync(join(dir, "statement.bin"));
  const fixture = existsSync(join(dir, "term.json"));
  const term: Term = fixture ? JSON.parse(readFileSync(join(dir, "term.json"), "utf8")) : own;
  const s = decodeStatement(bytes);
  checkPins(s, term.network);
  const known = fixture ? undefined : opts.knownChainwork?.(s.tipHash);
  if (known !== undefined && known !== s.chainwork) refuse(`proven chainwork 0x${s.chainwork.toString(16)} differs from the node's 0x${known.toString(16)} at that tip`);
  const hp = join(dir, "headers.hex");
  const headers = existsSync(hp) ? readFileSync(hp, "utf8").split(/\s+/).filter(Boolean).map((h) => Buffer.from(h, "hex")) : [];
  const seedsBound = bindSeeds(s, headers, term.seeds);
  const paid = s.pay ? matchPayment(s, term.payments, term.minConfs) : undefined;
  const wrap = existsSync(join(dir, "wrap.bin")) ? join(dir, "wrap.bin") : process.env.BSB_NOVA_WRAP;
  const verifier = opts.verifier ?? process.env.BSB_M13_VERIFY;
  let proof: NovaTermResult["proof"];
  if (!wrap) proof = "not checked: no wrap proof given";
  else if (!verifier) proof = "not checked: BSB_M13_VERIFY unset";
  else proof = verifyWrap(bytes, wrap, verifier).status;
  return {
    term: fixture ? "fixture" : "run", network: term.network, statement: sha256(bytes).toString("hex"),
    tip: { height: s.tipHeight, hash: s.tipHash, chainwork: "0x" + s.chainwork.toString(16) },
    chainwork: known !== undefined ? "equal to the node's" : "not compared", seedsBound,
    payment: paid ? { txid: paid.txid, vout: paid.vout, confirmations: s.pay!.confirmations } : "no PAY1 record", proof,
  };
}

if (process.argv[1]?.endsWith("nova-term.ts")) {
  const i = process.argv.indexOf("--dir");
  const dir = i > 0 ? process.argv[i + 1] : undefined;
  if (!dir) { console.error("usage: node layer1/nova-term.ts --dir <statement.bin, headers.hex, term.json[, wrap.bin]>  (BSB_M13_VERIFY=<m13-verify command>)"); process.exit(2); }
  try { console.log(JSON.stringify(checkNovaTermDir(dir, { network: "testnet4", seeds: [], payments: [], minConfs: 1 }), null, 2)); }
  catch (e) { console.error(e instanceof NovaRefused ? `refused: ${e.message}` : e); process.exit(1); }
}
