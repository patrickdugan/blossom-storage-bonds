// A header-chain check without a STARK: the stand-in for the ZeroSync-style proof of the chain that an
// on-chain payment receipt (layer1/onchain.ts) is checked against.
//
// THIS IS NOT THE STARK. rust-bitcoin's zk/sync light client accepts a chain tip from Stwo proofs of
// Raito's Cairo `chain_segment` program, linked from genesis, and checks a block against the proven
// Merkle Mountain Range of block hashes. That program cannot validate regtest headers as it stands
// (docs/design.md §4.5 lists what it would need), so here the verifier replays the headers themselves,
// from genesis, under the rules `chain_segment` proves: each header links to the previous one, its
// version meets the BIP34/66/65 minimum for its height, its time is above the median of the last
// eleven, its bits are exactly the required target (retargeted every 2016 blocks on mainnet, fixed on
// regtest), its double SHA-256 is at or below that target, and work adds up. Plus the rule a proof
// cannot carry, a time limit relative to the verifier's clock. What the STARK would change is the cost:
// 80 bytes per header and linear verification here, against a few proofs and an MMR path there. What
// the verifier learns is the same: a valid header chain from genesis with this much work, and the
// block hash at each height.
//
// Like any header-chain client, it learns which chain is real only from the work in it. A minimum-work
// floor (Core's nMinimumChainWork) belongs with every verifier. On regtest work is free, so a regtest
// run shows the mechanism, not the security: anyone can mine a regtest chain with a fake payment in it.
//
// The headers can come from anyone. serveHeaders() is a mirror over plain HTTP, and HeaderChain checks
// every header it is given, so a mirror can withhold headers but cannot make a verifier accept a bad
// one (on mainnet, under the work floor).

import { createHash } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

export interface ChainParams {
  readonly name: "regtest" | "mainnet";
  /** Display-order hex of block 0. */
  readonly genesis: string;
  readonly powLimit: bigint;
  /** Regtest's fPowNoRetargeting: bits never change. */
  readonly noRetarget: boolean;
  readonly bip34: number;
  readonly bip66: number;
  readonly bip65: number;
}

export const REGTEST: ChainParams = {
  name: "regtest",
  genesis: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
  powLimit: BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
  noRetarget: true,
  bip34: 1, bip66: 1, bip65: 1,
};
export const MAINNET: ChainParams = {
  name: "mainnet",
  genesis: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
  powLimit: BigInt("0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
  noRetarget: false,
  bip34: 227931, bip66: 363725, bip65: 388381,
};
export const paramsFor = (name: string): ChainParams => {
  if (name === "regtest") return REGTEST;
  if (name === "mainnet") return MAINNET;
  throw new Error(`no chain params for ${name}`);
};

const INTERVAL = 2016, TIMESPAN = 14 * 24 * 60 * 60;
/** Bitcoin Core's MAX_FUTURE_BLOCK_TIME. */
export const MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60;

export const sha256d = (b: Uint8Array): Buffer => createHash("sha256").update(createHash("sha256").update(b).digest()).digest();
/** Internal byte order <-> the reversed hex that RPC and explorers show. */
export const toDisplay = (b: Uint8Array): string => Buffer.from(b).reverse().toString("hex");
export const fromDisplay = (h: string): Buffer => Buffer.from(h, "hex").reverse();

export interface Header {
  readonly raw: Buffer;
  readonly version: number;     // signed, as Core reads nVersion
  readonly prev: string;        // display hex
  readonly merkleRoot: Buffer;  // internal order
  readonly time: number;
  readonly bits: number;
  readonly nonce: number;
  readonly hash: string;        // display hex
}

export function parseHeader(raw: Uint8Array): Header {
  const b = Buffer.from(raw);
  if (b.length !== 80) throw new Error(`a header is 80 bytes, not ${b.length}`);
  return {
    raw: b, version: b.readInt32LE(0), prev: toDisplay(b.subarray(4, 36)), merkleRoot: Buffer.from(b.subarray(36, 68)),
    time: b.readUInt32LE(68), bits: b.readUInt32LE(72), nonce: b.readUInt32LE(76), hash: toDisplay(sha256d(b)),
  };
}

/** Core's arith_uint256::SetCompact: the target, or null if negative, zero or overflowing. */
export function compactToTarget(bits: number): bigint | null {
  const size = bits >>> 24;
  let word = BigInt(bits & 0x007fffff);
  if (size <= 3) word >>= BigInt(8 * (3 - size));
  else word <<= BigInt(8 * (size - 3));
  const negative = word !== 0n && (bits & 0x00800000) !== 0;
  const overflow = word !== 0n && (size > 34 || (word > 0xffn && size > 33) || (word > 0xffffn && size > 32));
  return negative || overflow || word === 0n ? null : word;
}

/** Core's GetCompact. */
export function targetToCompact(target: bigint): number {
  let size = target === 0n ? 0 : Math.ceil(target.toString(16).length / 2);
  let compact = size <= 3 ? Number(target << BigInt(8 * (3 - size))) : Number(target >> BigInt(8 * (size - 3)));
  if (compact & 0x00800000) { compact >>>= 8; size++; }
  return (compact | (size << 24)) >>> 0;
}

/** Expected hashes to find a block at this target: 2^256 / (target + 1). */
export const workOf = (target: bigint): bigint => (1n << 256n) / (target + 1n);

export class HeaderError extends Error {
  readonly height: number;
  constructor(height: number, why: string) { super(`header ${height}: ${why}`); this.height = height; }
}

/** What a payment receipt needs from the chain: its height, and the block hash at a height. */
export interface HeaderSource {
  readonly height: number;
  hashAt(height: number): string | undefined;
}

/**
 * A header chain from genesis, every header checked. ingest() takes a run of consecutive raw headers
 * from any height up to one past the tip: headers it already holds are skipped, new ones extend the
 * tip, and a run that forks below the tip replaces the chain only if it ends with more work.
 */
export class HeaderChain implements HeaderSource {
  readonly params: ChainParams;
  private readonly hs: Header[] = [];
  private readonly cum: bigint[] = [];
  constructor(params: ChainParams) { this.params = params; }

  get height(): number { return this.hs.length - 1; }
  get tip(): string | undefined { return this.hs[this.hs.length - 1]?.hash; }
  get totalWork(): bigint { return this.cum[this.cum.length - 1] ?? 0n; }
  hashAt(h: number): string | undefined { return this.hs[h]?.hash; }
  headerAt(h: number): Header | undefined { return this.hs[h]; }
  workAt(h: number): bigint | undefined { return this.cum[h]; }

  /** Validate `hdr` as block `h` on top of `chain` (heights 0..h-1). Returns its work. */
  private check(chain: Header[], h: number, hdr: Header, now?: number): bigint {
    const p = this.params;
    if (h === 0) {
      if (hdr.hash !== p.genesis) throw new HeaderError(0, `not the ${p.name} genesis block`);
      return workOf(compactToTarget(hdr.bits)!);
    }
    const prev = chain[h - 1];
    if (hdr.prev !== prev.hash) throw new HeaderError(h, "does not link to the previous header");
    const min = h >= p.bip65 ? 4 : h >= p.bip66 ? 3 : h >= p.bip34 ? 2 : -Infinity;
    if (hdr.version < min) throw new HeaderError(h, `bad-version ${hdr.version}`);
    const times = chain.slice(Math.max(0, h - 11), h).map((x) => x.time).sort((a, b) => a - b);
    const mtp = times[Math.floor(times.length / 2)];
    if (hdr.time <= mtp) throw new HeaderError(h, `time ${hdr.time} is not above the median ${mtp}`);
    if (now !== undefined && hdr.time > now + MAX_FUTURE_BLOCK_TIME) throw new HeaderError(h, "time too far in the future");
    const want = this.requiredBits(chain, h);
    if (hdr.bits !== want) throw new HeaderError(h, `bits ${hdr.bits.toString(16)} are not the required ${want.toString(16)}`);
    const target = compactToTarget(want);
    if (target === null || target > p.powLimit) throw new HeaderError(h, "target out of range");
    if (BigInt("0x" + hdr.hash) > target) throw new HeaderError(h, "hash above target");
    return workOf(target);
  }

  /** Core's GetNextWorkRequired, without testnet's minimum-difficulty exception. */
  private requiredBits(chain: Header[], h: number): number {
    const last = chain[h - 1];
    if (this.params.noRetarget || h % INTERVAL !== 0) return last.bits;
    const first = chain[h - INTERVAL];
    let span = last.time - first.time;
    span = Math.min(Math.max(span, TIMESPAN / 4), TIMESPAN * 4);
    let t = (compactToTarget(last.bits)! * BigInt(span)) / BigInt(TIMESPAN);
    if (t > this.params.powLimit) t = this.params.powLimit;
    return targetToCompact(t);
  }

  /** Returns how many headers were new, and the height a reorg went back to, if any. */
  ingest(from: number, raw: Uint8Array, now?: number): { added: number; reorgFrom?: number } {
    if (raw.length % 80 !== 0) throw new Error(`${raw.length} bytes is not a whole number of headers`);
    if (from < 0 || from > this.hs.length) throw new Error(`a run starting at ${from} does not touch a chain of height ${this.height}`);
    const run: Header[] = [];
    for (let o = 0; o < raw.length; o += 80) run.push(parseHeader(raw.subarray(o, o + 80)));
    let k = 0;
    while (k < run.length && from + k <= this.height && run[k].hash === this.hs[from + k].hash) k++;
    if (k === run.length) return { added: 0 };
    const fork = from + k;
    const chain = this.hs.slice(0, fork);
    let work = this.cum[fork - 1] ?? 0n;
    const cum: bigint[] = [];
    for (let i = k; i < run.length; i++) {
      work += this.check(chain, chain.length, run[i], now);
      chain.push(run[i]);
      cum.push(work);
    }
    const reorg = fork <= this.height;
    if (reorg && work <= this.totalWork) return { added: 0 };
    this.hs.splice(fork, this.hs.length - fork, ...run.slice(k));
    this.cum.splice(fork, this.cum.length - fork, ...cum);
    return { added: run.length - k, ...(reorg ? { reorgFrom: fork } : {}) };
  }
}

// ── an untrusted header mirror over HTTP ──

type Rpc = (method: string, params?: unknown[]) => Promise<any>;

/** GET <path>?from=N[&max=M]: raw 80-byte headers N..min(tip, N+M-1), concatenated. */
export function serveHeaders(rpc: Rpc, maxPerRequest = 2000) {
  const cache = new Map<number, { hash: string; raw: Buffer }>();
  return async (req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> => {
    try {
      const from = Number(url.searchParams.get("from") ?? "0");
      const max = Math.min(Number(url.searchParams.get("max") ?? maxPerRequest), maxPerRequest);
      if (!Number.isSafeInteger(from) || from < 0 || !(max > 0)) { res.writeHead(400).end(); return; }
      const tip: number = await rpc("getblockcount");
      const out: Buffer[] = [];
      for (let h = from; h <= tip && out.length < max; h++) {
        const hash: string = await rpc("getblockhash", [h]);
        let c = cache.get(h);
        if (!c || c.hash !== hash) { c = { hash, raw: Buffer.from(await rpc("getblockheader", [hash, false]), "hex") }; cache.set(h, c); }
        out.push(c.raw);
      }
      res.writeHead(200, { "Content-Type": "application/octet-stream", "X-From": String(from) }).end(Buffer.concat(out));
    } catch (e) { res.writeHead(503, { "X-Reason": (e as Error).message.slice(0, 200) }).end(); }
  };
}

/** One poll of a mirror: ask from a few blocks below the tip, so a short reorg is seen. */
export async function syncFrom(chain: HeaderChain, url: string, overlap = 6): Promise<{ added: number; reorgFrom?: number }> {
  let total = 0, reorgFrom: number | undefined;
  for (;;) {
    const from = Math.max(0, chain.height + 1 - overlap);
    const r = await fetch(`${url}?from=${from}`);
    if (r.status !== 200) throw new Error(`header mirror: ${r.status}`);
    const raw = Buffer.from(await r.arrayBuffer());
    if (raw.length === 0) break;
    const got = chain.ingest(from, raw, Math.floor(Date.now() / 1000));
    total += got.added;
    if (got.reorgFrom !== undefined) reorgFrom = Math.min(reorgFrom ?? Infinity, got.reorgFrom);
    if (got.added === 0 || raw.length / 80 < 2000) break;
  }
  return { added: total, ...(reorgFrom !== undefined ? { reorgFrom } : {}) };
}
