import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { sha256 } from "./schnorr.ts";
import { blake2s } from "./blake2s.ts";
import { buildTree, CHUNK, merkleVerify, merkleProof } from "./storage_bonds.ts";
import {
  challengeIndices, dealsDigest, statementOutput, syntheticDeal, verifyNatively, witnessFelts, type Backend,
} from "./zk_pdp.ts";

const seed = sha256("test seed");
const BACKENDS: Backend[] = ["sha", "blake"];

test("blake2s matches node's blake2s256 and RFC 7693", () => {
  for (const len of [0, 1, 3, 63, 64, 65, 128, 4096, 5000]) {
    const d = Buffer.alloc(len, 0xa5);
    assert.ok(blake2s(d).equals(createHash("blake2s256").update(d).digest()), `length ${len}`);
  }
  assert.equal(blake2s(Buffer.from("abc")).toString("hex"),
    "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
  assert.notDeepEqual(blake2s(Buffer.from("abc"), Buffer.from("bsb-leaf")), blake2s(Buffer.from("abc")));
});

test("sha synthetic deals are exactly the storage_bonds chunk tree", () => {
  const d = syntheticDeal("sha", "x", 5);
  const chunks = Array.from({ length: 5 }, (_, i) => d.chunk(i)!);
  assert.ok(buildTree(chunks).root.equals(d.tree.root));
  assert.ok(merkleVerify(d.tree.root, 5, 4, chunks[4], merkleProof(d.tree, 4)));
});

for (const b of BACKENDS) {
  test(`${b}: indices depend on seed and deal, stay in range`, () => {
    const x = syntheticDeal(b, "a", 300), y = syntheticDeal(b, "b", 300);
    const ix = challengeIndices(b, seed, { root: x.tree.root, n: 300 }, 16);
    assert.deepEqual(ix, challengeIndices(b, seed, { root: x.tree.root, n: 300 }, 16));
    assert.notDeepEqual(ix, challengeIndices(b, seed, { root: y.tree.root, n: 300 }, 16));
    assert.notDeepEqual(ix, challengeIndices(b, sha256("other"), { root: x.tree.root, n: 300 }, 16));
    assert.ok(ix.every((i) => i >= 0 && i < 300));
  });

  test(`${b}: witness layout matches the Cairo Serde of Args`, () => {
    const d = syntheticDeal(b, "w", 7);   // depth 3
    const f = witnessFelts(b, seed, 2, [d]);
    // seed 8, q, deal count; root 8, n, openings len; per opening: len + 1024 words + last + path len + 3*8
    assert.equal(f.length, 8 + 2 + 8 + 2 + 2 * (1 + 1024 + 1 + 1 + 24));
    assert.equal(f[8], "0x2");
    assert.equal(f[9], "0x1");
    assert.equal(f[20], "0x400");
    if (b === "sha") assert.ok(BigInt(f[21]) < 0x1000000n, "leaf preimage starts with 0x00");
    else assert.equal(f[21 + 1024], "0x0");
  });

  test(`${b}: statement output and deal digest`, () => {
    const d = syntheticDeal(b, "s", 3);
    const out = statementOutput(b, seed, 4, [{ root: d.tree.root, n: 3 }]);
    assert.equal(out.length, 18);
    assert.equal(out[8], "0x4");
    assert.equal(out[9], "0x1");
    assert.notDeepEqual(dealsDigest(b, [{ root: d.tree.root, n: 3 }]), dealsDigest(b, [{ root: d.tree.root, n: 4 }]));
  });

  test(`${b}: a provider missing a challenged chunk has no honest witness`, () => {
    const d = syntheticDeal(b, "m", 64);
    const lost = challengeIndices(b, seed, { root: d.tree.root, n: 64 }, 4)[2];
    const holder = { tree: d.tree, chunk: (i: number) => (i === lost ? undefined : d.chunk(i)) };
    assert.throws(() => witnessFelts(b, seed, 4, [holder]), /not held/);
    assert.equal(verifyNatively(b, seed, 4, [holder]), false);
    assert.equal(verifyNatively(b, seed, 4, [d]), true);
    assert.equal(witnessFelts(b, seed, 4, [holder], () => Buffer.alloc(CHUNK)).length,
      witnessFelts(b, seed, 4, [d]).length);
  });
}
