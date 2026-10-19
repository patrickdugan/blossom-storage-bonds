import { test } from "node:test";
import assert from "node:assert/strict";
import { keyFrom, schnorrSign, schnorrVerify } from "./schnorr.ts";

test("BIP340 test vector 0", () => {
  const k = keyFrom(3n);
  assert.equal(k.x, "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");
  const sig = schnorrSign(Buffer.alloc(32), k.d, Buffer.alloc(32));
  assert.equal(sig.toString("hex").toUpperCase(),
    "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0");
  assert.ok(schnorrVerify(Buffer.alloc(32), Buffer.from(k.x, "hex"), sig));
  assert.ok(!schnorrVerify(Buffer.alloc(32, 1), Buffer.from(k.x, "hex"), sig));
});
