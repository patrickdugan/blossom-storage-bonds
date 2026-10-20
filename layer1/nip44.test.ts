// NIP-44 v2 against the official vectors. A few are embedded; the full set runs when
// fixtures/nip44.vectors.json is present (scripts/fetch-nip44-vectors.sh downloads it and checks its hash).

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { conversationKey, decrypt, encrypt, messageKeys, paddedLen } from "./nip44.ts";
import { keyFrom } from "../model/schnorr.ts";

const VECTORS = new URL("../fixtures/nip44.vectors.json", import.meta.url);
const PINNED = "269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040";
const sec = (h: string) => BigInt("0x" + h);

test("NIP-44 embedded vector: keys 1 and 2, nonce 1, plaintext 'a'", () => {
  const ck = conversationKey(1n, keyFrom(2n).x);
  assert.equal(ck.toString("hex"), "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d");
  assert.ok(conversationKey(2n, keyFrom(1n).x).equals(ck), "symmetric");
  const nonce = Buffer.from("00".repeat(31) + "01", "hex");
  const payload = encrypt("a", ck, nonce);
  assert.equal(payload, "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb");
  assert.equal(decrypt(payload, ck), "a");
});

test("NIP-44 padding table", () => {
  for (const [len, want] of [[16, 32], [32, 32], [33, 64], [37, 64], [45, 64], [49, 64], [64, 64], [65, 96], [100, 128], [111, 128], [200, 224], [250, 256], [320, 320], [383, 384], [384, 384], [400, 448], [500, 512], [512, 512], [515, 640], [700, 768], [800, 896], [900, 1024], [1020, 1024], [65536, 65536]]) {
    assert.equal(paddedLen(len), want, `len ${len}`);
  }
});

test("NIP-44 rejects tampering", () => {
  const ck = conversationKey(1n, keyFrom(2n).x);
  const p = Buffer.from(encrypt("pay the provider", ck), "base64");
  p[40] ^= 1;
  assert.throws(() => decrypt(p.toString("base64"), ck), /MAC/);
  assert.throws(() => encrypt("", ck), /1\.\.65535/);
});

test("NIP-44 full official vector set", { skip: !existsSync(VECTORS) && "fixtures/nip44.vectors.json not fetched" }, () => {
  const raw = readFileSync(VECTORS);
  assert.equal(createHash("sha256").update(raw).digest("hex"), PINNED, "vector file is the pinned version");
  const v2 = JSON.parse(raw.toString("utf8")).v2;
  for (const t of v2.valid.get_conversation_key) assert.equal(conversationKey(sec(t.sec1), t.pub2).toString("hex"), t.conversation_key);
  for (const t of v2.valid.get_message_keys.keys) {
    const k = messageKeys(Buffer.from(v2.valid.get_message_keys.conversation_key, "hex"), Buffer.from(t.nonce, "hex"));
    assert.equal(k.chachaKey.toString("hex"), t.chacha_key);
    assert.equal(k.chachaNonce.toString("hex"), t.chacha_nonce);
    assert.equal(k.hmacKey.toString("hex"), t.hmac_key);
  }
  for (const [len, want] of v2.valid.calc_padded_len) assert.equal(paddedLen(len), want);
  for (const t of v2.valid.encrypt_decrypt) {
    const ck = conversationKey(sec(t.sec1), keyFrom(sec(t.sec2)).x);
    assert.equal(ck.toString("hex"), t.conversation_key);
    assert.equal(encrypt(t.plaintext, ck, Buffer.from(t.nonce, "hex")), t.payload);
    assert.equal(decrypt(t.payload, ck), t.plaintext);
  }
  for (const t of v2.valid.encrypt_decrypt_long_msg) {
    const pt = t.pattern.repeat(t.repeat);
    assert.equal(createHash("sha256").update(pt).digest("hex"), t.plaintext_sha256);
    const payload = encrypt(pt, Buffer.from(t.conversation_key, "hex"), Buffer.from(t.nonce, "hex"));
    assert.equal(createHash("sha256").update(payload).digest("hex"), t.payload_sha256);
  }
  for (const len of v2.invalid.encrypt_msg_lengths) assert.throws(() => encrypt("x".repeat(len), Buffer.alloc(32, 1)));
  for (const t of v2.invalid.get_conversation_key) assert.throws(() => conversationKey(sec(t.sec1), t.pub2), Error, `vector: ${t.note}`);
  for (const t of v2.invalid.decrypt) assert.throws(() => decrypt(t.payload, Buffer.from(t.conversation_key, "hex")), Error, `vector: ${t.note}`);
});
