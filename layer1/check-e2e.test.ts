// Phase 7C: the CI outcome checker must fail runs where the property it asserts is false (independent
// review, 2026-10-23). Each case tampers with a recorded run and runs the real checker on it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const check = (r: unknown, kind: string): { ok: boolean; out: string } => {
  const f = join(mkdtempSync(join(tmpdir(), "bsb-check-")), "r.json");
  writeFileSync(f, JSON.stringify(r));
  try { return { ok: true, out: execFileSync(process.execPath, [join(root, "scripts", "check-e2e.mjs"), f, kind], { encoding: "utf8" }) }; }
  catch (e: any) { return { ok: false, out: String(e.stdout) }; }
};
const load = (name: string) => JSON.parse(readFileSync(join(root, "results", name), "utf8"));

test("CK01: the recorded runs pass", () => {
  assert.equal(check(load("full-stack.json"), "full-stack").ok, true);
  assert.equal(check(load("full-stack-onchain.json"), "full-stack").ok, true);
  assert.equal(check(load("market-7c-crash-probe.json"), "market").ok, true);
});

test("CK02: one unpaid honest epoch fails the check, though the total stays positive", () => {
  const r = load("full-stack.json");
  r.summary[0].epochs[1].paidSats = 0;
  const c = check(r, "full-stack");
  assert.equal(c.ok, false);
  assert.match(c.out, /honest epoch 2/);
});

test("CK03: a deleter refunded after recorded failures fails the check, however likely an escape", () => {
  const r = load("full-stack.json");
  r.summary.find((s: any) => s.role === "deletes 10%").bond.to = "provider";
  const c = check(r, "full-stack");
  assert.equal(c.ok, false);
  assert.match(c.out, /failed epoch\(s\) on record/);
});

test("CK04: a withholder that drew several sentinel challenges fails the check", () => {
  const r = load("market-7c-crash-probe.json");
  const w = r.summary.find((s: any) => s.role === "withholds");
  w.enforcement = [{}, {}, {}, {}];
  assert.equal(check(r, "market").ok, false);
});
