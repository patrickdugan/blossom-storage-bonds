// Phase 7C: a write-ahead payment ledger. Payment authorization must survive a crash, so each party
// appends a record and fsyncs it *before* acting on it:
// - the provider before it releases a preimage;
// - the client before it hands over a signature.
// After a restart, replaying the ledger restores exactly what the party had committed to.
//
// Format: one JSON object per line. A torn final line (a crash mid-append) is ignored, because its
// record was never acted on. Damage anywhere else is an error, never silently skipped.

import { closeSync, existsSync, fsyncSync, openSync, readFileSync, writeSync } from "node:fs";

export type LedgerRecord = { t: string } & Record<string, unknown>;

export class Ledger {
  readonly path: string;
  constructor(path: string) { this.path = path; }

  /** Append one record and fsync it. Returns only once the record is on disk. */
  append(rec: LedgerRecord): void {
    const fd = openSync(this.path, "a");
    try {
      writeSync(fd, JSON.stringify(rec) + "\n");
      fsyncSync(fd);
    } finally { closeSync(fd); }
  }

  /** Every complete record, in order. */
  replay(): LedgerRecord[] {
    if (!existsSync(this.path)) return [];
    const text = readFileSync(this.path, "utf8");
    const lines = text.split("\n");
    const complete = lines.slice(0, -1); // the last piece is "" after a final newline, or a torn line
    const out: LedgerRecord[] = [];
    complete.forEach((line, i) => {
      let rec: unknown;
      try { rec = JSON.parse(line); } catch { throw new Error(`${this.path}: line ${i + 1} is not JSON; the ledger is damaged`); }
      if (!rec || typeof (rec as LedgerRecord).t !== "string") throw new Error(`${this.path}: line ${i + 1} has no record type`);
      out.push(rec as LedgerRecord);
    });
    return out;
  }
}
