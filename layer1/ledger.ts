// Phase 7C: a write-ahead payment ledger. Payment authorization must survive a crash, so each party
// appends a record and fsyncs it *before* acting on it:
// - the provider before it releases a preimage;
// - the client before it hands over a signature.
// After a restart, replaying the ledger restores exactly what the party had committed to.
//
// Format: one JSON object per line. A torn final line (a crash mid-append) was never acted on: replay
// ignores it, and the first append after it truncates it, so the next record starts on a clean line.
// Damage anywhere else is an error, never silently skipped.

import { closeSync, existsSync, fsyncSync, ftruncateSync, openSync, readFileSync, writeSync } from "node:fs";

export type LedgerRecord = { t: string } & Record<string, unknown>;

/** Write every byte of `buf` at `fd`, looping over short writes. */
export function writeAll(fd: number, buf: Buffer): void {
  for (let off = 0; off < buf.length;) {
    const n = writeSync(fd, buf, off, buf.length - off);
    if (n <= 0) throw new Error("write made no progress");
    off += n;
  }
}

export class Ledger {
  readonly path: string;
  constructor(path: string) { this.path = path; }

  /** Append one record and fsync it. Returns only once the whole record is on disk. */
  append(rec: LedgerRecord): void {
    this.dropTornTail();
    const fd = openSync(this.path, "a");
    try {
      writeAll(fd, Buffer.from(JSON.stringify(rec) + "\n", "utf8"));
      fsyncSync(fd);
    } finally { closeSync(fd); }
  }

  /** Every complete record, in order. */
  replay(): LedgerRecord[] {
    if (!existsSync(this.path)) return [];
    const lines = readFileSync(this.path, "utf8").split("\n");
    const complete = lines.slice(0, -1); // the last piece is "" after a final newline, or a torn line
    return complete.map((line, i) => {
      let rec: unknown;
      try { rec = JSON.parse(line); } catch { throw new Error(`${this.path}: line ${i + 1} is not JSON; the ledger is damaged`); }
      if (!rec || typeof (rec as LedgerRecord).t !== "string") throw new Error(`${this.path}: line ${i + 1} has no record type`);
      return rec as LedgerRecord;
    });
  }

  /** Cut a torn final line, so an append never lands on the end of one. */
  private dropTornTail(): void {
    if (!existsSync(this.path)) return;
    const buf = readFileSync(this.path);
    if (buf.length === 0 || buf[buf.length - 1] === 0x0a) return;
    const keep = buf.lastIndexOf(0x0a) + 1;
    const fd = openSync(this.path, "r+");
    try { ftruncateSync(fd, keep); fsyncSync(fd); } finally { closeSync(fd); }
  }
}

/** Write a small file durably: write it whole, fsync it, then close. */
export function writeFileDurable(path: string, text: string): void {
  const fd = openSync(path, "w");
  try { writeAll(fd, Buffer.from(text, "utf8")); fsyncSync(fd); } finally { closeSync(fd); }
}
