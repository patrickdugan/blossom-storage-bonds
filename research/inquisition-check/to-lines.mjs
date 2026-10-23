// ADR-018: flatten an ADR-015/016/017 vector file into the line format inq_check.cpp reads.
// Usage: node to-lines.mjs vectors.json core_valid|bip347_valid > lines.txt
import { readFileSync } from 'node:fs';

const [file, field] = process.argv.slice(2);
if (!['core_valid', 'bip347_valid'].includes(field)) throw new Error('field must be core_valid or bip347_valid');
const v = JSON.parse(readFileSync(file, 'utf8'));
for (const c of v.cases) {
  if (typeof c[field] !== 'boolean') throw new Error(`${c.name} has no ${field}`);
  const spent = c.spent_outputs.flatMap((o) => [o.script_pub_key, String(o.value)]);
  console.log([c.name, String(c[field]), String(c.design_ok), c.raw_hex, String(c.input_index), String(c.spent_outputs.length), ...spent].join(' '));
}
