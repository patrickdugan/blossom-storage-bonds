#!/usr/bin/env python3
"""Adversarial checks against a real snapshot made by capture-snapshot.ts.

python3 fresh_snapshot_test.py <snapshot-dir>
Mutations update the manifest's file hash: rejection must come from the actual
header, statement or Merkle check, rather than a checksum of an old fixture.
"""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from fresh_snapshot import check_snapshot, finish, sha

SNAPSHOT = Path(sys.argv.pop(1)).resolve()


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bsb-proof-input-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "snapshot"
        shutil.copytree(SNAPSHOT, self.root)
        self.manifest = json.loads((self.root / "snapshot.json").read_text())

    def save(self, name, data):
        (self.root / name).write_bytes(data)
        self.manifest["sha256"][name] = sha(data).hex()
        self.flush()

    def flush(self):
        (self.root / "snapshot.json").write_text(json.dumps(self.manifest))

    def test_real_node_snapshot_and_generated_openings_pass(self):
        manifest, heights, journals = check_snapshot(self.root)
        self.assertEqual(heights, [170, 180, 190])
        self.assertEqual(manifest["chain"]["tip_height"], len((self.root / "chain/headers.bin").read_bytes()) // 80 - 1)
        self.assertEqual(len(set(journals)), 3)

    def test_changed_header_with_updated_file_hash_fails_parent_or_pow(self):
        raw = bytearray((self.root / "chain/headers.bin").read_bytes())
        raw[80 * 180 + 4] ^= 1
        self.save("chain/headers.bin", raw)
        with self.assertRaisesRegex(ValueError, "header 180: parent"):
            check_snapshot(self.root)

    def test_changed_chunk_with_updated_file_hash_fails_merkle_root(self):
        name = "hold-180/witness.bin"
        raw = bytearray((self.root / name).read_bytes())
        # Seed + q + count + three (root,n) entries + first opening's deal index.
        raw[32 + 4 + 4 + 3 * 36 + 4] ^= 1
        self.save(name, raw)
        with self.assertRaisesRegex(ValueError, "root mismatch"):
            check_snapshot(self.root)

    def test_relabelled_epoch_cannot_use_the_previous_seed(self):
        name = "hold-180/statement.json"
        statement = json.loads((self.root / name).read_text())
        statement["seed"] = json.loads((self.root / "hold-170/statement.json").read_text())["seed"]
        self.save(name, json.dumps(statement).encode())
        with self.assertRaisesRegex(ValueError, "epoch seed"):
            check_snapshot(self.root)

    def test_altered_term_q_cannot_reuse_witnesses(self):
        self.manifest["term"]["q"] = 17
        self.flush()
        with self.assertRaisesRegex(ValueError, "epoch seed or q"):
            check_snapshot(self.root)

    def test_trailing_witness_data_is_rejected(self):
        name = "hold-170/witness.bin"
        self.save(name, (self.root / name).read_bytes() + b"extra")
        with self.assertRaisesRegex(ValueError, "trailing holdings"):
            check_snapshot(self.root)

    def test_manifest_cannot_escape_snapshot_directory(self):
        first = next(iter(self.manifest["sha256"]))
        self.manifest["sha256"]["../outside"] = self.manifest["sha256"].pop(first)
        self.flush()
        with self.assertRaisesRegex(ValueError, "snapshot file list"):
            check_snapshot(self.root)

    def test_setup_image_cannot_be_relabelled(self):
        self.manifest["image_ids"]["term"] = "00" * 32
        self.flush()
        with self.assertRaisesRegex(ValueError, "pinned guests"):
            check_snapshot(self.root)

    def test_verifying_key_cannot_be_replaced_even_with_a_new_checksum(self):
        self.save("vk.json", b'{"nPublic": 1}')
        with self.assertRaisesRegex(ValueError, "verifying key differs"):
            check_snapshot(self.root)

    def test_previous_phase6_results_cannot_be_collected_as_this_fresh_proof(self):
        previous = json.loads((Path(__file__).resolve().parents[2] / "results/bitvm2-spike.json").read_text())
        output = Path(self.temp.name) / "old-output"
        output.mkdir()
        (output / "ids.json").write_text(json.dumps(previous["image_ids"]))
        (output / "chain.json").write_text(json.dumps(previous["m2"]["header_chain"]))
        with self.assertRaisesRegex(ValueError, "proven chain differs from snapshot"):
            finish(self.root, output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
