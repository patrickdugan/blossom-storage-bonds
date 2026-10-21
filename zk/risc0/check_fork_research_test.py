#!/usr/bin/env python3
"""Adversarial checks for independent fork-certificate readback; stdlib only."""
import argparse
import json
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from check_fork_research import headers, readback
from fresh_snapshot import json_file, sha

OPTIONS = None


class HeaderChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        report = json_file(Path(__file__).resolve().parents[2]/"results/bitvm-cumulative-work-forks.json")
        cls.raw = bytes.fromhex("".join(report["headers"]["honest"]))

    @staticmethod
    def remine(header, valid=True):
        h = bytearray(header)
        target = 0x7fffff << (8*(0x20-3))
        for nonce in range(1000):
            h[76:80] = nonce.to_bytes(4, "little")
            if (int.from_bytes(sha(sha(h)), "little") <= target) == valid:
                return bytes(h)
        raise AssertionError("regtest nonce search unexpectedly exhausted")

    def test_original_headers(self):
        chain = headers(self.raw)
        self.assertEqual((chain["height"], chain["work"]), (232, 466))

    def test_truncation(self):
        with self.assertRaises(ValueError): headers(self.raw[:-1])

    def test_parent(self):
        h = bytearray(self.raw[-80:]);h[4] ^= 1
        with self.assertRaisesRegex(ValueError, "parent"): headers(self.raw[:-80]+self.remine(h))

    def test_bits(self):
        h = bytearray(self.raw[-80:]);h[72] ^= 1
        with self.assertRaisesRegex(ValueError, "bits"): headers(self.raw[:-80]+h)

    def test_work(self):
        with self.assertRaisesRegex(ValueError, "proof of work"): headers(self.raw[:-80]+self.remine(self.raw[-80:], False))

    def test_median_time(self):
        h = bytearray(self.raw[-80:]);h[68:72] = bytes(4)
        with self.assertRaisesRegex(ValueError, "median time"): headers(self.raw[:-80]+self.remine(h))

    def test_future_time(self):
        h = bytearray(self.raw[-80:]);h[68:72] = (int(time.time())+7300).to_bytes(4, "little")
        with self.assertRaisesRegex(ValueError, "future"): headers(self.raw[:-80]+self.remine(h))

    def test_version(self):
        h = bytearray(self.raw[-80:]);h[:4] = (3).to_bytes(4, "little")
        with self.assertRaisesRegex(ValueError, "version"): headers(self.raw[:-80]+self.remine(h))

    def test_genesis(self):
        h = bytearray(self.raw[:80]);h[36] ^= 1
        with self.assertRaisesRegex(ValueError, "genesis"): headers(self.remine(h))


class CertificateChecks(unittest.TestCase):
    def checked(self, inputs, output, verifier=None):
        return readback(inputs, output, verifier, OPTIONS.compact)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.inputs, self.output = Path(self.temp.name)/"inputs", Path(self.temp.name)/"output"
        shutil.copytree(OPTIONS.inputs, self.inputs)
        shutil.copytree(OPTIONS.output, self.output)

    def replace_output_json(self, name, mutate):
        value = json_file(self.output/name);mutate(value)
        (self.output/name).write_text(json.dumps(value))
        manifest = json_file(self.output/"manifest.json")
        manifest["files"][name] = sha((self.output/name).read_bytes()).hex()
        (self.output/"manifest.json").write_text(json.dumps(manifest))

    def test_real_readback(self):
        result = self.checked(self.inputs, self.output, OPTIONS.receipt_verifier)
        self.assertEqual((result["original_work"], result["response_work"], result["candidate_work"]), (442,466,468))
        self.assertEqual(result["receipt_verified_now"], bool(OPTIONS.receipt_verifier))

    def test_journal_cannot_be_repaired_by_changing_manifest_hash(self):
        self.replace_output_json("fork.json", lambda value: value.update(journal="00"*32))
        with self.assertRaisesRegex(ValueError, "public statement"): self.checked(self.inputs, self.output)

    def test_image_cannot_be_repaired_by_changing_manifest_hash(self):
        self.replace_output_json("ids.json", lambda value: value.update({"fork_compact" if OPTIONS.compact else "fork": "00"*32}))
        with self.assertRaisesRegex(ValueError, "guest IDs"): self.checked(self.inputs, self.output)

    def test_different_graph_identity_is_bound_to_statement(self):
        manifest = json_file(self.inputs/"manifest.json");manifest["graph_id"] = "00"*32
        (self.inputs/"manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "statement bytes"): self.checked(self.inputs, self.output)

    def test_invented_work_metadata(self):
        manifest = json_file(self.inputs/"manifest.json");manifest["response"]["work"] = "1"
        (self.inputs/"manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "manifest response claim"): self.checked(self.inputs, self.output)

    def test_missing_guard_case(self):
        self.replace_output_json("guards.json", lambda value: value["cases"].pop())
        with self.assertRaisesRegex(ValueError, "guard cases"): self.checked(self.inputs, self.output)

    def test_receipt_bytes_require_cryptographic_verification(self):
        receipt = bytearray((self.output/"fork.bin").read_bytes());receipt[-1] ^= 1
        (self.output/"fork.bin").write_bytes(receipt)
        manifest = json_file(self.output/"manifest.json");manifest["files"]["fork.bin"] = sha(receipt).hex()
        (self.output/"manifest.json").write_text(json.dumps(manifest))
        # Honest scope: public readback alone cannot verify the altered seal.
        self.assertFalse(self.checked(self.inputs, self.output)["receipt_verified_now"])
        if OPTIONS.receipt_verifier:
            with self.assertRaises(subprocess.CalledProcessError):
                self.checked(self.inputs, self.output, OPTIONS.receipt_verifier)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--headers-only", action="store_true")
    parser.add_argument("--compact", action="store_true")
    parser.add_argument("--inputs", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--receipt-verifier", type=Path)
    OPTIONS = parser.parse_args()
    if not OPTIONS.headers_only and not (OPTIONS.inputs and OPTIONS.output):
        parser.error("--inputs and --output required")
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(HeaderChecks)
    if not OPTIONS.headers_only: suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(CertificateChecks))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
