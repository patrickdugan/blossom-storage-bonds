#!/usr/bin/env python3
"""Validate a regtest storage-proof snapshot, or collect actual prover outputs.

This is an input/output check, not a RISC Zero or Groth16 proof verifier. It uses
only Python's standard library so the proving job does not need Node installed.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

IDS = {
    "hold": "2ed618aa3231ba01749ec59d9172e4381eab81dbf900d0567160626372b116db",
    "term": "b484d0334620b87f4f2327e553784841fe3265cf2ec2126911d893def81a597a",
    "header_chain": "5cb173ee191a3edca1f448066bf16eb1071c828d55141889a3365a93ff22917d",
}
PROVER_IMAGE = "ozancw/risc0-to-bitvm2-groth16-prover@sha256:840b833190a86c87eb71473cd72bcaa3e3b90cefa9bf4ae785ab2de61bc9d262"
GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
VK_SHA256 = "2941dff0bd962ff8610773c9659c10d0dec561db1e2f6afecfbbe0d9cb457a7d"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).digest()


def json_file(path):
    text = Path(path).read_text(encoding="utf-8").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # bsb-r0 can print guest diagnostics before its final JSON result.
        return json.loads(text.splitlines()[-1])


def u32(value, name, positive=False):
    require(type(value) is int and (1 if positive else 0) <= value <= 0xffffffff,
            f"{name}: expected {'positive ' if positive else ''}u32")
    return value


def digest(value):
    require(isinstance(value, str) and len(value) == 64, "expected 32-byte hex digest")
    result = bytes.fromhex(value)
    require(len(result) == 32, "expected 32-byte hex digest")
    return result


class Reader:
    def __init__(self, raw):
        self.raw, self.pos = raw, 0

    def take(self, n):
        require(0 <= n <= len(self.raw) - self.pos, "truncated holdings witness")
        value = self.raw[self.pos:self.pos+n]
        self.pos += n
        return value

    def word(self):
        return int.from_bytes(self.take(4), "little")


def check_hold(raw, statement, seed, q):
    """Independently replay the SHA holdings statement and every Merkle opening."""
    require(statement["hash"] == "sha" and statement["mode"] == 1, "holdings mode/hash")
    require(statement["q"] == q and digest(statement["seed"]) == seed, "epoch seed or q")
    refs = [(digest(d["root"]), u32(d["n"], "chunks", True)) for d in statement["deals"]]
    require(0 < len(refs) <= 1024, "deal count")
    total = sum(n for _, n in refs)
    require(total < 2**32, "too many chunks")
    dset = sha(b"bsb/zk-pdp/dset|" + b"".join(root + n.to_bytes(8, "big") for root, n in refs))
    journal = seed + struct.pack(">III", q, 1, len(refs)) + dset
    require(statement["journal"] == journal.hex(), "statement journal")
    r = Reader(raw)
    require(r.take(32) == seed and r.word() == q and r.word() == len(refs), "witness statement")
    for root, n in refs:
        require(r.take(32) == root and r.word() == n, "witness deal differs from statement")
    nonce = sha(b"bsb/zk-pdp/hold|" + seed + dset)
    for j in range(q):
        g = int.from_bytes(sha(b"bsb/zk-pdp/chal|" + nonce + j.to_bytes(4, "little"))[:8], "little") % total
        k = 0
        while g >= refs[k][1]:
            g -= refs[k][1]
            k += 1
        require(r.word() == k, f"challenge {j}: wrong deal")
        h = sha(b"\x00" + r.take(4096))
        depth = (refs[k][1] - 1).bit_length()
        require(r.word() == depth, f"challenge {j}: path length")
        for level in range(depth):
            sibling = r.take(32)
            h = sha(b"\x01" + (sibling + h if (g >> level) & 1 else h + sibling))
        require(sha(b"\x02" + refs[k][1].to_bytes(8, "little") + h) == refs[k][0],
                f"challenge {j}: root mismatch (missing or altered data)")
    require(r.pos == len(raw), "trailing holdings witness bytes")
    return refs, dset, journal


def check_snapshot(directory):
    directory = Path(directory).resolve()
    manifest = json_file(directory / "snapshot.json")
    require(manifest["format"] == "bsb/fresh-proof-snapshot/v1", "snapshot format")
    require(manifest["network"] == "regtest", "only regtest snapshots are supported")
    require(manifest["image_ids"] == IDS, "snapshot image IDs differ from the pinned guests")
    term = manifest["term"]
    first = u32(term["first"], "first")
    step = u32(term["step"], "step", True)
    epochs = u32(term["epochs"], "epochs", True)
    depth = u32(term["depth"], "depth", True)
    q = u32(term["q"], "q", True)
    require(epochs <= 100 and q <= 64, "snapshot exceeds this job's epoch/challenge budget")
    heights = [first + i * step for i in range(epochs)]
    require(heights[-1] + depth <= manifest["chain"]["tip_height"], "final seed is too shallow")
    expected_files = {"chain/headers.bin", "chain/hashes.json", "vk.json"}
    for height in heights:
        expected_files.update((f"hold-{height}/witness.bin", f"hold-{height}/statement.json"))
    require(set(manifest["sha256"]) == expected_files, "snapshot file list differs from the scheduled inputs")
    require(manifest["sha256"]["vk.json"] == VK_SHA256, "verifying key differs from the pinned phase-6 key")
    for name, expected in manifest["sha256"].items():
        # No arbitrary manifest paths or symlink escapes, even when the manifest is untrusted.
        path = (directory / name).resolve()
        require(path.is_relative_to(directory), "snapshot file escapes its directory")
        require(sha(path.read_bytes()).hex() == expected, f"snapshot file hash: {name}")
    raw = (directory / "chain/headers.bin").read_bytes()
    require(len(raw) >= 80 and len(raw) % 80 == 0, "80-byte header encoding")
    count = len(raw) // 80
    require(count <= 100_000, "header count exceeds this snapshot job's limit")
    hashes, times, prev = [], [], bytes(32)
    target = 0x7fffff << (8 * (0x20 - 3))
    for height in range(count):
        header = raw[height*80:(height+1)*80]
        h = sha(sha(header))
        require(header[4:36] == prev, f"header {height}: parent")
        require(header[72:76] == bytes.fromhex("ffff7f20"), f"header {height}: regtest difficulty")
        require(int.from_bytes(h, "little") <= target, f"header {height}: proof of work")
        timestamp = int.from_bytes(header[68:72], "little")
        if height:
            require(int.from_bytes(header[:4], "little", signed=True) >= 4, f"header {height}: version")
            prior = sorted(times[-11:])
            require(timestamp > prior[len(prior)//2], f"header {height}: median time")
        hashes.append(h[::-1].hex())
        times.append(timestamp)
        prev = h
    require(hashes[0] == GENESIS, "snapshot is not rooted at regtest genesis")
    chain = manifest["chain"]
    require(chain == {"tip_height": count-1, "tip_hash": hashes[-1], "total_work": str(2*count)}, "snapshot chain claim")
    require(json_file(directory / "chain/hashes.json") == {"chain": "regtest", "hashes": hashes}, "header/hash snapshot mismatch")
    refs, dset = None, None
    journals = []
    for height in heights:
        require(height < count, "epoch outside snapshot")
        current_refs, current_dset, journal = check_hold(
            (directory / f"hold-{height}/witness.bin").read_bytes(),
            json_file(directory / f"hold-{height}/statement.json"), bytes.fromhex(hashes[height]), q)
        if refs is not None:
            require(current_refs == refs, "deal list changed between epochs")
        refs, dset = current_refs, current_dset
        journals.append(journal.hex())
    require(term["deal_count"] == len(refs) and term["deals_digest"] == dset.hex(), "term deal commitment")
    prefix = (b"bsb/r0-term|v1" + digest(IDS["hold"]) + digest(IDS["header_chain"])
              + struct.pack(">II", q, len(refs)) + dset + struct.pack(">IIII", first, step, epochs, depth))
    preimage = prefix + struct.pack(">I", count-1) + prev + (2*count).to_bytes(32, "big")
    require(len(preimage) == 202 and manifest["expected_preimage"] == preimage.hex(), "term preimage")
    require(manifest["expected_journal"] == sha(preimage).hex(), "term journal")
    return manifest, heights, journals


def finish(directory, output):
    manifest, heights, journals = check_snapshot(directory)
    output = Path(output)
    ids = json_file(output / "ids.json")
    require({k: ids[k] for k in IDS} == IDS, "prover guest image IDs differ from setup")
    chain = json_file(output / "chain.json")
    require(chain["tip_height"] == manifest["chain"]["tip_height"] and
            chain["tip_hash"] == manifest["chain"]["tip_hash"] and
            int(chain["total_work"], 16) == int(manifest["chain"]["total_work"]), "proven chain differs from snapshot")
    holds = []
    for height, expected in zip(heights, journals):
        hold = json_file(output / f"hold-{height}.json")
        require(hold["journal"] == expected and hold["image_id"] == IDS["hold"] and hold["kind"] == "succinct", "proven holdings statement")
        require((output / f"hold-{height}.bin").stat().st_size > 0, "missing holdings receipt")
        holds.append({"height": height, **hold})
    term = json_file(output / "term.json")
    require(term["preimage"] == manifest["expected_preimage"] and term["journal"] == manifest["expected_journal"], "proven term differs from snapshot")
    require(term["image_id"] == IDS["term"] and term["hold_id"] == IDS["hold"] and term["header_chain_id"] == IDS["header_chain"], "proven term images")
    require(all(term[k] == manifest["term"][k] for k in ("first", "step", "epochs", "depth")), "proven term schedule")
    g16 = json_file(output / "g16/groth16.json")
    require(g16["image"] == PROVER_IMAGE and g16["pre_state"] == IDS["term"], "Groth16 wrapper image")
    require(g16["journal"] == term["journal"] and g16["output_matches"] is True and g16["public_output_hex"] == g16["expected_output_hex"], "Groth16 journal binding")
    public = json_file(output / "g16/public.json")
    require(public == [g16["public_output_dec"]] and int(public[0]) == int(g16["public_output_hex"], 16), "Groth16 public output")
    require(public[0] == str(int(public[0])) and 0 <= int(public[0]) < 2**248, "canonical Groth16 public output")
    require(json_file(output / "g16/proof.json") == g16["proof"], "Groth16 proof output")
    for name in ["chain.bin", "term.bin"]:
        require((output / name).stat().st_size > 0, f"missing receipt {name}")
    # Same schema as the existing graph builder; no old proof or old journal is substituted.
    fixture = {
        "note": "Fresh snapshot proof; verify the Groth16 proof independently before graph use. Graph lifecycle and heavier-chain enforcement require separate transaction evidence.",
        "snapshot": manifest,
        "m2": {"header_chain": chain, "holds": holds, "term": term},
        "m3": {"groth16": g16},
    }
    path = output / "fixture.json"
    with path.open("x", encoding="utf-8") as f:
        json.dump(fixture, f, indent=2)
        f.write("\n")
    return str(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "finish"))
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("output", type=Path, nargs="?")
    args = parser.parse_args()
    if args.mode == "check":
        manifest, heights, _ = check_snapshot(args.snapshot)
        print(json.dumps({"snapshot_checked": True, "tip_height": manifest["chain"]["tip_height"], "epoch_heights": heights, "proof_generated": False}))
    else:
        require(args.output is not None, "finish requires the actual prover output directory")
        print(json.dumps({"fixture": finish(args.snapshot, args.output), "proof_verification": "still requires the independent Groth16 verifier"}))


if __name__ == "__main__":
    main()
