#!/usr/bin/env python3
"""Independent statement/header readback for the experimental work certificate.

Without --receipt-verifier this checks public inputs/outputs only. It does not
verify a RISC Zero seal or implement Bitcoin's collateral-dispute protocol.
"""
import argparse
import hashlib
import json
import struct
import subprocess
import time
from pathlib import Path

from fresh_snapshot import GENESIS, IDS, json_file, require, sha

FORK_ID = "8cf297b91e31b0ee52b57c876888f120416950ab3e7169d26c7315751da39457"
COMPACT_ID = "b1766c1d9ebf071acd684ea744d83908181a60d313ccb385661e3fe76ff855b1"


def headers(raw):
    require(raw and len(raw) % 80 == 0 and len(raw) <= 8_000_000, "header file size")
    hashes, timestamps, work = [], [], 0
    target = 0x7fffff << (8 * (0x20 - 3))
    for height in range(len(raw) // 80):
        h = raw[80*height:80*(height+1)]
        digest = sha(sha(h))
        require(h[4:36] == (hashes[-1] if hashes else bytes(32)), "header parent")
        require(h[72:76] == bytes.fromhex("ffff7f20"), "regtest bits")
        require(int.from_bytes(digest, "little") <= target, "header proof of work")
        timestamp = int.from_bytes(h[68:72], "little")
        require(timestamp <= int(time.time()) + 7200, "header from future")
        if height:
            require(int.from_bytes(h[:4], "little", signed=True) >= 4, "header version")
            recent = sorted(timestamps[-11:])
            require(timestamp > recent[len(recent)//2], "median time")
        hashes.append(digest)
        timestamps.append(timestamp)
        work += (1 << 256) // (target + 1)
    require(hashes[0][::-1].hex() == GENESIS, "regtest genesis")
    return {"height": len(hashes)-1, "hash": hashes[-1], "work": work, "hashes": hashes}


def readback(inputs, output, verifier=None, compact=False):
    version = "v2" if compact else "v1"
    image_id = COMPACT_ID if compact else FORK_ID
    inputs, output = Path(inputs).resolve(), Path(output).resolve()
    manifest = json_file(inputs / "manifest.json")
    require(manifest["format"] == "bsb/fork-proof-research-inputs/v1", "input format")
    require(manifest["network"] == "regtest" and manifest["graph_id_is_synthetic"] is True,
            "research graph identity/network")
    expected = {"common.bin", "original.bin", "response.bin", "candidate.bin", "term-preimage.bin"}
    require(set(manifest["files"]) == expected, "input file list")
    for name, digest in manifest["files"].items():
        require(sha((inputs/name).read_bytes()).hex() == digest, f"input file hash: {name}")
    result_manifest = json_file(output / "manifest.json")
    require(result_manifest["format"] == f"bsb/fork-proof-research-output/{version}", "output format")
    required = {f"{name}.{ext}" for name in ("common", "original", "response", "candidate", "fork")
                for ext in ("bin", "json", "time")}
    required.update({"fork.bin.input.bin", "fork.bin.statement.bin", "verify.json", "guards.json", "ids.json"})
    require(required <= set(result_manifest["files"]), "required proof artifacts missing")
    for name, digest in result_manifest["files"].items():
        require(Path(name).name == name and "/" not in name and "\\" not in name, "output path")
        path = (output/name).resolve()
        require(path.is_relative_to(output), "output file escapes directory")
        require(sha(path.read_bytes()).hex() == digest, f"output file hash: {name}")
    ids = json_file(output/"ids.json")
    require(all(ids[k] == value for k, value in IDS.items()) and ids["fork"] == FORK_ID
            and (not compact or ids["fork_compact"] == COMPACT_ID), "guest IDs")
    chains = {name: headers((inputs/f"{name}.bin").read_bytes()) for name in ("original", "response", "candidate")}
    original, response, candidate = (chains[name] for name in ("original", "response", "candidate"))
    require((inputs/"response.bin").read_bytes().startswith((inputs/"original.bin").read_bytes()), "response not an extension")
    require(candidate["work"] > response["work"], "candidate does not outweigh response")
    for name, chain in chains.items():
        claim = manifest[name]
        require((chain["height"], chain["hash"][::-1].hex(), str(chain["work"])) ==
                (claim["height"], claim["hash"], claim["work"]), f"manifest {name} claim")
        proved = json_file(output/f"{name}.json")
        require((proved["tip_height"], proved["tip_hash"], int(proved["total_work"], 16)) ==
                (chain["height"], chain["hash"][::-1].hex(), chain["work"]), f"proven {name} claim")
    p = (inputs/"term-preimage.bin").read_bytes()
    require(len(p) == 202 and p[:14] == b"bsb/r0-term|v1", "term encoding")
    require(p[14:46].hex() == IDS["hold"] and p[46:78].hex() == IDS["header_chain"], "term images")
    q, deals = struct.unpack(">II", p[78:86])
    first, step, epochs, depth, height = struct.unpack(">IIIII", p[118:138])
    require(q > 0 and deals > 0 and step > 0 and epochs > 0 and depth > 0, "term constants")
    require(first+(epochs-1)*step+depth <= height == original["height"], "term schedule")
    require(p[138:170] == original["hash"] and int.from_bytes(p[170:202], "big") == original["work"], "term claim")
    require(p.hex() == manifest["term_preimage"] and sha(p).hex() == manifest["term_journal"], "term digest")
    epoch, divergent = manifest["epoch_index"], manifest["divergent_height"]
    require(type(epoch) is int and 0 <= epoch < epochs, "epoch index")
    require(type(divergent) is int and 0 <= divergent <= min(first+epoch*step, response["height"], candidate["height"]), "fork position")
    require(response["hashes"][divergent] != candidate["hashes"][divergent], "no fork")
    graph = bytes.fromhex(manifest["graph_id"])
    require(len(graph) == 32, "graph identity size")
    statement = b"bsb/r0-fork|v1" + graph + sha(p)
    for chain in (original, response, candidate):
        statement += struct.pack(">I", chain["height"]) + chain["hash"] + chain["work"].to_bytes(32, "big")
    statement += struct.pack(">II", epoch, divergent) + response["hashes"][divergent] + candidate["hashes"][divergent]
    require(len(statement) == 354, "statement size")
    if compact:
        statement = b"bsb/r0-fork|v2" + statement[14:78] + statement[146:282]
        require(len(statement) == 214, "compact statement size")
    require(statement == (output/"fork.bin.statement.bin").read_bytes(), "statement bytes")
    proof = json_file(output/"fork.json")
    journal = sha(statement).hex()
    require(proof["image_id"] == image_id and proof["journal"] == journal and proof["statement_preimage"] == statement.hex(), "fork public statement")
    verification = json_file(output/"verify.json")
    require(verification["image_id"] == image_id and verification["journal"] == journal and verification["verified"] is True
            and verification["changed_journal_rejected"] is True and verification["wrong_image_rejected"] is True, "recorded verification")
    guards = json_file(output/"guards.json")
    cases = {c["case"]: c for c in guards["cases"]}
    expected_cases = {"header-image", "genesis-path", "term-claim", "unrelated-response", "weaker-candidate", "equal-work", "after-seed", "divergence-path", "invented-authenticated-work"}
    require(set(cases) == expected_cases and guards["image_id"] == image_id and guards["graph_id_change_changes_journal"] is True, "guest guard cases")
    require(all(c.get("guest_rejected") is True or c.get("prover_rejected") is True for c in cases.values()), "guest guard failure")
    if verifier:
        process = subprocess.run([str(verifier), "verify-fork-compact" if compact else "verify-fork", str(output/"fork.bin")], check=True, capture_output=True, text=True)
        verified = json.loads(process.stdout.strip().splitlines()[-1])
        require(verified == verification, "fresh receipt verification differs from recorded result")
    return {"format": f"bsb/fork-proof-readback/{version}", "header_chains_checked": True, "statement_checked": True,
            "journal": journal, "fork_image_id": image_id, "original_work": original["work"], "response_work": response["work"],
            "candidate_work": candidate["work"], "guest_rejection_cases": len(cases), "receipt_verified_now": bool(verifier),
            "scope": "Relative work certificate readback. Receipt verification is performed only when receipt_verified_now is true. No Groth16 or Bitcoin fork-dispute enforcement."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--receipt-verifier", type=Path)
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    print(json.dumps(readback(args.inputs, args.output, args.receipt_verifier, args.compact)))
