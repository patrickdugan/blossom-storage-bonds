// bsb-r0: the BitVM2 spike's RISC Zero host (docs/design.md §4.6).
//
// Milestone 1, the holdings statement (model/zk_pdp.ts, mode 1, "sha"):
//   bsb-r0 ids
//   bsb-r0 exec-hold <witness.bin>                       executor only: cycles and journal, no proof
//   bsb-r0 prove-hold <witness.bin> <receipt.bin> [--succinct] [--po2 N]
//   bsb-r0 verify-hold <receipt.bin>
// Milestone 2, seeds bound to a header chain (chainwayxyz/risc0-to-bitvm2's regtest image):
//   bsb-r0 prove-chain <headers.bin> <receipt.bin> --elf E [--prev R] [--count N] [--exec]
//   bsb-r0 prove-term <out.bin> --chain R --headers H --first F --step S --depth D [--exec] <hold.bin>...
//   bsb-r0 forge-demo <dir> --elf E --spv-elf F --chain R --headers H --first F --step S --depth D <hold.bin>...
// Milestone 3, the Groth16 wrap through risc0-to-bitvm2's circuit and pinned prover image:
//   bsb-r0 groth16 <term.bin> <dir>
//
// Witnesses come from zk/risc0/witness.ts, headers from zk/risc0/headers.ts. Every command prints
// one JSON line. A guest that panics (a missing chunk, a wrong path, a seed off the chain) exits
// non-zero with no receipt.

mod chain;
mod wrap;

use anyhow::{bail, ensure, Context, Result};
use borsh::BorshDeserialize;
use bsb_methods::{FORGE_ELF, FORGE_ID, HOLD_ELF, HOLD_ID, TERM_ELF, TERM_ID};
use risc0_to_bitvm2_core::final_circuit::FinalCircuitInput;
use risc0_to_bitvm2_core::header_chain::{BlockHeaderCircuitOutput, CircuitBlockHeader};
use risc0_to_bitvm2_core::merkle_tree::BitcoinMerkleTree;
use risc0_to_bitvm2_core::mmr_native::{MMRInclusionProof, MMRNative};
use risc0_to_bitvm2_core::spv::SPV;
use risc0_to_bitvm2_core::transaction::CircuitTransaction;
use risc0_zkvm::{
    compute_image_id, default_executor, default_prover, ExecutorEnv, ProveInfo, ProverOpts, Receipt, SessionInfo,
};
use serde_json::{json, Value};
use std::time::Instant;

fn id_hex(id: [u32; 8]) -> String {
    hex::encode(id_bytes(id))
}

fn id_bytes(id: [u32; 8]) -> Vec<u8> {
    id.iter().flat_map(|w| w.to_le_bytes()).collect()
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn num(args: &[String], name: &str) -> Result<u32> {
    flag(args, name).with_context(|| format!("{name} N"))?.parse().map_err(Into::into)
}

/// Positional arguments after `skip`, leaving out flags and their values.
fn positional(args: &[String], skip: usize, bare: &[&str]) -> Vec<String> {
    let mut out = vec![];
    let mut i = skip;
    while i < args.len() {
        if args[i].starts_with("--") {
            i += if bare.contains(&args[i].as_str()) { 1 } else { 2 };
        } else {
            out.push(args[i].clone());
            i += 1;
        }
    }
    out
}

fn env_for<'a>(input: &'a [u8], po2: Option<u32>) -> Result<ExecutorEnv<'a>> {
    let mut b = ExecutorEnv::builder();
    b.write_slice(input);
    if let Some(p) = po2 {
        b.segment_limit_po2(p);
    }
    b.build()
}

fn read_receipt(path: &str) -> Result<Receipt> {
    Ok(Receipt::try_from_slice(&std::fs::read(path).with_context(|| path.to_string())?)?)
}

fn exec_stats(info: &SessionInfo, t: Instant) -> Value {
    let user: u64 = info.segments.iter().map(|s| s.cycles as u64).sum();
    let padded: u64 = info.segments.iter().map(|s| 1u64 << s.po2).sum();
    json!({ "user_cycles": user, "padded_cycles": padded, "segments": info.segments.len(),
        "exec_s": t.elapsed().as_secs_f64(), "journal": hex::encode(&info.journal.bytes) })
}

fn prove_stats(info: &ProveInfo, t: f64) -> Value {
    let s = &info.stats;
    json!({ "segments": s.segments, "total_cycles": s.total_cycles, "user_cycles": s.user_cycles,
        "paging_cycles": s.paging_cycles, "reserved_cycles": s.reserved_cycles, "prove_s": t,
        "seal_bytes": info.receipt.seal_size(), "journal": hex::encode(&info.receipt.journal.bytes) })
}

/// Executes, or proves succinctly and writes the receipt to `out`.
fn run(env: ExecutorEnv, elf: &[u8], id: [u32; 8], exec: bool, out: Option<&str>) -> Result<Value> {
    let t = Instant::now();
    if exec {
        return Ok(exec_stats(&default_executor().execute(env, elf)?, t));
    }
    let info = default_prover().prove_with_opts(env, elf, &ProverOpts::succinct())?;
    let prove_s = t.elapsed().as_secs_f64();
    info.receipt.verify(id)?;
    let mut v = prove_stats(&info, prove_s);
    if let Some(path) = out {
        let bytes = borsh::to_vec(&info.receipt)?;
        std::fs::write(path, &bytes)?;
        v["receipt_bytes"] = json!(bytes.len());
    }
    Ok(v)
}

fn hold_journals(paths: &[String]) -> Result<(Vec<Receipt>, Vec<Vec<u8>>)> {
    let receipts: Vec<Receipt> = paths.iter().map(|p| read_receipt(p)).collect::<Result<_>>()?;
    for r in &receipts {
        r.verify(HOLD_ID)?;
    }
    let journals = receipts.iter().map(|r| r.journal.bytes.clone()).collect();
    Ok((receipts, journals))
}

fn term_env<'a>(input: &chain::TermInput, chain_receipt: &Receipt, holds: &[Receipt]) -> Result<ExecutorEnv<'a>> {
    let mut b = ExecutorEnv::builder();
    b.write_slice(&borsh::to_vec(input)?);
    b.add_assumption(chain_receipt.clone());
    for h in holds {
        b.add_assumption(h.clone());
    }
    b.build()
}

fn final_spv_env<'a>(out: &BlockHeaderCircuitOutput, spv: SPV, chain_receipt: &Receipt) -> Result<ExecutorEnv<'a>> {
    let input = FinalCircuitInput { block_header_circuit_output: out.clone(), spv };
    let mut b = ExecutorEnv::builder();
    b.write_slice(&borsh::to_vec(&input)?);
    b.add_assumption(chain_receipt.clone());
    b.build()
}

/// A transaction nobody broadcast, in a header nobody mined: (its SPV parts, the header's hash).
fn fake_payment(prev: [u8; 32]) -> Result<(CircuitTransaction, CircuitBlockHeader)> {
    // a version-2 transaction paying 21 BTC to OP_TRUE, from a made-up outpoint
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&hex::decode(
        "0200000001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000ffffffff0100ca9a3b00000000015100000000",
    )?)?;
    let tx = CircuitTransaction(tx);
    let header = CircuitBlockHeader {
        version: 0x2000_0000,
        prev_block_hash: prev,
        merkle_root: BitcoinMerkleTree::new(vec![tx.txid()]).root(),
        time: 1_900_000_000,
        bits: 0x207f_ffff,
        nonce: 0,
    };
    Ok((tx, header))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let po2 = flag(&args, "--po2").map(|s| s.parse()).transpose()?;
    let exec = args.iter().any(|a| a == "--exec");
    match args.get(1).map(String::as_str) {
        Some("ids") => {
            println!("{}", json!({ "hold": id_hex(HOLD_ID), "term": id_hex(TERM_ID), "forge": id_hex(FORGE_ID),
                "header_chain": id_hex(chain::HEADER_CHAIN_ID), "hold_elf_bytes": HOLD_ELF.len(), "term_elf_bytes": TERM_ELF.len() }));
        }
        Some("exec-hold") => {
            let input = std::fs::read(&args[2]).context("witness")?;
            let t = Instant::now();
            let info = default_executor().execute(env_for(&input, po2)?, HOLD_ELF)?;
            let mut v = exec_stats(&info, t);
            v["cmd"] = json!("exec-hold");
            v["witness_bytes"] = json!(input.len());
            println!("{v}");
        }
        Some("prove-hold") => {
            let input = std::fs::read(&args[2]).context("witness")?;
            let succinct = args.iter().any(|a| a == "--succinct");
            let opts = if succinct { ProverOpts::succinct() } else { ProverOpts::default() };
            let t = Instant::now();
            let info = default_prover().prove_with_opts(env_for(&input, po2)?, HOLD_ELF, &opts)?;
            let prove_s = t.elapsed().as_secs_f64();
            let t = Instant::now();
            info.receipt.verify(HOLD_ID)?;
            let verify_s = t.elapsed().as_secs_f64();
            let bytes = borsh::to_vec(&info.receipt)?;
            std::fs::write(&args[3], &bytes)?;
            let mut v = prove_stats(&info, prove_s);
            v["cmd"] = json!("prove-hold");
            v["kind"] = json!(if succinct { "succinct" } else { "composite" });
            v["witness_bytes"] = json!(input.len());
            v["verify_s"] = json!(verify_s);
            v["receipt_bytes"] = json!(bytes.len());
            v["image_id"] = json!(id_hex(HOLD_ID));
            println!("{v}");
        }
        Some("verify-hold") => {
            let receipt = read_receipt(&args[2])?;
            let t = Instant::now();
            receipt.verify(HOLD_ID)?;
            println!("{}", json!({ "cmd": "verify-hold", "ok": true, "verify_s": t.elapsed().as_secs_f64(),
                "journal": hex::encode(&receipt.journal.bytes) }));
        }
        Some("prove-chain") => {
            let elf = chain::load_elf(&flag(&args, "--elf").context("--elf")?)?;
            let headers = chain::read_headers(&args[2])?;
            let prev = flag(&args, "--prev").map(|p| read_receipt(&p)).transpose()?;
            let prev_out = prev.as_ref().map(chain::chain_output).transpose()?;
            let start = prev_out.as_ref().map_or(0, |o| o.chain_state.block_height as usize + 1);
            let count = flag(&args, "--count").map_or(Ok(headers.len() - start), |s| s.parse())?;
            let batch = headers[start..start + count].to_vec();
            let env = chain::chain_env(chain::HEADER_CHAIN_ID, prev.as_ref().zip(prev_out), batch)?;
            let mut v = run(env, &elf, chain::HEADER_CHAIN_ID, exec, Some(&args[3]))?;
            if !exec {
                let out = chain::chain_output(&read_receipt(&args[3])?)?;
                let mut best = out.chain_state.best_block_hash;
                best.reverse();
                v["tip_height"] = json!(out.chain_state.block_height);
                v["tip_hash"] = json!(hex::encode(best));
                v["total_work"] = json!(hex::encode(out.chain_state.total_work));
            }
            v["cmd"] = json!("prove-chain");
            v["from"] = json!(start);
            v["headers"] = json!(count);
            println!("{v}");
        }
        Some("prove-term") => {
            let chain_receipt = read_receipt(&flag(&args, "--chain").context("--chain")?)?;
            chain_receipt.verify(chain::HEADER_CHAIN_ID)?;
            let headers = chain::read_headers(&flag(&args, "--headers").context("--headers")?)?;
            let (holds, journals) = hold_journals(&positional(&args, 3, &["--exec"]))?;
            let input = chain::term_input(
                chain::chain_output(&chain_receipt)?, &headers, HOLD_ID, &journals,
                num(&args, "--first")?, num(&args, "--step")?, num(&args, "--depth")?,
            )?;
            let preimage = input.preimage(chain::HEADER_CHAIN_ID);
            let env = term_env(&input, &chain_receipt, &holds)?;
            let mut v = run(env, TERM_ELF, TERM_ID, exec, Some(&args[2]))?;
            ensure!(v["journal"] == json!(hex::encode(chain::sha256(&preimage))), "term journal is not SHA-256 of the preimage");
            v["cmd"] = json!("prove-term");
            v["epochs"] = json!(journals.len());
            v["first"] = json!(input.first_height);
            v["step"] = json!(input.step);
            v["depth"] = json!(input.depth);
            v["hold_id"] = json!(id_hex(HOLD_ID));
            v["header_chain_id"] = json!(id_hex(chain::HEADER_CHAIN_ID));
            v["preimage"] = json!(hex::encode(&preimage));
            v["image_id"] = json!(id_hex(TERM_ID));
            println!("{v}");
        }
        Some("forge-demo") => {
            // A chain state nobody mined, laundered through one step of the genuine header-chain
            // image. Then: upstream's final-spv accepts it, and the term guest does not.
            let dir = std::path::PathBuf::from(&args[2]);
            std::fs::create_dir_all(&dir)?;
            let elf = chain::load_elf(&flag(&args, "--elf").context("--elf")?)?;
            let spv_elf = std::fs::read(flag(&args, "--spv-elf").context("--spv-elf")?)?;
            let honest = read_receipt(&flag(&args, "--chain").context("--chain")?)?;
            let honest_out = chain::chain_output(&honest)?;
            let headers = chain::read_headers(&flag(&args, "--headers").context("--headers")?)?;
            let tip = honest_out.chain_state.block_height;
            let (first, step, depth) = (num(&args, "--first")?, num(&args, "--step")?, num(&args, "--depth")?);
            let (holds, journals) = hold_journals(&positional(&args, 3, &[]))?;
            let mut report = json!({ "cmd": "forge-demo", "spv_elf_id": hex::encode(compute_image_id(&spv_elf)?.as_bytes()) });

            // 1. forge guest: an arbitrary state whose block at `first` is a fake payment block
            let (tx, fake) = fake_payment(honest_out.chain_state.best_block_hash)?;
            let forged = BlockHeaderCircuitOutput {
                method_id: FORGE_ID,
                chain_state: chain::forged_state(&headers, tip, first, fake.compute_block_hash()),
            };
            let mut b = ExecutorEnv::builder();
            b.write_slice(&borsh::to_vec(&forged)?);
            report["forge"] = run(b.build()?, FORGE_ELF, FORGE_ID, false, Some(dir.join("forge.bin").to_str().unwrap()))?;
            let forge_receipt = read_receipt(dir.join("forge.bin").to_str().unwrap())?;

            // 2. the genuine image, prev = the forged output, zero headers
            let env = chain::chain_env(FORGE_ID, Some((&forge_receipt, forged.clone())), vec![])?;
            let laundered_path = dir.join("laundered-chain.bin");
            report["laundered"] = run(env, &elf, chain::HEADER_CHAIN_ID, false, Some(laundered_path.to_str().unwrap()))?;
            let laundered = read_receipt(laundered_path.to_str().unwrap())?;
            laundered.verify(chain::HEADER_CHAIN_ID)?;
            let lo = chain::chain_output(&laundered)?;
            report["laundered_receipt_verifies_under_header_chain_id"] = json!(true);
            report["laundered_journal_method_id"] = json!(id_hex(lo.method_id));
            report["laundered_total_work"] = json!(hex::encode(lo.chain_state.total_work));

            // 3. upstream final-spv (regtest ELF as published) over the laundered chain: a fake payment
            let mut mmr = MMRNative::new();
            for (i, h) in headers[..=tip as usize].iter().enumerate() {
                mmr.append(if i as u32 == first { fake.compute_block_hash() } else { h.compute_block_hash() });
            }
            let (_, mmr_proof) = mmr.generate_proof(first);
            let spv = SPV::new(tx.clone(), BitcoinMerkleTree::new(vec![tx.txid()]).generate_proof(0), fake.clone(), mmr_proof);
            let t = Instant::now();
            report["final_spv_on_laundered_chain"] = match default_executor().execute(final_spv_env(&lo, spv, &laundered)?, &spv_elf) {
                Ok(info) => { let mut v = exec_stats(&info, t); v["accepted"] = json!(true); v }
                Err(e) => json!({ "accepted": false, "error": e.to_string() }),
            };

            // 4. upstream final-spv over the honest chain, with a block that is not on it at all
            let (tx2, fake2) = fake_payment([0x11; 32])?;
            let bogus = MMRInclusionProof::new(0, 0, vec![[0u8; 32]; 7]);
            let spv2 = SPV::new(tx2.clone(), BitcoinMerkleTree::new(vec![tx2.txid()]).generate_proof(0), fake2, bogus);
            let t = Instant::now();
            report["final_spv_block_not_in_mmr"] = match default_executor().execute(final_spv_env(&honest_out, spv2, &honest)?, &spv_elf) {
                Ok(info) => { let mut v = exec_stats(&info, t); v["accepted"] = json!(true); v }
                Err(e) => json!({ "accepted": false, "error": e.to_string() }),
            };

            // 5. the term guest over the laundered chain, with honest holdings receipts
            let input = chain::term_input(lo.clone(), &headers, HOLD_ID, &journals, first, step, depth)?;
            let t = Instant::now();
            report["term_on_laundered_chain"] = match default_executor().execute(term_env(&input, &laundered, &holds)?, TERM_ELF) {
                Ok(info) => { let mut v = exec_stats(&info, t); v["accepted"] = json!(true); v }
                Err(e) => json!({ "accepted": false, "error": format!("{e:#}") }),
            };
            println!("{report}");
        }
        Some("groth16") => {
            let receipt = read_receipt(&args[2])?;
            receipt.verify(TERM_ID)?;
            let work = std::path::PathBuf::from(&args[3]);
            std::fs::create_dir_all(&work)?;
            let prep = wrap::prepare(&receipt, &work)?;
            let (docker_s, peak) = wrap::run_prover(&work)?;
            let got = wrap::read_output(&work)?;
            let image = id_bytes(TERM_ID);
            let want = wrap::expected_output(&image, &receipt.journal.bytes);
            let mut wrong_journal = receipt.journal.bytes.clone();
            wrong_journal[0] ^= 1;
            let wrong = wrap::expected_output(&image, &wrong_journal);
            let dec = |b: &[u8]| num_bigint::BigUint::from_bytes_be(b).to_str_radix(10);
            let (control_root, post_state, bn254_id) = wrap::constants();
            let proof: Value = serde_json::from_str(&std::fs::read_to_string(work.join("proof.json"))?)?;
            let v = json!({
                "cmd": "groth16", "image": wrap::PROVER_IMAGE, "identity_p254_s": prep.identity_s,
                "identity_seal_bytes": prep.seal_bytes, "docker_s": docker_s, "docker_peak_mem_mb": peak,
                "journal": hex::encode(&receipt.journal.bytes), "pre_state": hex::encode(&image),
                "control_root": hex::encode(control_root), "post_state": hex::encode(post_state),
                "bn254_control_id": hex::encode(bn254_id),
                "constants_digest": hex::encode(wrap::constants_digest(&image)),
                "public_output_hex": hex::encode(got), "public_output_dec": dec(&got),
                "expected_output_hex": hex::encode(want), "output_matches": got == want,
                "wrong_journal_output_dec": dec(&wrong), "proof": proof,
            });
            std::fs::write(work.join("groth16.json"), serde_json::to_string_pretty(&v)?)?;
            println!("{v}");
            ensure!(got == want, "public output does not match Blake3(constants ‖ journal)");
        }
        _ => bail!("usage: see the header of zk/risc0/host/src/main.rs"),
    }
    Ok(())
}
