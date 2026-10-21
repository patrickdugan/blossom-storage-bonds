//! Build the exact comparison input from already verified header receipts.
use crate::{
    chain,
    fork_relation::{self, AuthChain, ForkInput},
};
use anyhow::{ensure, Context, Result};
use bsb_methods::{FORK_COMPACT_ELF, FORK_COMPACT_ID, FORK_ELF, FORK_ID};

fn compact(args: &[String]) -> bool {
    args[1].ends_with("-compact")
}
fn method(args: &[String]) -> (&'static [u8], [u32; 8]) {
    if compact(args) {
        (FORK_COMPACT_ELF, FORK_COMPACT_ID)
    } else {
        (FORK_ELF, FORK_ID)
    }
}
fn statement(args: &[String], input: &ForkInput) -> Result<Vec<u8>> {
    if compact(args) {
        fork_relation::check_compact(input, chain::sha256)
    } else {
        fork_relation::check(input, chain::sha256)
    }
    .map_err(anyhow::Error::msg)
}
use risc0_to_bitvm2_core::header_chain::BlockHeaderCircuitOutput;
use risc0_zkvm::{ExecutorEnv, Receipt};
use serde_json::json;

fn auth(
    receipt: &Receipt,
    headers: &[risc0_to_bitvm2_core::header_chain::CircuitBlockHeader],
) -> Result<AuthChain> {
    receipt.verify(chain::HEADER_CHAIN_ID)?;
    let output = chain::chain_output(receipt)?;
    ensure!(
        headers.len() == output.chain_state.block_height as usize + 1,
        "header file must end at receipt tip"
    );
    let (_, mmr) = chain::mmr_of(headers, output.chain_state.block_height);
    Ok(AuthChain {
        genesis_path: mmr.generate_proof(0).1.inclusion_proof,
        tip_path: mmr
            .generate_proof(output.chain_state.block_height)
            .1
            .inclusion_proof,
        output,
    })
}
fn selected(args: &[String], flag: &str) -> Result<String> {
    super::flag(args, flag).with_context(|| flag.to_string())
}
pub fn prove(args: &[String]) -> Result<()> {
    let (elf, id) = method(args);
    let output = args.get(2).context("prove-fork <new-receipt.bin>")?;
    let input_path = format!("{output}.input.bin");
    let statement_path = format!("{output}.statement.bin");
    for path in [output.as_str(), &input_path, &statement_path] {
        ensure!(
            !std::path::Path::new(path).exists(),
            "refusing to overwrite {path}"
        );
    }
    let mut receipts = Vec::new();
    let mut headers = Vec::new();
    for name in ["original", "response", "candidate"] {
        receipts.push(super::read_receipt(&selected(args, &format!("--{name}"))?)?);
        headers.push(chain::read_headers(&selected(
            args,
            &format!("--{name}-headers"),
        )?)?);
    }
    let d = super::num(args, "--divergent-height")?;
    let original = auth(&receipts[0], &headers[0])?;
    let response = auth(&receipts[1], &headers[1])?;
    let candidate = auth(&receipts[2], &headers[2])?;
    ensure!(
        (d as usize) < headers[1].len() && (d as usize) < headers[2].len(),
        "divergence above supplied tip"
    );
    let (_, response_mmr) = chain::mmr_of(&headers[1], response.output.chain_state.block_height);
    let (_, candidate_mmr) = chain::mmr_of(&headers[2], candidate.output.chain_state.block_height);
    ensure!(
        original.output.chain_state.block_height <= response.output.chain_state.block_height,
        "response below original"
    );
    let original_tip_on_response = response_mmr
        .generate_proof(original.output.chain_state.block_height)
        .1
        .inclusion_proof;
    let input = ForkInput {
        graph_id: hex::decode(selected(args, "--graph-id")?)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("graph ID must be 32 bytes"))?,
        term_preimage: std::fs::read(selected(args, "--term-preimage")?)?,
        original,
        response,
        candidate,
        original_tip_on_response,
        epoch_index: super::num(args, "--epoch-index")?,
        divergent_height: d,
        response_divergent_hash: headers[1][d as usize].compute_block_hash(),
        response_divergent_path: response_mmr.generate_proof(d).1.inclusion_proof,
        candidate_divergent_hash: headers[2][d as usize].compute_block_hash(),
        candidate_divergent_path: candidate_mmr.generate_proof(d).1.inclusion_proof,
    };
    let statement = statement(args, &input)?;
    let bytes = borsh::to_vec(&input)?;
    std::fs::write(&input_path, &bytes)?;
    std::fs::write(&statement_path, &statement)?;
    let mut env = ExecutorEnv::builder();
    env.write_slice(&bytes);
    for receipt in receipts {
        env.add_assumption(receipt);
    }
    let exec = args.iter().any(|arg| arg == "--exec");
    let mut result = super::run(
        env.build()?,
        elf,
        id,
        exec,
        if exec { None } else { Some(output) },
    )?;
    ensure!(
        result["journal"] == hex::encode(chain::sha256(&statement)),
        "guest journal differs from native relation"
    );
    result["cmd"] = json!(args[1]);
    result["image_id"] = json!(super::id_hex(id));
    result["statement_preimage"] = json!(hex::encode(&statement));
    result["input_bytes"] = json!(bytes.len());
    let summary = |c: &BlockHeaderCircuitOutput| json!({"height":c.chain_state.block_height,"hash_internal":hex::encode(c.chain_state.best_block_hash),"work_be":hex::encode(c.chain_state.total_work)});
    result["original"] = summary(&input.original.output);
    result["response"] = summary(&input.response.output);
    result["candidate"] = summary(&input.candidate.output);
    result["scope"]=json!("Relative cumulative-work certificate under the pinned regtest header image. Does not prove globally heaviest chain, a storage holdings receipt, or Bitcoin-enforced slashing. Graph ID is a public binding value, not an observed funding transaction.");
    println!("{result}");
    Ok(())
}

/// Exercise the compiled guest on adversarial inputs after genuine receipts exist.
pub fn guards(args: &[String]) -> Result<()> {
    let (elf, id) = method(args);
    use borsh::BorshDeserialize;
    let base = std::fs::read(args.get(2).context("fork-guards <input.bin>")?)?;
    let original = ForkInput::try_from_slice(&base)?;
    let mut receipts = Vec::new();
    for (name, chain) in ["original", "response", "candidate"].iter().zip([
        &original.original,
        &original.response,
        &original.candidate,
    ]) {
        let receipt = super::read_receipt(&selected(args, &format!("--{name}"))?)?;
        receipt.verify(chain::HEADER_CHAIN_ID)?;
        ensure!(
            receipt.journal.bytes == borsh::to_vec(&chain.output)?,
            "base input differs from {name} receipt"
        );
        receipts.push(receipt);
    }
    let env_for = |input: &ForkInput| -> Result<ExecutorEnv<'static>> {
        let mut env = ExecutorEnv::builder();
        env.write_slice(&borsh::to_vec(input)?);
        for receipt in &receipts {
            env.add_assumption(receipt.clone());
        }
        Ok(env.build()?)
    };
    let mut cases = Vec::new();
    for name in [
        "header-image",
        "genesis-path",
        "term-claim",
        "unrelated-response",
        "weaker-candidate",
        "equal-work",
        "after-seed",
        "divergence-path",
    ] {
        let mut input = ForkInput::try_from_slice(&base)?;
        match name {
            "header-image" => input.candidate.output.method_id[0] ^= 1,
            "genesis-path" => input.candidate.genesis_path[0][0] ^= 1,
            "term-claim" => input.term_preimage[138] ^= 1,
            "unrelated-response" => {
                input.response = AuthChain::try_from_slice(&borsh::to_vec(&input.candidate)?)?
            }
            "weaker-candidate" => {
                input.candidate.output.chain_state.total_work =
                    input.original.output.chain_state.total_work
            }
            "equal-work" => {
                input.candidate.output.chain_state.total_work =
                    input.response.output.chain_state.total_work
            }
            "after-seed" => input.divergent_height += 1,
            "divergence-path" => input.candidate_divergent_path[0][0] ^= 1,
            _ => unreachable!(),
        }
        let execution = risc0_zkvm::default_executor().execute(env_for(&input)?, elf);
        ensure!(
            execution.is_err(),
            "guest accepted invalid guard case {name}"
        );
        cases.push(
            json!({"case":name,"guest_rejected":true,"error":execution.err().unwrap().to_string()}),
        );
    }
    let mut changed = ForkInput::try_from_slice(&base)?;
    changed.graph_id[0] ^= 1;
    let execution = risc0_zkvm::default_executor().execute(env_for(&changed)?, elf)?;
    let old = chain::sha256(&statement(args, &original)?);
    ensure!(
        execution.journal.bytes != old,
        "graph identity mutation did not change journal"
    );
    // Invented work passes the inequality but must fail receipt authentication when proving.
    let mut invented = ForkInput::try_from_slice(&base)?;
    invented.candidate.output.chain_state.total_work = [255; 32];
    statement(args, &invented)?;
    let forgery = super::run(env_for(&invented)?, elf, id, false, None);
    ensure!(
        forgery.is_err(),
        "prover accepted invented work without a matching header receipt"
    );
    cases.push(json!({"case":"invented-authenticated-work","prover_rejected":true,"error":format!("{:#}",forgery.err().unwrap())}));
    println!(
        "{}",
        json!({"cmd":args[1],"image_id":super::id_hex(id),"cases":cases,"graph_id_change_changes_journal":true,"scope":"Guest execution guards plus prover rejection of an unbacked header journal. No Bitcoin fork-dispute enforcement."})
    );
    Ok(())
}
