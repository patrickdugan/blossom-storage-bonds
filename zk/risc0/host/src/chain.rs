// Milestone 2: the header chain (chainwayxyz/risc0-to-bitvm2's regtest header-chain image, run as
// published) and the term guest that binds each epoch's seed to it.

use anyhow::{ensure, Context, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use risc0_to_bitvm2_core::header_chain::{
    BlockHeaderCircuitOutput, ChainState, CircuitBlockHeader, HeaderChainCircuitInput, HeaderChainPrevProofType,
};
use risc0_to_bitvm2_core::mmr_guest::MMRGuest;
use risc0_to_bitvm2_core::mmr_native::MMRNative;
use risc0_zkvm::{compute_image_id, ExecutorEnv, Receipt};
use sha2::{Digest as _, Sha256};

/// What the term guest pins (methods/term/src/bin/term.rs).
pub const HEADER_CHAIN_ID: [u32; 8] = [
    4000559452, 3695057433, 105444513, 2976837995, 2374114311, 2300056661, 2472162979, 2106663679,
];

pub fn load_elf(path: &str) -> Result<Vec<u8>> {
    let elf = std::fs::read(path).with_context(|| format!("header-chain ELF {path}"))?;
    let id: [u32; 8] = compute_image_id(&elf)?.as_words().try_into().unwrap();
    ensure!(id == HEADER_CHAIN_ID, "ELF image ID {id:?} is not the pinned regtest header-chain ID");
    Ok(elf)
}

pub fn read_headers(path: &str) -> Result<Vec<CircuitBlockHeader>> {
    let raw = std::fs::read(path)?;
    ensure!(raw.len() % 80 == 0, "headers.bin is not 80-byte headers");
    Ok(raw.chunks(80).map(|h| CircuitBlockHeader::try_from_slice(h).unwrap()).collect())
}

pub fn chain_output(r: &Receipt) -> Result<BlockHeaderCircuitOutput> {
    Ok(BlockHeaderCircuitOutput::try_from_slice(&r.journal.bytes)?)
}

/// The header-chain guest's input and assumptions, as upstream's host/src/main.rs builds them.
pub fn chain_env<'a>(
    method_id: [u32; 8],
    prev: Option<(&Receipt, BlockHeaderCircuitOutput)>,
    headers: Vec<CircuitBlockHeader>,
) -> Result<ExecutorEnv<'a>> {
    let input = HeaderChainCircuitInput {
        method_id,
        prev_proof: match &prev {
            Some((_, out)) => HeaderChainPrevProofType::PrevProof(out.clone()),
            None => HeaderChainPrevProofType::GenesisBlock,
        },
        block_headers: headers,
    };
    let mut b = ExecutorEnv::builder();
    b.write_slice(&borsh::to_vec(&input)?);
    if let Some((r, _)) = prev {
        b.add_assumption(r.clone());
    }
    b.build()
}

/// Block hashes (internal byte order) for heights 0..=tip and the MMR over them.
pub fn mmr_of(headers: &[CircuitBlockHeader], tip: u32) -> (Vec<[u8; 32]>, MMRNative) {
    let hashes: Vec<[u8; 32]> = headers[..=tip as usize].iter().map(|h| h.compute_block_hash()).collect();
    let mut mmr = MMRNative::new();
    for h in &hashes {
        mmr.append(*h);
    }
    (hashes, mmr)
}

#[derive(BorshSerialize)]
pub struct Epoch {
    pub journal: Vec<u8>,
    pub mmr_path: Vec<[u8; 32]>,
}

/// Must match TermInput in term.rs field for field.
#[derive(BorshSerialize)]
pub struct TermInput {
    pub chain: BlockHeaderCircuitOutput,
    pub hold_id: [u32; 8],
    pub q: u32,
    pub deal_count: u32,
    pub deals_digest: [u8; 32],
    pub first_height: u32,
    pub step: u32,
    pub depth: u32,
    pub epochs: Vec<Epoch>,
    pub genesis_path: Vec<[u8; 32]>,
}

impl TermInput {
    /// The 202-byte preimage whose SHA-256 is the term journal (term.rs).
    pub fn preimage(&self, header_chain_id: [u32; 8]) -> Vec<u8> {
        let cs = &self.chain.chain_state;
        let mut p = b"bsb/r0-term|v1".to_vec();
        for w in self.hold_id.iter().chain(header_chain_id.iter()) {
            p.extend_from_slice(&w.to_le_bytes());
        }
        p.extend_from_slice(&self.q.to_be_bytes());
        p.extend_from_slice(&self.deal_count.to_be_bytes());
        p.extend_from_slice(&self.deals_digest);
        for v in [self.first_height, self.step, self.epochs.len() as u32, self.depth, cs.block_height] {
            p.extend_from_slice(&v.to_be_bytes());
        }
        p.extend_from_slice(&cs.best_block_hash);
        p.extend_from_slice(&cs.total_work);
        p
    }
}

pub fn term_input(
    chain: BlockHeaderCircuitOutput,
    headers: &[CircuitBlockHeader],
    hold_id: [u32; 8],
    journals: &[Vec<u8>],
    first_height: u32,
    step: u32,
    depth: u32,
) -> Result<TermInput> {
    ensure!(!journals.is_empty(), "no epochs");
    let j0 = &journals[0];
    ensure!(j0.len() == 76, "holdings journal is 76 bytes");
    let (_, mmr) = mmr_of(headers, chain.chain_state.block_height);
    let epochs = journals
        .iter()
        .enumerate()
        .map(|(i, j)| {
            let (_, proof) = mmr.generate_proof(first_height + i as u32 * step);
            Epoch { journal: j.clone(), mmr_path: proof.inclusion_proof }
        })
        .collect();
    Ok(TermInput {
        chain,
        hold_id,
        q: u32::from_be_bytes(j0[32..36].try_into()?),
        deal_count: u32::from_be_bytes(j0[40..44].try_into()?),
        deals_digest: j0[44..76].try_into()?,
        first_height,
        step,
        depth,
        epochs,
        genesis_path: mmr.generate_proof(0).1.inclusion_proof,
    })
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// A chain state anyone can write down: the honest headers' MMR with the leaf at `height`
/// replaced by `fake` (internal order), and the most work a u256 holds.
pub fn forged_state(headers: &[CircuitBlockHeader], tip: u32, height: u32, fake: [u8; 32]) -> ChainState {
    let (mut hashes, _) = mmr_of(headers, tip);
    hashes[height as usize] = fake;
    let mut mmr = MMRGuest::new();
    for h in &hashes {
        mmr.append(*h);
    }
    let mut st = ChainState::new();
    st.block_height = tip;
    st.total_work = [0xff; 32];
    st.best_block_hash = hashes[tip as usize];
    st.block_hashes_mmr = mmr;
    st
}
