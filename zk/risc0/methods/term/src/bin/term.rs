// One proof for a bond term: every epoch's holdings receipt, with each seed bound to the block hash
// at its epoch height on a header chain proven by chainwayxyz/risc0-to-bitvm2's header-chain guest.
//
// Input (borsh): the header-chain journal, the holdings image ID, the term's constants (q, deal
// count, D, first height, step, depth) and per epoch the 76-byte holdings journal plus an MMR path.
// For epoch i at height h_i = first + i·step the guest checks:
//
//   - the holdings receipt (assumption) for that journal, under hold_id;
//   - its q, mode 1, deal count and D are the term's;
//   - its seed, reversed into internal byte order (layer1 seeds are RPC display-order hashes), is
//     leaf h_i of the chain's block-hash MMR, at that position and no other;
//   - h_i + depth ≤ the chain's tip height;
//
// and, once, that leaf 0 of that MMR is regtest's genesis hash, and that the header-chain receipt
// verifies under HEADER_CHAIN_ID with a journal naming that same image. The last check matters:
// the header-chain guest verifies its predecessor under the
// method_id its own input carries, so a receipt of the genuine image can wrap a chain state that
// another image made up (see forge.rs). risc0-to-bitvm2's final-spv guest does not make it.
//
// The journal is 32 bytes, as risc0-to-bitvm2's Groth16 circuit requires: SHA-256 of the term
// preimage below. Anything the BitVM graph must pin is in it.

#![no_main]

use borsh::BorshDeserialize;
use risc0_to_bitvm2_core::header_chain::BlockHeaderCircuitOutput;
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256};

risc0_zkvm::guest::entry!(main);

/// compute_image_id(elfs/regtest-header-chain-guest.bin) at risc0-to-bitvm2 efc448e, the value
/// its final-spv guest pins for regtest. The host checks the ELF against it before proving.
const HEADER_CHAIN_ID: [u32; 8] = [
    4000559452, 3695057433, 105444513, 2976837995, 2374114311, 2300056661, 2472162979, 2106663679,
];

/// Regtest's genesis hash, internal byte order (display 0f9188f1…2206). The header-chain guest
/// starts from an all-zero parent and accepts any header with valid work as block 0, so the chain's
/// network is pinned here.
const GENESIS: [u8; 32] = [
    0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
    0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
];

#[derive(BorshDeserialize)]
struct Epoch {
    journal: Vec<u8>,
    mmr_path: Vec<[u8; 32]>,
}

#[derive(BorshDeserialize)]
struct TermInput {
    chain: BlockHeaderCircuitOutput,
    hold_id: [u32; 8],
    q: u32,
    deal_count: u32,
    deals_digest: [u8; 32],
    first_height: u32,
    step: u32,
    depth: u32,
    epochs: Vec<Epoch>,
    genesis_path: Vec<[u8; 32]>,
}

fn sha(data: &[u8]) -> [u8; 32] {
    Impl::hash_bytes(data).as_bytes().try_into().unwrap()
}

fn pair(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(l);
    b[32..].copy_from_slice(r);
    sha(&b)
}

/// Leaf `index` of an MMR with these peaks (largest first, as MMRGuest keeps them). The peak and
/// the path length both follow from `size` and `index`, so a path cannot stand for another height.
fn mmr_has(peaks: &[[u8; 32]], size: u32, index: u32, leaf: &[u8; 32], path: &[[u8; 32]]) -> bool {
    assert_eq!(peaks.len() as u32, size.count_ones(), "malformed MMR");
    let (mut offset, mut peak) = (0u64, 0usize);
    for b in (0..32).rev() {
        if size & (1 << b) == 0 {
            continue;
        }
        let width = 1u64 << b;
        if (index as u64) < offset + width {
            if path.len() != b {
                return false;
            }
            let at = index as u64 - offset;
            let mut h = *leaf;
            for (i, sib) in path.iter().enumerate() {
                h = if (at >> i) & 1 == 0 { pair(&h, sib) } else { pair(sib, &h) };
            }
            return peaks[peak] == h;
        }
        offset += width;
        peak += 1;
    }
    false
}

fn main() {
    let input = TermInput::deserialize_reader(&mut env::stdin()).expect("term input");
    assert_eq!(input.chain.method_id, HEADER_CHAIN_ID, "header chain proven under another image");
    env::verify(HEADER_CHAIN_ID, &borsh::to_vec(&input.chain).unwrap()).unwrap();
    let cs = &input.chain.chain_state;
    let mmr = &cs.block_hashes_mmr;
    assert_eq!(mmr.size as u64, cs.block_height as u64 + 1, "chain does not start at genesis");
    assert!(mmr_has(&mmr.subroots, mmr.size, 0, &GENESIS, &input.genesis_path), "chain does not start at regtest genesis");
    assert!(!input.epochs.is_empty(), "no epochs");

    for (i, e) in input.epochs.iter().enumerate() {
        let height = input.first_height as u64 + i as u64 * input.step as u64;
        assert!(height + input.depth as u64 <= cs.block_height as u64, "seed block too shallow");
        assert_eq!(e.journal.len(), 76, "holdings journal size");
        env::verify(input.hold_id, &e.journal).unwrap();
        let j = &e.journal;
        assert_eq!(&j[32..36], &input.q.to_be_bytes(), "q");
        assert_eq!(&j[36..40], &1u32.to_be_bytes(), "mode");
        assert_eq!(&j[40..44], &input.deal_count.to_be_bytes(), "deal count");
        assert_eq!(&j[44..76], &input.deals_digest, "deal digest");
        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(&j[..32]);
        leaf.reverse();
        assert!(mmr_has(&mmr.subroots, mmr.size, height as u32, &leaf, &e.mmr_path), "seed is not the block hash at its height");
    }

    // "bsb/r0-term|v1" ‖ hold_id ‖ header_chain_id ‖ u32be(q, deal count) ‖ D ‖ u32be(first, step,
    // epochs, depth, tip height) ‖ tip hash (internal order) ‖ total work (u256be), 202 bytes
    let mut p = Vec::with_capacity(216);
    p.extend_from_slice(b"bsb/r0-term|v1");
    for w in input.hold_id.iter().chain(HEADER_CHAIN_ID.iter()) {
        p.extend_from_slice(&w.to_le_bytes());
    }
    for v in [input.q, input.deal_count] {
        p.extend_from_slice(&v.to_be_bytes());
    }
    p.extend_from_slice(&input.deals_digest);
    for v in [input.first_height, input.step, input.epochs.len() as u32, input.depth, cs.block_height] {
        p.extend_from_slice(&v.to_be_bytes());
    }
    p.extend_from_slice(&cs.best_block_hash);
    p.extend_from_slice(&cs.total_work);
    env::commit_slice(&sha(&p));
}
