//! Exact relation between three authenticated regtest header-chain journals.
//! The caller must verify all three receipts under HEADER_CHAIN_ID. This relation
//! does not certify global canonicality or authorize a Bitcoin collateral spend.
use borsh::{BorshDeserialize, BorshSerialize};
use risc0_to_bitvm2_core::header_chain::BlockHeaderCircuitOutput;

pub const HEADER_CHAIN_ID: [u32; 8] = [
    4000559452, 3695057433, 105444513, 2976837995, 2374114311, 2300056661, 2472162979, 2106663679,
];
const GENESIS: [u8; 32] = [
    0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
    0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
];

#[derive(BorshDeserialize, BorshSerialize)]
pub struct AuthChain {
    pub output: BlockHeaderCircuitOutput,
    pub genesis_path: Vec<[u8; 32]>,
    pub tip_path: Vec<[u8; 32]>,
}
#[derive(BorshDeserialize, BorshSerialize)]
pub struct ForkInput {
    pub graph_id: [u8; 32],
    pub term_preimage: Vec<u8>,
    pub original: AuthChain,
    pub response: AuthChain,
    pub candidate: AuthChain,
    pub original_tip_on_response: Vec<[u8; 32]>,
    pub epoch_index: u32,
    pub divergent_height: u32,
    pub response_divergent_hash: [u8; 32],
    pub response_divergent_path: Vec<[u8; 32]>,
    pub candidate_divergent_hash: [u8; 32],
    pub candidate_divergent_path: Vec<[u8; 32]>,
}
type Check<T> = Result<T, &'static str>;
fn need(ok: bool, why: &'static str) -> Check<()> {
    if ok {
        Ok(())
    } else {
        Err(why)
    }
}
pub fn mmr_has(
    peaks: &[[u8; 32]],
    size: u32,
    index: u32,
    leaf: [u8; 32],
    path: &[[u8; 32]],
    sha: impl Fn(&[u8]) -> [u8; 32],
) -> bool {
    if peaks.len() != size.count_ones() as usize || index >= size {
        return false;
    }
    let (mut offset, mut peak) = (0u64, 0usize);
    for bit in (0..32).rev() {
        if size & (1u32 << bit) == 0 {
            continue;
        }
        let width = 1u64 << bit;
        if (index as u64) < offset + width {
            if path.len() != bit {
                return false;
            }
            let mut h = leaf;
            let relative = index as u64 - offset;
            for (i, sibling) in path.iter().enumerate() {
                let mut pair = [0u8; 64];
                let (left, right) = if (relative >> i) & 1 == 0 {
                    (&h, sibling)
                } else {
                    (sibling, &h)
                };
                pair[..32].copy_from_slice(left);
                pair[32..].copy_from_slice(right);
                h = sha(&pair);
            }
            return peaks[peak] == h;
        }
        offset += width;
        peak += 1;
    }
    false
}
fn opening(
    c: &AuthChain,
    height: u32,
    hash: [u8; 32],
    path: &[[u8; 32]],
    sha: impl Fn(&[u8]) -> [u8; 32],
) -> bool {
    let mmr = &c.output.chain_state.block_hashes_mmr;
    mmr_has(&mmr.subroots, mmr.size, height, hash, path, sha)
}
fn chain(c: &AuthChain, sha: impl Fn(&[u8]) -> [u8; 32] + Copy) -> Check<()> {
    let state = &c.output.chain_state;
    need(
        c.output.method_id == HEADER_CHAIN_ID,
        "header journal names another image",
    )?;
    need(
        state.block_hashes_mmr.size as u64 == state.block_height as u64 + 1,
        "MMR does not start at genesis",
    )?;
    need(
        opening(c, 0, GENESIS, &c.genesis_path, sha),
        "wrong genesis opening",
    )?;
    need(
        opening(
            c,
            state.block_height,
            state.best_block_hash,
            &c.tip_path,
            sha,
        ),
        "wrong tip opening",
    )?;
    Ok(())
}
/// Return the exact public statement bytes; SHA256 of these is the certificate journal.
pub fn check(input: &ForkInput, sha: impl Fn(&[u8]) -> [u8; 32] + Copy) -> Check<Vec<u8>> {
    for c in [&input.original, &input.response, &input.candidate] {
        chain(c, sha)?;
    }
    let p = &input.term_preimage;
    need(p.len() == 202, "term preimage length")?;
    need(&p[..14] == b"bsb/r0-term|v1", "term domain")?;
    let id: Vec<u8> = HEADER_CHAIN_ID
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    need(p[46..78] == id, "term names another header image")?;
    let word = |offset| u32::from_be_bytes(p[offset..offset + 4].try_into().unwrap());
    let (first, step, epochs, depth) = (word(118), word(122), word(126), word(130));
    need(
        word(78) > 0 && word(82) > 0 && step > 0 && epochs > 0 && depth > 0,
        "invalid term schedule or constants",
    )?;
    need(input.epoch_index < epochs, "epoch index out of range")?;
    let last = first as u64 + (epochs as u64 - 1) * step as u64;
    let original = &input.original.output.chain_state;
    need(
        last + depth as u64 <= original.block_height as u64,
        "term extends beyond original tip",
    )?;
    need(
        word(134) == original.block_height
            && p[138..170] == original.best_block_hash
            && p[170..202] == original.total_work,
        "term names another original claim",
    )?;
    let response = &input.response.output.chain_state;
    need(
        response.block_height >= original.block_height,
        "response is shorter than original claim",
    )?;
    need(
        response.total_work >= original.total_work,
        "response has less work than original claim",
    )?;
    need(
        opening(
            &input.response,
            original.block_height,
            original.best_block_hash,
            &input.original_tip_on_response,
            sha,
        ),
        "response does not extend original claim",
    )?;
    let candidate = &input.candidate.output.chain_state;
    need(
        candidate.total_work > response.total_work,
        "candidate must beat responding branch work",
    )?;
    let seed = first as u64 + input.epoch_index as u64 * step as u64;
    need(
        input.divergent_height as u64 <= seed,
        "fork occurs after selected seed",
    )?;
    need(
        input.response_divergent_hash != input.candidate_divergent_hash,
        "branches do not conflict",
    )?;
    need(
        opening(
            &input.response,
            input.divergent_height,
            input.response_divergent_hash,
            &input.response_divergent_path,
            sha,
        ),
        "invalid response divergence opening",
    )?;
    need(
        opening(
            &input.candidate,
            input.divergent_height,
            input.candidate_divergent_hash,
            &input.candidate_divergent_path,
            sha,
        ),
        "invalid candidate divergence opening",
    )?;
    let mut statement = b"bsb/r0-fork|v1".to_vec();
    statement.extend_from_slice(&input.graph_id);
    statement.extend_from_slice(&sha(p));
    for state in [original, response, candidate] {
        statement.extend_from_slice(&state.block_height.to_be_bytes());
        statement.extend_from_slice(&state.best_block_hash);
        statement.extend_from_slice(&state.total_work);
    }
    statement.extend_from_slice(&input.epoch_index.to_be_bytes());
    statement.extend_from_slice(&input.divergent_height.to_be_bytes());
    statement.extend_from_slice(&input.response_divergent_hash);
    statement.extend_from_slice(&input.candidate_divergent_hash);
    Ok(statement)
}

#[cfg(test)]
mod tests {
    // These test the relation on real captured headers. Receipt authentication is
    // performed by the guest and host commands, not by this unit-test constructor.
    use super::*;
    use crate::chain;
    use risc0_to_bitvm2_core::{
        header_chain::{ChainState, CircuitBlockHeader},
        mmr_guest::MMRGuest,
    };
    fn branches() -> (Vec<CircuitBlockHeader>, Vec<CircuitBlockHeader>) {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../results/bitvm-cumulative-work-forks.json"
        ))
        .unwrap();
        let read = |name: &str| {
            v["headers"][name]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    CircuitBlockHeader::try_from_slice(&hex::decode(v.as_str().unwrap()).unwrap())
                        .unwrap()
                })
                .collect()
        };
        (read("honest"), read("alternative"))
    }
    fn auth(headers: &[CircuitBlockHeader], tip: u32) -> AuthChain {
        let (hashes, mmr) = chain::mmr_of(headers, tip);
        let mut state = ChainState::new();
        state.block_hashes_mmr = MMRGuest::new();
        for hash in hashes {
            state.block_hashes_mmr.append(hash);
        }
        state.block_height = tip;
        state.best_block_hash = headers[tip as usize].compute_block_hash();
        state.total_work = [0u8; 32];
        state.total_work[24..].copy_from_slice(&(2 * (tip as u64 + 1)).to_be_bytes());
        AuthChain {
            output: BlockHeaderCircuitOutput {
                method_id: HEADER_CHAIN_ID,
                chain_state: state,
            },
            genesis_path: mmr.generate_proof(0).1.inclusion_proof,
            tip_path: mmr.generate_proof(tip).1.inclusion_proof,
        }
    }
    fn input(candidate_tip: u32) -> ForkInput {
        let (a, b) = branches();
        let original = auth(&a, 220);
        let response = auth(&a, 232);
        let candidate = auth(&b, candidate_tip);
        let (_, am) = chain::mmr_of(&a, 232);
        let (_, bm) = chain::mmr_of(&b, candidate_tip);
        let mut p = vec![0u8; 202];
        p[..14].copy_from_slice(b"bsb/r0-term|v1");
        p[46..78].copy_from_slice(
            &HEADER_CHAIN_ID
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        for (offset, value) in [
            (78, 16u32),
            (82, 3),
            (118, 170),
            (122, 10),
            (126, 3),
            (130, 6),
            (134, 220),
        ] {
            p[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        p[138..170].copy_from_slice(&original.output.chain_state.best_block_hash);
        p[170..202].copy_from_slice(&original.output.chain_state.total_work);
        ForkInput {
            graph_id: [42; 32],
            term_preimage: p,
            original,
            response,
            candidate,
            original_tip_on_response: am.generate_proof(220).1.inclusion_proof,
            epoch_index: 0,
            divergent_height: 170,
            response_divergent_hash: a[170].compute_block_hash(),
            response_divergent_path: am.generate_proof(170).1.inclusion_proof,
            candidate_divergent_hash: b[170].compute_block_hash(),
            candidate_divergent_path: bm.generate_proof(170).1.inclusion_proof,
        }
    }
    #[test]
    fn stronger_branch_passes_and_binding_changes_are_visible() {
        let mut i = input(233);
        let statement = check(&i, chain::sha256).unwrap();
        i.graph_id[0] ^= 1;
        assert_ne!(statement, check(&i, chain::sha256).unwrap());
        i.term_preimage[86] ^= 1;
        assert_ne!(statement, check(&i, chain::sha256).unwrap());
    }
    #[test]
    fn beating_only_old_claim_or_tying_response_is_insufficient() {
        assert_eq!(
            check(&input(221), chain::sha256).unwrap_err(),
            "candidate must beat responding branch work"
        );
        assert_eq!(
            check(&input(232), chain::sha256).unwrap_err(),
            "candidate must beat responding branch work"
        );
    }
    #[test]
    fn unrelated_response_cannot_substitute_a_stronger_chain() {
        let mut i = input(233);
        let (_, b) = branches();
        i.response = auth(&b, 232);
        assert_eq!(
            check(&i, chain::sha256).unwrap_err(),
            "response does not extend original claim"
        );
    }
    #[test]
    fn wrong_genesis_method_and_tip_openings_are_rejected() {
        let mut i = input(233);
        i.candidate.output.method_id[0] ^= 1;
        assert!(check(&i, chain::sha256).is_err());
        let mut i = input(233);
        i.candidate.genesis_path[0][0] ^= 1;
        assert!(check(&i, chain::sha256).is_err());
        let mut i = input(233);
        i.candidate.output.chain_state.best_block_hash[0] ^= 1;
        assert!(check(&i, chain::sha256).is_err());
    }
    #[test]
    fn wrong_term_claim_and_header_id_are_rejected() {
        for offset in [0, 46, 134, 138, 170] {
            let mut i = input(233);
            i.term_preimage[offset] ^= 1;
            assert!(check(&i, chain::sha256).is_err(), "offset {offset}");
        }
        let mut i = input(233);
        i.term_preimage.pop();
        assert!(check(&i, chain::sha256).is_err());
    }
    #[test]
    fn seed_position_conflict_and_paths_are_checked() {
        let mut i = input(233);
        i.divergent_height = 171;
        assert_eq!(
            check(&i, chain::sha256).unwrap_err(),
            "fork occurs after selected seed"
        );
        let mut i = input(233);
        i.epoch_index = 3;
        assert_eq!(
            check(&i, chain::sha256).unwrap_err(),
            "epoch index out of range"
        );
        let mut i = input(233);
        i.candidate_divergent_hash = i.response_divergent_hash;
        assert_eq!(
            check(&i, chain::sha256).unwrap_err(),
            "branches do not conflict"
        );
        let mut i = input(233);
        i.candidate_divergent_path[0][0] ^= 1;
        assert!(check(&i, chain::sha256).is_err());
        let mut i = input(233);
        i.response_divergent_path.pop();
        assert!(check(&i, chain::sha256).is_err());
    }
    #[test]
    fn empty_or_overflowing_schedule_and_mmr_size_are_rejected() {
        for offset in [78, 82, 122, 126, 130] {
            let mut i = input(233);
            i.term_preimage[offset..offset + 4].fill(0);
            assert!(check(&i, chain::sha256).is_err());
        }
        let mut i = input(233);
        i.term_preimage[122..126].fill(255);
        assert!(check(&i, chain::sha256).is_err());
        let mut i = input(233);
        i.candidate.output.chain_state.block_hashes_mmr.size -= 1;
        assert!(check(&i, chain::sha256).is_err());
    }
}
