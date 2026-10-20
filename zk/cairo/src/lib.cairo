//! Aggregated storage proof: one provider, one epoch, every deal at once.
//!
//! Public statement (the program's output): a challenge seed, q, the number of deals and a
//! digest D of the deal list (each deal's chunk-tree root R_i and chunk count n_i). Witness: for
//! each deal, q chunks and their Merkle paths. The program accepts only if, for every deal i and
//! every j < q, the chunk at index
//!
//!     nonce_i = H("bsb/zk-pdp/deal|" ‖ seed ‖ R_i)
//!     idx_ij  = u64le(H("bsb/zk-pdp/chal|" ‖ nonce_i ‖ u32le(j))[0..8]) mod n_i
//!
//! opens to R_i in the chunk tree of model/storage_bonds.ts: 4 KiB chunks, leaf = H(0x00 ‖
//! chunk), node = H(0x01 ‖ left ‖ right) with the last node of an odd level paired with itself,
//! and R = H(0x02 ‖ u64le(n) ‖ top). The indices come from the seed inside the program, so the
//! prover cannot choose which chunks to show: a proof exists only if the prover holds every
//! challenged chunk (or finds a second preimage of H).
//!
//! H is SHA-256 (src/sha_tree.cairo), the tree the protocol uses today, computed in plain Cairo
//! with no syscall so the proof constrains every round. Built with `--features blake`, H is
//! Blake2s instead (src/blake_tree.cairo), with domain separation by personalization rather
//! than prefix bytes: the same statement over a tree that stwo-cairo proves with a native
//! opcode, there to measure what the hash choice costs.

#[cfg(feature: 'blake')]
mod blake_tree;
mod sha256;
#[cfg(not(feature: 'blake'))]
mod sha_tree;
#[cfg(feature: 'blake')]
use blake_tree as tree;
use core::integer::u32_safe_divmod;
#[cfg(not(feature: 'blake'))]
use sha_tree as tree;

pub type Digest = [u32; 8];

const TWO: NonZero<u32> = 2;

#[derive(Drop, Serde)]
struct Opening {
    /// The chunk as 1024 words, in the backend's layout (sha_tree: the leaf preimage
    /// 0x00 ‖ chunk without its last byte, big-endian; blake_tree: the chunk, little-endian).
    leaf: Array<u32>,
    /// sha_tree: the chunk's last byte. blake_tree: zero.
    last: u32,
    /// Siblings from the leaf level up.
    path: Array<Digest>,
}

#[derive(Drop, Serde)]
struct Deal {
    root: Digest,
    n: u32,
    /// Exactly q openings, for challenge j = 0..q in order.
    openings: Array<Opening>,
}

#[derive(Drop, Serde)]
struct Args {
    seed: Digest,
    q: u32,
    deals: Array<Deal>,
}

#[derive(Drop, Serde)]
struct Output {
    seed: Digest,
    q: u32,
    n_deals: u32,
    /// H("bsb/zk-pdp/dset|" ‖ for each deal: R_i ‖ n_i), see `tree::deals_digest`.
    deals_digest: Digest,
}

#[executable]
fn main(args: Args) -> Output {
    let Args { seed, q, deals } = args;
    assert(q > 0, 'q is zero');
    let n_deals = deals.len();
    assert(n_deals > 0, 'no deals');

    let mut dset: Array<u32> = array![];
    for deal in deals {
        let Deal { root, n, openings } = deal;
        assert(n > 0, 'empty deal');
        assert(openings.len() == q, 'wrong number of openings');
        tree::append_deal(ref dset, root, n);
        let nonce = tree::deal_nonce(seed, root);
        let depth = depth_of(n);
        let mut j: u32 = 0;
        for o in openings {
            verify_opening(root, n, depth, tree::challenge_index(nonce, j, n), o);
            j += 1;
        }
    }

    Output { seed, q, n_deals, deals_digest: tree::deals_digest(dset) }
}

fn verify_opening(root: Digest, n: u32, depth: u32, idx: u32, o: Opening) {
    let Opening { leaf, last, path } = o;
    assert(path.len() == depth, 'path length');
    let mut h = tree::leaf_hash(leaf, last);
    let mut i = idx;
    for sib in path {
        let (up, bit) = u32_safe_divmod(i, TWO);
        h = if bit == 1 {
            tree::node(sib, h)
        } else {
            tree::node(h, sib)
        };
        i = up;
    }
    assert(tree::root_hash(n, h) == root, 'root mismatch');
}

/// Merkle path length for n leaves: levels halve, rounding up, until one node is left.
fn depth_of(n: u32) -> u32 {
    let mut w = n;
    let mut d = 0;
    while w > 1 {
        w = (w + 1) / 2;
        d += 1;
    }
    d
}

#[cfg(test)]
mod tests {
    use super::depth_of;

    #[test]
    fn depths() {
        assert_eq!(depth_of(1), 0);
        assert_eq!(depth_of(2), 1);
        assert_eq!(depth_of(3), 2);
        assert_eq!(depth_of(256), 8);
        assert_eq!(depth_of(257), 9);
    }
}
