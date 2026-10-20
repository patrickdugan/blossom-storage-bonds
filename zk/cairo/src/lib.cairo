//! Aggregated storage proof: one provider, one epoch, every deal at once.
//!
//! Two modes. Mode 0 (per deal) is described below. Mode 1 (holdings) draws the q challenges
//! across all the provider's chunks at once, so the proof's cost depends on q and not on the
//! number of deals:
//!
//!     nonce = H_hold(seed ‖ D),  g_j = challenge_index(nonce, j, N),  N = Σ n_i
//!     g_j falls in deal k where n_0 + … + n_(k-1) ≤ g_j < n_0 + … + n_k, at idx = g_j − that sum
//!
//! Each opening names its deal, and the program checks that it is the deal g_j falls in. The
//! output gains the mode, so a verifier cannot mistake one kind of proof for the other.
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

/// Holdings mode: the opening for challenge j, and the deal it is in.
#[derive(Drop, Serde)]
struct Held {
    deal: u32,
    opening: Opening,
}

#[derive(Drop, Serde)]
struct Args {
    seed: Digest,
    q: u32,
    /// 0: q openings per deal. 1: q openings across all deals (`held`).
    mode: u32,
    deals: Array<Deal>,
    /// Holdings mode only, exactly q entries, for challenge j = 0..q in order.
    held: Array<Held>,
}

#[derive(Drop, Serde)]
struct Output {
    seed: Digest,
    q: u32,
    mode: u32,
    n_deals: u32,
    /// H("bsb/zk-pdp/dset|" ‖ for each deal: R_i ‖ n_i), see `tree::deals_digest`.
    deals_digest: Digest,
}

#[executable]
fn main(args: Args) -> Output {
    let Args { seed, q, mode, deals, held } = args;
    assert(q > 0, 'q is zero');
    let n_deals = deals.len();
    assert(n_deals > 0, 'no deals');
    assert(mode == 0 || mode == 1, 'unknown mode');
    if mode == 1 {
        return holdings(seed, q, deals, held);
    }
    assert(held.len() == 0, 'holdings openings in mode 0');

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

    Output { seed, q, mode, n_deals, deals_digest: tree::deals_digest(dset) }
}

fn holdings(seed: Digest, q: u32, deals: Array<Deal>, held: Array<Held>) -> Output {
    let n_deals = deals.len();
    let mut dset: Array<u32> = array![];
    let mut roots: Array<Digest> = array![];
    let mut ns: Array<u32> = array![];
    let mut total: u64 = 0;
    for deal in deals {
        let Deal { root, n, openings } = deal;
        assert(n > 0, 'empty deal');
        assert(openings.len() == 0, 'per-deal openings in mode 1');
        tree::append_deal(ref dset, root, n);
        roots.append(root);
        ns.append(n);
        total += n.into();
    }
    let total: u32 = total.try_into().expect('over 2^32 chunks');
    let digest = tree::deals_digest(dset);
    let nonce = tree::holdings_nonce(seed, digest);
    assert(held.len() == q, 'wrong number of openings');
    let mut j: u32 = 0;
    for h in held {
        let Held { deal, opening } = h;
        let (k, idx) = locate(ns.span(), tree::challenge_index(nonce, j, total));
        assert(deal == k, 'opening names the wrong deal');
        let n = *ns[k];
        verify_opening(*roots[k], n, depth_of(n), idx, opening);
        j += 1;
    }
    Output { seed, q, mode: 1, n_deals, deals_digest: digest }
}

/// The deal a global chunk index falls in, and the index within that deal.
fn locate(ns: Span<u32>, g: u32) -> (u32, u32) {
    let mut base: u32 = 0;
    let mut k: u32 = 0;
    let mut found: Option<(u32, u32)> = Option::None;
    for n in ns {
        if found.is_none() && g < base + *n {
            found = Option::Some((k, g - base));
        }
        base += *n;
        k += 1;
    }
    found.expect('index past the last deal')
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
    use super::{depth_of, locate};

    #[test]
    fn depths() {
        assert_eq!(depth_of(1), 0);
        assert_eq!(depth_of(2), 1);
        assert_eq!(depth_of(3), 2);
        assert_eq!(depth_of(256), 8);
        assert_eq!(depth_of(257), 9);
    }

    #[test]
    fn locates() {
        let ns = array![3, 1, 5].span();
        assert_eq!(locate(ns, 0), (0, 0));
        assert_eq!(locate(ns, 2), (0, 2));
        assert_eq!(locate(ns, 3), (1, 0));
        assert_eq!(locate(ns, 4), (2, 0));
        assert_eq!(locate(ns, 8), (2, 4));
    }
}
