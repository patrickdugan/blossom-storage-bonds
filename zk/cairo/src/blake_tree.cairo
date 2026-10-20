//! The same tree and challenge derivation with Blake2s-256 (`--features blake`), which stwo-cairo
//! proves with a native opcode. Domain separation is by Blake2s personalization (8 bytes:
//! "bsb-leaf", "bsb-node", "bsb-root", "bsb-deal", "bsb-chal", "bsb-dset", "bsb-hold") instead of prefix
//! bytes, so every preimage is word-aligned:
//!
//!     leaf = B_leaf(chunk)                      (64 blocks)
//!     node = B_node(left ‖ right)               (one block)
//!     R = B_root(u64le(n) ‖ top), nonce = B_deal(seed ‖ R)
//!     idx = u64le(B_chal(nonce ‖ u32le(j))[0..8]) mod n
//!     D = B_dset(for each deal: R ‖ u64le(n))
//!
//! Words are little-endian, as the opcode takes them. model/zk_pdp.ts has the reference.

use core::blake::{blake2s_compress, blake2s_finalize};
use core::box::BoxImpl;
use crate::Digest;

// Initial states: the Blake2s IV xor the parameter block (32-byte digest, no key, fanout 1,
// depth 1, the personalization in words 6 and 7).
const IV_LEAF: [u32; 8] = [
    0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x32e1aac9, 0x3d81a875,
];
const IV_NODE: [u32; 8] = [
    0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x32e1aac9, 0x3e84a277,
];
const IV_ROOT: [u32; 8] = [
    0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x32e1aac9, 0x2f8fa26b,
];
const IV_DEAL: [u32; 8] = [
    0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x32e1aac9, 0x3781a87d,
];
const IV_CHAL: [u32; 8] = [
    0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x32e1aac9, 0x3781a57a,
];
const IV_HOLD: [u32; 8] = [
    0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x32e1aac9, 0x3f8ca271,
];
const IV_DSET: [u32; 8] = [
    0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x32e1aac9, 0x2f85be7d,
];

/// Blake2s of `words` (4 bytes each, at least one word) from initial state `iv`.
fn hash_words(iv: [u32; 8], words: Span<u32>) -> Digest {
    let mut state = BoxImpl::new(iv);
    let mut rest = words;
    let mut count: u32 = 0;
    while rest.len() > 16 {
        let block = rest.multi_pop_front::<16>().unwrap();
        count += 64;
        state = blake2s_compress(state, count, *block);
    }
    count += rest.len() * 4;
    let mut last: Array<u32> = rest.into();
    while last.len() != 16 {
        last.append(0);
    }
    let block: Box<[u32; 16]> = *last.span().try_into().unwrap();
    blake2s_finalize(state, count, block).unbox()
}

pub fn leaf_hash(leaf: Array<u32>, last: u32) -> Digest {
    assert(leaf.len() == 1024, 'leaf length');
    assert(last == 0, 'no last byte in blake mode');
    hash_words(IV_LEAF, leaf.span())
}

pub fn node(left: Digest, right: Digest) -> Digest {
    let mut m: Array<u32> = left.span().into();
    m.append_span(right.span());
    hash_words(IV_NODE, m.span())
}

pub fn root_hash(n: u32, top: Digest) -> Digest {
    let mut m: Array<u32> = array![n, 0];
    m.append_span(top.span());
    hash_words(IV_ROOT, m.span())
}

pub fn deal_nonce(seed: Digest, root: Digest) -> Digest {
    let mut m: Array<u32> = seed.span().into();
    m.append_span(root.span());
    hash_words(IV_DEAL, m.span())
}

/// Holdings mode: nonce = B_hold(seed ‖ D).
pub fn holdings_nonce(seed: Digest, deals_digest: Digest) -> Digest {
    let mut m: Array<u32> = seed.span().into();
    m.append_span(deals_digest.span());
    hash_words(IV_HOLD, m.span())
}

pub fn challenge_index(nonce: Digest, j: u32, n: u32) -> u32 {
    let mut m: Array<u32> = nonce.span().into();
    m.append(j);
    let [d0, d1, _, _, _, _, _, _] = hash_words(IV_CHAL, m.span());
    let lo: u64 = d0.into();
    let hi: u64 = d1.into();
    ((lo + hi * 0x100000000) % n.into()).try_into().unwrap()
}

pub fn append_deal(ref dset: Array<u32>, root: Digest, n: u32) {
    dset.append_span(root.span());
    dset.append(n);
    dset.append(0);
}

pub fn deals_digest(entries: Array<u32>) -> Digest {
    hash_words(IV_DSET, entries.span())
}
