//! The protocol's chunk tree (model/storage_bonds.ts) and the epoch's challenge derivation, with
//! SHA-256. Words are big-endian. The 16-byte tags keep the challenge preimages word-aligned; the
//! tree's one-byte prefixes do not, so `shift_in` realigns those.

use core::integer::u32_safe_divmod;
use crate::Digest;
use crate::sha256::compute_sha256_u32_array;

const B256: NonZero<u32> = 0x100;

/// leaf = SHA256(0x00 ‖ chunk). `leaf` holds the first 4096 of the 4097 preimage bytes, so its
/// first word's top byte must be the zero prefix; `last` is the chunk's last byte.
pub fn leaf_hash(leaf: Array<u32>, last: u32) -> Digest {
    assert(leaf.len() == 1024, 'leaf length');
    assert(*leaf[0] < 0x1000000, 'leaf prefix is not 0x00');
    assert(last < 0x100, 'leaf last byte');
    compute_sha256_u32_array(leaf, last, 1)
}

/// node = SHA256(0x01 ‖ left ‖ right): 65 bytes.
pub fn node(left: Digest, right: Digest) -> Digest {
    let mut m: Array<u32> = array![];
    let carry = shift_in(0x01, left.span(), ref m);
    let tail = shift_in(carry, right.span(), ref m);
    compute_sha256_u32_array(m, tail, 1)
}

/// R = SHA256(0x02 ‖ u64le(n) ‖ top): 41 bytes. n < 2^32, so bytes 5..8 of the preimage are
/// zero, and the last of them prefixes `top`.
pub fn root_hash(n: u32, top: Digest) -> Digest {
    let (b012, b3) = u32_safe_divmod(bswap(n), B256);
    let mut m: Array<u32> = array![0x02000000 + b012, b3 * 0x1000000];
    let tail = shift_in(0, top.span(), ref m);
    compute_sha256_u32_array(m, tail, 1)
}

/// nonce = SHA256("bsb/zk-pdp/deal|" ‖ seed ‖ R): 80 bytes.
pub fn deal_nonce(seed: Digest, root: Digest) -> Digest {
    let mut m: Array<u32> = array![0x6273622f, 0x7a6b2d70, 0x64702f64, 0x65616c7c];
    m.append_span(seed.span());
    m.append_span(root.span());
    compute_sha256_u32_array(m, 0, 0)
}

/// idx = u64le(SHA256("bsb/zk-pdp/chal|" ‖ nonce ‖ u32le(j))[0..8]) mod n.
pub fn challenge_index(nonce: Digest, j: u32, n: u32) -> u32 {
    let mut m: Array<u32> = array![0x6273622f, 0x7a6b2d70, 0x64702f63, 0x68616c7c];
    m.append_span(nonce.span());
    m.append(bswap(j));
    let [d0, d1, _, _, _, _, _, _] = compute_sha256_u32_array(m, 0, 0);
    let lo: u64 = bswap(d0).into();
    let hi: u64 = bswap(d1).into();
    ((lo + hi * 0x100000000) % n.into()).try_into().unwrap()
}

/// Deal list entry: R ‖ u64be(n).
pub fn append_deal(ref dset: Array<u32>, root: Digest, n: u32) {
    dset.append_span(root.span());
    dset.append(0);
    dset.append(n);
}

/// D = SHA256("bsb/zk-pdp/dset|" ‖ entries).
pub fn deals_digest(entries: Array<u32>) -> Digest {
    let mut m: Array<u32> = array![0x6273622f, 0x7a6b2d70, 0x64702f64, 0x7365747c];
    m.append_span(entries.span());
    compute_sha256_u32_array(m, 0, 0)
}

/// Appends `prefix` (one byte) ‖ words to `out` as big-endian words, all but the final byte,
/// which it returns.
fn shift_in(prefix: u32, words: Span<u32>, ref out: Array<u32>) -> u32 {
    let mut carry = prefix;
    for w in words {
        let (hi, lo) = u32_safe_divmod(*w, B256);
        out.append(carry * 0x1000000 + hi);
        carry = lo;
    }
    carry
}

fn bswap(x: u32) -> u32 {
    let (x, b0) = u32_safe_divmod(x, B256);
    let (x, b1) = u32_safe_divmod(x, B256);
    let (b3, b2) = u32_safe_divmod(x, B256);
    b0 * 0x1000000 + b1 * 0x10000 + b2 * 0x100 + b3
}

#[cfg(test)]
mod tests {
    #[test]
    fn bswap() {
        assert_eq!(super::bswap(0x01020304), 0x04030201);
    }
}
