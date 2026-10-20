// Holdings mode (model/zk_pdp.ts, mode 1) on the protocol's SHA-256 tree, for RISC Zero.
//
//   D     = H("bsb/zk-pdp/dset|" ‖ (R_i ‖ u64be(n_i))*)
//   nonce = H("bsb/zk-pdp/hold|" ‖ seed ‖ D)
//   g_j   = u64le(H("bsb/zk-pdp/chal|" ‖ nonce ‖ u32le(j))[0..8]) mod N,   N = Σ n_i,  j < q
//
// g_j falls in deal k at index g_j − (n_0 + … + n_(k-1)). Each opening is that chunk and its path in
// the storage_bonds.ts tree: leaf H(0x00 ‖ chunk), node H(0x01 ‖ l ‖ r), the last node paired with
// itself, root H(0x02 ‖ u64le(n) ‖ top). Any failed check panics, and a panicking guest has no
// receipt. The journal is statementOutput's 19 felts as big-endian u32s (zk_pdp.ts journalBytes):
// seed ‖ q ‖ mode ‖ deal count ‖ D, 76 bytes. Input layout: zk_pdp.ts risc0Witness.
//
// Every hash goes through the zkVM's SHA-256 accelerator (risc0_zkvm::sha::Impl).

#![no_main]

use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl, Sha256};

risc0_zkvm::guest::entry!(main);

const CHUNK: usize = 4096;
const MODE: u32 = 1;

fn sha(data: &[u8]) -> [u8; 32] {
    Impl::hash_bytes(data).as_bytes().try_into().unwrap()
}

fn read_u32() -> u32 {
    let mut b = [0u8; 4];
    env::read_slice(&mut b);
    u32::from_le_bytes(b)
}

fn read32() -> [u8; 32] {
    let mut b = [0u8; 32];
    env::read_slice(&mut b);
    b
}

/// Levels above the leaves in a tree of n chunks: storage_bonds.ts merkleVerify's depth.
fn depth(n: u32) -> u32 {
    let (mut d, mut w) = (0, n);
    while w > 1 {
        w = w.div_ceil(2);
        d += 1;
    }
    d
}

fn main() {
    let seed = read32();
    let q = read_u32();
    let count = read_u32() as usize;
    assert!(count >= 1, "no deals");

    let mut roots = Vec::with_capacity(count);
    let mut sizes = Vec::with_capacity(count);
    let mut dset = Vec::with_capacity(16 + 40 * count);
    dset.extend_from_slice(b"bsb/zk-pdp/dset|");
    let mut total: u64 = 0;
    for _ in 0..count {
        let root = read32();
        let n = read_u32();
        assert!(n >= 1, "empty deal");
        dset.extend_from_slice(&root);
        dset.extend_from_slice(&(n as u64).to_be_bytes());
        total += n as u64;
        roots.push(root);
        sizes.push(n);
    }
    assert!(total < 1 << 32, "over 2^32 chunks");
    let d = sha(&dset);

    let mut hold = [0u8; 80];
    hold[..16].copy_from_slice(b"bsb/zk-pdp/hold|");
    hold[16..48].copy_from_slice(&seed);
    hold[48..].copy_from_slice(&d);
    let nonce = sha(&hold);

    let mut chal = [0u8; 52];
    chal[..16].copy_from_slice(b"bsb/zk-pdp/chal|");
    chal[16..48].copy_from_slice(&nonce);
    let mut leaf = vec![0u8; 1 + CHUNK]; // 0x00 ‖ chunk
    let mut node = [0u8; 65];
    node[0] = 1;
    let mut top = [0u8; 41];
    top[0] = 2;

    for j in 0..q {
        chal[48..].copy_from_slice(&j.to_le_bytes());
        let c = sha(&chal);
        let mut g = u64::from_le_bytes(c[..8].try_into().unwrap()) % total;
        let mut k = 0;
        while g >= sizes[k] as u64 {
            g -= sizes[k] as u64;
            k += 1;
        }
        let idx = g as u32;

        assert_eq!(read_u32() as usize, k, "opening names the wrong deal");
        env::read_slice(&mut leaf[1..]);
        let mut h = sha(&leaf);
        let len = read_u32();
        assert_eq!(len, depth(sizes[k]), "path length");
        for lvl in 0..len {
            let sib = read32();
            if (idx >> lvl) & 1 == 1 {
                node[1..33].copy_from_slice(&sib);
                node[33..].copy_from_slice(&h);
            } else {
                node[1..33].copy_from_slice(&h);
                node[33..].copy_from_slice(&sib);
            }
            h = sha(&node);
        }
        top[1..9].copy_from_slice(&(sizes[k] as u64).to_le_bytes());
        top[9..].copy_from_slice(&h);
        assert_eq!(sha(&top), roots[k], "root mismatch");
    }

    let mut journal = [0u8; 76];
    journal[..32].copy_from_slice(&seed);
    journal[32..36].copy_from_slice(&q.to_be_bytes());
    journal[36..40].copy_from_slice(&MODE.to_be_bytes());
    journal[40..44].copy_from_slice(&(count as u32).to_be_bytes());
    journal[44..].copy_from_slice(&d);
    env::commit_slice(&journal);
}
