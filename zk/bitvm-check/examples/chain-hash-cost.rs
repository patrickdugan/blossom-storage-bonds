//! Measure header double-SHA256 without assuming it proves chain membership or work.
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::Network;
use bitcoin_script_stack::stack::StackTracker;
use bitvm::hash::sha256_u4_stack::sha256_stack;
use bitvm::treepp::script;
use serde_json::json;

fn run() {
    let raw = serialize(&bitcoin::blockdata::constants::genesis_block(Network::Regtest).header);
    assert_eq!(raw.len(), 80);
    let expected = sha256d::Hash::hash(&raw).to_byte_array();
    let mut modes = Vec::new();
    for (add, xor) in [(false, false), (true, false), (false, true), (true, true)] {
        let mut first = StackTracker::new();
        let h80 = sha256_stack(&mut first, 80, add, xor);
        let mut second = StackTracker::new();
        let h32 = sha256_stack(&mut second, 32, add, xor);
        let kernel_bytes = h80.len() + h32.len();
        let full = script! {
            for byte in &raw { { *byte >> 4 } { *byte & 15 } }
            { h80 }
            { h32 }
            for byte in expected.iter().rev() {
                { *byte & 15 } OP_EQUALVERIFY { *byte >> 4 } OP_EQUALVERIFY
            }
            1
        };
        let result = bitvm::execute_script(full);
        assert!(
            result.success,
            "header hash must match native SHA256d: {:?}",
            result.error
        );
        modes.push(json!({
            "add_table": add, "full_xor_table": xor,
            "sha80_script_bytes": first.get_script().len(),
            "sha32_script_bytes": second.get_script().len(),
            "double_sha_script_bytes": kernel_bytes,
            "native_header_hash_matches": result.success,
            "interpreter_error": format!("{:?}", result.error),
            "max_stack_items": result.stats.max_nb_stack_items,
            "headers_under_block_limit_hashing_only": 3_984_000usize / kernel_bytes,
            "33_headers_hashing_only_bytes": 33 * kernel_bytes,
        }));
    }
    println!(
        "{}",
        json!({
            "bitvm_rev": "7d1ca36", "header": "Bitcoin Core regtest genesis",
            "raw_header_bytes": raw.len(), "modes": modes,
            "scope": "Hashing feasibility only. Excludes authentication, linking, PoW/difficulty, timestamps, work arithmetic, fork exclusion, transaction overhead and other witnesses. Not a chain-work verifier."
        })
    );
}

fn main() {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(run)
        .unwrap()
        .join()
        .unwrap();
}
