//! Resource measurement only: hashing and WOTS witness shape, not a fork-dispute leaf.
use bitcoin::hashes::{sha256, Hash};
use bitcoin_script_stack::stack::StackTracker;
use bitvm::hash::sha256_u4_stack::sha256_stack;
use bitvm::signatures::{Wots, Wots32, Wots4};
use bitvm::treepp::script;
use serde_json::json;

fn measured(name: &str, bytes: &[u8]) -> serde_json::Value {
    let expected = sha256::Hash::hash(bytes).to_byte_array();
    let mut tracker = StackTracker::new();
    let hash = sha256_stack(&mut tracker, bytes.len().try_into().unwrap(), false, false);
    let size = hash.len();
    let result = bitvm::execute_script(script! {
        for byte in bytes { { *byte >> 4 } { *byte & 15 } }
        { hash }
        for byte in expected.iter().rev() {
            { *byte & 15 } OP_EQUALVERIFY { *byte >> 4 } OP_EQUALVERIFY
        }
        1
    });
    json!({"name":name,"statement_bytes":bytes.len(),"native_sha256":expected.iter().map(|b|format!("{b:02x}")).collect::<String>(),
        "hash_script_bytes":size,"native_hash_matches":result.success,"interpreter_error":format!("{:?}",result.error),"max_stack_items":result.stats.max_nb_stack_items})
}
fn run() {
    let file = std::env::args()
        .nth(1)
        .expect("fork-binding-cost <v1-statement.bin>");
    let statement = std::fs::read(file).unwrap();
    assert_eq!(statement.len(), 354);
    assert_eq!(&statement[..14], b"bsb/r0-fork|v1");
    // A possible projection retains graph, term digest and both compared tip triples.
    // The original tip is already committed by the term digest. Divergence remains
    // a checked existential witness of the relation. No v2 guest is proved here.
    let mut projection = b"bsb/r0-fork|v2".to_vec();
    projection.extend_from_slice(&statement[14..78]);
    projection.extend_from_slice(&statement[146..282]);
    assert_eq!(projection.len(), 214);
    let key32 = Wots32::generate_secret_key();
    let key4 = Wots4::generate_secret_key();
    let witness32 = Wots32::sign_to_raw_witness(&key32, &[0u8; 32]);
    let witness4 = Wots4::sign_to_raw_witness(&key4, &[0u8; 4]);
    let count32 = witness32.len();
    let count4 = witness4.len();
    let v1 = measured("full-v1-statement", &statement);
    let projected = measured("projected-v2-statement", &projection);
    assert_eq!(
        projected["native_hash_matches"], true,
        "projection hashing must execute correctly"
    );
    println!(
        "{}",
        json!({"bitvm_rev":"7d1ca36","hash_modes":[v1,projected],"wots":{"items_per_32_byte_signature":count32,"items_per_4_byte_signature":count4,
        "v1_signatures_32_byte":10,"v1_signatures_4_byte":5,"v1_initial_witness_items":10*count32+5*count4,
        "projected_signatures_32_byte":6,"projected_signatures_4_byte":2,"projected_initial_witness_items":6*count32+2*count4},
        "scope":"Current SHA/WOTS resource measurements only. Does not include BLAKE3, WOTS verification, transaction overhead or a proved compact certificate. Does not solve permissionless challenge-input binding."})
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
