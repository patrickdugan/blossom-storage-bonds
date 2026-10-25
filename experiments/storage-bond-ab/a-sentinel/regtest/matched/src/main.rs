// Compiled from the unchanged original Rust Taproot sentinel harness by build.rs.
// Only its bond size (runtime 60k/40k) and output file path are parameterized.
include!(concat!(env!("OUT_DIR"), "/original_sentinel_adapted.rs"));
