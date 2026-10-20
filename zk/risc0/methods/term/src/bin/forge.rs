// Not part of the protocol: a guest that commits whatever header-chain output the host hands it.
// bsb-r0 forge-demo uses it to show that one step of the genuine header-chain image, with zero
// headers, turns this into a receipt of that image with a made-up chain state (term.rs, header).

#![no_main]

use borsh::BorshDeserialize;
use risc0_to_bitvm2_core::header_chain::BlockHeaderCircuitOutput;
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    let out = BlockHeaderCircuitOutput::deserialize_reader(&mut env::stdin()).expect("output");
    env::commit_slice(&borsh::to_vec(&out).unwrap());
}
