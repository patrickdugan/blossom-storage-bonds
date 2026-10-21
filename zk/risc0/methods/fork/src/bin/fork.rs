//! Research certificate only: proves a relative work comparison, not Bitcoin canonicality.
#![no_main]
#[path = "../../../../fork_relation.rs"]
mod fork_relation;
use borsh::BorshDeserialize;
use risc0_zkvm::{
    guest::env,
    sha::{Impl, Sha256},
};
risc0_zkvm::guest::entry!(main);
fn sha(bytes: &[u8]) -> [u8; 32] {
    Impl::hash_bytes(bytes).as_bytes().try_into().unwrap()
}
fn main() {
    let input =
        fork_relation::ForkInput::deserialize_reader(&mut env::stdin()).expect("fork input");
    let statement = fork_relation::check(&input, sha).expect("invalid fork comparison");
    for chain in [&input.original, &input.response, &input.candidate] {
        env::verify(
            fork_relation::HEADER_CHAIN_ID,
            &borsh::to_vec(&chain.output).unwrap(),
        )
        .unwrap();
    }
    env::commit_slice(&sha(&statement));
}
