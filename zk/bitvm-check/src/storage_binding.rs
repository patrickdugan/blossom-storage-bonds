//! Extra BitVM disprove leaf binding the asserted Groth16 input to this storage term.
//!
//! The graph pins the term prefix, RISC Zero wrapper constants, and the same WOTS public-input
//! key used by the Groth16 chunker. It also pins WOTS keys for the claimed chain tip. A validly
//! signed assertion opens this leaf iff the public input disagrees with the term's hash binding.
//! This is not a chain-work challenge or a complete bond graph.

use bitcoin_script_stack::stack::StackTracker;
use bitvm::hash::blake3::blake3_compute_script_with_limb;
use bitvm::hash::sha256_u4_stack::sha256_stack;
use bitvm::signatures::winternitz::{Converter, ToBytesConverter};
use bitvm::signatures::{Wots, Wots32, Wots4};
use bitvm::treepp::{script, Script};

pub struct BindingKeys {
    pub public_input: <Wots32 as Wots>::PublicKey,
    pub tip_height: <Wots4 as Wots>::PublicKey,
    pub tip_hash: <Wots32 as Wots>::PublicKey,
    pub total_work: <Wots32 as Wots>::PublicKey,
}

fn reverse_top(count: usize) -> Script {
    script! { for i in 1..count { { i } OP_ROLL } }
}

pub(crate) fn bytes_to_alt(count: usize) -> Script {
    script! { for _ in 0..count { OP_TOALTSTACK } }
}

// Convert numeric bytes (first byte on top) to normal-order high/low nibbles.
pub(crate) fn bytes_to_nibbles(count: usize) -> Script {
    script! {
        for _ in 0..count {
            0 OP_SWAP
            for (threshold, value) in [(128, 8), (64, 4), (32, 2), (16, 1)] {
                OP_DUP { threshold } OP_GREATERTHANOREQUAL
                OP_IF { threshold } OP_SUB OP_SWAP { value } OP_ADD OP_SWAP OP_ENDIF
            }
            OP_SWAP OP_TOALTSTACK OP_TOALTSTACK
        }
        for _ in 0..count * 2 { OP_FROMALTSTACK }
        { reverse_top(count * 2) }
    }
}

// BitVM's BLAKE3 input reverses bytes inside each u32 word, not the word order.
pub(crate) fn blake3_word_order() -> Script {
    script! {
        for _ in 0..8 {
            for depth in [6, 4, 2, 0] {
                { depth } OP_ROLL OP_TOALTSTACK
                { depth } OP_ROLL OP_TOALTSTACK
            }
        }
        for _ in 0..64 { OP_FROMALTSTACK }
    }
}

fn hash_term() -> Script {
    let mut tracker = StackTracker::new();
    script! {
        { bytes_to_nibbles(202) }
        { sha256_stack(&mut tracker, 202, false, false) }
    }
}

/// prefix = domain || hold ID || chain ID || u32be(q, deal count) || D ||
///          u32be(first, step, epoch count, depth), exactly 134 bytes.
/// The 68-byte suffix is u32be(tip height) || internal tip hash || u256be(total work).
/// Witness order (bottom to top): work signature, hash signature, height signature, public signature.
/// BitVM's public message is a BE scalar with the two nibbles of each byte swapped
/// (chunk/elements.rs serialize_to_byte_array). It is neither ordinary BE nor LE encoding.
pub fn disprove_term_binding(
    prefix: &[u8; 134],
    constants_digest: &[u8; 32],
    keys: &BindingKeys,
) -> Script {
    script! {
        { bound_digest(prefix, constants_digest, keys) }
        { public_input_mismatch() }
    }
}

// Both binding formats leave the expected BLAKE3 nibbles on the main stack and
// the signed chunker public-input bytes on the alt stack.
pub(crate) fn public_input_mismatch() -> Script {
    script! {
        // Truncate to 31 bytes, prepend zero, and compare the nibble-swapped BE scalar.
        OP_2DROP
        { bytes_to_alt(62) }
        0 0
        for _ in 0..62 { OP_FROMALTSTACK }
        for _ in 0..32 { OP_FROMALTSTACK }
        { bytes_to_nibbles(32) }
        for _ in 0..32 { OP_SWAP OP_TOALTSTACK OP_TOALTSTACK }
        for _ in 0..64 { OP_FROMALTSTACK }
        for i in (1..=64).rev() { { i } OP_ROLL OP_EQUAL OP_TOALTSTACK }
        1
        for _ in 0..64 { OP_FROMALTSTACK OP_BOOLAND }
        OP_NOT
    }
}
fn signed_journal(prefix: &[u8; 134], keys: &BindingKeys) -> Script {
    script! {
        { Wots32::checksig_verify(&keys.public_input) }
        { ToBytesConverter::get_script(&Wots32::PARAMETERS) }
        { bytes_to_alt(32) }
        { Wots4::checksig_verify(&keys.tip_height) }
        { ToBytesConverter::get_script(&Wots4::PARAMETERS) }
        { bytes_to_alt(4) }
        { Wots32::checksig_verify(&keys.tip_hash) }
        { ToBytesConverter::get_script(&Wots32::PARAMETERS) }
        { bytes_to_alt(32) }
        { Wots32::checksig_verify(&keys.total_work) }
        { ToBytesConverter::get_script(&Wots32::PARAMETERS) }
        { bytes_to_alt(32) }

        // Restore the dynamic suffix in reverse byte order, then prepend the pinned prefix.
        for _ in 0..68 { OP_FROMALTSTACK }
        for byte in prefix.iter().rev() { { *byte } }
        { hash_term() }

    }
}

fn bound_digest(prefix: &[u8; 134], constants_digest: &[u8; 32], keys: &BindingKeys) -> Script {
    script! {
        { signed_journal(prefix, keys) }
        { wrap_journal_digest(constants_digest) }
    }
}

pub(crate) fn wrap_journal_digest(constants_digest: &[u8; 32]) -> Script {
    script! {
        { bytes_to_alt(64) }
        for word in constants_digest.chunks_exact(4) {
            for byte in word.iter().rev() { { *byte >> 4 } { *byte & 15 } }
        }
        for _ in 0..64 { OP_FROMALTSTACK }
        { blake3_word_order() }
        { blake3_compute_script_with_limb(64, 4) }
    }
}

/// Proposed extra commitment for future graphs. Open on either an incorrect
/// Groth16 public input or a signed journal inconsistent with the original term.
/// This only punishes the provider's own inconsistent storage assertion. Reusing
/// its key in an opponent's binding does not pin a value: that provider can sign
/// another journal. Cross-party use needs value binding or an explicit, funded
/// equivocation game with enforceable response and withdrawal deadlines.
/// Witness order adds the journal signature above the existing four signatures.
pub fn disprove_term_binding_with_journal(
    prefix: &[u8; 134],
    constants_digest: &[u8; 32],
    keys: &BindingKeys,
    journal_key: &<Wots32 as Wots>::PublicKey,
) -> Script {
    script! {
        { Wots32::checksig_verify(journal_key) }
        { ToBytesConverter::get_script(&Wots32::PARAMETERS) }
        { bytes_to_alt(32) }
        { signed_journal(prefix, keys) }
        // Keep the computed term hash while comparing a copy with the signed journal.
        for _ in 0..64 { 63 OP_PICK }
        for _ in 0..32 { OP_FROMALTSTACK }
        for _ in 0..32 { OP_FROMALTSTACK }
        // Restore the public scalar to the alt stack, leaving the journal on top.
        for _ in 0..32 { 32 OP_ROLL OP_TOALTSTACK }
        { bytes_to_nibbles(32) }
        for i in (1..=64).rev() { { i } OP_ROLL OP_EQUAL OP_TOALTSTACK }
        1
        for _ in 0..64 { OP_FROMALTSTACK OP_BOOLAND }
        OP_NOT
        // Move the journal mismatch flag underneath the public scalar on the alt stack.
        for _ in 0..32 { OP_FROMALTSTACK }
        32 OP_ROLL OP_TOALTSTACK
        { bytes_to_alt(32) }
        { wrap_journal_digest(constants_digest) }
        { public_input_mismatch() }
        OP_FROMALTSTACK OP_BOOLOR
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};
    use bitcoin::hashes::{sha256 as native_sha256, Hash};
    use bitvm::execute_script;
    use serde_json::Value;
    use std::str::FromStr;

    fn bytes(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    struct Fixture {
        prefix: [u8; 134],
        constants: [u8; 32],
        tip: [u8; 4],
        hash: [u8; 32],
        work: [u8; 32],
        public: [u8; 32],
        journal: [u8; 32],
    }

    fn fixture() -> Fixture {
        let result: Value =
            serde_json::from_str(include_str!("../../../results/bitvm2-spike.json")).unwrap();
        let preimage = bytes(result["m2"]["term"]["preimage"].as_str().unwrap());
        assert_eq!(preimage.len(), 202);
        Fixture {
            prefix: preimage[..134].try_into().unwrap(),
            constants: bytes(
                result["m3"]["groth16"]["constants_digest"]
                    .as_str()
                    .unwrap(),
            )
            .try_into()
            .unwrap(),
            tip: preimage[134..138].try_into().unwrap(),
            hash: preimage[138..170].try_into().unwrap(),
            work: preimage[170..202].try_into().unwrap(),
            public: Fr::from_str(
                result["m3"]["groth16"]["public_output_dec"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap()
            .into_bigint()
            .to_bytes_be()
            .into_iter()
            .map(|b| b.rotate_left(4))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
            journal: bytes(result["m2"]["term"]["journal"].as_str().unwrap())
                .try_into()
                .unwrap(),
        }
    }

    // Test keys are generated afresh. These signatures are interpreter fixtures, never for funds.
    struct Signer {
        public: Vec<u8>,
        tip: Vec<u8>,
        hash: Vec<u8>,
        work: Vec<u8>,
    }
    impl Signer {
        fn new() -> Self {
            Self {
                public: Wots32::generate_secret_key(),
                tip: Wots4::generate_secret_key(),
                hash: Wots32::generate_secret_key(),
                work: Wots32::generate_secret_key(),
            }
        }
        fn keys(&self) -> BindingKeys {
            BindingKeys {
                public_input: Wots32::generate_public_key(&self.public),
                tip_height: Wots4::generate_public_key(&self.tip),
                tip_hash: Wots32::generate_public_key(&self.hash),
                total_work: Wots32::generate_public_key(&self.work),
            }
        }
        fn witness(&self, f: &Fixture) -> Script {
            script! {
                { Wots32::sign_to_raw_witness(&self.work, &f.work) }
                { Wots32::sign_to_raw_witness(&self.hash, &f.hash) }
                { Wots4::sign_to_raw_witness(&self.tip, &f.tip) }
                { Wots32::sign_to_raw_witness(&self.public, &f.public) }
            }
        }
    }

    #[test]
    fn storage_binding_signed_journal_has_correct_byte_order() {
        let f = fixture();
        let signer = Signer::new();
        let result = execute_script(script! {
            { signer.witness(&f) }
            { signed_journal(&f.prefix, &signer.keys()) }
            for byte in f.journal.iter().rev() { { *byte & 15 } OP_EQUALVERIFY { *byte >> 4 } OP_EQUALVERIFY }
            1
        });
        assert!(
            result.success,
            "signed journal error {:?}, max stack {}",
            result.error, result.stats.max_nb_stack_items
        );
    }

    #[test]
    fn storage_binding_digest_has_correct_public_scalar_byte_order() {
        let f = fixture();
        let signer = Signer::new();
        let result = execute_script(script! {
            { signer.witness(&f) }
            { bound_digest(&f.prefix, &f.constants, &signer.keys()) }
            OP_2DROP
            for byte in f.public.iter().skip(1).rev() { { *byte >> 4 } OP_EQUALVERIFY { *byte & 15 } OP_EQUALVERIFY }
            1
        });
        assert!(
            result.success,
            "binding digest error {:?}, max stack {}",
            result.error, result.stats.max_nb_stack_items
        );
    }
    #[test]
    fn storage_binding_sha256_layout_matches_real_term_journal() {
        let f = fixture();
        let preimage = [f.prefix.as_slice(), &f.tip, &f.hash, &f.work].concat();
        assert_eq!(
            native_sha256::Hash::hash(&preimage).to_byte_array(),
            f.journal
        );
        let s = script! {
            for byte in preimage.iter().rev() { { *byte } }
            { hash_term() }
            for byte in f.journal.iter().rev() { { *byte & 15 } OP_EQUALVERIFY { *byte >> 4 } OP_EQUALVERIFY }
            1
        };
        let result = execute_script(s);
        assert!(
            result.success,
            "error {:?}, max stack {}, final items {}",
            result.error,
            result.stats.max_nb_stack_items,
            result.final_stack.len()
        );
        assert!(result.stats.max_nb_stack_items <= 1000);
    }

    #[test]
    fn storage_binding_honest_term_cannot_be_disproved() {
        let f = fixture();
        let signer = Signer::new();
        let leaf = disprove_term_binding(&f.prefix, &f.constants, &signer.keys());
        let bytes = leaf.len();
        let result = execute_script(script! { { signer.witness(&f) } { leaf } });
        assert!(
            result.error.is_none(),
            "honest evaluation must reach false rather than fail an opcode: {:?}",
            result.error
        );
        assert!(
            !result.success,
            "error {:?}, max stack {}, final items {}",
            result.error,
            result.stats.max_nb_stack_items,
            result.final_stack.len()
        );
        assert_eq!(result.final_stack.len(), 1);
        assert!(result.stats.max_nb_stack_items <= 1000);
        println!(
            "storage binding leaf: {bytes} script bytes; max stack {}",
            result.stats.max_nb_stack_items
        );
    }

    #[test]
    fn storage_binding_slashes_signed_public_input_for_another_term() {
        let f = fixture();
        let signer = Signer::new();
        let mut prefix = f.prefix;
        // q is the first u32 after the 14-byte domain and two image IDs.
        prefix[81] ^= 1;
        let result = execute_script(
            script! { { signer.witness(&f) } { disprove_term_binding(&prefix, &f.constants, &signer.keys()) } },
        );
        assert!(
            result.success,
            "error {:?}, max stack {}, final items {}",
            result.error,
            result.stats.max_nb_stack_items,
            result.final_stack.len()
        );
        assert!(result.stats.max_nb_stack_items <= 1000);
    }

    #[test]
    fn storage_binding_slashes_changed_tip_and_wrong_public_and_image() {
        for which in 0..5 {
            let mut f = fixture();
            let signer = Signer::new();
            match which {
                0 => f.tip[3] ^= 1,
                1 => f.hash[0] ^= 1,
                2 => f.public[0] ^= 1,
                3 => f.work[31] ^= 1,
                _ => f.constants[0] ^= 1,
            }
            let result = execute_script(
                script! { { signer.witness(&f) } { disprove_term_binding(&f.prefix, &f.constants, &signer.keys()) } },
            );
            assert!(
                result.success,
                "case {which}: {:?}, stack {}",
                result.error, result.stats.max_nb_stack_items
            );
            assert!(result.stats.max_nb_stack_items <= 1000);
        }
    }

    #[test]
    fn storage_binding_wrong_signer_cannot_open_disprove_leaf() {
        let f = fixture();
        let signer = Signer::new();
        let wrong = Signer::new();
        let result = execute_script(
            script! { { wrong.witness(&f) } { disprove_term_binding(&f.prefix, &f.constants, &signer.keys()) } },
        );
        assert!(!result.success);
        assert!(
            result.error.is_some(),
            "a signature must fail before the binding verdict"
        );
    }

    #[test]
    fn term_journal_commitment_matches_the_same_signed_term() {
        let mut maximum_stack = 0;
        let mut script_bytes = 0;
        for case in 0..4 {
            let mut f = fixture();
            let signer = Signer::new();
            let journal_secret = Wots32::generate_secret_key();
            let journal_key = Wots32::generate_public_key(&journal_secret);
            let mut journal = f.journal;
            if case & 1 != 0 {
                journal[0] ^= 1;
            }
            if case & 2 != 0 {
                f.public[0] ^= 1;
            }
            let leaf = disprove_term_binding_with_journal(
                &f.prefix,
                &f.constants,
                &signer.keys(),
                &journal_key,
            );
            let result = execute_script(script! {
                { signer.witness(&f) }
                { Wots32::sign_to_raw_witness(&journal_secret, &journal) }
                { leaf.clone() }
            });
            assert_eq!(
                result.success,
                case != 0,
                "journal binding case {case}: {:?}",
                result.error
            );
            assert!(leaf.len() < 3_984_000 && result.stats.max_nb_stack_items <= 1000);
            maximum_stack = maximum_stack.max(result.stats.max_nb_stack_items);
            script_bytes = leaf.len();
        }
        println!(
            "BSB_BINDING_STATS {}",
            serde_json::json!({"kind":"original-term-plus-journal-arithmetic","script_bytes":script_bytes,"max_stack_items":maximum_stack,"measured_cases":4,"scope":"Proposed journal commitment for future setup only; existing graph remains unchanged."})
        );
    }

    #[test]
    fn term_journal_commitment_rejects_an_unrelated_key() {
        let f = fixture();
        let signer = Signer::new();
        let secret = Wots32::generate_secret_key();
        let wrong_key = Wots32::generate_public_key(&Wots32::generate_secret_key());
        let result = execute_script(script! {
            { signer.witness(&f) }
            { Wots32::sign_to_raw_witness(&secret, &f.journal) }
            { disprove_term_binding_with_journal(&f.prefix, &f.constants, &signer.keys(), &wrong_key) }
        });
        assert!(!result.success && result.error.is_some());
    }
}
