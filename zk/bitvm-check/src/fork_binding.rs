//! Binding arithmetic for a proposed compact relative-work statement.
//! This supplies neither a compact-certificate guest nor challenger-key registration.
use crate::storage_binding::{
    blake3_word_order, bytes_to_alt, bytes_to_nibbles, public_input_mismatch,
};
use bitcoin_script_stack::stack::StackTracker;
use bitvm::hash::{blake3::blake3_compute_script_with_limb, sha256_u4_stack::sha256_stack};
use bitvm::signatures::winternitz::{Converter, ToBytesConverter};
use bitvm::signatures::{Wots, Wots32, Wots4};
use bitvm::treepp::{script, Script};

pub struct ForkBindingKeys {
    pub public_input: <Wots32 as Wots>::PublicKey,
    pub term_journal: <Wots32 as Wots>::PublicKey,
    pub response_height: <Wots4 as Wots>::PublicKey,
    pub response_hash: <Wots32 as Wots>::PublicKey,
    pub response_work: <Wots32 as Wots>::PublicKey,
    pub candidate_height: <Wots4 as Wots>::PublicKey,
    pub candidate_hash: <Wots32 as Wots>::PublicKey,
    pub candidate_work: <Wots32 as Wots>::PublicKey,
}

/// Proposed v2: domain || fixed graph ID || term journal || response triple || candidate triple.
/// The term journal already binds the original triple. The proof relation must retain its
/// original-tip membership and seed-divergence checks, even though those witnesses are private.
/// Witness order is reversed field order, ending with the chunker's nibble-swapped public scalar.
/// This leaf opens exactly on a binding mismatch under the caller's eight fixed WOTS keys.
pub fn disprove_compact_fork_binding(
    graph_id: &[u8; 32],
    constants_digest: &[u8; 32],
    keys: &ForkBindingKeys,
) -> Script {
    let mut prefix = b"bsb/r0-fork|v2".to_vec();
    prefix.extend_from_slice(graph_id);
    let mut tracker = StackTracker::new();
    script! {
        { Wots32::checksig_verify(&keys.public_input) }
        { ToBytesConverter::get_script(&Wots32::PARAMETERS) }
        { bytes_to_alt(32) }
        { Wots32::checksig_verify(&keys.term_journal) }
        { ToBytesConverter::get_script(&Wots32::PARAMETERS) }
        { bytes_to_alt(32) }
        { Wots4::checksig_verify(&keys.response_height) }
        { ToBytesConverter::get_script(&Wots4::PARAMETERS) }
        { bytes_to_alt(4) }
        { Wots32::checksig_verify(&keys.response_hash) }
        { ToBytesConverter::get_script(&Wots32::PARAMETERS) }
        { bytes_to_alt(32) }
        { Wots32::checksig_verify(&keys.response_work) }
        { ToBytesConverter::get_script(&Wots32::PARAMETERS) }
        { bytes_to_alt(32) }
        { Wots4::checksig_verify(&keys.candidate_height) }
        { ToBytesConverter::get_script(&Wots4::PARAMETERS) }
        { bytes_to_alt(4) }
        { Wots32::checksig_verify(&keys.candidate_hash) }
        { ToBytesConverter::get_script(&Wots32::PARAMETERS) }
        { bytes_to_alt(32) }
        { Wots32::checksig_verify(&keys.candidate_work) }
        { ToBytesConverter::get_script(&Wots32::PARAMETERS) }
        { bytes_to_alt(32) }
        for _ in 0..168 { OP_FROMALTSTACK }
        for byte in prefix.iter().rev() { { *byte } }
        { bytes_to_nibbles(214) }
        { sha256_stack(&mut tracker,214,false,false) }
        { bytes_to_alt(64) }
        for word in constants_digest.chunks_exact(4) {
            for byte in word.iter().rev() { { *byte >> 4 } { *byte & 15 } }
        }
        for _ in 0..64 { OP_FROMALTSTACK }
        { blake3_word_order() }
        { blake3_compute_script_with_limb(64,4) }
        { public_input_mismatch() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::{sha256, Hash};
    use serde_json::Value;
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    struct Fixture {
        graph: [u8; 32],
        constants: [u8; 32],
        fields: Vec<Vec<u8>>,
    }
    fn fixture() -> Fixture {
        let v: Value = serde_json::from_str(include_str!(
            "../../../results/bitvm-cumulative-work-certificate.json"
        ))
        .unwrap();
        let full = unhex(v["statement_preimage"].as_str().unwrap());
        assert_eq!(full.len(), 354);
        let graph = full[14..46].try_into().unwrap();
        let constants = [42u8; 32];
        let mut statement = b"bsb/r0-fork|v2".to_vec();
        statement.extend_from_slice(&full[14..78]);
        statement.extend_from_slice(&full[146..282]);
        let journal = sha256::Hash::hash(&statement).to_byte_array();
        let digest = blake3::hash(&[constants.as_slice(), journal.as_slice()].concat());
        let mut public = vec![0];
        public.extend_from_slice(&digest.as_bytes()[..31]);
        for byte in &mut public {
            *byte = byte.rotate_left(4);
        }
        let fields = vec![
            public,
            full[46..78].to_vec(),
            full[146..150].to_vec(),
            full[150..182].to_vec(),
            full[182..214].to_vec(),
            full[214..218].to_vec(),
            full[218..250].to_vec(),
            full[250..282].to_vec(),
        ];
        Fixture {
            graph,
            constants,
            fields,
        }
    }
    struct Signer {
        secrets: Vec<Vec<u8>>,
        keys: ForkBindingKeys,
    }
    impl Signer {
        fn new() -> Self {
            let secrets: Vec<Vec<u8>> = (0..8)
                .map(|i| {
                    if i == 2 || i == 5 {
                        Wots4::generate_secret_key()
                    } else {
                        Wots32::generate_secret_key()
                    }
                })
                .collect();
            let keys = ForkBindingKeys {
                public_input: Wots32::generate_public_key(&secrets[0]),
                term_journal: Wots32::generate_public_key(&secrets[1]),
                response_height: Wots4::generate_public_key(&secrets[2]),
                response_hash: Wots32::generate_public_key(&secrets[3]),
                response_work: Wots32::generate_public_key(&secrets[4]),
                candidate_height: Wots4::generate_public_key(&secrets[5]),
                candidate_hash: Wots32::generate_public_key(&secrets[6]),
                candidate_work: Wots32::generate_public_key(&secrets[7]),
            };
            Self { secrets, keys }
        }
        fn witness(&self, f: &Fixture) -> Script {
            script! { for i in (0..8).rev() {
                if i==2||i==5 { { Wots4::sign_to_raw_witness(&self.secrets[i],f.fields[i].as_slice().try_into().unwrap()) } }
                else { { Wots32::sign_to_raw_witness(&self.secrets[i],f.fields[i].as_slice().try_into().unwrap()) } }
            } }
        }
    }
    #[test]
    fn honest_binding_is_closed_and_every_field_mismatch_opens() {
        let mut f = fixture();
        let signer = Signer::new();
        let leaf = disprove_compact_fork_binding(&f.graph, &f.constants, &signer.keys);
        assert!(leaf.len() < 3_984_000);
        let honest = bitvm::execute_script(script! {{ signer.witness(&f) } { leaf.clone() }});
        assert!(
            honest.error.is_none(),
            "honest binding aborted: {:?}",
            honest.error
        );
        assert_eq!(honest.final_stack.len(), 1);
        assert!(!honest.success, "honest compact binding opened");
        assert!(honest.stats.max_nb_stack_items <= 1000);
        let mut maximum_stack = honest.stats.max_nb_stack_items;
        for index in 0..8 {
            let signer = Signer::new();
            let leaf = disprove_compact_fork_binding(&f.graph, &f.constants, &signer.keys);
            let changed_byte = f.fields[index].len() - 1;
            f.fields[index][changed_byte] ^= 1;
            let result = bitvm::execute_script(script! {{ signer.witness(&f) } { leaf.clone() }});
            assert!(result.success, "mismatch {index}: {:?}", result.error);
            assert!(result.stats.max_nb_stack_items <= 1000);
            maximum_stack = maximum_stack.max(result.stats.max_nb_stack_items);
            f.fields[index][changed_byte] ^= 1;
        }
        println!(
            "BSB_BINDING_STATS {}",
            serde_json::json!({"kind":"compact-fork-arithmetic","script_bytes":leaf.len(),"max_stack_items":maximum_stack,"measured_cases":9,"scope":"Proposed compact binding only; no compact guest or graph registration."})
        );
    }
    #[test]
    fn setup_identity_and_constants_are_bound() {
        let mut f = fixture();
        let signer = Signer::new();
        let witness = signer.witness(&f);
        f.graph[0] ^= 1;
        assert!(bitvm::execute_script(script! {{ witness.clone() } { disprove_compact_fork_binding(&f.graph,&f.constants,&signer.keys) }}).success);
        f.graph[0] ^= 1;
        f.constants[0] ^= 1;
        assert!(bitvm::execute_script(script! {{ witness } { disprove_compact_fork_binding(&f.graph,&f.constants,&signer.keys) }}).success);
    }
    #[test]
    fn unrelated_signing_key_cannot_supply_the_public_input() {
        let f = fixture();
        let mut signer = Signer::new();
        let witness = signer.witness(&f);
        signer.keys.public_input = Wots32::generate_public_key(&Wots32::generate_secret_key());
        let result = bitvm::execute_script(
            script! {{ witness } { disprove_compact_fork_binding(&f.graph,&f.constants,&signer.keys) }},
        );
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn a_bn254_modulus_alias_cannot_bypass_the_public_binding() {
        use ark_ff::{BigInteger, PrimeField};
        let mut f = fixture();
        let modulus = <ark_bn254::Fr as PrimeField>::MODULUS.to_bytes_be();
        let mut carry = 0u16;
        for i in (0..32).rev() {
            let sum = f.fields[0][i].rotate_left(4) as u16 + modulus[i] as u16 + carry;
            f.fields[0][i] = (sum as u8).rotate_left(4);
            carry = sum >> 8;
        }
        assert_eq!(carry, 0);
        let signer = Signer::new();
        let result = bitvm::execute_script(script! {
            { signer.witness(&f) }
            { disprove_compact_fork_binding(&f.graph, &f.constants, &signer.keys) }
        });
        assert!(
            result.success,
            "noncanonical public-input alias escaped binding"
        );
        assert!(result.stats.max_nb_stack_items <= 1000);
    }
}
