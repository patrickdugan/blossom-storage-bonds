//! Isolated penalty for a subset-signature bank releasing more than eight secrets.
//! This is not Binohash introspection, message authentication, or a fork protocol.
use bitvm::treepp::{script, Script};

pub const SUBSET_BANK_SIZE: usize = 120;
pub const SUBSET_REVEALS: usize = 8;
pub type SubsetBank = [[u8; 20]; SUBSET_BANK_SIZE];
pub type SubsetBanks = [SubsetBank; 2];

/// A single bank is fixed in the leaf. Two rounds must use independent banks.
/// Witness: nine (32-byte preimage, absolute index) pairs, in reverse pair order.
/// Strictly increasing absolute indices rule out replaying or reordering one secret.
pub fn prove_subset_overdisclosure(banks: &SubsetBanks, round: usize) -> Script {
    assert!(round < 2);
    let unique: std::collections::HashSet<_> = banks.iter().flatten().collect();
    assert_eq!(
        unique.len(),
        2 * SUBSET_BANK_SIZE,
        "commitments must be unique within and across rounds"
    );
    let bank = &banks[round];
    script! {
        { -1 } OP_TOALTSTACK
        for key in bank.iter().rev() { { key.to_vec() } }
        for _ in 0..SUBSET_REVEALS+1 {
            { SUBSET_BANK_SIZE } OP_ROLL
            OP_DUP { SUBSET_BANK_SIZE } OP_LESSTHAN OP_VERIFY
            OP_DUP OP_FROMALTSTACK OP_GREATERTHAN OP_VERIFY
            OP_DUP OP_TOALTSTACK
            OP_PICK
            { SUBSET_BANK_SIZE+1 } OP_ROLL
            OP_SIZE 32 OP_EQUALVERIFY
            OP_HASH160 OP_EQUALVERIFY
        }
        for _ in 0..SUBSET_BANK_SIZE/2 { OP_2DROP }
        OP_FROMALTSTACK OP_DROP OP_TRUE
    }
}

pub fn subset_overdisclosure_witness(entries: &[(i64, Vec<u8>)]) -> Script {
    assert_eq!(entries.len(), SUBSET_REVEALS + 1);
    script! { for (index, preimage) in entries.iter().rev() { { preimage.clone() } { *index } } }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::{hash160, sha256, Hash};
    #[test]
    fn one_disclosure_cannot_open_the_nine_secret_penalty() {
        let secret: Vec<_> = (0..SUBSET_BANK_SIZE)
            .map(|i| {
                sha256::Hash::hash(format!("public test bank 0 index {i}").as_bytes())
                    .to_byte_array()
            })
            .collect();
        let bank: SubsetBank =
            std::array::from_fn(|i| hash160::Hash::hash(&secret[i]).to_byte_array());
        let other: SubsetBank = std::array::from_fn(|i| {
            hash160::Hash::hash(format!("public test bank 1 index {i}").as_bytes()).to_byte_array()
        });
        let banks = [bank, other];
        let leaf = prove_subset_overdisclosure(&banks, 0);
        for case in 0..7 {
            let mut entries: Vec<_> = (0..9).map(|i| (i as i64, secret[i].to_vec())).collect();
            match case {
                0 => {}
                1 => entries[8] = entries[7].clone(),
                2 => entries.swap(0, 1),
                3 => {
                    entries[8].1 = sha256::Hash::hash(b"other round's revealed secret")
                        .to_byte_array()
                        .to_vec()
                }
                4 => entries[0].0 = -1,
                5 => entries[8].0 = SUBSET_BANK_SIZE as i64,
                6 => entries = (111..120).map(|i| (i as i64, secret[i].to_vec())).collect(),
                _ => unreachable!(),
            }
            let result = bitvm::execute_script(
                script! { { subset_overdisclosure_witness(&entries) } { leaf.clone() } },
            );
            assert_eq!(
                result.success,
                case == 0 || case == 6,
                "case {case}: {:?}",
                result.error
            );
            if result.success {
                assert_eq!(result.final_stack.len(), 1);
            }
            assert!(result.stats.max_nb_stack_items <= 1000);
            eprintln!(
                "subset bank case {case}: {} script bytes, max stack {}",
                leaf.clone().compile().len(),
                result.stats.max_nb_stack_items
            );
        }
    }
    #[test]
    fn duplicate_commitments_are_rejected_before_script_construction() {
        let bank: SubsetBank = std::array::from_fn(|i| {
            hash160::Hash::hash(format!("unique test index {i}").as_bytes()).to_byte_array()
        });
        assert!(
            std::panic::catch_unwind(|| prove_subset_overdisclosure(&[bank, bank], 0)).is_err()
        );
        let other: SubsetBank = std::array::from_fn(|i| {
            hash160::Hash::hash(format!("other test index {i}").as_bytes()).to_byte_array()
        });
        let mut banks = [bank, other];
        banks[0][1] = banks[0][0];
        assert!(std::panic::catch_unwind(|| prove_subset_overdisclosure(&banks, 0)).is_err());
    }
}
