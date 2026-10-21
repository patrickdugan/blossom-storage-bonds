//! A penalty witness for two different WOTS32 messages under one setup key.
//! This does not authenticate history or provide challenger registration.
use bitvm::signatures::{Wots, Wots32};
use bitvm::treepp::{script, Script};

pub fn prove_wots32_equivocation(key: &<Wots32 as Wots>::PublicKey) -> Script {
    script! {
        { Wots32::checksig_verify(key) }
        for _ in 0..64 { OP_TOALTSTACK }
        { Wots32::checksig_verify(key) }
        OP_1 OP_TOALTSTACK
        for i in 0..64 {
            OP_FROMALTSTACK { 64 - i } OP_ROLL OP_FROMALTSTACK OP_EQUAL OP_BOOLAND OP_TOALTSTACK
        }
        OP_FROMALTSTACK OP_NOT
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_distinct_authenticated_messages_open_the_penalty() {
        for case in 0..4 {
            let secret = Wots32::generate_secret_key();
            let key = Wots32::generate_public_key(&secret);
            let first = [0x85u8; 32];
            let mut second = first;
            if case != 0 {
                second[if case == 1 { 0 } else { 31 }] ^= if case == 1 { 0x10 } else { 1 };
            }
            let other = Wots32::generate_secret_key();
            let leaf = prove_wots32_equivocation(&key);
            let length = leaf.clone().compile().len();
            let result = bitvm::execute_script(script! {
                { Wots32::sign_to_raw_witness(&secret,&first) }
                { Wots32::sign_to_raw_witness(if case==3 {&other}else{&secret},&second) }
                { leaf }
            });
            if case == 3 {
                assert!(!result.success && result.error.is_some());
            } else {
                assert!(result.error.is_none(), "{:?}", result.error);
                assert_eq!(result.success, case != 0);
                assert_eq!(result.final_stack.len(), 1);
            }
            assert!(result.stats.max_nb_stack_items <= 1000);
            eprintln!(
                "equivocation case {case}: script {length}, max stack {}",
                result.stats.max_nb_stack_items
            );
        }
    }
}
