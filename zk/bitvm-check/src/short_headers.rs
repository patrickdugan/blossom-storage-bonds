//! Direct, bounded REGTEST header verification for a small dispute contract.
//! At most three headers after a pinned checkpoint; this is not a long-chain verifier.
use crate::storage_binding::bytes_to_nibbles;
use bitcoin_script_stack::stack::StackTracker;
use bitvm::{
    hash::sha256_u4_stack::sha256_stack,
    signatures::winternitz::{Converter, ToBytesConverter},
    signatures::{Wots, Wots32, Wots4},
    treepp::{script, Script},
};

pub const MAX_SHORT_HEADERS: usize = 3;
pub struct ShortHeaderContext {
    pub anchor_hash: [u8; 32],
    pub anchor_times: [u32; 11],
    pub max_time: u32,
    pub original_key: <Wots32 as Wots>::PublicKey,
    pub count_key: <Wots4 as Wots>::PublicKey,
}
#[derive(Clone, Copy)]
pub enum HeaderMode {
    Claim,
    Response,
    Counterexample,
    Challenge,
}

fn copy_nibble(index: usize, extra: usize) -> Script {
    script! {{159-index+extra} OP_PICK}
}
fn field_number(offset: usize) -> Script {
    // LE u32 constrained to the current pre-2038 timestamp/version domain.
    script! {
        {copy_nibble(offset*2+6,0)} 8 OP_LESSTHAN OP_VERIFY
        0
        for j in [6,7,4,5,2,3,0,1] {
            for _ in 0..4 {OP_DUP OP_ADD}
            {copy_nibble(offset*2+j,1)} OP_ADD
        }
    }
}
fn median_11() -> Script {
    // Select the six greatest values. The sixth is the median. Scratch items
    // sit above the persistent prior timestamps on the alt stack.
    script! {
        for size in (6..=11).rev() {
            for _ in 0..size-1 {OP_2DUP OP_MIN OP_TOALTSTACK OP_MAX}
            if size>6 {for _ in 0..size-1 {OP_FROMALTSTACK}}
        }
        OP_TOALTSTACK
        OP_2DROP OP_2DROP OP_DROP
        OP_FROMALTSTACK
        for _ in 0..5 {OP_FROMALTSTACK OP_DROP}
    }
}
fn timestamp(context: &ShortHeaderContext, step: usize) -> Script {
    script! {
        {field_number(68)}
        OP_DUP {context.max_time as i64} OP_LESSTHANOREQUAL OP_VERIFY
        // Save T below the eleven values whose median we compute.
        for _ in 0..step {OP_FROMALTSTACK}
        for j in 0..step {{step-1-j} OP_PICK OP_TOALTSTACK}
        for t in context.anchor_times.iter().skip(step) {{*t as i64}}
        {median_11()}
        OP_OVER OP_TOALTSTACK OP_GREATERTHAN OP_VERIFY
    }
}
fn pow_le_regtest() -> Script {
    // SHA256d bytes represent the numeric hash little-endian. Compare every
    // nibble against the exact 0x207fffff target, not just the top bit.
    let mut target = [0u8; 32];
    target[29] = 0xff;
    target[30] = 0xff;
    target[31] = 0x7f;
    script! {
        0 OP_TOALTSTACK // strict-less flag
        1 OP_TOALTSTACK // equal-prefix flag
        for byte in (0..32).rev() {
            for low in [false,true] {
                {63-(byte*2+usize::from(low))} OP_PICK
                {if low {target[byte]&15}else{target[byte]>>4}}
                OP_2DUP OP_LESSTHAN
                OP_FROMALTSTACK // equal prefix
                OP_DUP OP_TOALTSTACK
                OP_BOOLAND
                // Reorder the two persistent flags without changing operands.
                OP_FROMALTSTACK OP_FROMALTSTACK OP_ROT OP_BOOLOR OP_TOALTSTACK
                OP_TOALTSTACK
                OP_EQUAL OP_FROMALTSTACK OP_BOOLAND OP_TOALTSTACK
            }
        }
        OP_FROMALTSTACK OP_FROMALTSTACK OP_BOOLOR OP_VERIFY
    }
}
pub fn short_headers(context: &ShortHeaderContext, count: usize, mode: HeaderMode) -> Script {
    assert!((1..=MAX_SHORT_HEADERS).contains(&count));
    assert!(context.max_time < i32::MAX as u32);
    assert!(context.anchor_times.iter().all(|t| *t <= context.max_time));
    let orig_items = 2 * Wots32::TOTAL_DIGIT_LEN as usize;
    let mut sha80 = StackTracker::new();
    let h80 = sha256_stack(&mut sha80, 80, false, false);
    let mut sha32 = StackTracker::new();
    let h32 = sha256_stack(&mut sha32, 32, false, false);
    script! {
        for step in 0..count {
            // Raw header bytes arrive first-byte-on-top. Convert only the next
            // header, keeping the other headers compact to respect the stack cap.
            for j in 0..80 {{j} OP_PICK 0 256 OP_WITHIN OP_VERIFY}
            {bytes_to_nibbles(80)}
            if step==0 {
                for (i,b) in context.anchor_hash.iter().enumerate() {
                    {copy_nibble(8+i*2,0)} {*b>>4} OP_EQUALVERIFY
                    {copy_nibble(9+i*2,0)} {*b&15} OP_EQUALVERIFY
                }
            } else {
                for j in 8..72 {{copy_nibble(j,0)} OP_FROMALTSTACK OP_EQUALVERIFY}
            }
            {field_number(0)} 4 OP_GREATERTHANOREQUAL OP_VERIFY
            {timestamp(context,step)}
            for (i,b) in [0xffu8,0xff,0x7f,0x20].iter().enumerate() {
                {copy_nibble(144+i*2,0)} {*b>>4} OP_EQUALVERIFY
                {copy_nibble(145+i*2,0)} {*b&15} OP_EQUALVERIFY
            }
            {h80.clone()} {h32.clone()}
            {pow_le_regtest()}
            if step==0 {
                for _ in 0..64 {OP_TOALTSTACK}
                // Bring the provider's original-hash signature over the remaining headers.
                for _ in 0..orig_items {{(count-1)*80+orig_items-1} OP_ROLL}
                {Wots32::checksig_verify(&context.original_key)}
                {ToBytesConverter::get_script(&Wots32::PARAMETERS)}
                {bytes_to_nibbles(32)}
                for _ in 0..64 {OP_FROMALTSTACK}
                1 OP_TOALTSTACK
                for j in 0..64 {
                    OP_FROMALTSTACK {j+1} OP_PICK {j+66} OP_PICK OP_EQUAL OP_BOOLAND OP_TOALTSTACK
                }
                for _ in 0..64 {64 OP_ROLL OP_DROP}
                OP_FROMALTSTACK
                if matches!(mode,HeaderMode::Counterexample|HeaderMode::Challenge) {OP_NOT}
                OP_VERIFY
            }
            if step+1<count {for _ in 0..64 {OP_TOALTSTACK}}
            else {for _ in 0..32 {OP_2DROP}}
        }
        for _ in 0..count {OP_FROMALTSTACK OP_DROP}
        if matches!(mode,HeaderMode::Challenge) { {count} 1 OP_GREATERTHAN OP_VERIFY }
        if matches!(mode,HeaderMode::Response|HeaderMode::Counterexample) {
            {Wots4::checksig_verify(&context.count_key)}
            {ToBytesConverter::get_script(&Wots4::PARAMETERS)}
            0 OP_EQUALVERIFY 0 OP_EQUALVERIFY 0 OP_EQUALVERIFY
            if matches!(mode,HeaderMode::Response) {{count} OP_EQUALVERIFY}
            else {OP_DUP 1 4 OP_WITHIN OP_VERIFY {count} OP_SWAP OP_GREATERTHAN OP_VERIFY}
        }
        OP_TRUE
    }
}
pub fn header_byte_witness(headers: &[[u8; 80]]) -> Script {
    script! {for header in headers.iter().rev(){for byte in header.iter().rev(){{*byte}}}}
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::{sha256d, Hash};
    use bitcoin::{blockdata::constants::genesis_block, consensus::encode::serialize, Network};
    fn mine(prev: [u8; 32], time: u32) -> [u8; 80] {
        let mut h = [0u8; 80];
        h[..4].copy_from_slice(&0x20000000u32.to_le_bytes());
        h[4..36].copy_from_slice(&prev);
        h[68..72].copy_from_slice(&time.to_le_bytes());
        h[72..76].copy_from_slice(&0x207fffffu32.to_le_bytes());
        for n in 0..u32::MAX {
            h[76..].copy_from_slice(&n.to_le_bytes());
            let hash = sha256d::Hash::hash(&h).to_byte_array();
            let mut target = [0u8; 32];
            target[29] = 0xff;
            target[30] = 0xff;
            target[31] = 0x7f;
            if hash.iter().rev().cmp(target.iter().rev()).is_le() {
                return h;
            }
        }
        unreachable!()
    }
    #[test]
    fn direct_header_chain_and_signature_binding() {
        std::thread::Builder::new().stack_size(64*1024*1024).spawn(||{
            let genesis=genesis_block(Network::Regtest).header;let raw=serialize(&genesis);let anchor=sha256d::Hash::hash(&raw).to_byte_array();
            let orig_secret=Wots32::generate_secret_key();let count_secret=Wots4::generate_secret_key();
            let context=ShortHeaderContext{anchor_hash:anchor,anchor_times:[genesis.time;11],max_time:genesis.time+7200,original_key:Wots32::generate_public_key(&orig_secret),count_key:Wots4::generate_public_key(&count_secret)};
            let a=mine(anchor,genesis.time+1);let b=mine(sha256d::Hash::hash(&a).to_byte_array(),genesis.time+2);
            let original=Wots32::sign_to_raw_witness(&orig_secret,&sha256d::Hash::hash(&a).to_byte_array());
            for (count,headers) in [(1,vec![a]),(2,vec![a,b])]{
                let count_sig=Wots4::sign_to_raw_witness(&count_secret,&(count as u32).to_be_bytes());
                let leaf=short_headers(&context,count,HeaderMode::Response);
                let result=bitvm::execute_script(script!{{count_sig}{original.clone()}{header_byte_witness(&headers)}{leaf.clone()}});
                eprintln!("headers {count}: bytes {}, max stack {}, error {:?}",leaf.len(),result.stats.max_nb_stack_items,result.error);
                assert!(result.success,"{:?}",result.error);assert_eq!(result.final_stack.len(),1);assert!(result.stats.max_nb_stack_items<=1000);
            }
        }).unwrap().join().unwrap();
    }
    #[test]
    fn exact_target_boundary_and_median() {
        let mut target = [0u8; 32];
        target[29] = 255;
        target[30] = 255;
        target[31] = 127;
        for (hash, valid) in [
            (target, true),
            (
                {
                    let mut h = target;
                    h[0] = 1;
                    h
                },
                false,
            ),
            ([0; 32], true),
            ([255; 32], false),
        ] {
            let r = bitvm::execute_script(
                script! {for b in hash {{b>>4}{b&15}} {pow_le_regtest()} for _ in 0..32 {OP_2DROP} 1},
            );
            assert_eq!(r.success, valid, "exact target boundary");
        }
        for values in [[9, 1, 5, 4, 3, 2, 11, 8, 10, 6, 7], [4; 11]] {
            let mut sorted = values;
            sorted.sort();
            let r = bitvm::execute_script(
                script! {77 OP_TOALTSTACK for v in values {{v}} {median_11()} {sorted[5]} OP_EQUALVERIFY OP_FROMALTSTACK 77 OP_EQUAL},
            );
            assert!(r.success, "median preserves caller alt stack");
        }
    }
    #[test]
    fn outsider_counterexample_uses_public_provider_disclosures() {
        std::thread::Builder::new().stack_size(64*1024*1024).spawn(||{
            let genesis=genesis_block(Network::Regtest).header;let anchor=sha256d::Hash::hash(&serialize(&genesis)).to_byte_array();
            let orig_secret=Wots32::generate_secret_key();let count_secret=Wots4::generate_secret_key();
            let c=ShortHeaderContext{anchor_hash:anchor,anchor_times:[genesis.time;11],max_time:genesis.time+7200,original_key:Wots32::generate_public_key(&orig_secret),count_key:Wots4::generate_public_key(&count_secret)};
            let a=mine(anchor,genesis.time+1);let b=mine(sha256d::Hash::hash(&a).to_byte_array(),genesis.time+2);let d=mine(sha256d::Hash::hash(&b).to_byte_array(),genesis.time+3);
            let x=mine(anchor,genesis.time+4);let y=mine(sha256d::Hash::hash(&x).to_byte_array(),genesis.time+5);let z=mine(sha256d::Hash::hash(&y).to_byte_array(),genesis.time+6);
            let orig=Wots32::sign_to_raw_witness(&orig_secret,&sha256d::Hash::hash(&a).to_byte_array());let count=Wots4::sign_to_raw_witness(&count_secret,&2u32.to_be_bytes());
            let leaf=short_headers(&c,3,HeaderMode::Counterexample);
            for (headers,valid) in [(vec![x,y,z],true),(vec![a,b,d],false),({let mut h=vec![x,y,z];h[1][4]^=1;h},false)] {
                let r=bitvm::execute_script(script!{{count.clone()}{orig.clone()}{header_byte_witness(&headers)}{leaf.clone()}});
                eprintln!("counter valid={valid}: bytes {}, max stack {}, error {:?}",leaf.len(),r.stats.max_nb_stack_items,r.error);
                assert_eq!(r.success,valid);assert!(r.stats.max_nb_stack_items<=1000);
            }
        }).unwrap().join().unwrap();
    }
}
