// Checks a Groth16 proof from the risc0-to-bitvm2 prover with BitVM's verifier (github.com/BitVM/
// BitVM 7d1ca36, "DO NOT USE IN PRODUCTION"), and runs a chunked disprove of an invalid assertion.
// Everything runs in BitVM's script interpreter (bitcoin-scriptexec), not in transactions.
//
//   bsb-bitvm-check <dir> --wrong-public <decimal> [--out result.json]
//
// <dir> holds vk.json (snarkjs export of the prover image's zkey), proof.json and public.json.
//
//   1. arkworks: e(A,B) = e(α,β)·e(L,γ)·e(C,δ) for the public input, and not for --wrong-public.
//   2. BitVM chunker: the verifier compiled into its disprove tapscripts for this key; the honest
//      assertion, Winternitz-signed, executed against every one of them (none may succeed).
//   3. Disprove: the same proof asserted with --wrong-public, and the honest assertion with one
//      intermediate value corrupted. validate_assertions finds the failing chunk, and its disprove
//      script, run with the signed values as witness, must succeed.
//
// The Winternitz secrets are fixed TEST values derived from TEST_SECRET. Never use them for funds.

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use bitcoin::ScriptBuf;
use bitvm::chunk::api::{
    api_generate_full_tapscripts, api_generate_partial_script, api_get_assertions_from_signature,
    api_get_signature_from_assertion, generate_signatures, generate_signatures_for_any_proof,
    type_conversion_utils::utils_raw_witnesses_from_signatures, validate_assertions, PublicKeys, Signatures,
    NUM_HASH, NUM_PUBS, NUM_TAPS, NUM_U256,
};
use bitvm::signatures::{Wots, Wots16, Wots32};
use serde_json::{json, Value};
use std::str::FromStr;
use std::time::Instant;

const TEST_SECRET: &str = "b5b0000000000000000000000000000000000000";

fn fq(v: &Value) -> Fq {
    Fq::from_str(v.as_str().unwrap()).unwrap()
}
fn g1(v: &Value) -> G1Affine {
    G1Affine::new(fq(&v[0]), fq(&v[1]))
}
/// snarkjs writes G2 coordinates as [c0, c1].
fn g2(v: &Value) -> G2Affine {
    G2Affine::new(Fq2::new(fq(&v[0][0]), fq(&v[0][1])), Fq2::new(fq(&v[1][0]), fq(&v[1][1])))
}

fn read(dir: &str, f: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{dir}/{f}")).unwrap()).unwrap()
}

fn secrets() -> Vec<String> {
    (0..NUM_PUBS + NUM_U256 + NUM_HASH).map(|i| format!("{TEST_SECRET}{i:04x}")).collect()
}

/// BitVM's get_pubkeys (crate-private in 7d1ca36), from the public Wots API.
#[allow(deprecated)]
fn pubkeys(secrets: &[String]) -> PublicKeys {
    let w32 = |i: usize| Wots32::generate_public_key(&Wots32::secret_from_str(&secrets[i]));
    let w16 = |i: usize| Wots16::generate_public_key(&Wots16::secret_from_str(&secrets[i]));
    (
        std::array::from_fn(w32),
        std::array::from_fn(|i| w32(NUM_PUBS + i)),
        std::array::from_fn(|i| w16(NUM_PUBS + NUM_U256 + i)),
    )
}

fn witness_bytes(s: &Signatures) -> usize {
    utils_raw_witnesses_from_signatures(s).iter().flatten().map(|w| w.len()).sum()
}

/// validate_assertions, then the disprove script it points at, executed with its witness.
fn disprove(vk: &VerifyingKey<Bn254>, sigs: Signatures, pks: PublicKeys, scripts: &[ScriptBuf; NUM_TAPS]) -> Value {
    let t = Instant::now();
    match validate_assertions(vk, sigs, pks, scripts) {
        None => json!({ "found": false, "validate_s": t.elapsed().as_secs_f64() }),
        Some((index, hint)) => {
            let validate_s = t.elapsed().as_secs_f64();
            let witness_len = hint.clone().compile().len();
            let full = hint.push_script(scripts[index].clone());
            let len = full.len();
            let t = Instant::now();
            let res = bitvm::execute_script(full);
            json!({
                "found": true, "tap_index": index, "validate_s": validate_s,
                "locking_script_bytes": scripts[index].len(), "witness_script_bytes": witness_len,
                "script_plus_witness_bytes": len, "under_4mb_less_16k": len < 4_000_000 - 16_000,
                "executes": res.success, "max_stack_items": res.stats.max_nb_stack_items, "exec_s": t.elapsed().as_secs_f64(),
            })
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = &args[1];
    let flag = |k: &str| args.iter().position(|a| a == k).map(|i| args[i + 1].clone());
    let wrong = Fr::from_str(&flag("--wrong-public").expect("--wrong-public")).unwrap();

    let v = read(dir, "vk.json");
    assert_eq!(v["nPublic"], 1);
    let vk = VerifyingKey::<Bn254> {
        alpha_g1: g1(&v["vk_alpha_1"]),
        beta_g2: g2(&v["vk_beta_2"]),
        gamma_g2: g2(&v["vk_gamma_2"]),
        delta_g2: g2(&v["vk_delta_2"]),
        gamma_abc_g1: v["IC"].as_array().unwrap().iter().map(g1).collect(),
    };
    let p = read(dir, "proof.json");
    let proof = Proof::<Bn254> { a: g1(&p["pi_a"]), b: g2(&p["pi_b"]), c: g1(&p["pi_c"]) };
    assert!(proof.a.is_on_curve() && proof.b.is_on_curve() && proof.c.is_on_curve());
    let public = Fr::from_str(read(dir, "public.json")[0].as_str().unwrap()).unwrap();

    let pvk = ark_groth16::prepare_verifying_key(&vk);
    let t = Instant::now();
    let ark_ok = Groth16::<Bn254>::verify_proof(&pvk, &proof, &[public]).unwrap();
    let ark_s = t.elapsed().as_secs_f64();
    let ark_wrong = Groth16::<Bn254>::verify_proof(&pvk, &proof, &[wrong]).unwrap();
    println!("arkworks: honest {ark_ok}, wrong public input {ark_wrong}");

    let t = Instant::now();
    let partial = api_generate_partial_script(&vk);
    let compile_s = t.elapsed().as_secs_f64();
    let secrets = secrets();
    let pks = pubkeys(&secrets);
    let scripts: [ScriptBuf; NUM_TAPS] = api_generate_full_tapscripts(pks, &partial).try_into().unwrap();
    let sizes: Vec<usize> = scripts.iter().map(|s| s.len()).collect();
    let total: usize = sizes.iter().sum();
    println!("BitVM disprove tapscripts: {} scripts, {} bytes, largest {}", sizes.len(), total, sizes.iter().max().unwrap());

    let t = Instant::now();
    let honest = generate_signatures(proof.clone(), vec![public], &vk, secrets.clone());
    let honest_s = t.elapsed().as_secs_f64();
    let honest_ok = honest.is_ok();
    println!("BitVM: honest assertion, every disprove script fails: {honest_ok}");
    let mut out = json!({
        "bitvm_rev": "7d1ca36", "warning": "BitVM: DO NOT USE IN PRODUCTION. Winternitz secrets are test values.",
        "arkworks": { "verifies": ark_ok, "wrong_public_verifies": ark_wrong, "verify_s": ark_s },
        "tapscripts": { "count": sizes.len(), "total_bytes": total, "largest_bytes": sizes.iter().max(),
            "smallest_bytes": sizes.iter().min(), "compile_s": compile_s },
        "honest": { "all_disprove_scripts_fail": honest_ok, "sign_and_execute_all_s": honest_s },
    });
    let honest = honest.expect("BitVM rejected the honest proof");
    out["honest"]["assertion_witness_bytes"] = json!(witness_bytes(&honest));
    out["honest"]["assertions"] = json!({ "u256": NUM_PUBS + NUM_U256, "hash": NUM_HASH });
    let t = Instant::now();
    out["honest"]["validate"] = disprove(&vk, honest.clone(), pks, &scripts);
    out["honest"]["validate"]["s"] = json!(t.elapsed().as_secs_f64());

    let wrong_sigs = generate_signatures_for_any_proof(proof, vec![wrong], &vk, secrets.clone());
    out["wrong_public_input"] = disprove(&vk, wrong_sigs, pks, &scripts);
    println!("disprove, wrong public input: {}", out["wrong_public_input"]);

    let mut asserts = api_get_assertions_from_signature(honest);
    asserts.2[NUM_HASH / 2][0] ^= 1;
    let corrupt = api_get_signature_from_assertion(asserts, secrets);
    out["corrupted_intermediate"] = disprove(&vk, corrupt, pks, &scripts);
    println!("disprove, corrupted intermediate hash {}: {}", NUM_HASH / 2, out["corrupted_intermediate"]);

    let s = serde_json::to_string_pretty(&out).unwrap();
    match flag("--out") {
        Some(f) => std::fs::write(f, s).unwrap(),
        None => println!("{s}"),
    }
}
