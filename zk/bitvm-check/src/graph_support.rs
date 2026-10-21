//! Shared local storage-graph helpers. Private WOTS state is never serialized.

use crate::storage_binding::BindingKeys;
use crate::storage_graph::CommitmentKey;
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use bitcoin::{
    hashes::{sha256, Hash},
    taproot::{LeafVersion, TapNodeHash},
    ScriptBuf, Witness,
};
use bitvm::chunk::api::{
    api_generate_full_tapscripts, api_get_signature_from_assertion,
    type_conversion_utils::utils_raw_witnesses_from_signatures, Assertions, PublicKeys, Signatures,
    NUM_HASH, NUM_PUBS, NUM_TAPS, NUM_U256,
};
use bitvm::signatures::{Wots, Wots16, Wots32, Wots4};
use serde_json::Value;
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

pub fn bytes(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}
pub fn hex(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn read(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
pub fn emit(value: Value) {
    println!("BSB_GRAPH {}", value);
    io::stdout().flush().unwrap();
}
pub fn write(path: impl AsRef<Path>, value: Value) {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    f.write_all(&serde_json::to_vec(&value).unwrap()).unwrap();
}
pub fn vk(dir: &Path) -> (VerifyingKey<Bn254>, Proof<Bn254>, Fr) {
    let v = read(dir.join("vk.json"));
    let p = read(dir.join("proof.json"));
    let public = read(dir.join("public.json"));
    assert_eq!(v["nPublic"], 1);
    assert_eq!(v["IC"].as_array().unwrap().len(), 2);
    let f = |v: &Value| Fq::from_str(v.as_str().unwrap()).unwrap();
    let g1 = |v: &Value| G1Affine::new(f(&v[0]), f(&v[1]));
    let g2 = |v: &Value| {
        G2Affine::new(
            Fq2::new(f(&v[0][0]), f(&v[0][1])),
            Fq2::new(f(&v[1][0]), f(&v[1][1])),
        )
    };
    let key = VerifyingKey {
        alpha_g1: g1(&v["vk_alpha_1"]),
        beta_g2: g2(&v["vk_beta_2"]),
        gamma_g2: g2(&v["vk_gamma_2"]),
        delta_g2: g2(&v["vk_delta_2"]),
        gamma_abc_g1: v["IC"].as_array().unwrap().iter().map(g1).collect(),
    };
    let proof = Proof {
        a: g1(&p["pi_a"]),
        b: g2(&p["pi_b"]),
        c: g1(&p["pi_c"]),
    };
    let public = Fr::from_str(public[0].as_str().unwrap()).unwrap();
    assert!(Groth16::<Bn254>::verify_proof(
        &ark_groth16::prepare_verifying_key(&key),
        &proof,
        &[public]
    )
    .unwrap());
    (key, proof, public)
}

pub struct Commitments {
    secrets: Vec<String>,
    chain: [Vec<u8>; 3],
    journal: Option<Vec<u8>>,
    pub pks: PublicKeys,
}
#[allow(deprecated)]
impl Commitments {
    pub fn fresh() -> Self {
        let secrets = (0..NUM_PUBS + NUM_U256 + NUM_HASH)
            .map(|_| hex(&Wots32::generate_secret_key()))
            .collect::<Vec<_>>();
        let pks = (
            std::array::from_fn(|i| {
                Wots32::generate_public_key(&Wots32::secret_from_str(&secrets[i]))
            }),
            std::array::from_fn(|i| {
                Wots32::generate_public_key(&Wots32::secret_from_str(&secrets[NUM_PUBS + i]))
            }),
            std::array::from_fn(|i| {
                Wots16::generate_public_key(&Wots16::secret_from_str(
                    &secrets[NUM_PUBS + NUM_U256 + i],
                ))
            }),
        );
        Self {
            secrets,
            journal: None,
            chain: [
                Wots4::generate_secret_key(),
                Wots32::generate_secret_key(),
                Wots32::generate_secret_key(),
            ],
            pks,
        }
    }
    pub fn fresh_with_journal() -> Self {
        let mut result = Self::fresh();
        result.journal = Some(Wots32::generate_secret_key());
        result
    }
    pub fn journal_key(&self) -> Option<<Wots32 as Wots>::PublicKey> {
        self.journal
            .as_ref()
            .map(|key| Wots32::generate_public_key(key))
    }
    pub fn binding_keys(&self) -> BindingKeys {
        BindingKeys {
            public_input: self.pks.0[0],
            tip_height: Wots4::generate_public_key(&self.chain[0]),
            tip_hash: Wots32::generate_public_key(&self.chain[1]),
            total_work: Wots32::generate_public_key(&self.chain[2]),
        }
    }
    pub fn keys(&self) -> Vec<CommitmentKey> {
        let mut result = Vec::new();
        result.extend(self.pks.0.iter().map(|k| CommitmentKey::Bytes32(*k)));
        result.extend(self.pks.1.iter().map(|k| CommitmentKey::Bytes32(*k)));
        result.extend(self.pks.2.iter().map(|k| CommitmentKey::Bytes16(*k)));
        result.push(CommitmentKey::Bytes4(Wots4::generate_public_key(
            &self.chain[0],
        )));
        result.push(CommitmentKey::Bytes32(Wots32::generate_public_key(
            &self.chain[1],
        )));
        result.push(CommitmentKey::Bytes32(Wots32::generate_public_key(
            &self.chain[2],
        )));
        if let Some(key) = self.journal_key() {
            result.push(CommitmentKey::Bytes32(key));
        }
        result
    }
    pub fn sign(
        &self,
        assertions: Assertions,
        preimage: &[u8],
    ) -> (Signatures, Vec<Witness>, Vec<Vec<u8>>) {
        assert_eq!(preimage.len(), 202);
        let signatures = api_get_signature_from_assertion(assertions, self.secrets.clone());
        let mut witnesses = utils_raw_witnesses_from_signatures(&signatures)
            .into_iter()
            .map(|w| Witness::from_slice(&w))
            .collect::<Vec<_>>();
        let tip: [u8; 4] = preimage[134..138].try_into().unwrap();
        let hash: [u8; 32] = preimage[138..170].try_into().unwrap();
        let work: [u8; 32] = preimage[170..202].try_into().unwrap();
        let chain = [
            Wots4::sign_to_raw_witness(&self.chain[0], &tip),
            Wots32::sign_to_raw_witness(&self.chain[1], &hash),
            Wots32::sign_to_raw_witness(&self.chain[2], &work),
        ];
        witnesses.extend(chain.iter().cloned());
        let mut binding = Vec::new();
        for w in [&chain[2], &chain[1], &chain[0]] {
            binding.extend(w.iter().map(|x| x.to_vec()));
        }
        binding.extend(
            Wots32::signature_to_raw_witness(&signatures.0[0])
                .iter()
                .map(|x| x.to_vec()),
        );
        if let Some(secret) = &self.journal {
            let message = sha256::Hash::hash(preimage).to_byte_array();
            let signature = Wots32::sign_to_raw_witness(secret, &message);
            binding.extend(signature.iter().map(|x| x.to_vec()));
            witnesses.push(signature);
        }
        (signatures, witnesses, binding)
    }
}

pub struct Scripts {
    cache: PathBuf,
    manifest: Value,
    locks: Vec<ScriptBuf>,
}
impl Scripts {
    pub fn new(cache: PathBuf, proof_dir: &Path, pks: PublicKeys) -> Self {
        let manifest = read(cache.join("manifest.json"));
        assert_eq!(manifest["bitvm_rev"], "7d1ca36");
        assert_eq!(manifest["count"], NUM_TAPS);
        assert_eq!(
            manifest["vk_sha256"],
            sha256::Hash::hash(&std::fs::read(proof_dir.join("vk.json")).unwrap()).to_string()
        );
        let empty = vec![ScriptBuf::new(); NUM_TAPS];
        let locks = api_generate_full_tapscripts(pks, &empty);
        Self {
            cache,
            manifest,
            locks,
        }
    }
    pub fn full(&self, index: usize) -> ScriptBuf {
        let partial = std::fs::read(self.cache.join(format!("{index:03}.bin"))).unwrap();
        assert_eq!(
            self.manifest["script_sha256"][index],
            sha256::Hash::hash(&partial).to_string(),
            "cache script hash"
        );
        let mut result = self.locks[index].to_bytes();
        result.extend(partial);
        ScriptBuf::from_bytes(result)
    }
    pub fn hashes(&self) -> Vec<TapNodeHash> {
        (0..NUM_TAPS)
            .map(|index| TapNodeHash::from_script(&self.full(index), LeafVersion::TapScript))
            .collect()
    }
}

#[cfg(test)]
mod journal_tests {
    use super::*;
    use crate::storage_binding::{disprove_term_binding, disprove_term_binding_with_journal};
    use crate::storage_graph::{JOURNAL_SLOT_COUNT, SLOT_COUNT, TERM_JOURNAL_SLOT};
    use ark_ff::{BigInteger, PrimeField};
    use bitvm::treepp::script;

    #[test]
    fn registered_journal_key_and_signed_digest_follow_the_same_term() {
        let f: Value =
            serde_json::from_str(include_str!("../../../results/bitvm2-spike.json")).unwrap();
        let preimage = bytes(f["m2"]["term"]["preimage"].as_str().unwrap());
        let constants: [u8; 32] = bytes(f["m3"]["groth16"]["constants_digest"].as_str().unwrap())
            .try_into()
            .unwrap();
        let public =
            Fr::from_str(f["m3"]["groth16"]["public_output_dec"].as_str().unwrap()).unwrap();
        let public: [u8; 32] = public
            .into_bigint()
            .to_bytes_be()
            .into_iter()
            .map(|b| b.rotate_left(4))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        for case in 0..3 {
            let commitments = if case == 0 {
                Commitments::fresh()
            } else {
                Commitments::fresh_with_journal()
            };
            let keys = commitments.keys();
            assert_eq!(
                keys.len(),
                if case == 0 {
                    SLOT_COUNT
                } else {
                    JOURNAL_SLOT_COUNT
                }
            );
            if let Some(key) = commitments.journal_key() {
                match keys[TERM_JOURNAL_SLOT] {
                    CommitmentKey::Bytes32(registered) => assert_eq!(registered, key),
                    _ => panic!("journal slot has wrong type"),
                }
            }
            // Only the public input is used by the binding; this is not a Groth16 trace test.
            let assertions: Assertions =
                ([public; NUM_PUBS], [[0; 32]; NUM_U256], [[0; 16]; NUM_HASH]);
            let mut claimed = preimage.clone();
            if case == 2 {
                claimed[81] ^= 1;
            }
            let (_, witnesses, binding) = commitments.sign(assertions, &claimed);
            assert_eq!(witnesses.len(), keys.len());
            let prefix = preimage[..134].try_into().unwrap();
            let leaf = match commitments.journal_key() {
                Some(key) => disprove_term_binding_with_journal(
                    prefix,
                    &constants,
                    &commitments.binding_keys(),
                    &key,
                ),
                None => disprove_term_binding(prefix, &constants, &commitments.binding_keys()),
            };
            let result =
                bitvm::execute_script(script! { for item in binding { { item } } { leaf } });
            assert!(
                result.error.is_none(),
                "binding aborted: {:?}",
                result.error
            );
            assert_eq!(
                result.success,
                case == 2,
                "only the incorrectly signed journal should open"
            );
            assert_eq!(result.final_stack.len(), 1);
        }
    }
}
