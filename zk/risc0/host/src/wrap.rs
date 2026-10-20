// The Groth16 wrap through chainwayxyz/risc0-to-bitvm2's circuit (groth16_proof/circuits/
// verify_for_guest.circom) and prover image. Written from the circuit's inputs, following the steps
// of their host/src/docker.rs stark_to_succinct, which has no license and is not copied here. The
// only intended difference: the image is pinned by digest, not `:latest`.
//
//   succinct receipt → identity_p254 → seal + claim bits → input.json → docker (witness generator,
//   rapidsnark, Citrea's zkey) → proof.json, public.json
//
// The one public output is the first 31 bytes of
//   Blake3( SHA256( bitrev(control_root) ‖ pre_state ‖ post_state ‖ BN254 identity control ID ) ‖ journal )
// where pre_state is the guest's image ID and the journal must be exactly 32 bytes.

use anyhow::{bail, ensure, Context, Result};
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{Receipt, SuccinctReceiptVerifierParameters, SystemState};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

pub const PROVER_IMAGE: &str = "ozancw/risc0-to-bitvm2-groth16-prover@sha256:840b833190a86c87eb71473cd72bcaa3e3b90cefa9bf4ae785ab2de61bc9d262";

fn bits_msb_first(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().flat_map(|&b| (0..8).rev().map(move |i| (b >> i) & 1)).collect()
}

fn as_strings(bits: &[u8]) -> Vec<String> {
    bits.iter().map(|b| b.to_string()).collect()
}

/// The circuit constants other than the image ID: the succinct verifier's control root, the
/// post-state digest of a run that halted normally, and the BN254 identity control ID.
pub fn constants() -> ([u8; 32], [u8; 32], [u8; 32]) {
    let root: [u8; 32] = SuccinctReceiptVerifierParameters::default().control_root.as_bytes().try_into().unwrap();
    let post: [u8; 32] = SystemState { pc: 0, merkle_root: Default::default() }.digest().into();
    let id_bn254: [u8; 32] = risc0_circuit_recursion::control_id::BN254_IDENTITY_CONTROL_ID.into();
    (root, post, id_bn254)
}

/// SHA256 over the circuit constants: the first half of the public output's preimage.
pub fn constants_digest(image_id: &[u8]) -> [u8; 32] {
    let (control_root, post, id_bn254) = constants();
    let root_bits_reversed: Vec<u8> = control_root.iter().map(|b| b.reverse_bits()).collect();
    let mut h = Sha256::new();
    h.update(&root_bits_reversed);
    h.update(image_id);
    h.update(post);
    h.update(id_bn254);
    h.finalize().into()
}

/// The Groth16 public input this receipt must produce, as 31 big-endian bytes.
pub fn expected_output(image_id: &[u8], journal: &[u8]) -> [u8; 31] {
    let mut h = blake3::Hasher::new();
    h.update(&constants_digest(image_id));
    h.update(journal);
    h.finalize().as_bytes()[..31].try_into().unwrap()
}

pub struct Prepared {
    pub identity_s: f64,
    pub seal_bytes: usize,
}

/// identity_p254 and input.json in `work`.
pub fn prepare(receipt: &Receipt, work: &Path) -> Result<Prepared> {
    let succinct = receipt.inner.succinct().context("need a succinct receipt")?;
    ensure!(receipt.journal.bytes.len() == 32, "the circuit takes a 32-byte journal");
    let t = Instant::now();
    let ident = risc0_zkvm::recursion::identity_p254(succinct)?;
    let identity_s = t.elapsed().as_secs_f64();
    let seal = ident.get_seal_bytes();
    let mut iop = Vec::new();
    risc0_groth16::to_json(&*seal, &mut iop)?;
    let mut input: Value = serde_json::from_slice(&iop)?;

    let claim = succinct.claim.clone().value()?;
    let pre = claim.pre.digest();
    let post = claim.post.digest();
    let mut root = SuccinctReceiptVerifierParameters::default().control_root.as_bytes().to_vec();
    root.reverse();
    let hex_root = hex::encode(&root);
    let dec = |h: &str| num_bigint::BigUint::parse_bytes(h.as_bytes(), 16).unwrap().to_str_radix(10);
    let (a1, a0) = (dec(&hex_root[..32]), dec(&hex_root[32..]));
    let mut id_bits = bits_msb_first(ident.control_id.as_bytes());
    id_bits.drain(248..250);

    input["journal_digest_bits"] = json!(bits_msb_first(&receipt.journal.bytes));
    input["pre_state_digest_bits"] = json!(as_strings(&bits_msb_first(pre.as_bytes())));
    input["post_state_digest_bits"] = json!(as_strings(&bits_msb_first(post.as_bytes())));
    input["id_bn254_fr_bits"] = json!(as_strings(&id_bits));
    input["control_root"] = json!([a0, a1]);
    std::fs::write(work.join("input.json"), serde_json::to_string_pretty(&input)?)?;
    std::fs::write(work.join("seal.r0"), &seal)?;
    Ok(Prepared { identity_s, seal_bytes: seal.len() })
}

fn docker(args: &[&str]) -> Result<String> {
    let out = Command::new("docker").args(args).output()?;
    ensure!(out.status.success(), "docker {}: {}", args[0], String::from_utf8_lossy(&out.stderr));
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

/// docker run of the pinned prover on `work` (input.json → proof.json, public.json). Returns the
/// wall time and the container's peak memory in MiB, read from its cgroup v1 high-water mark.
pub fn run_prover(work: &Path) -> Result<(f64, Option<u64>)> {
    let t = Instant::now();
    let mount = format!("{}:/mnt", work.canonicalize()?.display());
    let cid = docker(&["run", "-d", "--platform=linux/amd64", "-v", &mount, PROVER_IMAGE])?;
    let cgroups = [
        format!("/sys/fs/cgroup/memory/docker/{cid}/memory.max_usage_in_bytes"),
        format!("/sys/fs/cgroup/memory/system.slice/docker-{cid}.scope/memory.max_usage_in_bytes"),
    ];
    let mut peak: Option<u64> = None;
    loop {
        for f in &cgroups {
            if let Some(v) = std::fs::read_to_string(f).ok().and_then(|s| s.trim().parse::<u64>().ok()) {
                peak = Some(peak.map_or(v, |p| p.max(v)));
            }
        }
        if docker(&["inspect", "-f", "{{.State.Running}}", &cid])? != "true" {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let secs = t.elapsed().as_secs_f64();
    let code = docker(&["inspect", "-f", "{{.State.ExitCode}}", &cid])?;
    let logs = Command::new("docker").args(["logs", &cid]).output()?;
    std::fs::write(work.join("prover.log"), [logs.stdout.as_slice(), logs.stderr.as_slice()].concat())?;
    docker(&["rm", &cid])?;
    if code != "0" {
        bail!("prover image exited {code}; see {}/prover.log", work.display());
    }
    Ok((secs, peak.map(|b| b >> 20)))
}

/// public.json's one output as 31 big-endian bytes.
pub fn read_output(work: &Path) -> Result<[u8; 31]> {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(work.join("public.json"))?)?;
    let n = num_bigint::BigUint::parse_bytes(v[0].as_str().context("public.json")?.as_bytes(), 10).unwrap();
    let mut b = n.to_bytes_be();
    ensure!(b.len() <= 31, "output over 248 bits");
    while b.len() < 31 {
        b.insert(0, 0);
    }
    Ok(b.try_into().unwrap())
}
