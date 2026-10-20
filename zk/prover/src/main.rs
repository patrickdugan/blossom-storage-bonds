//! `bsb-zk`: prove and verify the aggregated storage proof (zk/cairo) with stwo-cairo.
//!
//!   bsb-zk prove  --executable zk_pdp.executable.json --args args.json --out proof.json
//!                 [--hash sha|blake] [--max-log-rows K] [--stop-after execute]
//!       Runs the program's standalone entry point in proof mode (no bootloader) on the
//!       witness, then proves the run. A witness that does not open every challenged chunk
//!       makes the program panic, and there is then nothing to prove: the command reports
//!       `"run": "failed"` and exits 2.
//!
//!   bsb-zk verify --executable zk_pdp.executable.json --proof proof.json
//!                 --statement statement.json [--hash sha|blake] [--max-log-rows K]
//!       The public verifier. The proof's public program must be exactly the executable's
//!       bytecode, its claim must have the shape this program produces (security
//!       parameters, preprocessed trace, builtins, output segment), its output must equal the
//!       statement's (seed, q, deal count, deal-list digest, which the statement's author
//!       computes from the deals it cares about), and the STARK must verify. Exits non-zero
//!       on any failure.
//!
//! Each command prints one JSON object with its timings and results.

use std::path::{Path, PathBuf};
use std::time::Instant;

use blake2::{Blake2s256, Digest as _};
use cairo_air::utils::{deserialize_proof_from_file, serialize_proof_to_file, ProofFormat};
use cairo_air::verifier::verify_cairo;
use cairo_air::{CairoProof, PreProcessedTraceVariant};
use cairo_lang_executable::executable::{EntryPointKind, Executable, ExecutableEntryPoint};
use cairo_lang_execute_utils::{program_and_hints_from_executable, user_args_from_flags};
use cairo_lang_runner::{Arg, CairoHintProcessor};
use cairo_vm::cairo_run::CairoRunConfig;
use cairo_vm::types::builtin_name::BuiltinName;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;
use stwo::core::vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo_cairo_adapter::adapter::adapt;
use stwo_cairo_adapter::PublicSegmentContext;
use stwo_cairo_prover::prover::{prove_cairo, ChannelHash, ProverParameters};

/// The builtins each zk_pdp build uses, in the executable's order. Pinned here rather than
/// read from the executable file, because the verifier learns which builtin each public
/// segment belongs to only from this pattern. The Blake2s build needs no bitwise builtin: the
/// hash is an opcode.
fn builtins(hash: &str) -> &'static [&'static str] {
    match hash {
        "sha" => &["output", "range_check", "bitwise"],
        "blake" => &["output", "range_check"],
        _ => panic!("--hash sha|blake"),
    }
}

/// 96-bit parameters (as Raito and rust-bitcoin's zk-sync use): pow 26, blowup 2, 70 queries.
fn pcs_config() -> PcsConfig {
    PcsConfig { pow_bits: 26, fri_config: FriConfig { log_last_layer_degree_bound: 0, log_blowup_factor: 1, n_queries: 70 } }
}

#[derive(Default)]
struct Opts {
    executable: PathBuf,
    args: Option<PathBuf>,
    out: Option<PathBuf>,
    proof: Option<PathBuf>,
    statement: Option<PathBuf>,
    max_log_rows: Option<u32>,
    stop_after_execute: bool,
    hash: String,
}

fn parse(args: impl Iterator<Item = String>) -> Opts {
    let mut a = args;
    let mut o = Opts { hash: "sha".into(), ..Default::default() };
    while let Some(k) = a.next() {
        let mut v = || a.next().unwrap_or_else(|| panic!("{k} needs a value"));
        match k.as_str() {
            "--executable" => o.executable = v().into(),
            "--args" => o.args = Some(v().into()),
            "--out" => o.out = Some(v().into()),
            "--proof" => o.proof = Some(v().into()),
            "--statement" => o.statement = Some(v().into()),
            "--max-log-rows" => o.max_log_rows = Some(v().parse().expect("--max-log-rows")),
            "--stop-after" if v() == "execute" => o.stop_after_execute = true,
            "--hash" => o.hash = v(),
            _ => panic!("unknown argument {k}"),
        }
    }
    o
}

/// One JSON object of results.
#[derive(Default)]
struct Report(Vec<(String, String)>);

impl Report {
    fn num(&mut self, k: &str, v: f64) { self.0.push((k.into(), format!("{v:.3}"))); }
    fn int(&mut self, k: &str, v: u64) { self.0.push((k.into(), v.to_string())); }
    fn text(&mut self, k: &str, v: &str) { self.0.push((k.into(), format!("{v:?}"))); }
    fn raw(&mut self, k: &str, v: String) { self.0.push((k.into(), v)); }
    fn line(&self) -> String {
        let body: Vec<String> = self.0.iter().map(|(k, v)| format!("\"{k}\": {v}")).collect();
        format!("{{{}}}", body.join(", "))
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    let o = parse(args);
    let (report, code) = match cmd.as_str() {
        "prove" => prove(&o),
        "verify" => (verify(&o), 0),
        _ => panic!("usage: bsb-zk prove|verify ... (see the module docs)"),
    };
    println!("{}", report.line());
    std::process::exit(code);
}

fn variant(o: &Opts) -> PreProcessedTraceVariant {
    match o.max_log_rows {
        Some(k) => PreProcessedTraceVariant::CanonicalWithoutPedersenUpTo(k),
        None => PreProcessedTraceVariant::CanonicalWithoutPedersen,
    }
}

fn standalone(exe: &Executable) -> &ExecutableEntryPoint {
    exe.entrypoints.iter().find(|e| matches!(e.kind, EntryPointKind::Standalone)).expect("standalone entry point")
}

fn load_executable(path: &Path, hash: &str) -> Executable {
    let exe: Executable = serde_json::from_reader(std::fs::File::open(path).expect("executable")).expect("executable json");
    let builtins: Vec<&str> = standalone(&exe).builtins.iter().map(|b| b.to_str()).collect();
    assert_eq!(builtins, self::builtins(hash), "executable builtins differ from the pinned list");
    // A syscall's result is a hint the proof does not constrain in direct mode.
    for (pc, hints) in &exe.program.hints {
        for h in hints {
            let s = serde_json::to_string(h).expect("hint json");
            assert!(!s.contains("SystemCall") && !s.contains("Cheatcode"), "program has a syscall hint at pc {pc}");
        }
    }
    exe
}

// ---------------------------------------------------------------------------- prove

fn run_direct(exe: &Executable, args_path: &Path) -> Result<CairoRunner, String> {
    let (program, string_to_hint) = program_and_hints_from_executable(exe, standalone(exe)).expect("program");
    let user_args = user_args_from_flags(Some(&args_path.to_path_buf()), &[]).expect("user args");
    let mut hint_processor = CairoHintProcessor {
        runner: None,
        user_args: vec![vec![Arg::Array(user_args)]],
        string_to_hint,
        starknet_state: Default::default(),
        run_resources: Default::default(),
        syscalls_used_resources: Default::default(),
        no_temporary_segments: false,
        markers: Default::default(),
        panic_traceback: Default::default(),
    };
    let config = CairoRunConfig {
        trace_enabled: true,
        relocate_mem: true,
        layout: LayoutName::all_cairo_stwo,
        disable_trace_padding: true,
        proof_mode: true,
        // Complete builtin instances the program only partly read; the adapter needs whole ones.
        fill_holes: true,
        ..Default::default()
    };
    cairo_vm::cairo_run::cairo_run_program(&program, &config, &mut hint_processor).map_err(|e| format!("{e}"))
}

fn prove(o: &Opts) -> (Report, i32) {
    let mut r = Report::default();
    let total = Instant::now();
    let exe = load_executable(&o.executable, &o.hash);
    let t = Instant::now();
    let runner = match run_direct(&exe, o.args.as_ref().expect("--args")) {
        Ok(runner) => runner,
        Err(e) => {
            r.text("run", "failed");
            r.text("error", &e.chars().take(400).collect::<String>());
            peak_rss(&mut r);
            return (r, 2);
        }
    };
    r.text("run", "completed");
    r.num("execute_s", t.elapsed().as_secs_f64());
    r.int("steps", runner.vm.get_current_step() as u64);
    for b in runner.vm.get_builtin_runners() {
        if let Ok(used) = b.get_used_cells(&runner.vm.segments) {
            r.int(&format!("cells_{}", b.name().to_str()), used as u64);
        }
    }
    if o.stop_after_execute {
        r.num("total_s", total.elapsed().as_secs_f64());
        peak_rss(&mut r);
        return (r, 0);
    }

    let t = Instant::now();
    let mut input = adapt(&runner).expect("adapt");
    // `adapt` assumes the bootloader's builtins; describe the program's own.
    let builtins: Vec<_> = runner.get_program().iter_builtins().copied().collect();
    input.public_segment_context = PublicSegmentContext::new(&builtins);
    drop(runner);
    r.num("adapt_s", t.elapsed().as_secs_f64());

    let t = Instant::now();
    let params = ProverParameters {
        channel_hash: ChannelHash::Blake2s,
        channel_salt: None,
        pcs_config: pcs_config(),
        preprocessed_trace: variant(o),
        store_polynomials_coefficients: false,
    };
    let proof = prove_cairo::<Blake2sMerkleChannel>(input, params).expect("prove");
    r.num("prove_s", t.elapsed().as_secs_f64());

    let out = o.out.as_ref().expect("--out");
    serialize_proof_to_file(&proof, out, ProofFormat::Json).expect("write proof");
    r.int("proof_bytes", std::fs::metadata(out).expect("proof file").len());
    r.raw("output", hex_list(&output_felts(&proof)));
    r.num("total_s", total.elapsed().as_secs_f64());
    peak_rss(&mut r);
    (r, 0)
}

// ---------------------------------------------------------------------------- verify

/// Blake2s over the public program, felt by felt (eight little-endian u32 limbs each).
/// Pinning this to the zk_pdp bytecode is what makes a proof about that program.
fn program_id<'a>(words: impl Iterator<Item = &'a [u32; 8]>) -> ([u8; 32], usize) {
    let mut h = Blake2s256::new();
    let mut n = 0;
    for w in words {
        for limb in w {
            h.update(limb.to_le_bytes());
        }
        n += 1;
    }
    (h.finalize().into(), n)
}

fn bytecode_limbs(exe: &Executable) -> Vec<[u32; 8]> {
    exe.program
        .bytecode
        .iter()
        .map(|b| {
            let bytes = cairo_vm::Felt252::from(b).to_bytes_le();
            let mut limbs = [0u32; 8];
            for (i, c) in bytes.chunks_exact(4).enumerate() {
                limbs[i] = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
            }
            limbs
        })
        .collect()
}

/// The public output section as big-endian felts.
fn output_felts(proof: &CairoProof<Blake2sMerkleHasher>) -> Vec<[u8; 32]> {
    proof
        .claim
        .public_data
        .public_memory
        .output
        .iter()
        .map(|(_, limbs)| {
            let mut be = [0u8; 32];
            for (i, l) in limbs.iter().enumerate() {
                be[28 - 4 * i..32 - 4 * i].copy_from_slice(&l.to_be_bytes());
            }
            be
        })
        .collect()
}

fn hex_list(felts: &[[u8; 32]]) -> String {
    let items: Vec<String> = felts.iter().map(|f| format!("\"0x{}\"", hex(f).trim_start_matches('0'))).collect();
    format!("[{}]", items.join(", ").replace("\"0x\"", "\"0x0\""))
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn felt_from_hex(s: &str) -> [u8; 32] {
    let s = s.trim_start_matches("0x");
    assert!(s.len() <= 64 && s.chars().all(|c| c.is_ascii_hexdigit()), "bad felt {s}");
    let padded = format!("{s:0>64}");
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[i] = u8::from_str_radix(&padded[2 * i..2 * i + 2], 16).unwrap();
    }
    be
}

/// What `verify_cairo` reads from the proof without checking it, pinned here (the lesson of
/// rust-bitcoin's zk-sync reviews): each would otherwise let a prover make a valid proof say
/// something else.
fn check_claim_shape(
    proof: &CairoProof<Blake2sMerkleHasher>,
    hash: &str,
    root: &str,
    n_out: usize,
) -> Result<(), String> {
    use BuiltinName as B;
    let c = proof.stark_proof.config;
    let want = pcs_config();
    if (c.pow_bits, c.fri_config.log_blowup_factor, c.fri_config.n_queries, c.fri_config.log_last_layer_degree_bound)
        != (want.pow_bits, want.fri_config.log_blowup_factor, want.fri_config.n_queries, 0)
    {
        return Err(format!("unexpected PCS config {c:?}"));
    }
    if proof.channel_salt.is_some() {
        return Err("unexpected channel salt".into());
    }
    let got = format!("{}", proof.stark_proof.commitments[0]);
    if got != root {
        return Err(format!("preprocessed root {got} is not {root}"));
    }
    let segs = &proof.claim.public_data.public_memory.public_segments;
    let has = |b: B| builtins(hash).contains(&b.to_str());
    let pattern = [
        (segs.pedersen.is_some(), has(B::pedersen)),
        (segs.range_check_128.is_some(), has(B::range_check)),
        (segs.ecdsa.is_some(), has(B::ecdsa)),
        (segs.bitwise.is_some(), has(B::bitwise)),
        (segs.ec_op.is_some(), has(B::ec_op)),
        (segs.keccak.is_some(), has(B::keccak)),
        (segs.poseidon.is_some(), has(B::poseidon)),
        (segs.range_check_96.is_some(), has(B::range_check96)),
        (segs.add_mod.is_some(), has(B::add_mod)),
        (segs.mul_mod.is_some(), has(B::mul_mod)),
    ];
    if pattern.iter().any(|(got, want)| got != want) {
        return Err(format!("builtin segments {pattern:?} (present, expected)"));
    }
    let pd = &proof.claim.public_data;
    let out = &segs.output;
    let n = pd.public_memory.output.len() as u32;
    if out.start_ptr.value != pd.final_state.ap.0 || out.stop_ptr.value != out.start_ptr.value + n || n as usize != n_out {
        return Err(format!(
            "output segment [{}, {}) with {n} felts, final ap {}",
            out.start_ptr.value, out.stop_ptr.value, pd.final_state.ap.0
        ));
    }
    Ok(())
}

fn verify(o: &Opts) -> Report {
    let mut r = Report::default();
    let total = Instant::now();
    let exe = load_executable(&o.executable, &o.hash);
    let (expected_id, expected_len) = program_id(bytecode_limbs(&exe).iter());

    let statement: serde_json::Value =
        serde_json::from_reader(std::fs::File::open(o.statement.as_ref().expect("--statement")).expect("statement"))
            .expect("statement json");
    let want: Vec<[u8; 32]> = statement["output"]
        .as_array()
        .expect("statement.output")
        .iter()
        .map(|v| felt_from_hex(v.as_str().expect("felt string")))
        .collect();

    let t = Instant::now();
    let root = format!(
        "{}",
        stwo_cairo_prover::witness::preprocessed_trace::generate_preprocessed_commitment_root::<Blake2sMerkleChannel>(
            pcs_config().fri_config.log_blowup_factor,
            variant(o)
        )
    );
    r.num("preprocessed_root_s", t.elapsed().as_secs_f64());

    let t = Instant::now();
    let path = o.proof.as_ref().expect("--proof");
    let proof: CairoProof<Blake2sMerkleHasher> = deserialize_proof_from_file(path, ProofFormat::Json).expect("read proof");
    r.num("load_s", t.elapsed().as_secs_f64());

    let (id, n) = program_id(proof.claim.public_data.public_memory.program.iter().map(|(_, w)| w));
    assert!(id == expected_id && n == expected_len, "public program is not zk_pdp ({n} words, expected {expected_len})");
    r.text("program_id", &hex(&id));
    check_claim_shape(&proof, &o.hash, &root, want.len()).unwrap_or_else(|e| panic!("claim shape: {e}"));
    let got = output_felts(&proof);
    assert!(got == want, "public output {} is not the statement's {}", hex_list(&got), hex_list(&want));

    let t = Instant::now();
    verify_cairo::<Blake2sMerkleChannel>(proof, variant(o)).unwrap_or_else(|e| panic!("STARK: {e:?}"));
    r.num("stark_verify_s", t.elapsed().as_secs_f64());
    r.text("result", "verified");
    r.num("total_s", total.elapsed().as_secs_f64());
    r
}

fn peak_rss(r: &mut Report) {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else { return };
    if let Some(kib) = status.lines().find(|l| l.starts_with("VmHWM:")).and_then(|l| l.split_whitespace().nth(1)) {
        if let Ok(kib) = kib.parse::<f64>() {
            r.num("peak_rss_mib", kib / 1024.0);
        }
    }
}
