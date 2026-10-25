// Build-time adapter for the audited original Phase-1 Taproot sentinel harness.
// The source code in /regtest is never edited. This experimental clone only
// substitutes the original BOND constant with a runtime 60k/40k fixture value
// and redirects the public regression receipt to a private output directory.
use std::{env,fs,path::PathBuf};
fn main(){
    let here=PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let source=here.join("../../../../../regtest/src/main.rs").canonicalize().unwrap();
    let rpc=here.join("../../../../../regtest/src/rpc.rs").canonicalize().unwrap();
    println!("cargo:rerun-if-changed={}",source.display());
    println!("cargo:rerun-if-changed={}",rpc.display());
    let original=fs::read_to_string(&source).unwrap();
    let mut code=original.replace("//!","//");
    // Preserve the reference 144-block CSV in original comparisons. Only
    // the A/B shared-PDP run chooses the same six-block challenge policy
    // as scenario.mjs; the actual Bitcoin CSV semantics remain unchanged.
    println!("cargo:rerun-if-env-changed=BSB_A_SHARED_PDP");
    if std::env::var("BSB_A_SHARED_PDP").as_deref() == Ok("1") {
        let delay="const DELTA: u16 = 144;";
        assert_eq!(code.matches(delay).count(),1,"upstream CSV policy changed");
        code=code.replace(delay,"const DELTA: u16 = 6;");
    }
    let bond_const="const BOND: Amount = Amount::from_sat(100_000_000);";
    assert_eq!(code.matches(bond_const).count(),1,"upstream bond constant changed");
    code=code.replace(bond_const,r#"
fn bond() -> Amount {
    let n: u64 = std::env::var("BSB_A_BOND_SATS")
        .expect("set the small A/B bond value")
        .parse().expect("A/B bond sats must be an integer");
    assert!(n == 60_000 || n == 40_000, "A/B experiments permit only 60k and 40k sats");
    Amount::from_sat(n)
}
"#);
    code=code.replace("BOND","bond()");
    // Replacing the constant name must not change the runtime env-var key.
    code=code.replace("BSB_A_bond()_SATS","BSB_A_BOND_SATS");
    let mod_line="mod rpc;";
    assert_eq!(code.matches(mod_line).count(),1);
    code=code.replace(mod_line,&format!("#[path = {:?}]\nmod rpc;",rpc.to_string_lossy()));
    let fixture="concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/../fixtures/sentinels.json\")";
    assert_eq!(code.matches(fixture).count(),1);
    code=code.replace(fixture,
        "std::env::var(\"BSB_A_SENTINELS_JSON\").unwrap_or_else(|_| concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/../../../../../fixtures/sentinels.json\").to_owned())");
    let output="let path = concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/../results/regtest.json\");";
    assert_eq!(code.matches(output).count(),1);
    code=code.replace(output,
        "let path = std::env::var(\"BSB_A_RESULT_PATH\").expect(\"provide private A/B report path\");");
    let mk="std::fs::create_dir_all(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/../results\")).unwrap();";
    assert_eq!(code.matches(mk).count(),1);
    code=code.replace(mk,
        "std::fs::create_dir_all(std::path::Path::new(&path).parent().unwrap()).unwrap();");
    // Commitments in Bitcoin witnesses must match the original shared PDP
    // Merkle-derived fixture exactly, not only a test label in Node.
    let anchor="\"k\": k, \"delta\": DELTA, \"bond_sats\": bond().to_sat(),";
    assert_eq!(code.matches(anchor).count(),1,"upstream report shape changed");
    code=code.replace(anchor,
        "\"k\": k, \"delta\": DELTA, \"bond_sats\": bond().to_sat(), \"ab_sentinel_h\": sen.iter().map(|s| s.h.iter().map(|byte| format!(\"{byte:02x}\")).collect::<String>()).collect::<Vec<_>>(),");
    let target=PathBuf::from(env::var("OUT_DIR").unwrap()).join("original_sentinel_adapted.rs");
    fs::write(target,code).unwrap();
}
