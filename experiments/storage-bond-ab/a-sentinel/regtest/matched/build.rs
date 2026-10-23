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
    let mod_line="mod rpc;";
    assert_eq!(code.matches(mod_line).count(),1);
    code=code.replace(mod_line,&format!("#[path = {:?}]\nmod rpc;",rpc.to_string_lossy()));
    let fixture="concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/../fixtures/sentinels.json\")";
    assert_eq!(code.matches(fixture).count(),1);
    code=code.replace(fixture,
        "concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/../../../../../fixtures/sentinels.json\")");
    let output="let path = concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/../results/regtest.json\");";
    assert_eq!(code.matches(output).count(),1);
    code=code.replace(output,
        "let path = std::env::var(\"BSB_A_RESULT_PATH\").expect(\"provide private A/B report path\");");
    let mk="std::fs::create_dir_all(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/../results\")).unwrap();";
    assert_eq!(code.matches(mk).count(),1);
    code=code.replace(mk,
        "std::fs::create_dir_all(std::path::Path::new(&path).parent().unwrap()).unwrap();");
    let target=PathBuf::from(env::var("OUT_DIR").unwrap()).join("original_sentinel_adapted.rs");
    fs::write(target,code).unwrap();
}
