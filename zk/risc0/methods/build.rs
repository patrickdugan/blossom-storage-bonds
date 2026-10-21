fn main() {
    println!("cargo:rerun-if-changed=../fork_relation.rs");
    risc0_build::embed_methods();
}
