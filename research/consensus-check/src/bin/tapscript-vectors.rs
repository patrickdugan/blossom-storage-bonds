//! ADR-015/016 checker on stock Bitcoin Core 26 libbitcoinconsensus with Taproot enabled.
#[path = "../tapscript_check.rs"]
mod tapscript_check;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tapscript_check::run("core_valid", "Bitcoin Core 26 Taproot cases")
}
