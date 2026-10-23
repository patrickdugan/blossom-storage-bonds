//! ADR-016 checker: Bitcoin Core 26 libbitcoinconsensus + bip347.patch (OP_CAT in tapscript, BIP347
//! semantics). This is a local research build, not activated Bitcoin consensus. Run prepare.sh first.
#[path = "../../consensus-check/src/tapscript_check.rs"]
mod tapscript_check;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tapscript_check::run("bip347_valid", "Bitcoin Core 26 + BIP347 patch")
}
