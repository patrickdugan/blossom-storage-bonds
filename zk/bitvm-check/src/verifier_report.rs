//! Fail-closed checks for the standalone BitVM experiment's recorded outcomes.
//! These validate evidence fields, not a proof supplied by an untrusted claimant.
use bitvm::chunk::api::{NUM_HASH, NUM_PUBS, NUM_TAPS, NUM_U256};
use serde_json::Value;

const SCRIPT_BUDGET: u64 = 4_000_000 - 16_000;

fn boolean(report: &Value, path: &str, expected: bool) -> Result<(), String> {
    if report.pointer(path).and_then(Value::as_bool) == Some(expected) {
        Ok(())
    } else {
        Err(format!("{path}: expected {expected}"))
    }
}
fn number(report: &Value, path: &str) -> Result<u64, String> {
    report
        .pointer(path)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{path}: expected unsigned integer"))
}
pub fn validate(report: &Value) -> Result<(), String> {
    if report["bitvm_rev"].as_str() != Some("7d1ca36") {
        return Err("unexpected BitVM revision".into());
    }
    boolean(report, "/arkworks/verifies", true)?;
    boolean(report, "/arkworks/wrong_public_verifies", false)?;
    boolean(report, "/honest/all_disprove_scripts_fail", true)?;
    boolean(report, "/honest/validate/found", false)?;
    if number(report, "/tapscripts/count")? != NUM_TAPS as u64 {
        return Err("wrong tapscript count".into());
    }
    if number(report, "/honest/assertions/u256")? != (NUM_PUBS + NUM_U256) as u64
        || number(report, "/honest/assertions/hash")? != NUM_HASH as u64
    {
        return Err("wrong assertion counts".into());
    }
    let largest = number(report, "/tapscripts/largest_bytes")?;
    let smallest = number(report, "/tapscripts/smallest_bytes")?;
    if smallest == 0
        || smallest > largest
        || largest >= SCRIPT_BUDGET
        || number(report, "/tapscripts/total_bytes")? < largest
    {
        return Err("invalid tapscript size range".into());
    }
    for name in ["wrong_public_input", "corrupted_intermediate"] {
        let base = format!("/{name}");
        boolean(report, &format!("{base}/found"), true)?;
        boolean(report, &format!("{base}/executes"), true)?;
        boolean(report, &format!("{base}/under_4mb_less_16k"), true)?;
        let locking = number(report, &format!("{base}/locking_script_bytes"))?;
        let witness = number(report, &format!("{base}/witness_script_bytes"))?;
        let total = number(report, &format!("{base}/script_plus_witness_bytes"))?;
        let stack = number(report, &format!("{base}/max_stack_items"))?;
        let tap = number(report, &format!("{base}/tap_index"))?;
        if tap >= NUM_TAPS as u64
            || locking == 0
            || locking > largest
            || witness == 0
            || locking.checked_add(witness) != Some(total)
            || total >= SCRIPT_BUDGET
            || stack == 0
            || stack > 1000
        {
            return Err(format!(
                "{name}: disprove exceeds resource budget or has inconsistent measurements"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn known() -> Value {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../results/bitvm2-spike.json")).unwrap();
        fixture["m3"]["bitvm"].clone()
    }
    #[test]
    fn actual_historical_evidence_passes() {
        validate(&known()).unwrap();
    }
    #[test]
    fn omitted_disproves_never_count_as_success() {
        for name in ["wrong_public_input", "corrupted_intermediate"] {
            let mut value = known();
            value.as_object_mut().unwrap().remove(name);
            assert!(validate(&value).is_err());
            let mut value = known();
            value[name] = json!({"found":false});
            assert!(validate(&value).is_err());
        }
    }
    #[test]
    fn failed_or_oversized_disproves_are_rejected() {
        for name in ["wrong_public_input", "corrupted_intermediate"] {
            for (field, bad) in [
                ("executes", json!(false)),
                ("under_4mb_less_16k", json!(false)),
                ("max_stack_items", json!(1001)),
                ("tap_index", json!(NUM_TAPS)),
                ("script_plus_witness_bytes", json!(SCRIPT_BUDGET)),
                ("witness_script_bytes", json!(0)),
            ] {
                let mut value = known();
                value[name][field] = bad;
                assert!(validate(&value).is_err(), "{name}/{field}");
            }
        }
    }
    #[test]
    fn invalid_honest_and_pairing_results_are_rejected() {
        for (path, bad) in [
            ("/arkworks/verifies", json!(false)),
            ("/arkworks/wrong_public_verifies", json!(true)),
            ("/honest/all_disprove_scripts_fail", json!(false)),
            ("/honest/validate/found", json!(true)),
            ("/tapscripts/count", json!(0)),
            ("/honest/assertions/hash", json!(0)),
            ("/tapscripts/largest_bytes", json!(SCRIPT_BUDGET)),
        ] {
            let mut value = known();
            *value.pointer_mut(path).unwrap() = bad;
            assert!(validate(&value).is_err(), "{path}");
        }
    }
    #[test]
    fn wrong_types_cannot_pass_as_true_or_false() {
        let mut value = known();
        value["wrong_public_input"]["executes"] = json!("true");
        assert!(validate(&value).is_err());
        let mut value = known();
        value["honest"]["validate"]["found"] = Value::Null;
        assert!(validate(&value).is_err());
    }
}
