//! Real 2-of-3 BIP340-compatible FROST threshold signatures, but NOT yet
//! BIP341 transaction signing, Sapio MID, distributed custody or Filecoin proof.
//!
//! This isolated reference uses Zcash Foundation frost-secp256k1-tr 3.0.0.
//! An ephemeral trusted dealer hands shares to simulated separate participants
//! in one OS process. Never store or print shares/nonce material. The
//! Taproot-specific ciphersuite was outside the cited legacy NCC audit scope.

use frost_secp256k1_tr as frost;
use rand_core::OsRng;
use secp256k1::{Message, PublicKey, Secp256k1, XOnlyPublicKey, schnorr};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap, env, error::Error, fs,
    io::Write, path::Path,
};

type ErrBox = Box<dyn Error>;
type Packages = BTreeMap<frost::Identifier, frost::keys::KeyPackage>;

fn hex(bytes: impl AsRef<[u8]>) -> String {
    let mut result = String::new();
    for byte in bytes.as_ref() {
        result.push_str(&format!("{byte:02x}"));
    }
    result
}
fn hash(bytes: &[u8]) -> [u8;32] {
    let digest = Sha256::digest(bytes);
    digest.into()
}
fn digest(protocol: &str, evidence: &str) -> [u8;32] {
    hash(format!("BSB-FROST-BIP340-NONTRANSACTION-V1|{protocol}|{evidence}|100000|alice60000|bob40000").as_bytes())
}

struct Signed {
    signature: frost::Signature,
    incomplete_rejected: bool,
}

fn sign_two(
    selected: &[frost::Identifier],
    packages: &Packages,
    public: &frost::keys::PublicKeyPackage,
    message: &[u8;32],
    rng: &mut OsRng,
) -> Result<Signed, ErrBox> {
    if selected.len() != 2 || selected[0] == selected[1] {
        return Err("requires two distinct ephemeral test participants".into());
    }
    let mut commitment_map=BTreeMap::new();
    let mut nonce_map=BTreeMap::new();
    for identifier in selected {
        let package=packages.get(identifier).ok_or("unknown participant")?;
        let (nonces,commitments)=frost::round1::commit(package.signing_share(),rng);
        nonce_map.insert(*identifier,nonces);
        commitment_map.insert(*identifier,commitments);
    }
    let signing=frost::SigningPackage::new(commitment_map,message);
    let mut shares=BTreeMap::new();
    for identifier in selected {
        let nonces=nonce_map.get(identifier).ok_or("missing private signing nonce")?;
        let key_package=packages.get(identifier).ok_or("unknown key package")?;
        let signed=frost::round2::sign(&signing,nonces,key_package)?;
        shares.insert(*identifier,signed);
    }
    let signature=frost::aggregate(&signing,&shares,public)?;
    let removed=shares.remove(&selected[1]);
    assert!(removed.is_some());
    let incomplete_rejected=frost::aggregate(&signing,&shares,public).is_err();
    if !incomplete_rejected {
        return Err("single signature share unexpectedly aggregated to a 2-of-3 signature".into());
    }
    public.verifying_key().verify(message,&signature)?;
    Ok(Signed{signature,incomplete_rejected})
}

fn bitcoin_xonly(public: &frost::keys::PublicKeyPackage) -> Result<XOnlyPublicKey,ErrBox> {
    let serialized=public.verifying_key().serialize()?;
    let point=match serialized.len() {
        33 => PublicKey::from_slice(&serialized)?.x_only_public_key().0,
        32 => XOnlyPublicKey::from_slice(&serialized)?,
        _ => return Err("unexpected threshold verifying key serialization".into()),
    };
    Ok(point)
}

fn verify_bitcoin(message: &[u8;32],signature: &frost::Signature,key: &XOnlyPublicKey)
    -> Result<Vec<u8>,ErrBox>
{
    let bytes=signature.serialize()?;
    if bytes.len() != 64 {return Err("FROST signature is not 64-byte BIP340".into());}
    let sig=schnorr::Signature::from_slice(&bytes)?;
    let msg=Message::from_digest(*message);
    Secp256k1::verification_only().verify_schnorr(&sig,&msg,key)?;
    let different=hash(b"BTC is not validating any Filecoin claim in this experiment");
    if Secp256k1::verification_only()
       .verify_schnorr(&sig,&Message::from_digest(different),key).is_ok() {
        return Err("threshold signature verified a different Bitcoin message".into());
    }
    Ok(bytes)
}

fn result(evidence_hash:&str)->Result<Value,ErrBox>{
    if evidence_hash.len()!=64||!evidence_hash.bytes().all(|c|c.is_ascii_hexdigit()){
        return Err("supply the real 64-hex-character shared Alice epoch-2 Merkle evidence hash".into());
    }
    let mut rng=OsRng;
    let (shares,public)=frost::keys::generate_with_dealer(
        3,2,frost::keys::IdentifierList::Default,&mut rng)?;
    let mut packages=Packages::new();
    for (id,share) in shares {
        packages.insert(id,frost::keys::KeyPackage::try_from(share)?);
    }
    if packages.len()!=3 {return Err("dealer did not produce three verified shares".into());}
    let identifiers=packages.keys().copied().collect::<Vec<_>>();
    let key=bitcoin_xonly(&public)?;
    let signed_msg=digest("storage-fault-real-reference-evidence",evidence_hash);
    let mut proofs=Vec::new();
    for pair in [[0usize,1],[0,2],[1,2]] {
        let selected=[identifiers[pair[0]],identifiers[pair[1]]];
        let signed=sign_two(&selected,&packages,&public,&signed_msg,&mut rng)?;
        let bytes=verify_bitcoin(&signed_msg,&signed.signature,&key)?;
        proofs.push(json!({
            "signingParticipants":[pair[0]+1,pair[1]+1],
            "bip340SignatureHex":hex(bytes),
            "secp256k1CrossVerified":true,
            "missingSecondSignatureShareRejected":signed.incomplete_rejected,
        }));
    }
    let malicious_msg=digest("colluding-signers-fabricated-payout",evidence_hash);
    let collusion=sign_two(&identifiers[..2],&packages,&public,&malicious_msg,&mut rng)?;
    let malicious_signature=verify_bitcoin(&malicious_msg,&collusion.signature,&key)?;
    if public.verifying_key().verify(&signed_msg,&collusion.signature).is_ok() {
        return Err("colluding quorums' different message verified as honest intent".into());
    }
    Ok(json!({
        "schema":"bsb-frost-bip340-cryptographic-roundtrip-v1",
        "network":"no-bitcoin-chain",
        "sourceEvidenceHash":evidence_hash,
        "threshold":2,
        "participants":3,
        "trustedDealerEphemeral":true,
        "separateOsProcesses":false,
        "nonceCommitmentRounds":2,
        "sourceCiphersuite":"frost-secp256k1-tr=3.0.0",
        "bip340GroupPublicKeyXOnlyHex":hex(key.serialize()),
        "messageDigestHex":hex(signed_msg),
        "honestSignatures":proofs,
        "adversarialThreshold":{
            "twoColludersCanSignUnauthorizedMessage":true,
            "unauthorizedMessageDigestHex":hex(malicious_msg),
            "unauthorizedBip340SignatureHex":hex(malicious_signature),
            "validForOriginalAuthorizedMessage":false,
        },
        "limits":{
            "keySharesNeverSerialized":true,
            "secp256k1CrossVerified":true,
            "bip341TransactionSighashSigned":false,
            "btcMempoolOrBlockVerified":false,
            "sapioMidEnforced":false,
            "p2trTapTweakApplied":false,
            "independentBlossomPdpEvidenceConsumedOnlyAsHash":true,
            "frostCiphersuiteCoveredByLegacyAudit":false,
            "distributedFrostSigningCustodyVerified":false
        }
    }))
}

fn run()->Result<(),ErrBox>{
    let mut args=env::args().skip(1);
    let hash=args.next().ok_or("usage: bsb-frost-bip340-proof EVIDENCE_SHA256 [OUTPUT_JSON]")?;
    let path=args.next();
    if args.next().is_some(){return Err("only one output path may be supplied".into());}
    let summary=result(&hash)?;
    let serialized=serde_json::to_string_pretty(&summary)?+"\n";
    if let Some(path)=path {
        let mut opts=fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]{
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file=opts.open(Path::new(&path))?;
        file.write_all(serialized.as_bytes())?;
        file.sync_all()?;
    }
    print!("{serialized}");
    Ok(())
}
fn main(){
    if let Err(err)=run(){ eprintln!("FROST test failed: {err}"); std::process::exit(1); }
}
