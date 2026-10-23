//! Offline BIP341/BIP340 pre-signature and Taproot-template evidence.
 //!
 //! Actual rust-bitcoin transaction serialization and Schnorr preflight,
 //! with fabricated outpoints and public test keys. Does NOT run Bitcoin
 //! Core consensus/UTXO validation, script interpretation or mining.
 //!
 //! Generates one complete two-generation witness-stable sentinel example,
 //! direct terminal refund/forfeit templates, plus signature mutation checks.
#[path = "../common.rs"]
mod common;
use common::*;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::{sha256,Hash};
use bitcoin::transaction::Version;
use bitcoin::{Amount,OutPoint,ScriptBuf,Sequence,Transaction,TxOut,Txid,Network,Address};
use bitcoin::secp256k1::Secp256k1;
use serde_json::{json,Value};

fn signatures(
    secp:&bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    tx:&Transaction, prev:&TxOut, script:&ScriptBuf,
    p:&Party,c:&Party
) -> (Vec<u8>,Vec<u8>) {
    (script_sig(secp,tx,prev,script,p),script_sig(secp,tx,prev,script,c))
}

fn value_check(tx:&Transaction, value:Amount, expected:&ScriptBuf) {
    assert_eq!(tx.input.len(),1,"presigned parent has exactly one input");
    assert_eq!(tx.output.len(),2,"presigned parent has successor and P2A");
    assert_eq!(tx.output[0].value,value,"successor carries exact bond amount");
    assert_eq!(&tx.output[0].script_pubkey,expected);
    assert_eq!(tx.output[1].value,Amount::ZERO);
    assert_eq!(tx.output[1].script_pubkey,p2a());
    assert_eq!(tx.version,Version(3));
    assert_eq!(tx.lock_time,LockTime::ZERO);
}
fn pair_row(
    secp:&bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    tx:&Transaction,prev:&TxOut,leaf:&ScriptBuf,
    p:&Party,c:&Party, witness:Vec<Vec<u8>>,
    name:&str
) -> Value {
    let (sig_p,sig_c)=signatures(secp,tx,prev,leaf,p,c);
    assert!(verify_script_sig(secp,tx,prev,leaf,&p.x,&sig_p));
    assert!(verify_script_sig(secp,tx,prev,leaf,&c.x,&sig_c));
    let mut changed_dest=tx.clone();
    changed_dest.output[0].script_pubkey=Address::p2tr(secp,p.x,None,Network::Regtest).script_pubkey();
    assert!(!verify_script_sig(secp,&changed_dest,prev,leaf,&p.x,&sig_p));
    assert!(!verify_script_sig(secp,&changed_dest,prev,leaf,&c.x,&sig_c));
    let mut changed_amount=tx.clone();
    changed_amount.output[0].value=BOND-CLOSE_FEE;
    assert!(!verify_script_sig(secp,&changed_amount,prev,leaf,&p.x,&sig_p));
    let mut changed_prevout=tx.clone();
    changed_prevout.input[0].previous_output.txid=Txid::from_byte_array([0x7f;32]);
    assert!(!verify_script_sig(secp,&changed_prevout,prev,leaf,&p.x,&sig_p));
    let tx_with_witness=with_witness(tx.clone(),witness.clone());
    assert_eq!(tx_with_witness.compute_txid(),tx.compute_txid());
    let mut wrong_opening=witness.clone();
    wrong_opening[0]=vec![0xfau8;wrong_opening[0].len()];
    let wrong_witness=with_witness(tx.clone(),wrong_opening);
    assert_eq!(wrong_witness.compute_txid(),tx.compute_txid());
    assert_ne!(wrong_witness.compute_wtxid(),tx_with_witness.compute_wtxid());
    let mut wrong_control=witness.clone();
    wrong_control.last_mut().unwrap()[0]^=1;
    let wrong_control_tx=with_witness(tx.clone(),wrong_control);
    assert_eq!(wrong_control_tx.compute_txid(),tx.compute_txid());
    let mut wrong_leaf=witness.clone();
    let leaf_idx=wrong_leaf.len()-2;
    wrong_leaf[leaf_idx]=vec![0x51u8];
    let wrong_leaf_tx=with_witness(tx.clone(),wrong_leaf);
    json!({
       "name":name, "txid":tx.compute_txid().to_string(),
       "wtxid":tx_with_witness.compute_wtxid().to_string(),
       "raw_hex":serialize_hex(&tx_with_witness),
       "version":tx.version.0,"lock_time":tx.lock_time.to_consensus_u32(),
       "inputs":tx.input.len(),"outputs":tx.output.len(),
       "out0_value":tx.output[0].value.to_sat(),
       "out0_script":tx.output[0].script_pubkey.to_hex_string(),
       "anchor_value":tx.output[1].value.to_sat(),
       "anchor_script":tx.output[1].script_pubkey.to_hex_string(),
       "spent_script":prev.script_pubkey.to_hex_string(),
       "spent_value":prev.value.to_sat(),
       "script_hex":leaf.to_hex_string(),
       "valid_provider_sig":true,"valid_client_sig":true,
       "mutated_output_provider_sig_valid":false,
       "mutated_output_client_sig_valid":false,
       "mutated_amount_provider_sig_valid":false,
       "mutated_prevout_provider_sig_valid":false,
       "witness_keeps_txid":true,
       "adversarial_raw_hex":{
           "redirect_successor":serialize_hex(&with_witness(changed_dest,witness.clone())),
           "reduce_successor":serialize_hex(&with_witness(changed_amount,witness.clone())),
           "replace_prevout":serialize_hex(&with_witness(changed_prevout,witness.clone())),
           "wrong_sentinel_opening":serialize_hex(&wrong_witness),
           "wrong_control_block":serialize_hex(&wrong_control_tx),
           "wrong_leaf_script":serialize_hex(&wrong_leaf_tx)
       }
    })
}
fn main() {
    let secp=Secp256k1::new();
    let p=party(&secp,"formal-evidence-provider-public-test-only");
    let c=party(&secp,"formal-evidence-client-public-test-only");
    let seed=vec![0x42u8;16];
    let sentinel_hash=sha256::Hash::hash(&seed).to_byte_array();
    let mut answer=seed.clone();
    answer.extend(std::iter::repeat(0x5eu8).take(64));
    let answer_hash=sha256::Hash::hash(&answer).to_byte_array();
    let spec=vec![(sentinel_hash,vec![answer_hash]),(sentinel_hash,vec![answer_hash])];
    let funding=OutPoint{txid:Txid::from_byte_array([0x11;32]),vout:0};
    // NUMS mode equals the operational bsb-bond tool. MuSig2 is a separate
    // configuration with a separate authorization path.
    let chain=build_chain(&secp,nums(),&p.x,&c.x,&spec,960_000);
    let t=presign_chain(&secp,&chain,&p,&c,funding);
    assert_eq!(chain.bonds.len(),3);
    assert_eq!(chain.challenged.len(),2);
    assert_eq!(t.challenge.len(),2);
    assert_eq!(t.respond.len(),2);
    assert_eq!(chain.refund.to_hex_string(),refund_leaf(&p.x,960_000).to_hex_string());
    assert_eq!(chain.forfeit.to_hex_string(),forfeit_leaf(&c.x,DELTA).to_hex_string());
    let mut rows=vec![];
    for i in 0..2 {
        let cp=&t.challenge[i];
        let rp=&t.respond[i];
        assert_eq!(rp.input[0].previous_output.txid,cp.compute_txid());
        assert_eq!(rp.input[0].previous_output.vout,0);
        let expect_bond_outpoint=if i==0 {
            funding
        } else {
            OutPoint{txid:t.respond[i-1].compute_txid(),vout:0}
        };
        assert_eq!(cp.input[0].previous_output,expect_bond_outpoint);
        value_check(cp,BOND,&chain.challenged[i].spk);
        value_check(rp,BOND,&chain.bonds[i+1].spk);
        let bond_prev=TxOut{value:BOND,script_pubkey:chain.bonds[i].spk.clone()};
        let challenged_prev=TxOut{value:BOND,script_pubkey:chain.challenged[i].spk.clone()};
        let (_pc,cc)=signatures(&secp,cp,&bond_prev,&chain.challenge_leaves[i],&p,&c);
        let (pr,_cr)=signatures(&secp,rp,&challenged_prev,&chain.respond_leaves[i],&p,&c);
        let challenge_witness=vec![
            seed.clone(),t.sig_p_challenge[i].clone(),cc,
            chain.challenge_leaves[i].to_bytes(),control(&chain.bonds[i],&chain.challenge_leaves[i])
        ];
        let respond_witness=vec![
            answer.clone(),t.sig_c_respond[i].clone(),pr,
            chain.respond_leaves[i].to_bytes(),control(&chain.challenged[i],&chain.respond_leaves[i])
        ];
        let c_row=pair_row(&secp,cp,&bond_prev,&chain.challenge_leaves[i],&p,&c,
            challenge_witness,&format!("challenge-{i}"));
        let r_row=pair_row(&secp,rp,&challenged_prev,&chain.respond_leaves[i],&p,&c,
            respond_witness,&format!("response-{i}"));
        rows.push(c_row);rows.push(r_row);
    }
    // Both terminal exit transaction templates come directly from the
    // operational bond.rs, with fee paid out of bond as CLOSE_FEE.
    let tx_forfeit=Transaction{
        version:Version(2),lock_time:LockTime::ZERO,
        input:vec![txin(OutPoint{txid:t.challenge[1].compute_txid(),vout:0},
            Sequence::from_height(DELTA))],
        output:vec![TxOut{value:BOND-CLOSE_FEE,
            script_pubkey:Address::p2tr(&secp,c.x,None,Network::Regtest).script_pubkey()}]
    };
    let tx_refund=Transaction{
        version:Version(2),lock_time:LockTime::from_height(960_000).unwrap(),
        input:vec![txin(OutPoint{txid:t.respond[0].compute_txid(),vout:0},
            Sequence::ENABLE_LOCKTIME_NO_RBF)],
        output:vec![TxOut{value:BOND-CLOSE_FEE,
            script_pubkey:Address::p2tr(&secp,p.x,None,Network::Regtest).script_pubkey()}]
    };
    let refund_prev=TxOut{value:BOND,script_pubkey:chain.bonds[1].spk.clone()};
    let forfeit_prev=TxOut{value:BOND,script_pubkey:chain.challenged[1].spk.clone()};
    let refund_sig=script_sig(&secp,&tx_refund,&refund_prev,&chain.refund,&p);
    let forfeit_sig=script_sig(&secp,&tx_forfeit,&forfeit_prev,&chain.forfeit,&c);
    assert!(verify_script_sig(&secp,&tx_refund,&refund_prev,&chain.refund,&p.x,&refund_sig));
    assert!(verify_script_sig(&secp,&tx_forfeit,&forfeit_prev,&chain.forfeit,&c.x,&forfeit_sig));
    let refund_witness=vec![refund_sig,chain.refund.to_bytes(),control(&chain.bonds[1],&chain.refund)];
    let forfeit_witness=vec![forfeit_sig,chain.forfeit.to_bytes(),control(&chain.challenged[1],&chain.forfeit)];
    let refund_signed=with_witness(tx_refund.clone(),refund_witness.clone());
    let forfeit_signed=with_witness(tx_forfeit.clone(),forfeit_witness.clone());
    // Stale signatures reject payout changes, but a NEW signature from the
    // authorized unilateral spender may select any destination. These positive
    // redirections are intentional counterexamples to fixed-recipient coverage.
    let mut redirect_forfeit=tx_forfeit.clone();
    redirect_forfeit.output[0].script_pubkey=
      Address::p2tr(&secp,p.x,None,Network::Regtest).script_pubkey();
    let forged_forfeit=with_witness(redirect_forfeit.clone(),forfeit_witness.clone());
    let redirect_forfeit_sig=script_sig(&secp,&redirect_forfeit,&forfeit_prev,&chain.forfeit,&c);
    let consent_forfeit=with_witness(redirect_forfeit,
      vec![redirect_forfeit_sig,chain.forfeit.to_bytes(),control(&chain.challenged[1],&chain.forfeit)]);
    let mut redirect_refund=tx_refund.clone();
    redirect_refund.output[0].script_pubkey=
      Address::p2tr(&secp,c.x,None,Network::Regtest).script_pubkey();
    let forged_refund=with_witness(redirect_refund.clone(),refund_witness.clone());
    let redirect_refund_sig=script_sig(&secp,&redirect_refund,&refund_prev,&chain.refund,&p);
    let consent_refund=with_witness(redirect_refund,
      vec![redirect_refund_sig,chain.refund.to_bytes(),control(&chain.bonds[1],&chain.refund)]);
    // A fresh signer cannot bypass the relative CSV or absolute CLTV check.
    let mut immature_forfeit=tx_forfeit.clone();
    immature_forfeit.input[0].sequence=Sequence::from_height(DELTA-1);
    let immature_forfeit_sig=script_sig(&secp,&immature_forfeit,&forfeit_prev,&chain.forfeit,&c);
    let immature_forfeit=with_witness(immature_forfeit,
      vec![immature_forfeit_sig,chain.forfeit.to_bytes(),control(&chain.challenged[1],&chain.forfeit)]);
    let mut premature_refund=tx_refund.clone();
    premature_refund.lock_time=LockTime::from_height(959_999).unwrap();
    let premature_refund_sig=script_sig(&secp,&premature_refund,&refund_prev,&chain.refund,&p);
    let premature_refund=with_witness(premature_refund,
      vec![premature_refund_sig,chain.refund.to_bytes(),control(&chain.bonds[1],&chain.refund)]);
    let mut final_seq_refund=tx_refund.clone();
    final_seq_refund.input[0].sequence=Sequence::MAX;
    let final_seq_refund_sig=script_sig(&secp,&final_seq_refund,&refund_prev,&chain.refund,&p);
    let final_seq_refund=with_witness(final_seq_refund,
      vec![final_seq_refund_sig,chain.refund.to_bytes(),control(&chain.bonds[1],&chain.refund)]);
    let wrong_forfeit_sig=script_sig(&secp,&tx_forfeit,&forfeit_prev,&chain.forfeit,&p);
    let wrong_forfeit=with_witness(tx_forfeit.clone(),
      vec![wrong_forfeit_sig,chain.forfeit.to_bytes(),control(&chain.challenged[1],&chain.forfeit)]);
    let wrong_refund_sig=script_sig(&secp,&tx_refund,&refund_prev,&chain.refund,&c);
    let wrong_refund=with_witness(tx_refund.clone(),
      vec![wrong_refund_sig,chain.refund.to_bytes(),control(&chain.bonds[1],&chain.refund)]);
    assert_eq!(refund_signed.output[0].value+CLOSE_FEE,BOND);
    assert_eq!(forfeit_signed.output[0].value+CLOSE_FEE,BOND);
    let output=json!({
       "schema":"bsb/taproot-real-serialization-evidence/v1",
       "scope":"offline real rust-bitcoin BIP341/BIP340 signature preflight, NOT Bitcoin Core consensus",
       "internal_key":"NUMS",
       "bond_sat":BOND.to_sat(),"parent_sat_fee":0,"parent_p2a_script":p2a().to_hex_string(),
       "sentinel_rounds":spec.len(),
       "final_bond_spk":chain.bonds[2].spk.to_hex_string(),
       "final_bond_leaves":["refund"],
       "transactions":rows,
       "forfeit":{
           "txid":tx_forfeit.compute_txid().to_string(),"raw_hex":serialize_hex(&forfeit_signed),
           "spent_script":forfeit_prev.script_pubkey.to_hex_string(),
           "spent_value":forfeit_prev.value.to_sat(),
           "input_sequence":tx_forfeit.input[0].sequence.to_consensus_u32(),
           "expected_csv":DELTA,"valid_client_sig":true,
           "output_value":tx_forfeit.output[0].value.to_sat(),"fee_sat":CLOSE_FEE.to_sat(),
           "output_script":tx_forfeit.output[0].script_pubkey.to_hex_string(),
           "attacks":{
               "stale_signature_redirect":serialize_hex(&forged_forfeit),
               "fresh_signature_before_csv":serialize_hex(&immature_forfeit),
               "wrong_signer":serialize_hex(&wrong_forfeit)
           },
           "authorized_redirect_raw_hex":serialize_hex(&consent_forfeit)
       },
       "refund":{
           "txid":tx_refund.compute_txid().to_string(),"raw_hex":serialize_hex(&refund_signed),
           "spent_script":refund_prev.script_pubkey.to_hex_string(),
           "spent_value":refund_prev.value.to_sat(),
           "lock_time":tx_refund.lock_time.to_consensus_u32(),"valid_provider_sig":true,
           "output_value":tx_refund.output[0].value.to_sat(),"fee_sat":CLOSE_FEE.to_sat(),
           "output_script":tx_refund.output[0].script_pubkey.to_hex_string(),
           "attacks":{
               "stale_signature_redirect":serialize_hex(&forged_refund),
               "fresh_signature_before_cltv":serialize_hex(&premature_refund),
               "fresh_signature_final_sequence":serialize_hex(&final_seq_refund),
               "wrong_signer":serialize_hex(&wrong_refund)
           },
           "authorized_redirect_raw_hex":serialize_hex(&consent_refund)
       }
    });
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
