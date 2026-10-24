//! Test-only driver copied into an exact, checked-out Sapio SHA by CI.
 //! Real compiled MID guest + ONLINE ProgramOracle signatures and synthetic
 //! funded-example UTXOs. Not native Bitcoin consensus or FROST integration.
use bitcoin::{
    bip32::Xpub,consensus::encode::serialize_hex,Amount,OutPoint,
    Transaction,TxOut
};
use sapio_base::secp::secp;
use sapio_contrib::contracts::layertree::{
    tree::Node,witness,Config,LayerTree,Transition,Tree
};
use sapio_integration_tests::layertree_example as example;
use serde_json::{json,Value};
type ErrBox=Box<dyn std::error::Error>;
fn hex(bytes:impl AsRef<[u8]>)->String{
    bytes.as_ref().iter().map(|b|format!("{b:02x}")).collect()
}
fn root(node:Node)->Value{
    json!({"merkleSumHash":hex(node.hash),"satoshis":node.sum,
        "canonicalNodeBytesHex":hex(node.serialize())})
}
fn tx(tx:&Transaction)->Value{
    json!({
        "txid":tx.compute_txid().to_string(),
        "wtxid":tx.compute_wtxid().to_string(),
        "hex":serialize_hex(tx),
        "vbytes":tx.vsize(),
        "inputOutpoints":tx.input.iter().map(|v|v.previous_output.to_string()).collect::<Vec<_>>(),
        "allWitnessInputsNonempty":tx.input.iter().all(|v|!v.witness.is_empty()),
        "outputs":tx.output.iter().enumerate().map(|(index,o)|json!({
            "index":index,"sats":o.value.to_sat(),
            "scriptPubkeyHex":hex(o.script_pubkey.as_bytes()),
        })).collect::<Vec<_>>()
    })
}
fn run()->Result<(),ErrBox>{
    let contract=LayerTree::new(
        Config{depth:2,..example::contract()?.config().clone()},
        Xpub::from_priv(secp(),&example::oracle_key())
    )?;
    let mut tree=Tree::new(2)?;
    let alice=example::member(210,60_000);
    let bob=example::member(211,40_000);
    tree.set(0,Some(alice.clone()))?;
    tree.set(1,Some(bob.clone()))?;
    let before=tree.root();
    assert_eq!(before.sum,100_000);
    let compiled=example::compile(&contract,&tree)?;
    let initial_coin=example::Coin{
        outpoint:example::outpoint(90),
        txout:TxOut{
            value:Amount::from_sat(before.sum),
            script_pubkey:(&compiled.address).into()
        }
    };
    let first=example::prepare_step(
        &contract,&tree,initial_coin.clone(),
        Transition::Exit{count:1},vec![example::payout(&alice)],
        0,91,
        |sign,m|witness::exit(&tree,&[(0,false,sign(&example::key(210)))],m)
    )?;
    assert_eq!(first.next.root().sum,40_000);
    let alice_tx=example::finish(&first,&example::oracle()?)?;
    assert_eq!(alice_tx.input.len(),2);
    assert_eq!(alice_tx.output[0].value.to_sat(),40_000);
    assert_eq!(alice_tx.output[1],example::payout(&alice));
    let old_sum=100_000+first.sponsor.txout.value.to_sat();
    let new_sum:u64=alice_tx.output.iter().map(|o|o.value.to_sat()).sum();
    assert_eq!(old_sum-new_sum,example::FEE_SATS);

    let second=example::prepare_step(
        &contract,&first.next,
        example::Coin{
            outpoint:OutPoint::new(alice_tx.compute_txid(),0),
            txout:alice_tx.output[0].clone()
        },
        Transition::Exit{count:1},vec![example::payout(&bob)],
        0,92,
        |sign,m|witness::exit(&first.next,&[(1,false,sign(&example::key(211)))],m)
    )?;
    assert_eq!(second.next.root(),Node::empty(2));
    let bob_tx=example::finish(&second,&example::oracle()?)?;
    assert_eq!(bob_tx.input.len(),2);
    assert_eq!(bob_tx.output[0].value,Amount::ZERO);
    assert_eq!(bob_tx.output[1],example::payout(&bob));
    assert_eq!(bob_tx.input[0].previous_output,OutPoint::new(alice_tx.compute_txid(),0));
    let bob_in=40_000+second.sponsor.txout.value.to_sat();
    let bob_out:u64=bob_tx.output.iter().map(|o|o.value.to_sat()).sum();
    assert_eq!(bob_in-bob_out,example::FEE_SATS);
    assert_ne!(example::payout(&alice).script_pubkey,example::payout(&bob).script_pubkey);

    println!("{}",serde_json::to_string_pretty(&json!({
        "schema":"bsb-sapio-pinned-mid-two-exits-v1",
        "pinnedSource":"34363851a11d0f2b3ddb27c050537c1a2e5b7e9b",
        "network":"synthetic-Sapio-fixture-outpoints-NOT-chain",
        "initialPrincipalSats":100_000,
        "initialCoinOutpoint":initial_coin.outpoint.to_string(),
        "principalRoots":{
            "initial":root(before),
            "afterAlice":root(first.next.root()),
            "afterBob":root(second.next.root())
        },
        "payoutScripts":{
            "alice":hex(example::payout(&alice).script_pubkey.as_bytes()),
            "bob":hex(example::payout(&bob).script_pubkey.as_bytes())
        },
        "otherMemberSignatureRequired":false,
        "onlineSapioEmulationOracleRequired":true,
        "bitcoinConsensusRecognizesMidGuest":false,
        "sameScriptAsFundedFrostCarrier":false,
        "sourceBlossomPdpHashCryptographicallyBound":false,
        "aliceExit":tx(&alice_tx),
        "bobExit":tx(&bob_tx),
        "feeSatsPerExit":example::FEE_SATS,
        "allMidOracleGuestWitnessesSigned":true,
        "allLineageValuesConserved":true
    }))?);
    Ok(())
}
fn main(){
    if let Err(error)=run(){
        eprintln!("Pinned two-member MID oracle example failed: {error}");
        std::process::exit(1);
    }
}
