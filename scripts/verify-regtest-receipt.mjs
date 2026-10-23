/**
 * Offline verifier for the exported regtest bond settlement receipt.
 *
 * Accepts JSON produced by audit-regtest-context.mjs, with no RPC or network.
 * Rechecks genesis-anchored header PoW and cumulative work, each txid Merkle
 * proof, each BIP141 coinbase/SegWit commitment from actual raw bytes, and
 * the bond's UTXO ancestry/amounts and height-only CSV/CLTV conditions.
 *
 * IMPORTANT: a supplied header chain is only a valid candidate. Its maximal
 * work among all possible competing chains, and full Bitcoin consensus
 * block/script validation, are not proven by this receipt. Those were
 * checked by the trusted full node at export time, and remain assumptions
 * for an offline consumer unless independently authenticated.
 */
import {readFileSync} from 'node:fs';
import {parseTx} from '../layer1/onchain.ts';
import {
  verifyRegtestHeaderChain,bindInclusionToHeaderChain
} from '../model/regtest_header_chain.mjs';
import {authenticateSerializedWitnessInclusion}
  from '../model/bitcoin_serialized_receipt.mjs';
import {forfeitContextOk,refundContextOk}
  from '../model/contextual_finality.mjs';

function invariant(p,message){
  if(!p)throw Error('regtest portable receipt: '+message);
}
const BOND=100_000_000n, FEE=1_000n, DELTA=144;
const isP2TR=s=>s?.length===34 && s[0]===0x51 && s[1]===0x20;
export function verifyPortableRegtestReceipt(report,trust={}){
  invariant(report?.schema==='bsb/core-active-chain-context/v1',
    'unexpected evidence format');
  invariant(report.network==='regtest','wrong network');
  const hc=report.headerChain;
  invariant(hc && Array.isArray(hc.headers),'header evidence absent');
  const headers=hc.headers;
  // Optional independent tip/work bounds can be supplied by a caller that
  // has authenticated them outside this JSON receipt. Never silently
  // upgrade a self-declared archive tip into an independently trusted tip.
  const expectedTip=trust.expectedTip??hc.tip;
  const minimumChainwork=trust.minimumChainwork??hc.cumulativeWorkDecimal;
  const checked=verifyRegtestHeaderChain(headers,{
    expectedTip,minimumChainwork
  });
  invariant(checked.cumulativeWorkHex===hc.cumulativeWorkHex,
    'header cumulative work fields disagree');
  invariant(checked.tipHeight===report.tip &&
    checked.tip===hc.coreClaimedBestTip,
    'inconsistent receipt tip/claimed active tip');
  invariant(BigInt('0x'+hc.coreClaimedChainworkHex)===
    BigInt(checked.cumulativeWorkDecimal),
    'Core work field differs from independently checked work');
  invariant(report.reportChecks>=21,
    'missing original full-node acceptance/rejection tests');
  const map=new Map();
  invariant(Array.isArray(report.inclusionProofs) &&
    report.inclusionProofs.length>=9,'not all bond transactions included');
  for(const inclusion of report.inclusionProofs){
    const verified=authenticateSerializedWitnessInclusion(inclusion);
    invariant(bindInclusionToHeaderChain(inclusion,headers,checked),
      'txid and wtxid witnesses refer to an unverified header');
    invariant(!map.has(verified.txid),'duplicate inclusion receipts');
    map.set(verified.txid,{
      ...verified,confirmedHeight:inclusion.height,
      parsed:parseTx(Buffer.from(inclusion.witness.witnessedRawHex,'hex'))
    });
  }
  const match=(txid)=>{
    const receipt=map.get(txid);
    invariant(receipt,'unavailable transaction inclusion: '+txid);
    return receipt;
  };
  const spendOne=(receipt)=>{
    invariant(receipt.parsed.inputs.length===1,
      'expected single-input bond spend');
    const input=receipt.parsed.inputs[0];
    invariant(input.vout===0,'bond spend must use successor vout zero');
    const parent=match(input.txid);
    invariant(parent.parsed.outputs.length>=1 &&
      isP2TR(parent.parsed.outputs[0].script) &&
      parent.parsed.outputs[0].value===BOND,
      'parent must fund the 1 BTC bonded P2TR output');
    invariant(parent.confirmedHeight<=receipt.confirmedHeight,
      'spend preceded source transaction');
    return parent;
  };
  const expectedParentNames=['challenge-0','response-0','challenge-1'];
  invariant(Array.isArray(report.parents)&&report.parents.length===3,
    'missing pre-signed parent transitions');
  const ordered=[];
  for(let i=0;i<expectedParentNames.length;i++){
    const row=report.parents[i];
    invariant(row.path===expectedParentNames[i],
      'unexpected presigned state order');
    const tx=match(row.txid);
    const parent=spendOne(tx);
    invariant(tx.confirmedHeight===row.confirmedHeight &&
      parent.confirmedHeight===row.sourceHeight,
      'source-height mismatch');
    invariant(tx.parsed.version===3 && tx.parsed.locktime===0 &&
      tx.parsed.outputs.length===2 &&
      tx.parsed.outputs[0].value===BOND &&
      isP2TR(tx.parsed.outputs[0].script) &&
      tx.parsed.outputs[1].value===0n &&
      tx.parsed.outputs[1].script.toString('hex')==='51024e73',
      'pre-signed parent output or P2A anchor changed');
    if(i>0)invariant(parent.txid===ordered[i-1].txid,
      'bond does not follow the advertised presigned cursor');
    ordered.push(tx);
  }
  const forfeit=match(report.forfeit.txid);
  const forfeitedParent=spendOne(forfeit);
  invariant(forfeitedParent.txid===ordered[2].txid &&
    forfeitedParent.txid===report.forfeit.spentTxid,
    'forfeit does not spend second challenged state');
  invariant(forfeit.parsed.version===2 &&
    forfeit.parsed.locktime===0 &&
    forfeit.parsed.inputs[0].sequence===DELTA &&
    forfeit.parsed.outputs.length===1 &&
    forfeit.parsed.outputs[0].value===BOND-FEE,
    'forfeit template differs from actual signed transaction');
  invariant(forfeitContextOk({
    version:forfeit.parsed.version,sequence:forfeit.parsed.inputs[0].sequence,
    delay:DELTA,outpointHeight:forfeitedParent.confirmedHeight,
    candidateHeight:forfeit.confirmedHeight
  }),'CSV forfeit not mature on the supplied header chain');
  invariant(report.forfeit.spentOutputHeight===forfeitedParent.confirmedHeight &&
    report.forfeit.spendingHeight===forfeit.confirmedHeight &&
    report.forfeit.minimumHeight===forfeitedParent.confirmedHeight+DELTA,
    'claimed CSV heights disagree with authentic inclusion');
  const refund=match(report.refund.txid);
  const refundParent=spendOne(refund);
  invariant(refund.parsed.version===2 &&
    refund.parsed.inputs[0].sequence===0xfffffffe &&
    refund.parsed.outputs.length===1 &&
    refund.parsed.outputs[0].value===BOND-FEE &&
    refund.parsed.locktime===report.refund.signedLockTime,
    'refund template differs from actual signed transaction');
  invariant(refundContextOk({
    contractEndHeight:refund.parsed.locktime,
    nLockTime:refund.parsed.locktime,
    sequence:refund.parsed.inputs[0].sequence,
    candidateHeight:refund.confirmedHeight
  }),'CLTV refund not final in this header chain');
  invariant(refundParent.txid===report.refund.spentTxid &&
    refundParent.confirmedHeight===report.refund.spentOutputHeight &&
    refund.confirmedHeight===report.refund.spendingHeight &&
    refund.parsed.locktime+1===report.refund.minimumHeight,
    'claimed CLTV heights differ from actual inclusion');
  const cooperative=match(report.cooperative.txid);
  const coopParent=spendOne(cooperative);
  invariant(coopParent.confirmedHeight===report.cooperative.sourceHeight &&
    cooperative.confirmedHeight===report.cooperative.spendingHeight,
    'cooperative outpoint height mismatch');
  invariant(cooperative.parsed.outputs.length===2 &&
    cooperative.parsed.outputs.reduce((a,o)=>a+o.value,0n)===BOND-FEE,
    'jointly signed close does not conserve bond minus fee');
  return {
    schema:'bsb/offline-regtest-cryptographic-receipt/v1',
    result:'verified cryptographic candidate-chain evidence',
    network:'regtest',
    genesis:checked.genesis,
    tipHeight:checked.tipHeight,
    tip:checked.tip,
    cumulativeWorkDecimal:checked.cumulativeWorkDecimal,
    externalTipCompared:trust.expectedTip!==undefined,
    externalMinWorkCompared:trust.minimumChainwork!==undefined,
    transactionsChecked:map.size,
    normalMerkleAuthenticated:true,
    bip141WitnessAuthenticated:true,
    parentAndPayoutAmountsChecked:true,
    contextualHeightArithmeticChecked:true,
    externalAssumptions:[
      'This is one valid-work genesis-anchored candidate chain, not independently proven to be the global active best chain',
      'This verifier does not execute complete Bitcoin block/UTXO/Script consensus; the exporting Core node did',
      'The user has not independently authenticated a trusted chainwork threshold, checkpoint or tip from an outside source'
    ]
  };
}
if(process.argv[1]&&import.meta.url===new URL('file://'+process.argv[1]).href){
  const path=process.argv[2];
  if(!path)throw Error('expected archived regtest receipt JSON path');
  const evidence=JSON.parse(readFileSync(path,'utf8'));
  const checked=verifyPortableRegtestReceipt(evidence);
  let rejectedWrongTip=false;
  try{verifyPortableRegtestReceipt(evidence,{expectedTip:'ff'.repeat(32)});}
  catch{rejectedWrongTip=true;}
  invariant(rejectedWrongTip,'external trusted-tip mismatch went undetected');
  let rejectedGreaterWork=false;
  try{verifyPortableRegtestReceipt(evidence,{
    minimumChainwork:(BigInt(checked.cumulativeWorkDecimal)+1n).toString()
  });}catch{rejectedGreaterWork=true;}
  invariant(rejectedGreaterWork,'external chainwork minimum went unenforced');
  // Prevent an untrusted archive from pretending to contain a stronger
  // Bitcoin header or a different witness commitment.
  const wrong={...evidence,inclusionProofs:[...evidence.inclusionProofs]};
  wrong.inclusionProofs[0]={...wrong.inclusionProofs[0],
    witness:{...wrong.inclusionProofs[0].witness,
      coinbaseCommitmentScript:'6a24aa21a9ed'+'ab'.repeat(32)}};
  let rejected=false;
  try{verifyPortableRegtestReceipt(wrong);}catch{rejected=true;}
  invariant(rejected,'forged coinbase commitment passed offline audit');
  console.log(JSON.stringify({...checked,
    adversarialUnboundCommitmentRejected:true,
    adversarialExternalTipMismatchRejected:true,
    adversarialExternalWorkThresholdRejected:true},null,2));
}
