// Read-only Bitcoin Core transaction parsing and relay-time P2A fee-child.
import {spawnSync} from 'node:child_process';
export const need=(ok,why)=>{if(!ok)throw Error(why);};
export const amount=n=>{
  need(Number.isSafeInteger(n)&&n>=0,'Bitcoin amount in satoshis required');
  return Number((n/100_000_000).toFixed(8));
};
export const sats=x=>{
  const s=String(x),[whole,decimal='']=s.split('.');
  need(/^\d+$/.test(whole)&&/^\d*$/.test(decimal)&&decimal.length<=8,
    'invalid Bitcoin exact decimal amount');
  return Number(BigInt(whole)*100_000_000n+BigInt(decimal.padEnd(8,'0')));
};
export const point=str=>{
  const x=/^([a-f0-9]{64}):(\d+)$/i.exec(String(str));
  need(x&&Number.isSafeInteger(Number(x[2])),'invalid saved Bitcoin outpoint');
  return {txid:x[1],vout:Number(x[2])};
};
export function bitcoin(binary,datadir){
  need(binary.startsWith('/')&&datadir.startsWith('/'),
    'Bitcoin RPC paths must be absolute');
  return (method,args=[],wallet=null)=>{
    const fields=['-regtest','-datadir='+datadir];
    if(wallet)fields.push('-rpcwallet='+wallet);
    const cmd=[...fields,method,...args.map(a=>typeof a==='object'?JSON.stringify(a):String(a))];
    const v=spawnSync(binary,cmd,{encoding:'utf8',shell:false,
      timeout:30000,maxBuffer:8_000_000});
    need(!v.error&&v.status===0,
      'Bitcoin '+method+' failed: '+String(v.stderr||v.error).slice(0,650));
    if(!v.stdout.trim())return null;
    try{return JSON.parse(v.stdout);}catch{return v.stdout.trim();}
  };
}
export function decodedParent(node,rec,expectedValue){
  need(rec&&rec.noSponsorInput===true&&rec.feePaidByParentSats===0&&
    rec.version===3&&typeof rec.signedHex==='string',
    'missing immutable fee-independent signed FROST parent');
  const tx=node('decoderawtransaction',[rec.signedHex]);
  need(tx.txid===rec.txid&&tx.hash===rec.wtxid&&
    tx.version===3&&tx.vsize===rec.vsize&&
    tx.vin.length===1&&tx.vin[0].txinwitness?.length===1&&
    tx.vin[0].txinwitness[0].length===128,
    'signed P2TR FROST Bitcoin witness differs from frozen original');
  need(tx.vin[0].txid+':'+tx.vin[0].vout===rec.carrierBefore&&
    tx.vout.length===rec.outputs.length&&
    tx.vout.map(o=>sats(o.value)).reduce((a,b)=>a+b,0)===expectedValue,
    'parent changes source UTXO or subtracts collateral for miner fees');
  for(let i=0;i<tx.vout.length;i++){
    const actual=tx.vout[i],wanted=rec.outputs[i];
    need(actual.n===i&&wanted.vout===i&&sats(actual.value)===wanted.sats&&
      actual.scriptPubKey?.hex===wanted.script_pubkey_hex,
      'frozen Taproot recipient script or principal output changed');
  }
  const a=rec.anchorOutIndex;
  need(a===tx.vout.length-1&&sats(tx.vout[a].value)===0&&
    tx.vout[a].scriptPubKey.hex==='51024e73',
    'v3 parent is missing standard zero-value P2A anchor');
  return {...tx,hex:rec.signedHex};
}
export function child(node,parent,feeWallet,feeSats=3000){
  need(parent.version===3&&parent.vout.length>=2 &&
    parent.vout[parent.vout.length-1].scriptPubKey.hex==='51024e73',
    'child requires original zero-value P2A anchor');
  const coins=node('listunspent',[1,9999999],feeWallet);
  need(Array.isArray(coins),'fee payer could not load independent wallet UTXOs');
  const candidates=coins.filter(c=>sats(c.amount)>=feeSats+1000&&c.spendable)
    .sort((a,b)=>a.txid.localeCompare(b.txid)||a.vout-b.vout);
  need(candidates.length>0,'no relay-time fee payer UTXO remains spendable');
  const coin=candidates[0],inSats=sats(coin.amount);
  const anchor={txid:parent.txid,vout:parent.vout.length-1};
  const txinputs=[anchor,{txid:coin.txid,vout:coin.vout}];
  const destination=node('getnewaddress',[],feeWallet);
  need(typeof destination==='string','external fee address missing');
  const outputs={[destination]:amount(inSats-feeSats)};
  const unsigned=node('createrawtransaction',[txinputs,outputs]);
  const p2a=[{txid:anchor.txid,vout:anchor.vout,
    scriptPubKey:'51024e73',amount:0}];
  const sig=node('signrawtransactionwithwallet',[unsigned,p2a],feeWallet);
  need(sig&&typeof sig.hex==='string',
    'relay payer did not provide signed TRUC P2A fee-child transaction');
  const signed=node('decoderawtransaction',[sig.hex]);
  const checks={
    version3:signed.version===3,
    inputs2:signed.vin.length===2,
    outputs1:signed.vout.length===1,
    anchorTxid:signed.vin[0]?.txid===anchor.txid,
    anchorVout:signed.vin[0]?.vout===anchor.vout,
    feeCoinTxid:signed.vin[1]?.txid===coin.txid,
    feeCoinVout:signed.vin[1]?.vout===coin.vout,
    anchorWitnessEmpty:!signed.vin[0]?.txinwitness?.length,
    feeInputSigned:Boolean(signed.vin[1]?.txinwitness?.length),
    correctChange:signed.vout.length===1 &&
      sats(signed.vout[0].value)===inSats-feeSats
  };
  need(Object.values(checks).every(Boolean),
    'relay-time fee child disagrees with exact Bitcoin input/output contract: '+
    JSON.stringify(checks));
  const original=parent.txid;
  need(signed.vin[0].txid===original,'fresh fee child mutated the frozen parent');
  return {signedHex:sig.hex,tx:signed,feeCoin:coin,
    inputSats:inSats,childFeeSats:feeSats,anchor,
    totalPackageVbytes:parent.vsize+signed.vsize};
}
export function submit(node,parent,feeChild){
  need(feeChild.tx.vin[0].txid===parent.txid,
    'P2A child did not spend the specific immutable FROST parent');
  const packageResult=node('submitpackage',[
    [parent.hex,feeChild.signedHex]
  ]);
  need(packageResult?.package_msg==='success',
    'Bitcoin Core rejected FROST zero-fee parent + dynamic P2A child package: '+
    JSON.stringify(packageResult).slice(0,700));
  return packageResult;
}
