/**
 * Independently parse real rust-bitcoin BIP341 template evidence.
 *
 * This checks generated transaction bytes using the existing TypeScript
 * Bitcoin transaction parser, independent of Rust transaction serialization.
 * It does not establish on-chain validity of the witness Script or funding.
 *
 * Usage:
 * node --experimental-strip-types model/verify_formal_evidence.mjs /tmp/bsb-taproot-evidence.json
 */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {parseTx} from '../layer1/onchain.ts';

const sha256d=b=>createHash('sha256').update(
  createHash('sha256').update(b).digest()).digest();
const wtxid=raw=>Buffer.from(sha256d(raw)).reverse().toString('hex');
const validHex=x=>typeof x==='string' && /^[0-9a-f]+$/i.test(x) && x.length%2===0;

export function verifyEvidence(e){
  assert.equal(e.schema,'bsb/taproot-real-serialization-evidence/v1');
  assert.equal(e.internal_key,'NUMS');
  assert.match(e.scope,/NOT Bitcoin Core consensus/);
  assert.equal(e.bond_sat,100_000_000);
  assert.equal(e.parent_sat_fee,0);
  assert.equal(e.parent_p2a_script,'51024e73');
  assert.equal(e.sentinel_rounds,2);
  assert.deepEqual(e.final_bond_leaves,['refund']);
  assert.equal(e.transactions.length,4);
  const records=new Map();
  for(const item of e.transactions){
    assert.ok(validHex(item.raw_hex));
    const raw=Buffer.from(item.raw_hex,'hex');
    const tx=parseTx(raw);
    assert.equal(tx.txid,item.txid,'independent txid check');
    assert.equal(wtxid(raw),item.wtxid,'independent witness txid check');
    assert.notEqual(item.txid,item.wtxid);
    assert.equal(tx.version,3);
    assert.equal(tx.locktime,0);
    assert.equal(tx.inputs.length,1);
    assert.equal(tx.outputs.length,2);
    assert.equal(tx.outputs[0].value,100_000_000n);
    assert.equal(tx.outputs[1].value,0n);
    assert.equal(tx.outputs[1].script.toString('hex'),'51024e73');
    assert.equal(tx.outputs[0].script.toString('hex'),item.out0_script);
    assert.equal(item.out0_value,100_000_000);
    assert.equal(item.anchor_value,0);
    assert.equal(item.anchor_script,'51024e73');
    assert.equal(item.spent_value,100_000_000);
    assert.equal(item.valid_provider_sig,true);
    assert.equal(item.valid_client_sig,true);
    for(const key of [
      'mutated_output_provider_sig_valid',
      'mutated_output_client_sig_valid',
      'mutated_amount_provider_sig_valid',
      'mutated_prevout_provider_sig_valid'
    ]) assert.equal(item[key],false,'signed-field mutation must fail');
    const attackNames=[
      'redirect_successor','reduce_successor','replace_prevout',
      'wrong_sentinel_opening','wrong_control_block','wrong_leaf_script'
    ];
    assert.deepEqual(Object.keys(item.adversarial_raw_hex??{}).sort(),
      [...attackNames].sort(),'full adversarial evidence set required');
    for(const [attack,hex] of Object.entries(item.adversarial_raw_hex)){
      assert.ok(validHex(hex),'attack must contain real serialized transaction bytes');
      const attackRaw=Buffer.from(hex,'hex');
      const mutated=parseTx(attackRaw);
      if(attack==='wrong_sentinel_opening'||attack==='wrong_control_block'||
         attack==='wrong_leaf_script'){
        assert.equal(mutated.txid,tx.txid,
          'witness-only substitution must preserve txid');
        assert.notEqual(wtxid(attackRaw),item.wtxid,
          'witness-only substitution changes full transaction witness digest');
      } else {
        assert.notEqual(mutated.txid,tx.txid,
          'prevout and output mutations must alter the txid');
      }
    }
    records.set(item.name,tx);
  }
  for(let round=0;round<2;round++){
    const ch=records.get('challenge-'+round);
    const rsp=records.get('response-'+round);
    assert.ok(ch && rsp);
    assert.equal(rsp.inputs[0].txid,ch.txid);
    assert.equal(rsp.inputs[0].vout,0);
    if(round>0)assert.equal(ch.inputs[0].txid,records.get('response-'+(round-1)).txid);
  }
  const f=e.forfeit,r=e.refund;
  assert.ok(validHex(f.raw_hex) && validHex(r.raw_hex));
  const ft=parseTx(Buffer.from(f.raw_hex,'hex')),rt=parseTx(Buffer.from(r.raw_hex,'hex'));
  assert.equal(ft.txid,f.txid);
  assert.equal(rt.txid,r.txid);
  assert.equal(ft.inputs[0].txid,records.get('challenge-1').txid);
  assert.equal(rt.inputs[0].txid,records.get('response-0').txid);
  assert.equal(f.input_sequence,144);
  assert.equal(f.expected_csv,144);
  assert.equal(r.lock_time,960_000);
  assert.equal(ft.locktime,0);
  assert.equal(rt.locktime,960_000);
  assert.equal(ft.outputs.length,1);
  assert.equal(rt.outputs.length,1);
  assert.equal(ft.outputs[0].value,99_999_000n);
  assert.equal(rt.outputs[0].value,99_999_000n);
  assert.equal(f.fee_sat,1000);
  assert.equal(r.fee_sat,1000);
  assert.equal(f.spent_value,100_000_000);
  assert.equal(r.spent_value,100_000_000);
  assert.match(f.spent_script,/^5120[0-9a-f]{64}$/);
  assert.match(r.spent_script,/^5120[0-9a-f]{64}$/);
  assert.equal(f.valid_client_sig,true);
  assert.equal(r.valid_provider_sig,true);
  const expectTerminal=(kind,row,original,expectedAttacks)=>{
    assert.deepEqual(Object.keys(row.attacks??{}).sort(),expectedAttacks.sort());
    for(const [label,rawHex] of Object.entries(row.attacks)){
      assert.ok(validHex(rawHex),'terminal attack must have raw bytes');
      const mutant=parseTx(Buffer.from(rawHex,'hex'));
      if(label==='wrong_signer')assert.equal(mutant.txid,original.txid);
      else assert.notEqual(mutant.txid,original.txid);
    }
    assert.ok(validHex(row.authorized_redirect_raw_hex));
    const consent=parseTx(Buffer.from(row.authorized_redirect_raw_hex,'hex'));
    assert.notEqual(consent.txid,original.txid);
    assert.equal(consent.outputs[0].value,99_999_000n);
  };
  expectTerminal('forfeit',f,ft,
    ['stale_signature_redirect','fresh_signature_before_csv','wrong_signer']);
  expectTerminal('refund',r,rt,
    ['stale_signature_redirect','fresh_signature_before_cltv',
     'fresh_signature_final_sequence','wrong_signer']);
  return {ok:true,parents:4,terminals:2,certificate:'UNFUNDED'};
}
if(process.argv[1] && import.meta.url===new URL('file://'+process.argv[1]).href) {
  const path=process.argv[2];
  if(!path)throw Error('evidence JSON path required');
  console.log(JSON.stringify(verifyEvidence(JSON.parse(readFileSync(path,'utf8')))));
}
