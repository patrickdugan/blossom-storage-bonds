/**
 * Source-level Taproot spend-path inventory for the Blossom prototype.
 *
 * This is a drift detector over the checked-in Rust source. It checks
 * selected constructor expressions/transaction templates for the known
 * regtest demo, standalone bond agent, and payment channel.
 *
 * IMPORTANT: source-text checks are NOT Rust AST verification, BIP341/342
 * consensus interpretation, or exhaustive detection of every future code
 * path. The Lean ConsensusCoverage theorem is still conditional.
 */
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';

const root = new URL('../', import.meta.url);
export function loadSource(path) {
  if (!/^[a-z0-9_./-]+$/i.test(path) || path.startsWith('/') || path.includes('..'))
    throw Error('unapproved source path');
  return readFileSync(new URL(path, root), 'utf8');
}
const noComments=s=>s.replace(/\/\*[\s\S]*?\*\//g,'').replace(/\/\/[^\n]*/g,'');
const count=(s,re)=>[...s.matchAll(re)].length;
function expect(fragment,pattern,label) {
  if (!pattern.test(fragment))throw Error('Taproot exit source changed: '+label);
}
function fnBlock(text,signature) {
  const start=text.indexOf(signature);
  if(start<0)throw Error('Taproot function missing: '+signature);
  const brace=text.indexOf('{',start+signature.length);
  if(brace<0)throw Error('Taproot function body missing: '+signature);
  let depth=0;
  for(let k=brace;k<text.length;k++){
    if(text[k]==='{')depth++;
    else if(text[k]==='}' && --depth===0)return text.slice(brace,k+1);
  }
  throw Error('unterminated Rust function: '+signature);
}
export const paths = Object.freeze({
  demo: Object.freeze({
    id:'regtest/main.rs',
    internalKey:'two-party MuSig2 aggregate',
    keypath:'joint cooperative close enabled',
    liveLeaves:['challenge','refund'],
    challengedLeaves:['response','forfeit'],
    finalLiveLeaves:['refund']
  }),
  agent: Object.freeze({
    id:'regtest/src/bin/bond.rs',
    internalKey:'NUMS unknown-discrete-log point',
    keypath:'assumed unavailable',
    liveLeaves:['challenge','refund'],
    challengedLeaves:['response','forfeit'],
    finalLiveLeaves:['refund']
  }),
  channel: Object.freeze({
    id:'regtest/src/bin/bond.rs payment channel',
    internalKey:'NUMS unknown-discrete-log point',
    keypath:'assumed unavailable',
    liveLeaves:['joint cooperative script','client CLTV refund'],
    challengedLeaves:[],
    finalLiveLeaves:[]
  })
});
const expectedAgentCommands=[
  'accept','challenge','forfeit','fund','presign','refund','respond','status'
];
/** Throws on changes to the specific Rust construction patterns listed.
 * Returns a declaration of known path families, not a consensus proof.
 */
export function auditTaprootSources(overrides={}) {
  const read=(name)=>noComments(overrides[name]??loadSource(name));
  const common=read('regtest/src/common.rs');
  const demo=read('regtest/src/main.rs');
  const agent=read('regtest/src/bin/bond.rs');
  const body=fnBlock(common,'pub fn build_chain(');
  const signed=fnBlock(common,'pub fn script_sig(');
  const template=fnBlock(common,'pub fn presigned(');
  const ch=fnBlock(agent,'fn load_chan(');
  const load=fnBlock(agent,'fn load_bond(');
  const chanState=fnBlock(agent,'fn chan_state(');
  // Leaf construction: two on every active bond/challenged state, a single
  // refund leaf after the final configured sentinel.
  expect(body,/challenge_leaves\.iter\(\)\.map\(\|l\| state\(secp,\s*internal,\s*&\[l,\s*&refund\]\)\)/,
    'live challenge/refund paired leaves');
  expect(body,/respond_leaves\.iter\(\)\.map\(\|l\| state\(secp,\s*internal,\s*&\[l,\s*&forfeit\]\)\)/,
    'challenged response/forfeit paired leaves');
  expect(body,/bonds\.push\(state\(secp,\s*internal,\s*&\[&refund\]\)\)/,
    'final live refund-only state');
  if(count(body,/state\(secp,\s*internal,\s*&\[/g)!==3)
    throw Error('Taproot exit source changed: builder gained or lost a state construction');
  // Agent selects NUMS every time it funds/loads the bond; demo chooses
  // the MuSig2 aggregate x-only key instead.
  expect(load,/build_chain\(secp,\s*nums\(\),\s*&d\.p,\s*&d\.c,\s*&d\.sh,\s*d\.t_end\)/,
    'agent loaded bond uses NUMS');
  expect(agent,/let ch = build_chain\(secp,\s*nums\(\),\s*&d\.p,\s*&d\.c,\s*&d\.sh,\s*d\.t_end\)/,
    'agent funding uses NUMS');
  expect(demo,/let internal = XOnlyPublicKey::from_slice\(&agg\.serialize_xonly\(\)\)/,
    'demo uses MuSig2 aggregated internal key');
  expect(demo,/musig_keypath_sig\(/,'demo tests cooperative keypath signature');
  // First-class transaction authorization depends on Bitcoin's BIP341
  // Taproot default sighash over all prevouts and all outputs.
  expect(signed,/taproot_script_spend_signature_hash\(0,\s*&Prevouts::All\(&\[prev\.clone\(\)\]\),\s*lh,\s*TapSighashType::Default\)/,
    'script-path Default sighash and Prevouts::All');
  expect(template,/version:\s*Version\(3\)/,'v3 transaction template');
  expect(template,/value:\s*BOND,\s*script_pubkey:\s*to\.clone\(\)/,
    'bond value conserved in presigned parent');
  expect(template,/value:\s*Amount::ZERO,\s*script_pubkey:\s*p2a\(\)/,
    'P2A anchor in presigned transaction');
  expect(agent,/Sequence::from_height\(DELTA\)/,'relative CSV forfeiture sequence');
  expect(agent,/lock_time:\s*LockTime::from_height\(d\.t_end\)/,
    'refund uses absolute CLTV height');
  expect(agent,/TxOut\s*\{\s*value:\s*BOND\s*-\s*CLOSE_FEE,\s*script_pubkey:\s*spk_of\(secp,\s*&me\.x\)\s*\}/,
    'client forfeiture/provider refund output amount fixed');
  // Channel contract is a NUMS P2TR with script-path mutual close or
  // unilateral delayed client refund. Its funded UTXO is independent.
  expect(ch,/state\(secp,\s*nums\(\),\s*&\[&coop,\s*&refund\]\)/,
    'payment channel NUMS with two Script leaves');
  expect(ch,/OP_CHECKSIGVERIFY.*OP_CHECKSIG/s,
    'channel cooperative leaf requires two signatures');
  expect(ch,/OP_CLTV.*OP_CHECKSIG/s,
    'channel client CLTV refund leaf');
  expect(chanState,/script_pubkey:\s*spk_of\(secp,\s*&ch\.p\)/,
    'payment channel provider output');
  expect(chanState,/script_pubkey:\s*spk_of\(secp,\s*&ch\.c\)/,
    'payment channel client change output');
  expect(chanState,/ch\.capacity\s*-\s*Amount::from_sat\(paid\)\s*-\s*CHAN_FEE/,
    'payment split conserves channel capacity and fee');
  const cmds=[...new Set([...agent.matchAll(/Some\("bond-([a-z-]+)"\)/g)].map(x=>x[1]))].sort();
  if(JSON.stringify(cmds)!==JSON.stringify(expectedAgentCommands))
    throw Error('Taproot exit source changed: bond agent commands: '+JSON.stringify(cmds));
  return {
    schema:'bsb/taproot-source-inventory/v1',
    disclaimer:'Source drift checks only; NOT consensus coverage or proof of unreachable alternate paths',
    bondAmountSats:100000000,
    challengeLimit:'k rounds plus one final refund-only live state',
    parentFee:'zero-fee v3 with P2A; separate CPFP child pays from fee wallet',
    configurations:paths,
    agentCommands:cmds
  };
}
if(process.argv[1] && import.meta.url===new URL('file://'+process.argv[1]).href)
  console.log(JSON.stringify(auditTaprootSources(),null,2));
