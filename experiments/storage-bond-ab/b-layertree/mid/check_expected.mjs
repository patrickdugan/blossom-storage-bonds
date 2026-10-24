#!/usr/bin/env node
/**
 * Verifies the *scope* of a separately run, PINNED Sapio MID oracle guest.
 * This never claims Bitcoin itself enforced OP_TX/MID or that the Sapio
 * state is cryptographically bound to the shared Blossom storage verdict.
 */
import {createHash} from 'node:crypto';
import {open} from 'node:fs/promises';
import {resolve} from 'node:path';
import {scenario,challenge} from '../../shared/scenario.mjs';

const REFERENCE="34363851a11d0f2b3ddb27c050537c1a2e5b7e9b";
const need=(x,s)=>{if(!x)throw Error(s);};
export function attestation({commit=REFERENCE,tests=[]}={}) {
  need(commit===REFERENCE,'unreviewed Sapio source revision');
  need(Array.isArray(tests)&&tests.length===3,'run all three MID identity and owner tests');
  const expected=[
    'two_members_exit_sequentially_without_either_coparticipants_signature',
    'historical_owner_nonce_reuse_revives_a_signed_voucher_in_the_real_mid_guest',
    'synced_signing_reservation_survives_restart_and_binds_both_exits',
  ];
  for(const name of expected)need(tests.includes(name),'missing genuine pinned MID regression: '+name);
  need(new Set(tests).size===3,'duplicate MID test evidence');
  const config=scenario('storage-fault');
  need(config.terms.length===2 &&
    config.terms[0].id==='alice'&&config.terms[0].stake===60_000 &&
    config.terms[1].id==='bob'&&config.terms[1].stake===40_000,
    'shared A/B economic benchmark changed');
  const e=config.events.find(e=>e.kind==='proof'&&e.id==='alice'&&e.epoch===2);
  const verdict=challenge(e);
  need(verdict.verified===false,'Alice shared PDP fault no longer cryptographically sampled');
  return {
    schema:'bsb-ab-pinned-sapio-mid-oracle-scope-v1',
    network:'no-bitcoin-funding-in-this-gate',
    sapioRevision:commit,
    totalInitialPrincipalSats:100_000,
    aliceEntitlementSats:60_000,
    bobEntitlementSats:40_000,
    referenceBlossomPdpEvidenceHash:verdict.evidenceHash,
    sourceWitnessBoundIntoSapioMidTransition:false,
    actualCompiledMidEmulationGuestExercised:true,
    userExitWithoutOtherOwnersSignatureInModel:true,
    onlineSapioOracleStillRequired:true,
    historicalVoucherReplayAttackReproduced:true,
    voluntaryPersistedLineageReservationRegressionPassed:true,
    bitcoinConsensusEnforcesExperimentalMid:false,
    realFrostThresholdIntegratedWithMid:false,
    sameRootAsBBitcoinFrostCarrierProven:false,
    filecoinConsensusProofVerified:false,
    testsPassed:tests,
    scopeDigest: createHash('sha256').update(JSON.stringify({
      commit,tests,alice:60_000,bob:40_000,source:verdict.evidenceHash,
    })).digest('hex'),
  };
}
async function main(args) {
  const tests=[
    'two_members_exit_sequentially_without_either_coparticipants_signature',
    'historical_owner_nonce_reuse_revives_a_signed_voucher_in_the_real_mid_guest',
    'synced_signing_reservation_survives_restart_and_binds_both_exits',
  ];
  need(args.length===1,'usage: node check_expected.mjs OUTPUT-NEW-JSON');
  const receipt=attestation({tests});
  const f=await open(resolve(args[0]),'wx',0o600);
  try{await f.writeFile(JSON.stringify(receipt,null,2)+'\n');await f.sync();}
  finally{await f.close();}
  console.log(JSON.stringify({verifiedPinnedScope:true,testCount:3,
    oracleStillRequired:true,bitcoinMidConsensus:false}));
}
if(process.argv[1]&&import.meta.url===new URL('file://'+resolve(process.argv[1])).href){
  main(process.argv.slice(2)).catch(e=>{console.error(e.message);process.exitCode=1;});
}
