import test from 'node:test';
import assert from 'node:assert/strict';
import {serializeTransaction} from './txid_admission.mjs';
import {decodeLegacyTransaction,stripCodeSeparators,encodePushData,findAndDelete,legacySignatureHash} from './legacy_sighash.mjs';

// Expected digests from Bitcoin Core src/test/data/sighash.json (legacy SIGHASH test vectors).
// https://github.com/bitcoin/bitcoin/blob/master/src/test/data/sighash.json
const CASES=[
  [
    '907c2bc503ade11cc3b04eb2918b6f547b0630ab569273824748c87ea14b0696526c66ba740200000004ab65ababfd1f9bdd4ef073c7afc4ae00da8a66f429c917a0081ad1e1dabce28d373eab81d8628de802000000096aab5253ab52000052ad042b5f25efb33beec9f3364e8a9139e8439d9d7e26529c3c30b6c3fd89f8684cfd68ea0200000009ab53526500636a52ab599ac2fe02a526ed040000000008535300516352515164370e010000000003006300ab2ec229',
    '',2,1864164639,'31af167a6cf3f9d5f6875caa4d31704ceb0eba078d132b78dab52c3b8997317e'
  ],
  [
    'a0aa3126041621a6dea5b800141aa696daf28408959dfb2df96095db9fa425ad3f427f2f6103000000015360290e9c6063fa26912c2e7fb6a0ad80f1c5fea1771d42f12976092e7a85a4229fdb6e890000000001abc109f6e47688ac0e4682988785744602b8c87228fcef0695085edf19088af1a9db126e93000000000665516aac536affffffff8fe53e0806e12dfd05d67ac68f4768fdbe23fc48ace22a5aa8ba04c96d58e2750300000009ac51abac63ab5153650524aa680455ce7b000000000000499e50030000000008636a00ac526563ac5051ee030000000003abacabd2b6fe000000000003516563910fb6b5',
    '65',0,-1391424484,'48d6a1bd2cd9eec54eb866fc71209418a950402b5d7e52363bfb75c98e141175'
  ],
  [
    '6e7e9d4b04ce17afa1e8546b627bb8d89a6a7fefd9d892ec8a192d79c2ceafc01694a6a7e7030000000953ac6a51006353636a33bced1544f797f08ceed02f108da22cd24c9e7809a446c61eb3895914508ac91f07053a01000000055163ab516affffffff11dc54eee8f9e4ff0bcf6b1a1a35b1cd10d63389571375501af7444073bcec3c02000000046aab53514a821f0ce3956e235f71e4c69d91abe1e93fb703bd33039ac567249ed339bf0ba0883ef300000000090063ab65000065ac654bec3cc504bcf499020000000005ab6a52abac64eb060100000000076a6a5351650053bbbc130100000000056a6aab53abd6e1380100000000026a51c4e509b8',
    'acab655151',0,479279909,'2a3d95b09237b72034b23f2d2bb29fa32a58ab5c6aa72f6aafdfa178ab1dd01c'
  ],
];
for(let i=0;i<CASES.length;i++)test(`L0${i+1}: digest matches Bitcoin Core legacy sighash vector`,()=>{
  const [raw,script,index,hashType,expected]=CASES[i];
  const decoded=decodeLegacyTransaction(raw);
  assert.equal(serializeTransaction(decoded).toString('hex'),raw);
  assert.equal(legacySignatureHash(decoded,index,script,hashType),expected);
});
test('L04: FindAndDelete removes only complete signature pushes at op boundaries',()=>{
  const signature='aabb',push=encodePushData(signature);
  assert.equal(push,'02aabb');
  const found=findAndDelete(push+'51'+push+'51',signature);
  assert.equal(found.removed,2);assert.equal(found.script,'5151');
  const insidePush=findAndDelete('04'+push+'ccdd51',signature);
  assert.equal(insidePush.removed,0);assert.equal(insidePush.script,'04'+push+'ccdd51');
});
test('L05: OP_CODESEPARATOR is stripped as an opcode, preserved inside pushed data',()=>{
  assert.equal(stripCodeSeparators('51ab0252ab53'),'510252ab53');
});
test('L06: SIGHASH_SINGLE out-of-range bug returns uint256 1',()=>{
  const decoded=decodeLegacyTransaction(CASES[0][0]);
  // Input index 2 exists while this fixture has two outputs.
  assert.equal(decoded.vout.length,2);
  assert.equal(legacySignatureHash(decoded,2,'',3),'00'.repeat(31)+'01');
});
test('L07: signature-selected deletion changes the digest by mutating scriptCode',()=>{
  const decoded=decodeLegacyTransaction(CASES[2][0]);
  const sig='aabb',script='51'+encodePushData(sig)+'52';
  const withoutDelete=legacySignatureHash(decoded,0,script,1);
  const withDelete=legacySignatureHash(decoded,0,script,1,[sig]);
  assert.notEqual(withoutDelete,withDelete);
});
test('L08: truncated bytes and invalid PUSHDATA are rejected',()=>{
  assert.throws(()=>decodeLegacyTransaction('01000000'),RangeError);
  assert.throws(()=>stripCodeSeparators('4d02'),RangeError);
});
