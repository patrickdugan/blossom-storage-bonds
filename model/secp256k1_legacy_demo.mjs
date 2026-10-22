/**
 * Minimal SECp256k1 arithmetic for test-only Bitcoin Script signature experiments.
 * Pure BigInt for deterministic vector checking. Not side-channel resistant,
 * not suitable for real keys, transactions, or production signatures.
 */
export const P=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
export const N=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
export const G={
  x:0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  y:0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
};
export const mod=(a,m)=>((a%m)+m)%m;
export function powmod(a,e,m){if(e<0n)throw Error('negative exponent');let z=1n;for(a=mod(a,m);e;e>>=1n,a=a*a%m)if(e&1n)z=z*a%m;return z;}
export function inverse(a,m){let [b,x,y,u,v]=[m,1n,0n,0n,1n];a=mod(a,m);if(a===0n)throw Error('inverse of zero');while(b){const q=a/b;[a,b]=[b,a-q*b];[x,u]=[u,x-q*u];[y,v]=[v,y-q*v];}if(a!==1n)throw Error('not invertible');return mod(x,m);}
export function add(A,B){
  if(A===null)return B;if(B===null)return A;
  if(A.x===B.x && A.y!==B.y)return null;
  if(A.x===B.x && A.y===0n)return null;
  const tangent=A.x===B.x;
  const slope=tangent?mod(3n*A.x*A.x*inverse(2n*A.y,P),P):mod((B.y-A.y)*inverse(B.x-A.x,P),P);
  const x=mod(slope*slope-A.x-B.x,P);const y=mod(slope*(A.x-x)-A.y,P);return {x,y};
}
export function multiply(k,A=G){let result=null;for(k=mod(k,N);k;k>>=1n,A=add(A,A))if(k&1n)result=add(result,A);return result;}
export function hexScalar(v,width=32){const h=v.toString(16);if(h.length>width*2)throw Error('scalar too large');return h.padStart(width*2,'0');}
export function liftX(x,odd=false){if(x<0n || x>=P)throw Error('bad x');const rhs=mod(x*x*x+7n,P);let y=powmod(rhs,(P+1n)/4n,P);if(mod(y*y,P)!==rhs)throw Error('no lift');if(Boolean(y&1n)!==Boolean(odd))y=P-y;return {x,y};}
export function pubkey(Pt){if(!Pt)throw Error('point infinity');return ((Pt.y&1n)?'03':'02')+hexScalar(Pt.x);}
export function parsePubkey(hex){if(!/^(02|03)[0-9a-f]{64}$/i.test(hex))throw Error('invalid compressed pubkey');return liftX(BigInt('0x'+hex.slice(2)),hex.slice(0,2)==='03');}
export function verifyECDSA({z,r,s,publicKey}){
  if(!publicKey||r<=0n||r>=N||s<=0n||s>=N)return false;
  const w=inverse(s,N),u=mod(z*w,N),v=mod(r*w,N);
  const X=add(multiply(u),multiply(v,publicKey));return X!==null&&mod(X.x,N)===r;
}
export function recoverPublicKey({z,r,s,odd=false,j=0n}){
  if(r<=0n||r>=N||s<=0n||s>=N)throw Error('invalid signature scalar');
  const R=liftX(r+j*N,odd);
  const Q=multiply(inverse(r,N),add(multiply(s,R),multiply(-mod(z,N))));
  if(!verifyECDSA({z,r,s,publicKey:Q}))throw Error('recovered key mismatch');return Q;
}
export function encodeDERInteger(i){if(i<=0n||i>=N)throw Error('bad ECDSA component');let h=i.toString(16);if(h.length%2)h='0'+h;let b=Buffer.from(h,'hex');if(b[0]>=0x80)b=Buffer.concat([Buffer.from([0]),b]);return Buffer.concat([Buffer.from([0x02,b.length]),b]);}
export function encodeBitcoinSignature(r,s,hashType){const R=encodeDERInteger(r),S=encodeDERInteger(s),payload=Buffer.concat([R,S]);if(payload.length>127)throw Error('too long');return Buffer.concat([Buffer.from([0x30,payload.length]),payload,Buffer.from([hashType])]).toString('hex');}
export function parseBitcoinSignature(signatureHex){
  const a=Buffer.from(signatureHex,'hex');if(a.length<9||a[0]!==0x30||a[1]!==a.length-3||a[2]!==0x02)throw Error('malformed DER');
  const lenR=a[3],startS=4+lenR;if(lenR<1||startS+2>=a.length||a[startS]!==0x02)throw Error('bad r');
  const lenS=a[startS+1],startValueS=startS+2;
  if(lenS<1 || startValueS+lenS!==a.length-1)throw Error('bad s length');
  const rb=a.subarray(4,startS),sb=a.subarray(startValueS,startValueS+lenS);
  for(const b of [rb,sb]) if((b[0]&0x80)!==0 || (b.length>1&&b[0]===0 && !(b[1]&0x80)))throw Error('non-DER integer');
  const r=BigInt('0x'+rb.toString('hex')),s=BigInt('0x'+sb.toString('hex'));
  if(!r||!s||r>=N||s>=N)throw Error('invalid signature value');return {r,s,hashType:a[a.length-1]};
}
/** Bitcoin Core's legacy signature-hash JSON is in uint256 DISPLAY order.
 * Its digest *bytes* (reversed from display) are interpreted big-endian by ECDSA. */
export const displayHashToZ=display=>BigInt('0x'+Buffer.from(display,'hex').reverse().toString('hex'));
