/**
 * A SPECIFICATION ORACLE for a proposed permissionless long-chain contest.
 * Script cannot implement this module as written. It assumes a trusted complete
 * view of all timely certificates, their inclusion heights, and exact verified
 * chain work. A Bitcoin graph must realize each property without this oracle.
 */
import { createHash } from 'node:crypto';
const H = value => createHash('sha256').update(value).digest('hex');
const err = reason => {throw new Error(reason);};

export function certificateDigest(c) {
  if(!c || typeof c.id !== 'string' || !c.id || !/^[0-9a-f]{64}$/i.test(c.headerRoot) ||
     typeof c.work !== 'bigint' || c.work<0n || !Number.isSafeInteger(c.height) || c.height<0)
    err('invalid certificate fields');
  return H('BSB/ADMISSION/CERT/V1\0'+JSON.stringify([c.id,c.headerRoot.toLowerCase(),c.work.toString()]));
}
export class ContestSpecification {
  constructor({admissionEnd,responseBlocks}) {
    if(!Number.isSafeInteger(admissionEnd)||admissionEnd<0||!Number.isSafeInteger(responseBlocks)||responseBlocks<1)
      err('invalid windows');
    this.admissionEnd=admissionEnd;
    this.responseBlocks=responseBlocks;
    this.phase='admit';
    this.journal=new Map();
    this.replies=new Set();
    this.cutoffRoot=null;
    this.responseDeadline=null;
  }
  submit(cert,{confirmedHeight,verifiedExactWork}) {
    if(this.phase!=='admit')err('admission closed');
    if(!Number.isSafeInteger(confirmedHeight)||confirmedHeight<0||confirmedHeight>this.admissionEnd)
      err('certificate not admitted in time');
    // Verified chain linkage and exact cumulative work are external fixture truth.
    if(!verifiedExactWork)err('certificate proof invalid');
    const digest=certificateDigest(cert);
    if(cert.height!==confirmedHeight)err('certificate confirmation height mismatch');
    if(this.journal.has(cert.id)) {
      if(this.journal.get(cert.id).digest!==digest)err('certificate identifier equivocation');
      return {status:'duplicate',digest};
    }
    const entry=Object.freeze({id:cert.id,digest,work:cert.work,confirmedHeight});
    this.journal.set(cert.id,entry);
    return {status:'admitted',digest};
  }
  strongest() {
    const all=[...this.journal.values()];
    if(!all.length)return [];
    const max=all.reduce((a,c)=>a>c.work?a:c.work,0n);
    return all.filter(c=>c.work===max).sort((a,b)=>a.digest.localeCompare(b.digest));
  }
  freeze(height) {
    if(this.phase!=='admit')err('already frozen');
    if(!Number.isSafeInteger(height)||height<=this.admissionEnd)err('cutoff not passed');
    this.phase='respond';
    this.responseDeadline=this.admissionEnd+this.responseBlocks+1;
    this.cutoffRoot=H('BSB/ADMISSION/JOURNAL/V1\0'+JSON.stringify(
      [...this.journal.values()].sort((a,b)=>a.digest.localeCompare(b.digest)).map(c=>[c.digest,c.work.toString(),c.confirmedHeight])
    ));
    return {journalRoot:this.cutoffRoot,required:this.strongest().map(c=>c.digest)};
  }
  rebut({id,digest,proofMatchesCertificate,height}) {
    if(this.phase!=='respond')err('not in rebuttal');
    if(!Number.isSafeInteger(height)||height>this.responseDeadline||height<=this.admissionEnd)err('response outside window');
    const candidate=this.strongest().find(c=>c.id===id);
    if(!candidate || candidate.digest!==digest)err('response not bound to admitted strongest certificate');
    if(!proofMatchesCertificate)err('invalid rebuttal proof');
    this.replies.add(digest);
    return {status:'answered',id};
  }
  payout(height,claimedJournalRoot=this.cutoffRoot) {
    if(this.phase!=='respond')return 'locked';
    if(claimedJournalRoot!==this.cutoffRoot)return 'locked';
    const pending=this.strongest().filter(c=>!this.replies.has(c.digest));
    if(!pending.length)return 'provider';
    if(height>this.responseDeadline)return 'forfeit';
    return 'locked';
  }
}
