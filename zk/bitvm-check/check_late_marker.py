import argparse,hashlib,json
from pathlib import Path
if not __debug__: raise RuntimeError("Run this audit without Python -O; its assertions must be active")
parser=argparse.ArgumentParser(description='Decode and hash the actual mined late-marker counterexamples; no Script verification.')
parser.add_argument('report',type=Path)
parser.add_argument('vectors',type=Path)
parser.add_argument('--out',type=Path)
args=parser.parse_args()
r=json.loads(args.report.read_text())
v=json.loads(args.vectors.read_text())
def sha(b):return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def tx(raw):
    b=bytes.fromhex(raw);o=0
    def take(n):
        nonlocal o
        assert 0<=n<=len(b)-o
        x=b[o:o+n];o+=n;return x
    def integer(n):return int.from_bytes(take(n),'little')
    def compact():
        f=integer(1)
        if f<253:return f
        size={253:2,254:4,255:8}[f];n=integer(size)
        assert n>={2:253,4:65536,8:4294967296}[size];return n
    version=take(4);assert take(2)==b'\x00\x01';start=o
    ins=[]
    for _ in range(compact()):
        point=take(36);script=take(compact());sequence=take(4);ins.append((point,script,sequence))
    outs=[]
    for _ in range(compact()):outs.append((integer(8),take(compact())))
    end=o;witness=[]
    for _ in ins:witness.append([take(compact()) for _ in range(compact())])
    lock=take(4);assert o==len(b)
    return {'txid':sha(version+b[start:end]+lock)[::-1].hex(),'wtxid':sha(b)[::-1].hex(),'inputs':ins,'outputs':outs,'witness':witness}
assert r['network']=='regtest' and r['checks']['nodeStopped'] is True
assert len(r['mined'])==3 and len(r['admitted'])==7 and len(r['rejected'])==12
rows=[]
for name,mode,count,flag in [('single-trivial-marker','single',2,0x83),('all-marker-omission','all',1,0x81),('strict-original-control','strict',2,0)]:
    record=next(x for x in r['mined'] if x['name']==name)
    actual=tx(record['hex']);base=tx(v['setup']['transactions'][mode]['hex'])
    assert actual['txid']==record['txid'] and actual['wtxid']==record['wtxid']
    assert actual['inputs'][0]==base['inputs'][0]
    assert actual['witness'][0]==base['witness'][0]
    sig=actual['witness'][0][0]
    assert (len(sig)==64 if not flag else len(sig)==65 and sig[-1]==flag)
    assert len(actual['inputs'])==count and len(actual['outputs'])==1
    assert actual['outputs'][0]==(99_995_000,bytes.fromhex(v['setup']['payout_script']))
    assert record['payout_sats']==actual['outputs'][0][0] and record['payout_script']==actual['outputs'][0][1].hex()
    assert record['input_count']==len(actual['inputs'])
    if mode=='single':assert len(actual['witness'][1])==2 and actual['witness'][1][0]==b'\x51'
    if mode=='strict':assert record['hex']==v['setup']['transactions']['strict']['hex']
    rows.append({'case':name,'presignature_reused_byte_for_byte':True,'sighash':flag,'input_count':count,'txid_and_wtxid_match':True,'fixed_payout_verified':True})
result={'format':'bsb/late-marker-byte-audit/v1','cases':rows,'scope':'Independent stdlib decoding and hashing of actual Core-mined bytes; not a new Script execution or signature verification.'}
if args.out:
    with args.out.open('x',encoding='utf8') as f: f.write(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
