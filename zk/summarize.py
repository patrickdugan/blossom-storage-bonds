"""Table and extrapolation for the aggregated storage proof benchmark.

    python zk/summarize.py results/zk-pdp.jsonl ["machine label"] > results/zk-pdp.md

Reads the JSON lines zk/bench.sh writes. Per backend it fits, by least squares over the runs that
proved,

    steps  = s0 + C * (s_leaf + depth * s_level)      (C = deals * q challenged chunks)
    time   = t0 + t1 * C,   peak RSS = m0 + m1 * C     (at the measured depth mix)

and extrapolates to a provider holding 1 GiB and 1 TiB per epoch. What a proof costs depends on
C and the tree depth, not on the bytes stored, so each size is shown for a few ways to split it
into deals. Above what fits one proof here (WSL capped at 4.5 GB), the rows give the cost of
splitting the epoch into proofs of the largest C that fit, which is what this prover can do
without recursion.
"""
import json
import math
import sys

rows = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
MACHINE = sys.argv[2] if len(sys.argv) > 2 else "laptop: Ryzen AI 9 365, WSL capped at 4.5 GB, 4 prover threads"
print(f"Machine: {MACHINE}.")
print()
rows.sort(key=lambda r: (r["hash"] != "sha", r["deals"] * r["q"], r["chunks_per_deal"], r["deals"]))
ok = [r for r in rows if r.get("verify", {}).get("result") == "verified"]


def depth(n):
    d = 0
    while n > 1:
        n = (n + 1) // 2
        d += 1
    return d


def lstsq(xs, ys):
    """Least squares for y = X b, X given as rows; tiny normal equations solved by Gauss."""
    k = len(xs[0])
    a = [[sum(x[i] * x[j] for x in xs) for j in range(k)] + [sum(x[i] * y for x, y in zip(xs, ys))] for i in range(k)]
    for c in range(k):
        p = max(range(c, k), key=lambda r: abs(a[r][c]))
        a[c], a[p] = a[p], a[c]
        for r in range(k):
            if r != c and a[c][c]:
                f = a[r][c] / a[c][c]
                a[r] = [x - f * y for x, y in zip(a[r], a[c])]
    return [a[i][k] / a[i][i] for i in range(k)]


print("| backend | deals | q | chunks/deal (depth) | challenged C | Cairo steps | K | prove (s) | total (s) | peak RSS (MiB) | proof (MB) | STARK verify (s) | result |")
print("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
for r in rows:
    c = r["deals"] * r["q"]
    n = r["chunks_per_deal"]
    if "verify" in r:
        v = r["verify"]
        print(f"| {r['hash']} | {r['deals']} | {r['q']} | {n} ({depth(n)}) | {c} | {r['steps']:,} | {r['k']} | {r['prove_s']:.1f} | "
              f"{r['total_s']:.1f} | {r['peak_rss_mib']:,.0f} | {r['proof_bytes'] / 1e6:.1f} | "
              f"{v.get('stark_verify_s', float('nan')):.3f} | {v['result']} |")
    else:
        print(f"| {r['hash']} | {r['deals']} | {r['q']} | {n} ({depth(n)}) | {c} | | {r.get('k', '')} | | | | | | {r['error'][:80]} |")

fits = {}
for h in ("sha", "blake"):
    rs = [r for r in ok if r["hash"] == h]
    if len(rs) < 3:
        continue
    C = [r["deals"] * r["q"] for r in rs]
    D = [depth(r["chunks_per_deal"]) for r in rs]
    s0, sl, sd = lstsq([[1, c, c * d] for c, d in zip(C, D)], [r["steps"] for r in rs])
    t0, t1 = lstsq([[1, c] for c in C], [r["total_s"] for r in rs])
    m0, m1 = lstsq([[1, c] for c in C], [r["peak_rss_mib"] for r in rs])
    cmax = max(C)
    big = max((r for r in rs), key=lambda r: r["deals"] * r["q"])
    fits[h] = dict(s0=s0, s_leaf=sl, s_level=sd, t0=t0, t1=t1, m0=m0, m1=m1, cmax=cmax,
                   tmax=t0 + t1 * cmax, proof_mb=sum(r["proof_bytes"] for r in rs) / len(rs) / 1e6,
                   verify_s=sum(r["verify"]["stark_verify_s"] for r in rs) / len(rs),
                   cli_verify_s=sum(r["verify"]["total_s"] for r in rs) / len(rs))

print()
print("Fits (least squares over the verified runs):")
print()
for h, f in fits.items():
    print(f"- {h}: steps ≈ {f['s0']:,.0f} + C·({f['s_leaf']:,.0f} + {f['s_level']:,.0f}·depth); "
          f"total time ≈ {f['t0']:.1f} s + {f['t1']:.2f} s·C; peak RSS ≈ {f['m0']:,.0f} + {f['m1']:,.1f} MiB·C; "
          f"largest C proved here {f['cmax']} (fit: {f['tmax']:.0f} s); proof ≈ {f['proof_mb']:.1f} MB; STARK verify ≈ {f['verify_s'] * 1000:.0f} ms "
          f"(the CLI's total, ≈ {f['cli_verify_s']:.1f} s, is mostly recomputing the preprocessed root, which a verifier caches)")

GiB, TiB = 2**30, 2**40
scen = [
    ("1 GiB", "1 deal of 1 GiB", 1, 2**18),
    ("1 GiB", "1,024 deals of 1 MiB", 1024, 2**8),
    ("1 TiB", "1 deal of 1 TiB", 1, 2**28),
    ("1 TiB", "1,024 deals of 1 GiB", 1024, 2**18),
    ("1 TiB", "1,048,576 deals of 1 MiB", 2**20, 2**8),
]
Q = 8
print()
print(f"Extrapolation at q = {Q} per deal (layer 1's default). C = deals × q. 'One proof' is the peak RSS a single "
      "proof would need by the memory fit. 'Split' = ⌈C / C_max⌉ proofs of the largest C "
      "proved here, run one after another on this machine (time from the fit); each proof is verified on its own.")
print()
print("| per epoch | split into | backend | C | Cairo steps | one proof: peak RSS | proofs if split | prover time, split (h) | proof bytes, split | STARK verify, split (s) |")
print("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
for size, how, deals, n in scen:
    for h, f in fits.items():
        c = deals * Q
        steps = f["s0"] + c * (f["s_leaf"] + f["s_level"] * depth(n))
        mem = (f["m0"] + f["m1"] * c) / 1024
        fits_one = f"{mem:,.1f} GiB" + (" (fits here)" if c <= f["cmax"] else "")
        k = math.ceil(c / f["cmax"])
        t = k * f["tmax"] / 3600
        print(f"| {size} | {how} | {h} | {c:,} | {steps:,.3g} | {fits_one} | {k:,} | {t:,.2f} | "
              f"{k * f['proof_mb']:,.0f} MB | {k * f['verify_s']:,.1f} |")
json.dump(fits, open(sys.argv[1].replace(".jsonl", "-fits.json"), "w"), indent=1)
