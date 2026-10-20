| backend | deals | q | chunks/deal (depth) | challenged C | Cairo steps | K | prove (s) | total (s) | peak RSS (MiB) | proof (MB) | STARK verify (s) | result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| sha | 1 | 1 | 256 (8) | 1 | 1,387,657 | 20 | 28.5 | 30.3 | 3,047 | 10.6 | 0.020 | verified |
| sha | 1 | 1 | 262144 (18) | 1 | 1,709,247 | 20 | 29.0 | 31.3 | 3,256 | 10.5 | 0.017 | verified |
| sha | 1 | 2 | 256 (8) | 2 | 2,711,274 | 20 | 33.5 | 37.5 | 3,958 | 10.5 | 0.017 | verified |
| sha | 2 | 1 | 256 (8) | 2 | | 21 | | | | | | memory-bound: swap passed 1024 MiB at K=21 |
| sha | 1 | 3 | 256 (8) | 3 | | 21 | | | | | | memory-bound: swap passed 1024 MiB at K=21 |
| blake | 1 | 1 | 256 (8) | 1 | 26,501 | 20 | 24.8 | 24.9 | 2,010 | 10.7 | 0.016 | verified |
| blake | 1 | 4 | 256 (8) | 4 | 101,438 | 20 | 20.1 | 20.3 | 2,108 | 11.0 | 0.019 | verified |
| blake | 4 | 4 | 256 (8) | 16 | 404,237 | 20 | 27.1 | 27.7 | 2,522 | 11.0 | 0.019 | verified |
| blake | 1 | 16 | 262144 (18) | 16 | 499,666 | 20 | 24.7 | 25.3 | 2,635 | 11.1 | 0.017 | verified |
| blake | 8 | 4 | 256 (8) | 32 | 807,969 | 20 | 31.1 | 32.3 | 3,120 | 11.3 | 0.020 | verified |
| blake | 16 | 4 | 256 (8) | 64 | 1,615,441 | 20 | 39.7 | 42.3 | 3,973 | 11.3 | 0.017 | verified |
| blake | 1 | 64 | 262144 (18) | 64 | 1,993,378 | 20 | 56.9 | 59.9 | 4,005 | 11.1 | 0.017 | verified |
| blake | 32 | 4 | 256 (8) | 128 | | 21 | | | | | | memory-bound: swap passed 1024 MiB at K=21 |
| blake | 16 | 16 | 256 (8) | 256 | | 20 | | | | | | memory-bound: swap passed 1024 MiB at K=20 |
| blake | 64 | 4 | 256 (8) | 256 | | 20 | | | | | | memory-bound: swap passed 1024 MiB at K=20 |
| blake | 64 | 16 | 256 (8) | 1024 | | 20 | | | | | | memory-bound: swap passed 1024 MiB at K=20 |

Fits (least squares over the verified runs):

- sha: steps ≈ 64,040 + C·(1,066,345 + 32,159·depth); total time ≈ 24.1 s + 6.72 s·C; peak RSS ≈ 2,344 + 807.1 MiB·C; largest C proved here 2 (fit: 38 s); proof ≈ 10.5 MB; STARK verify ≈ 18 ms (the CLI's total, ≈ 1.1 s, is mostly recomputing the preprocessed root, which a verifier caches)
- blake: steps ≈ 976 + C·(20,495 + 591·depth); total time ≈ 20.0 s + 0.47 s·C; peak RSS ≈ 2,039 + 30.9 MiB·C; largest C proved here 64 (fit: 50 s); proof ≈ 11.1 MB; STARK verify ≈ 18 ms (the CLI's total, ≈ 1.2 s, is mostly recomputing the preprocessed root, which a verifier caches)

Extrapolation at q = 8 per deal (layer 1's default). C = deals × q. 'One proof' is the peak RSS a single proof would need by the memory fit (this machine has 4.5 GB). 'Split' = ⌈C / C_max⌉ proofs of the largest C proved here, run one after another on this machine (time from the fit); each proof is verified on its own.

| per epoch | split into | backend | C | Cairo steps | one proof: peak RSS | proofs if split | prover time, split (h) | proof bytes, split | STARK verify, split (s) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 GiB | 1 deal of 1 GiB | sha | 8 | 1.32e+07 | 8.6 GiB | 4 | 0.04 | 42 MB | 0.1 |
| 1 GiB | 1 deal of 1 GiB | blake | 8 | 2.5e+05 | 2.2 GiB (fits here) | 1 | 0.01 | 11 MB | 0.0 |
| 1 GiB | 1,024 deals of 1 MiB | sha | 8,192 | 1.08e+10 | 6,459.4 GiB | 4,096 | 42.71 | 43,168 MB | 73.7 |
| 1 GiB | 1,024 deals of 1 MiB | blake | 8,192 | 2.07e+08 | 249.6 GiB | 128 | 1.78 | 1,416 MB | 2.3 |
| 1 TiB | 1 deal of 1 TiB | sha | 8 | 1.58e+07 | 8.6 GiB | 4 | 0.04 | 42 MB | 0.1 |
| 1 TiB | 1 deal of 1 TiB | blake | 8 | 2.97e+05 | 2.2 GiB (fits here) | 1 | 0.01 | 11 MB | 0.0 |
| 1 TiB | 1,024 deals of 1 GiB | sha | 8,192 | 1.35e+10 | 6,459.4 GiB | 4,096 | 42.71 | 43,168 MB | 73.7 |
| 1 TiB | 1,024 deals of 1 GiB | blake | 8,192 | 2.55e+08 | 249.6 GiB | 128 | 1.78 | 1,416 MB | 2.3 |
| 1 TiB | 1,048,576 deals of 1 MiB | sha | 8,388,608 | 1.11e+13 | 6,612,085.0 GiB | 4,194,304 | 43,730.28 | 44,204,062 MB | 75,497.5 |
| 1 TiB | 1,048,576 deals of 1 MiB | blake | 8,388,608 | 2.12e+11 | 253,523.2 GiB | 131,072 | 1,826.02 | 1,450,381 MB | 2,340.6 |
