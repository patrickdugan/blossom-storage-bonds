Machine: math VPS: 8 cores, 31 GB RAM, no swap, 8 prover threads, RSS capped at 28 GB.

| backend | deals | q | chunks/deal (depth) | challenged C | Cairo steps | K | prove (s) | total (s) | peak RSS (MiB) | proof (MB) | STARK verify (s) | result |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| sha | 1 | 1 | 256 (8) | 1 | 1,387,657 | 20 | 12.6 | 14.1 | 3,090 | 10.6 | 0.019 | verified |
| sha | 1 | 2 | 256 (8) | 2 | 2,711,274 | 20 | 15.0 | 17.7 | 3,999 | 10.5 | 0.019 | verified |
| sha | 1 | 4 | 256 (8) | 4 | 5,358,508 | 21 | 26.3 | 31.8 | 7,400 | 11.4 | 0.020 | verified |
| sha | 2 | 4 | 256 (8) | 8 | 10,685,241 | 22 | 50.5 | 61.5 | 14,202 | 12.4 | 0.021 | verified |
| sha | 1 | 8 | 262144 (18) | 8 | 13,224,016 | 23 | 74.5 | 87.8 | 21,704 | 13.2 | 0.022 | verified |
| sha | 4 | 4 | 256 (8) | 16 | 21,354,403 | 23 | 100.3 | 122.1 | 27,390 | 13.3 | 0.021 | verified |
| sha | 8 | 4 | 256 (8) | 32 | | 23 | | | | | | memory-bound at K=23: guard: RSS 29033 MiB > 28000 MiB, killing |
| blake | 1 | 1 | 256 (8) | 1 | 26,501 | 20 | 9.9 | 10.0 | 2,021 | 10.7 | 0.019 | verified |
| blake | 4 | 4 | 256 (8) | 16 | 404,237 | 20 | 11.8 | 12.4 | 2,534 | 11.0 | 0.020 | verified |
| blake | 16 | 4 | 256 (8) | 64 | 1,615,441 | 20 | 16.3 | 18.2 | 4,172 | 11.3 | 0.020 | verified |
| blake | 32 | 4 | 256 (8) | 128 | 3,230,385 | 21 | 27.8 | 31.9 | 7,422 | 12.2 | 0.022 | verified |
| blake | 64 | 4 | 256 (8) | 256 | 6,460,273 | 22 | 50.8 | 58.9 | 13,923 | 12.8 | 0.022 | verified |
| blake | 1 | 256 | 262144 (18) | 256 | 7,968,226 | 22 | 59.4 | 68.4 | 15,948 | 13.0 | 0.022 | verified |
| blake | 128 | 4 | 256 (8) | 512 | 12,920,049 | 23 | 99.4 | 115.7 | 26,818 | 14.0 | 0.024 | verified |
| blake | 256 | 4 | 256 (8) | 1024 | | 20 | | | | | | memory-bound at K=20: guard: RSS 28863 MiB > 28000 MiB, killing |

Fits (least squares over the verified runs):

- sha: steps ≈ 44,637 + C·(1,078,611 + 31,601·depth); total time ≈ 6.6 s + 7.58 s·C; peak RSS ≈ 1,784 + 1,719.9 MiB·C; largest C proved here 16 (fit: 128 s); proof ≈ 11.9 MB; STARK verify ≈ 20 ms (the CLI's total, ≈ 1.2 s, is mostly recomputing the preprocessed root, which a verifier caches)
- blake: steps ≈ 734 + C·(20,521 + 589·depth); total time ≈ 7.7 s + 0.21 s·C; peak RSS ≈ 1,626 + 49.8 MiB·C; largest C proved here 512 (fit: 116 s); proof ≈ 12.1 MB; STARK verify ≈ 21 ms (the CLI's total, ≈ 0.9 s, is mostly recomputing the preprocessed root, which a verifier caches)

Extrapolation at q = 8 per deal (layer 1's default). C = deals × q. 'One proof' is the peak RSS a single proof would need by the memory fit. 'Split' = ⌈C / C_max⌉ proofs of the largest C proved here, run one after another on this machine (time from the fit); each proof is verified on its own.

| per epoch | split into | backend | C | Cairo steps | one proof: peak RSS | proofs if split | prover time, split (h) | proof bytes, split | STARK verify, split (s) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 GiB | 1 deal of 1 GiB | sha | 8 | 1.32e+07 | 15.2 GiB (fits here) | 1 | 0.04 | 12 MB | 0.0 |
| 1 GiB | 1 deal of 1 GiB | blake | 8 | 2.5e+05 | 2.0 GiB (fits here) | 1 | 0.03 | 12 MB | 0.0 |
| 1 GiB | 1,024 deals of 1 MiB | sha | 8,192 | 1.09e+10 | 13,761.2 GiB | 512 | 18.18 | 6,092 MB | 10.4 |
| 1 GiB | 1,024 deals of 1 MiB | blake | 8,192 | 2.07e+08 | 400.3 GiB | 16 | 0.52 | 194 MB | 0.3 |
| 1 TiB | 1 deal of 1 TiB | sha | 8 | 1.58e+07 | 15.2 GiB (fits here) | 1 | 0.04 | 12 MB | 0.0 |
| 1 TiB | 1 deal of 1 TiB | blake | 8 | 2.97e+05 | 2.0 GiB (fits here) | 1 | 0.03 | 12 MB | 0.0 |
| 1 TiB | 1,024 deals of 1 GiB | sha | 8,192 | 1.35e+10 | 13,761.2 GiB | 512 | 18.18 | 6,092 MB | 10.4 |
| 1 TiB | 1,024 deals of 1 GiB | blake | 8,192 | 2.55e+08 | 400.3 GiB | 16 | 0.52 | 194 MB | 0.3 |
| 1 TiB | 1,048,576 deals of 1 MiB | sha | 8,388,608 | 1.12e+13 | 14,089,681.4 GiB | 524,288 | 18,614.45 | 6,238,684 MB | 10,660.5 |
| 1 TiB | 1,048,576 deals of 1 MiB | blake | 8,388,608 | 2.12e+11 | 408,304.6 GiB | 16,384 | 529.19 | 198,826 MB | 348.7 |
