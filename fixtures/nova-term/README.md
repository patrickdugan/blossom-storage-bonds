# Nova term fixtures

Inputs to `layer1/nova-term.ts` and `full-stack.ts --nova-term`, from
[garbled-snark-verifier/nova-bitvm3](https://github.com/patrickdugan/garbled-snark-verifier/tree/main/nova-bitvm3).

| Directory | `statement.bin` | Proof |
| --- | --- | --- |
| `testnet4-0-4` | Guest A's committed values (1,164 bytes, SHA-256 `d3b478b0…2fa0`): testnet4 heights 0–4 folded by Nova, k = 1, from the genesis state. Cut out of `m13/fixtures/a-compressed.bin` at the offset where its SHA-256 equals the `committed_values_sha256` of `m13/fixtures/a-statement.json`. | `m13/fixtures/a-wrap-blake3-v2.bin`; `m13-verify verify-v2` accepts it (0.2 s) and refuses it against any other statement. |
| `testnet4-0-4-pay1` | The same 1,164 bytes followed by the 128-byte PAY1 record the M16 guest commits for the same segment and payment block 1's coinbase output 0 (50 tBTC, P2PKH, headers 1–4, so 4 confirmations). The record is built from public chain data in M16's layout. | None: this record is built by hand, not proved. |
| `mainnet-m16` | M16's real mainnet statement (`m13/fixtures/m16-public.bin`, 1,292 bytes, SHA-256 `cae6068f…c869`): guest A's chain statement for tip 975,072 plus a PAY1 record for output `a652ab0c…0045:0` (940,000 sats, 22-byte script, block 975,067, 6 confirmations). `statement.json` is its expectation file. | `wrap.bin` = `m16-wrap-blake3-v2.bin` (1.1 MB); `m13-verify verify-v2` accepts it under program key `dfc68a5d…cb60`. |

## M16 mode: the client paid the provider on chain

`checkProviderPaid` in `layer1/nova-term.ts` accepts a statement only if all of these hold:

- the wrap verifies under the pinned M16 program key for exactly these public bytes (`m13-verify` runs on an expectation file the module rebuilds from its pins and sha256(public bytes));
- `statement.json`, when present, names the pinned program key and a committed-values digest equal to sha256(public bytes);
- magic `NHC1`, k = 1, Nova key sha256 `6aa50d09…6da1` and sha256(z0) `b6eeaf96…f045` are the mainnet pins (the testnet4 pin holds z0 as bytes);
- the PAY1 record ends at the proven tip, pays a script whose SHA-256 equals the provider's registered script, with value at least the amount owed and confirmations at least the term's minimum.

A `term.json` with a `provider` entry (`scriptSha256`, `owedSats`, `minConfs`) selects this mode in `checkNovaTermDir` and in `full-stack.ts --nova-term`. The mode refuses to run without a wrap proof and `BSB_M13_VERIFY`; `--nova-unverified` runs every other check and reports `proof: "not checked: ..."`. `mainnet-m16/term.json` registers the script of the real payment at 940,000 sats owed and 6 confirmations.

Results (2026-11-11):

| Run | Result |
| --- | --- |
| `node --test layer1/nova-term.test.ts` with the real m13-verify in WSL (`BSB_M13_VERIFY`, `BSB_NOVA_WRAP`) | 11 of 11 pass, 0 skipped. M16 tests: real proof accepted (also at lower owed and fewer confirmations); refused for tampered public bytes (statement digest check, and `m13-verify refused` against the real proof), wrong program key, wrong script, value 940,001 owed, 7 confirmations required, wrong z0, `NHT4` magic under mainnet pins, a guest A statement, a verifier that refuses. |
| Same without the env vars | 10 of 11 pass, 1 skipped (guest A real-proof test); the M16 tests use a stand-in verifier that accepts, so the proof-dependent refusals run against the real verifier only when the env vars are set. |
| `node layer1/nova-term.ts --dir fixtures/nova-term/mainnet-m16` with the real verifier | `proof: "verified"`, payment `a652ab0c…:0`, 940,000 sats, 6 confirmations. Without the verifier: `refused: the M16 term needs a wrap proof and BSB_M13_VERIFY`. |
| CI, `full-stack` `--pay ln` leg | `--nova-term fixtures/nova-term/mainnet-m16 --nova-unverified` (the runners have no m13-verify). The `--pay onchain` leg keeps `testnet4-0-4-pay1`. |


`headers.hex` holds testnet4 headers 0–4, one per line, read from Bitcoin Core 31.1 (`getblockheader <hash> false`).
The last one hashes to the tip in both statements (`000000008f57…4265`).

`term.json` takes the place of a run's own term: the network, the epoch seeds (heights 2, 3, 4), the
payments the PAY1 record must match, and the confirmations required (3).

Check one directory:

```
node layer1/nova-term.ts --dir fixtures/nova-term/testnet4-0-4
BSB_M13_VERIFY="wsl.exe -d Ubuntu-24.04 -u root -- <m13-verify>" BSB_NOVA_WRAP=<a-wrap-blake3-v2.bin> node layer1/nova-term.ts --dir fixtures/nova-term/testnet4-0-4
```
