# Nova term fixtures

Inputs to `layer1/nova-term.ts` and `full-stack.ts --nova-term`, from
[garbled-snark-verifier/nova-bitvm3](https://github.com/patrickdugan/garbled-snark-verifier/tree/main/nova-bitvm3).

| Directory | `statement.bin` | Proof |
| --- | --- | --- |
| `testnet4-0-4` | Guest A's committed values (1,164 bytes, SHA-256 `d3b478b0…2fa0`): testnet4 heights 0–4 folded by Nova, k = 1, from the genesis state. Cut out of `m13/fixtures/a-compressed.bin` at the offset where its SHA-256 equals the `committed_values_sha256` of `m13/fixtures/a-statement.json`. | `m13/fixtures/a-wrap-blake3-v2.bin`; `m13-verify verify-v2` accepts it (0.2 s) and refuses it against any other statement. |
| `testnet4-0-4-pay1` | The same 1,164 bytes followed by the 128-byte PAY1 record the M16 guest commits for the same segment and payment block 1's coinbase output 0 (50 tBTC, P2PKH, headers 1–4, so 4 confirmations). The record is built from public chain data in M16's layout. | None. M16 has not been proved, and its program key is not pinned, so `verifyWrap` refuses a PAY1 proof. |

`headers.hex` holds testnet4 headers 0–4, one per line, read from Bitcoin Core 31.1 (`getblockheader <hash> false`).
The last one hashes to the tip in both statements (`000000008f57…4265`).

`term.json` takes the place of a run's own term: the network, the epoch seeds (heights 2, 3, 4), the
payments the PAY1 record must match, and the confirmations required (3).

Check one directory:

```
node layer1/nova-term.ts --dir fixtures/nova-term/testnet4-0-4
BSB_M13_VERIFY="wsl.exe -d Ubuntu-24.04 -u root -- <m13-verify>" BSB_NOVA_WRAP=<a-wrap-blake3-v2.bin> node layer1/nova-term.ts --dir fixtures/nova-term/testnet4-0-4
```
