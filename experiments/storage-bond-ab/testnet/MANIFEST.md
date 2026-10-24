# A/B signet/testnet4 receipt manifest

The separate `observe.mjs` tool audits Bitcoin transactions that were already
created and confirmed by a genuine client, signing service and Bitcoin Core
testnet node. It accepts **signet** or **testnet4** and refuses mainnet.

## Input contract

Create one file per protocol backend. Every field in this illustrative
template must be replaced with real data from its independently retained
signed transactions and agreed payout scripts:

```json
{
  "schema": "bsb-ab-testnet-receipt-v1",
  "network": "signet",
  "backend": "A-sentinel",
  "minimum_confirmations": 3,
  "transactions": [
    {
      "role": "fund",
      "txid": "<actual-64-character-txid>",
      "wtxid": "<actual-64-character-witness-id>",
      "inputs": ["<exact-spent-parent-txid>:0"],
      "exact_inputs": true,
      "outputs": [
        {"vout": 0, "script_pubkey_hex": "<exact-p2tr-output-script>", "sats": 60000},
        {"vout": 1, "script_pubkey_hex": "<exact-change-script>", "sats": 12345}
      ],
      "exact_outputs": true
    }
  ]
}
```

The sample placeholders are deliberately invalid. Include every actual
input, funding change output, payout, and zero-value P2A anchor for each
transaction. `vout` indexing, full amount and scripts must match Bitcoin
Core exactly. The observer uses the full raw transaction to rehash the
**witness transaction ID**, checks confirmations on the current active
chain, follows every Bitcoin parent input for fees, and records vsize.

Recommended transaction roles are `fund`, `challenge`, `response`,
`forfeit`, `refund`, `refresh`, `payout`, and `fee-child`. Put both
independent Alice/Bob Taproot bond tracks in A's manifest; B's manifest
should include its pooled carrier and all refreshes. Preserve the
independently signed terms document outside these observational receipts.

## Run

```bash
node experiments/storage-bond-ab/testnet/observe.mjs \
  --manifest /private/A-sentinel-signet.json \
  --bitcoin-cli /path/to/bitcoin-cli \
  --datadir /private/bitcoin \
  --out /private/A-observed.json
```

Repeat with B, using a separate output path. Output files are written with
exclusive creation (`wx`) so previous test results cannot be overwritten.
Keep wallet seeds, federation signing shares, RPC credentials, and original
private backing documents off the repository.

## What this receipt establishes

- This particular Bitcoin Core instance reports transactions confirmed on
  its active chain at the requested depth.
- Their complete raw witness bytes match the independently pinned wtxids.
- Every selected spent outpoint, recipient amount and output script matches
  the supplied agreement; extra outputs or inputs fail.
- Observed virtual bytes and satoshi fees are derived from transactions
  that the full node knows.

## Remaining security obligations

The receipt relies on the local full node for Bitcoin consensus and best
chain selection. An already-spent client output may be a legitimate
redemption. A confirmed signature alone does not establish that the signer
evaluated Filecoin or Blossom correctly. Both protocols require audits of
their actual Taproot keypath/leaf authorization, participant key custody,
correct agreed entitlement mapping, and complete package relay behavior.

Protocol B additionally requires cryptographic FROST threshold evidence,
a falsifiable federation compromise model, persistent replay defense, and
independent Filecoin finality/fault verification. The experimental MID
interpreter is not a Bitcoin consensus opcode. Report threshold-authorized
BTC spends as **federated settlement** until the policy is consensus-bound.

### A/B experimental controls

Pre-register the matching challenge epochs, storage files, fault conditions,
confirmation depth, Bitcoin fee target, timeouts and initial principal.
Record the availability of actual signed exits during a FROST outage and
the cost of recovering without a signer. Compare network transaction
bytes/fees from these receipts; keep cryptographic safety and liveness
properties as separately scored acceptance gates.
