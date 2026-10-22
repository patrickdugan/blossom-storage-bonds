# Binohash admission research

**Status: BLOCKED AT BITCOIN CONSENSUS ENFORCEMENT.** The published model and transaction serialization experiments use idealized authorization at precisely the stage that still needs a real Bitcoin contract.

Current research: **132 deterministic Node tests passing** (10 files). Run:

```bash
node --test model/*.test.mjs
```

This command needs Node 22+, uses no external packages, and starts no bitcoin node or proof job. The dedicated GitHub workflow runs only these tests.

### Research artifacts

- [ADR-001: journal cursor and joint settlement](cursor-architecture.md): candidate UTXO topology, fee sponsorship, exact-work ties, freeze race, required Bitcoin enforcement
- [Next transaction-level acceptance gate](next-step.md): direct script and refund criteria
- [Binohash admission review](../binohash-admission-review.md): original attacks against selected challenge roots and provider refunds
- `model/utxo_admission_graph*.mjs`: UTXO conflict and stale spending paths
- `model/journal_cursor*.mjs`: chained cursor, live joint spend and hypothetical challenger funding
- `model/cutoff_race.test.mjs`: last-block and post-cutoff transaction conflicts
- `model/cursor_sighash.test.mjs`: four real legacy signature-hash mode commitment cases
- `model/binohash_budget*.mjs`: published opcode-count and script-size arithmetic
- `model/legacy_sighash*.mjs`: Bitcoin Core vectors and legacy FindAndDelete
- `model/contest_spec*.mjs`: reference specification with **omniscient journal and chain-work oracle**

### Provenance

This GitHub branch begins at pushed `phase-6-bitvm2-spike` (`a8c9bb11`). The owner's Phase 7 commit `4494714`, including the six-transaction / 151-header stronger-fork regression, has not been pushed here; integration with that fixture has **not** occurred.

The tests are adversarial protocol models, serialization, and signature-hash checks. The construction has **not** produced a Bitcoin consensus-valid, permissionless long-chain admission covenant. It has not run production Binohash grinding or sent any transaction to miners. The optimistic path to a working solution is an independently enforced, unique cursor-successor transition that can survive arbitrary challengers and then be co-spent at settlement. A stale provider-only refund leaf must be removed from every bond path.

The working PR remains draft until a successful Bitcoin-level construction exists.
