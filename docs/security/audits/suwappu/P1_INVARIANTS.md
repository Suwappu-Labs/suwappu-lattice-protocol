# P1 — Invariant authoring (status)

Date: 2026-06-07 · Methodology: canonical lock-and-mint bridge invariants, Handler+ghost-var pattern (mirrors `OptimisticBridgeChallenge.invariant.t.sol`).

## Centerpiece delivered: cross-domain supply harness (RED, as required)

File: `contracts/test/invariant/SuwappuSupply.invariant.t.sol`

Deploys the SOURCE-chain `SuwappuVault` together with the DEST-chain `SuwappuMintAdapter` + `SuwappuWrappedToken` in one EVM and models the **relayer as the adversary** (the bridge's real trust boundary — this harness did not exist before). `feeBps=0` so net==gross for exact supply/collateral accounting.

Two canonical invariants, **both RED on current code** with deterministic fuzzer counterexamples:

### INV-SUPPLY — `wrapped.totalSupply() <= vault.totalLocked(asset)`
**FAIL.** Counterexample (shrunk to 1 call): `maliciousMint(0x098c, 1970179052, 0x4Bb8…)` → supply `1970179052` > locked `0`. Proves **C1**: `SuwappuMintAdapter.mint` never recomputes/compares the commitId, so a relayer mints arbitrary unbacked supply. (Reproduced across seeds: `…2315615929 > 0`.)

### INV-XOR — each vault commitId reaches at most one of {minted, unlocked, refunded}
**FAIL.** Counterexample: `lock → unlock → … → honestMint` → a commitId reaches >1 terminal outcome. Proves **C2 / cross-domain double-spend**: source collateral can be released (unlock/refund) while the dest mint stands, because vault and adapter share no on-chain state.

These two findings are now backed by reproducible fuzzer traces (seeds recorded in CI output), not manual reading. They must go GREEN only after the C1 (commitId binding) and C2 (refund/unlock-vs-mint gating) fixes land in P7, and RED again if those fixes are reverted.

## Complete RED proof set (all 8 confirmed findings now have deterministic proofs)

| # | Finding | Test (file → name) | RED evidence |
|---|---|---|---|
| C1 | relayer arbitrary mint (no commitId binding) | `invariant/SuwappuSupply.invariant.t.sol` → `invariant_supply_le_collateral` | `maliciousMint` → supply `1.97e9 > 0` locked |
| C2 | cross-domain double-spend (refund/unlock vs mint) | `invariant/SuwappuSupply.invariant.t.sol` → `invariant_one_commit_one_outcome` | `lock→unlock/refund-after-mint` → commit >1 terminal |
| C3 | ZK: no access control + anchorDigest unbound | `security/SuwappuZKVerifier.security.t.sol` → `test_C3_...` | attacker finalizes arbitrary digest w/ unbound proof |
| C4 | ZK: code-less `sp1Verifier` accepts all proofs | `security/SuwappuZKVerifier.security.t.sol` → `test_C4_...` | junk proof finalizes via staticcall-to-EOA |
| C5 | FOT under-collateralization | `security/SuwappuCustody.security.t.sol` → `test_C5_...` | `totalLocked 100e18 > balance 98e18` |
| C6 | escrow `sweepUnclaimed` cross-round drain | `security/SuwappuCustody.security.t.sol` → `test_C6_...` | escrow balance `0 < 10e18` owed |
| C7 | escrow multi-token under-claim | `security/SuwappuCustody.security.t.sol` → `test_C7_...` | second-token claim reverts `AlreadyClaimed` |
| C8 | guardian selector not bound to target | `security/SuwappuCustody.security.t.sol` → `test_C8_...` | guardian pauses unintended target |

All are written as **secure-property assertions** (RED now, GREEN only after the P7 fix, RED again on revert).

## CRITICAL architectural finding (discovered while designing the C1 fix)

**C1/C2/C3 cannot be fixed in isolation — their real remediation IS the P5b on-chain-PQ work.** The destination-side `MintAdapter.mint(commitId, recipient, amount, sourceChainId)` does **not receive** the fields needed to recompute the vault's `commitId` (vault address, `_lockNonce`, original `from`, token, `destRecipient`). A naïve "recompute commitId" patch would only hash relayer-supplied fields — still fully relayer-trusted, no added security. The *sound* fix is for `mint`/`unlock`/`finalize` to require an **on-chain-verified proof that the source-chain lock (that exact commit) actually happened** — i.e., the on-chain ML-DSA/anchor verification built in P5b. This validates the plan's coupling: **C1, C2, C3 land together with P5b**, not as standalone patches.

The **isolated, independently-fixable** findings are **C4, C5, C6, C7, C8** (P7 quick wins, no P5b dependency).

## Remaining invariants to author (P1 cont., lower priority)
INV-VAULT-FEE (Echidna), INV-NONCE (Echidna), INV-MINT-ONCE (Echidna), INV-MINT-BIND (Halmos symbolic — formalizes C1), INV-DELAY-FLOOR, INV-PQ-ONCHAIN (P5b).
