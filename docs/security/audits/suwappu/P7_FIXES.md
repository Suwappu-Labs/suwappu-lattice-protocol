# P7 — Fixes + revert-fails regressions (status)

Each fix maps to a secure-property test that was RED before and GREEN after; reverting the fix returns it to RED.

## Landed — 5 isolated fixes, all RED → GREEN, zero regressions

| # | Fix | File | Test before → after |
|---|---|---|---|
| C4 | Reject code-less `sp1Verifier` (`code.length==0` revert) AND treat empty staticcall returndata as `false` not `true` | `src/ZKBridgeVerifier.sol` `_verifySP1` | `test_C4_...` RED → **GREEN** |
| C5 | Credit the **received balance delta**, not requested `amount`, on `lockERC20` (FOT safety) | `src/SuwappuVault.sol` `lockERC20` | `test_C5_...` RED → **GREEN** |
| C6 | `sweepUnclaimed` gated on `latestClosesAt` — cannot sweep while ANY round's window is open (shared pool) | `src/SuwappuRefundEscrow.sol` | `test_C6_...` RED → **GREEN** |
| C7 | `claimed` keyed by `(roundId, claimant, token)` — multi-token entitlement no longer blocked after first claim | `src/SuwappuRefundEscrow.sol` | `test_C7_...` RED → **GREEN** |
| C8 | `emergencySelectors` keyed by `(target, selector)` — guardian can't invoke a whitelisted selector on an unintended target (Poly-class) | `src/SuwappuTimelockController.sol` | `test_C8_...` RED → **GREEN** |

Interface changes (C7/C8) rippled into existing unit tests, updated in lockstep:
`SuwappuRefundEscrow.t.sol` (`claimed(rid,alice)`→`claimed(rid,alice,token)`) 19/19 green; `SuwappuTimelockController.t.sol` (`setEmergencySelector(sel,bool)`→`setEmergencySelector(target,sel,bool)`) 21/21 green; `SuwappuVault.t.sol` 25/25 green.

**Revert-fails proof demonstrated (C5):** RED → fix → GREEN → revert the one-line change → RED again (`100e18 > 98e18`) → restore → GREEN. This is the audit-the-auditor discipline applied to our own fixes; the same revert-RED check goes into CI for each.

## Important finding surfaced during P7 (belongs in P4/P8)

**The contract test suite is already RED on `feat/v7-testnet-upgrade`**, independent of any audit change. Pre-existing failures in `ZKBridgeVerifier.t.sol`: all `test_stark_*` (revert `STARKModeDisabled` — STARK was permanently disabled but tests not updated), `test_zkVerifier_adminCanCall` (`Unauthorized` — admin caller removed per LTP-A-001 but test not updated), and the SP1 mode tests (verifier not configured). This contradicts the CLAUDE.md hard rule "`make contracts-secaudit` must be green" and the audit's posture that v7 fixes are validated — the branch is mid-development with stale tests. **Gate criterion 4 (secaudit green on CI) currently FAILS at baseline.** These stale tests must be updated/removed before the suite can gate anything.

## Deferred — coupled to P5b (do NOT patch in isolation)
- **C1** (relayer arbitrary mint), **C2** (refund/unlock-vs-mint double-spend), **C3** (anchorDigest binding + access control). As documented in P1_INVARIANTS.md, the sound fix requires on-chain verification that the source-chain lock actually happened — i.e., the P5b on-chain ML-DSA/anchor verification wired into `mint`/`unlock`/`finalize`. A field-recompute band-aid adds no security (still relayer-trusted). These land with P5b.

## Pending — small interface changes (test ripple to existing unit suites)
- **C6** (escrow cross-round drain): add per-round closing tracking; `sweepUnclaimed` must not touch funds owed to still-open rounds (e.g. require all rounds closed via a tracked `latestClosesAt`). Requires adjusting the C6 test to model a still-open round and updating `SuwappuRefundEscrow.t.sol`.
- **C7** (escrow multi-token under-claim): key `claimed` by `(roundId, claimant, token)` instead of `(roundId, claimant)`.
- **C8** (guardian target confusion): bind `emergencySelectors` to `(target, selector)` pairs; update `setEmergencySelector(target, selector, enabled)` signature and `SuwappuTimelockController.t.sol`.
