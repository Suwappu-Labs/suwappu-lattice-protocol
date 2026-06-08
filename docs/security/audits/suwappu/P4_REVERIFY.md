# P4 — Prior-audit re-verification (status)

> **Scope banner.** All findings below are LTP/ETP/governance/HSM items from the
> self-produced `docs/security/audits/internal/SECURITY_AUDIT_2026-05-15.md`.
> The Suwappu custody contracts that hold user funds were **never** in that
> audit; their risk is owned by P1–P3/P7, not this matrix. Re-verification here
> confirms whether each claimed fix is *present in source* and whether its
> *regression test actually runs and passes* on the current branch
> (`feat/v7-testnet-upgrade`).

## Source-presence + regression status

| Finding | Source present? | Regression test | Status |
|---|---|---|---|
| LTP-A-031 (`_anchor` checks `signerExpiresAt`) | ✅ `LTPAnchorRegistry.sol:545` | `SCN_015_SignerRotationGrace.t.sol` | **GREEN 8/8** — genuinely re-verified |
| LTP-A-007 (MODE_SIMULATED rejected in prod) | ✅ `ZKBridgeVerifier.sol:127` | `ZKBridgeVerifier.t.sol` (partial) | source ok; suite RED at baseline (see below) |
| LTP-A-006 (5 independent resolution paths) | ✅ all 5 fns in `OptimisticBridgeChallenge.sol` (197/301/329/368/404) | `OptimisticBridgeChallenge.invariant.t.sol` | **GREEN 5/5** invariants (I1–I6), incl. arbiter/fraud gating |
| LTP-A-016/019 (timelock floor, pause bypass) | ✅ | `SCN_016`, `SCN_019` | **GREEN** (5/5, 9/9) |
| LTP-A-002 (gov threshold; Ronin/Harmony) | partial | `SCN_008`, `SCN_009` | **🔴 REGRESSION TESTS CANNOT RUN — see finding below** |
| LTP-A-008 (cross-chain replay; Orbit) | ✅ chainid stamping | `SCN_004` | **🔴 test suite cannot run — same cause** |

## P4 FINDING — Deprecating `LTPMultiSig` via constructor-revert silently disabled security regression suites

`LTPMultiSig` was deprecated by making its constructor unconditionally
`revert("LTPMultiSig: DEPRECATED…")` (`src/LTPMultiSig.sol:80`). But **7 test
files still deploy `new LTPMultiSig(...)`** in `setUp()` / test bodies, so they
now revert before exercising any assertion:

- `test/security/historical/SCN_008_Ronin_ActiveSetCollapse.t.sol` — **fully dead** (setUp reverts). This is the **LTP-A-002 governance-threshold regression** — there is now **no working proof** of the Ronin-class defense on this branch.
- `test/security/historical/SCN_009_Harmony_LowThreshold.t.sol` — 5/9 dead (the H1/H3 threshold tests). Also LTP-A-002.
- `test/security/historical/SCN_004_Orbit_MultisigSubversion.t.sol` (+ its invariant + echidna) — dead. This is the **LTP-A-008 replay** regression.
- `test/LTPAnchorRegistry.t.sol` — a secondary multisig-integration contract in the file reverts (the core `LTPAnchorRegistryTest`, 48 tests, still passes).
- `test/L2ForkTest.t.sol` — fork path.

**Impact:** The audit's posture that LTP-A-002 and LTP-A-008 are validated is **overstated on this branch** — their executable regressions don't run. This is the same class of problem found in P7 (`ZKBridgeVerifier.t.sol` stale STARK/admin/SP1 tests): the v7 branch is mid-refactor and the security suite is RED at baseline, contradicting the CLAUDE.md hard rule "`make contracts-secaudit` must be green."

**Remediation (tracked for P7/P8):** migrate the 7 affected test files off `LTPMultiSig` onto the Gnosis-Safe / `SuwappuTimelockController` harness (or a non-reverting mock) so the LTP-A-002 / LTP-A-008 regressions execute again. Until then, **gate criterion 4 (secaudit green) FAILS at baseline** and these two findings are effectively unverified.

## Genuinely re-verified (GREEN)
LTP-A-031, LTP-A-006, LTP-A-016, LTP-A-019 — source present AND regression green.

## Not yet revert-tested
The plan's "revert the fix → confirm RED" step was run for our own P7 fixes (C5
demonstrated). For the prior-audit fixes, revert-testing is pending for the
GREEN ones (LTP-A-031/006); deferred because the higher-priority finding is that
LTP-A-002/008 regressions don't run at all.
