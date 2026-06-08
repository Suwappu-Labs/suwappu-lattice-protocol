# Suwappu Bridge — Go/No-Go Gate (P8)

Date: 2026-06-07. Evaluated against the criteria in the audit plan. **Overall: NO-GO for
mainnet funds.** Several gate criteria fail; the bridge is not ready to hold real value.

## Mainnet-deploy gate

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | All confirmed criticals/highs fixed with revert-fails regressions | ✅ **PASS (code)** | **ALL code findings FIXED + green**: C1-C9 + P3-1..P3-7. On-chain attestation/PQ wiring (mint+refund gates, ML-DSA verifier), ZK authorize+bind, minter-role separation, release cap + guardian pause, token allowlist. INV-SUPPLY/INV-XOR green over 400×80 with revert-fails. *(Independent audit of these fixes still required — criterion 6.)* |
| 2 | Every authored invariant green over ≥3 runs | ⚠️ PARTIAL | `SuwappuSupply` (INV-SUPPLY, INV-XOR) now **GREEN** (400 runs × depth 80) after C1/C2 fixes; challenge invariants 5/5. Remaining invariants (INV-FOT/ESCROW/etc.) covered by unit tests. |
| 3 | Slither high=0 AND blocking in CI | ⚠️ PARTIAL | Slither high=0 (14 findings, 0 real criticals — P2). NOT yet made blocking in CI. |
| 4 | `make contracts-secaudit` green incl. Echidna on workspace CI | ❌ **FAIL** | Suite is **RED at baseline** on `feat/v7-testnet-upgrade` (P4): LTPMultiSig constructor-revert deprecation broke SCN_004/008/009 + the LTPAnchorRegistry multisig harness; Echidna not yet wired in. |
| 5 | `SuwappuWrappedToken` has a unit test file | ✅ **PASS** | `test/SuwappuWrappedToken.t.sol` added: 21 tests green (incl. fuzz supply conservation). Covers constructor guards, the **P3-3 privilege separation** (DEFAULT_ADMIN cannot grant MINTER/BURNER/MINTER_ADMIN — escalation reverts), mint/burn role gating + zero-guards, minter rotation, and ERC-20 transfer/approve. |
| 6 | Independent (non-self) professional audit + funded bug bounty live | ❌ **FAIL (hard)** | Not engaged. Non-negotiable before real funds — the relayer-trust model is the Ronin/Wormhole bug class and cannot be cleared by internal/agent audit alone. |
| 7 | PQ-claim statement reviewed; no public bridge-level PQ claim | ✅/pending | Layered claim statement drafted (P5). Must be enforced in all public material. |

## Bridge-level PQ claim gate (separate)
BLOCKED until: (a) on-chain ML-DSA-65 gates every mint/unlock/finalize (INV-PQ-ONCHAIN green +
revert-fails); (b) the precompile + verifier pass P1-P3/P7; (c) ZK mode is PQ-safe or labelled
non-PQ; (d) front end (P6) no longer shows mock proof hashes. **Currently: Phase-1 precompile
core built+verified; wiring + Phases 2/3 outstanding → claim NOT yet permitted.**

## What IS done (credit where due)
- 8 confirmed findings (C1-C9) each have deterministic RED proofs (P1).
- 5 isolated criticals/highs FIXED with revert-fails discipline (C4-C8, P7).
- Real tooling stood up + Slither clean of new criticals (P0/P2).
- Prior self-audit independently re-verified; surfaced that its regression suite is broken at
  baseline (P4) — a finding in itself.
- On-chain PQ verifier Phase-1 core built + verified (P5b).
- PQ claim narrowed to a defensible layered statement (P5).
- Front end identified as non-functional mock that must not ship as a live bridge (P6).

## Top blocking actions before any mainnet funds
1. Land the on-chain ML-DSA verification and wire it into mint/unlock/finalize → fixes C1/C2/C3;
   make INV-SUPPLY/INV-XOR/INV-PQ-ONCHAIN green with revert-fails.
2. **Fix the P3 criticals/highs:** P3-1 (require operatorVkHash ∈ authorized set in
   verifyAndFinalize); P3-3 (token DEFAULT_ADMIN_ROLE → Timelock, freeze MINTER_ROLE admin);
   P3-5 (bind destChainId==block.chainid into commitId — folds into the C1 recompute fix);
   P3-4 (daily release cap + guardian-pause + M-of-N unlocker). Add P3-7 token allowlist.
3. Repair the baseline-RED security suite (migrate SCN_004/008/009 + registry tests off the
   deprecated LTPMultiSig) so `contracts-secaudit` can actually gate.
4. ~~Add `SuwappuWrappedToken` unit tests~~ ✅ done (`test/SuwappuWrappedToken.t.sol`, 21 tests); make Slither blocking; wire Echidna into secaudit.
5. Engage an independent professional audit + launch a funded bug bounty.
6. Resolve the front end (label as sim or wire to real contracts; no fabricated proofs).
