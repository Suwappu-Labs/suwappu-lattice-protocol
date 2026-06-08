# P2 — Automated analysis (status)

Tool: Slither (latest), full-project compile via forge (via_ir, solc 0.8.24), config `contracts/slither.config.json`. Raw output: `/tmp/slither.{out,err}` (committed excerpt below). Echidna/Medusa/Aderyn/Semgrep pending install.

## Result: 14 findings, **0 new criticals** beyond C1–C8

Slither confirms the surface the invariant/manual passes already mapped and surfaces no additional high-severity custody bug. Triage of the only two High-category hits:

| Slither finding | Location | Verdict |
|---|---|---|
| `_transfer` "sends eth to arbitrary user" | `SuwappuRefundEscrow.sol:351`, `SuwappuVault.sol:443` | **FALSE-POSITIVE (by-design).** Recipient is user-supplied but every caller is access-gated: vault `unlock` (onlyUnlocker), `claimRefund` (to `c.from` only), escrow `claim` (merkle-proof-gated), `emergencyWithdraw`/`sweep` (onlyAdmin). Slither cannot see the upstream gating. |
| Reentrancy in `ZKBridgeVerifier.verifyAndFinalize` | `ZKBridgeVerifier.sol:112-158` | **FALSE-POSITIVE for reentrancy.** CEI is correct: `verifiedProofs[proofId]=true` (line 152) is set *before* the external `challengeContract.finalizeWithZKProof` call (line 155). NOTE: the *access-control + digest-binding* defects on this same function are the real bug — tracked as **C3** (already RED-proven), not a reentrancy issue. |

Remaining 12 are informational/low: `dangerous-strict-equalities` (benign `== 0` balance guards in `sweepUnclaimed`/`_lock`/`sweepFees`), `block-timestamp` comparisons (expected for timeout logic), `missing-zero-address-validation` (`SuwappuWrappedToken.sourceToken_`), `missing-events`, `low-level-calls` (the guarded ETH `call`), `dead-code`, `unused-state-variable`. None change the risk picture.

## Takeaway
Static analysis adds no new findings — the custody-layer risk is dominated by the **business-logic / cross-domain trust** bugs (C1–C8) that static tools structurally cannot catch, which is exactly why the invariant harness (P1) and manual attack-class review (P3) are the load-bearing techniques here. This matches the bridge-audit literature: supply-invariant and trusted-relayer breaks are found by invariant fuzzing, not linting.

## Pending (P2 cont.)
Echidna/Medusa on the single-contract property harnesses (INV-VAULT-FEE, INV-NONCE, INV-MINT-ONCE), Semgrep smart-contract ruleset, SMTChecker (`solc --model-checker-engine chc`) per custody contract — once those binaries are installed (P0 remainder).
