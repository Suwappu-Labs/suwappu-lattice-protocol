# Suwappu Bridge — Security Audit Report

Date: 2026-06-07 · Scope: `gsx-lattice-protocol/contracts/src` (custody + verification, ~3,600 LOC)
+ `suwappu-bridge` (Next.js front end) · Method: standards-grounded program (OWASP SCSVS v2 /
EEA EthTrust SL v2 / OWASP SC Top 10 2026 / Trail-of-Bits phased), real tooling, invariant-driven,
with adversarial multi-agent review and independent re-verification.

> **This is an internal/agent audit. It is NOT a substitute for an independent professional audit
> + funded bug bounty, both of which are hard preconditions before holding real funds.**

## Verdict: 🔴 NO-GO for mainnet funds

The custody layer holds funds on a **trusted-relayer model with no on-chain proof that a source
lock occurred**, and review surfaced multiple ways to mint unbacked supply or drain collateral.
Five findings are fixed; the highest-impact ones are not. See `GATE.md` for the criteria table.

## Findings register

Severity = realistic impact. "Proof" = how it's substantiated (forge invariant / forge unit /
code-evident). All RED tests live in `contracts/test/{invariant,security}/Suwappu*`.

| ID | Sev | Title | Status | Proof |
|---|---|---|---|---|
| C1 | 🔴 Crit | `MintAdapter.mint` never binds commitId → relayer mints arbitrary unbacked tokens | **OPEN** (needs on-chain PQ) | INV-SUPPLY (RED) |
| C2 | 🔴 Crit | Refund/unlock-vs-mint cross-domain double-spend | **OPEN** (needs on-chain PQ) | INV-XOR (RED) |
| C3 | 🟠 High | ZK `verifyAndFinalize`: no access control + anchorDigest unbound | **OPEN** | forge unit (RED) |
| P3-1 | 🔴 Crit | ZK verifier never checks `operatorVkHash` ∈ authorized set (self-signed proof finalizes) | **OPEN** | code-evident |
| P3-3 | 🔴 Crit | WrappedToken `DEFAULT_ADMIN_ROLE` = parallel unconstrained minter | **OPEN** | forge unit ✓ |
| P3-5 | 🟠 High | One lock → N mints across adapter instances | **OPEN** | forge unit ✓ |
| P3-4 | 🟠 High | No rate-limit/ceiling/threshold on `unlock`/`mint` (1 key drains TVL) | **OPEN** | code-evident |
| C4 | 🟠 High | `_verifySP1` accepts code-less verifier | **FIXED** | revert-fails ✓ |
| C5 | 🟡 Med | Vault FOT under-collateralization (inbound) | **FIXED** | revert-fails ✓ |
| C6 | 🟡 Med | Escrow `sweepUnclaimed` cross-round drain | **FIXED** | forge unit ✓ |
| C7 | 🟡 Med | Escrow claim not keyed by token | **FIXED** | forge unit ✓ |
| C8 | 🟡 Med | Guardian selector not bound to target | **FIXED** | forge unit ✓ |
| P3-7 | 🟡 Med | Rebasing-token post-lock solvency drift | OPEN | code-evident |
| P3-2, P3-6 | 🔵 Low | sp1ProgramVKey zero-default; ZK proofId omits chainId/addr | OPEN | code-evident |
| C9/FE1 | 🚨 Prod | Front end 100% mock, displays fabricated proofs as real | OPEN | P6 |

**Open: 4 critical, 3 high, 1 medium + lows + the product risk. Fixed: 5 (C4–C8).**

## Root cause (the one thing)
Every critical reduces to: **the bridge has no trust-minimized, on-chain binding between
source-lock state, destination-mint state, and a verified operator/proof.** Mint/unlock/finalize
trust a relayer/unlocker/operator set with no on-chain check that the claimed event happened or
that the signer is authorized. This is the Ronin/Wormhole bug class — not fully reducible to an
on-chain invariant, which is precisely why an independent audit + bounty are mandatory.

## What was done well (defenses confirmed)
- Reentrancy: all payout paths `nonReentrant` + CEI; no ERC-777 hooks (P3 clean).
- No delegatecall/selector storage-hijack surface; C8 (target,selector) binding sound (P3 clean).
- Two-step admin transfer on Vault/MintAdapter/Escrow; OZ Timelock with per-selector delays.
- The optimistic-challenge bond machinery's invariants (I1–I6) pass.

## Phase artifacts
`P0_TOOLING` · `P1_INVARIANTS` · `P2_AUTOMATED` · `P3_MANUAL` · `P4_REVERIFY` · `P5_PQ_CLAIM` ·
`P5b_ONCHAIN_PQ` · `P6_FRONTEND` · `GATE`. Also: the prior self-audit's regression suite is
**RED at baseline** (P4) — `contracts-secaudit` cannot currently gate anything until repaired.

## Post-quantum claim
On-chain custody/finalization is **not** PQ today (LTP-A-001 by-design; ZK mode is Shor-broken
Groth16/BLS12-381). The defensible public statement is the **layered** one in `P5_PQ_CLAIM.md`.
The on-chain ML-DSA verifier (P5b) Phase-1 core is built + verified (`suwappu-mldsa-precompile`,
8/8); wiring it in is what closes C1/C2/C3 and unlocks a true bridge-level PQ claim.

## Prioritized remediation (before any mainnet funds)
See `GATE.md` "Top blocking actions". In short: land on-chain ML-DSA verification + wire to
mint/unlock/finalize (closes C1/C2/C3/P3-1/P3-5); lock down token admin (P3-3); add release
rate-limits + pause (P3-4); token allowlist (P3-7); repair the baseline-RED test suite; add
WrappedToken tests; make Slither blocking + wire Echidna; **engage an independent audit + bounty**;
fix the front end. Do not deploy with real funds until these land.
