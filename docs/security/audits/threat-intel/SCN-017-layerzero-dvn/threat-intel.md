# SCN-017 — Threat intelligence sources

This scenario covers a **structural class** rather than a single
named exploit — the "verifier-set governance downgrade" pattern.

## Adjacent / canonical incidents

- **LayerZero / Stargate DVN-count debate** (early 2024) —
  community discussion about reducing DVN set size for cost/UX.
  No exploit shipped; structural risk surfaced.
- **Multichain (Jul 2023, ~\$125M)** — operator-only signing
  set; verifier-set governance was effectively 1-of-1 from
  the start (SCN-012).
- **Various "rug" bridges** — silent re-pointing of validator
  set to attacker addresses via a governance call.

## Primary sources

- **LayerZero / Stargate community fora** (Discord / GitHub
  discussions) — the DVN debate is community-record.
- **Vitalik Buterin's "anti-correlated signers" blog** — covers
  the broader principle of verifier-set independence.

## Secondary technical analyses

- **L2Beat** — risk framework for bridge verifier-set
  governance.
- **Halborn / Trail of Bits** retrospectives on bridges with
  governance paths to reduce verifier counts.

## Root primitive

A verifier-set governance path that lets an operator (or
compromised admin) silently reduce the number of independent
verifiers below the trust-model threshold. The defense is
**path-separation enforced at the contract layer**: distinct
roles, no single party able to lift all checks.

## Mapping to LTP

LTP's OptimisticBridgeChallenge implements **three independent
resolution paths** (LTP-A-006 Option E):
- Admin path (resolveChallenge)
- Independent-arbiter path (resolveChallengeByArbiter)
- Time-decay path (resolveByTimeDecay)

The `setArbiter` setter explicitly rejects `arbiter == admin`
(line 282), enforcing path-separation at configuration time. The
grace-period setter has a 24h floor (line 289) preventing
shrinkage of the time-decay safety net.

## Date of last verification

2026-05-17 — SCN-017 added under R-3.
