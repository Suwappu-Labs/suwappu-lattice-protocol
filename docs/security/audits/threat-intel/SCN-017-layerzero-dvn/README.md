# SCN-017 — LayerZero DVN-count downgrade

**Status.** VERIFIED-GREEN expected.
**Layer.** 4 — Governance.
**Historical pattern.** LayerZero / Stargate "DVN downgrade" debate, early 2024.
**LTP-A-* link.** [LTP-A-006](../../internal/SECURITY_AUDIT_2026-05-15.md)
(admin-monopoly challenge resolver — Option E independent
arbiter + time-decay paths).

## What happened (LayerZero / Stargate debate)

In early 2024 the LayerZero community debated whether Stargate
integrators could reduce their DVN (Decentralized Verifier
Network) configuration to a single DVN for cost / UX reasons.
The structural risk: **any governance path that lets an operator
silently reduce the independent-verifier count is a path that
degrades the trust model.**

No specific exploit shipped here — the debate was prospective —
but the class is shared with several real incidents where a
verifier-set governance path proved too permissive (Multichain
operator-only signing, several "rugged" bridges that quietly
re-pointed to attacker-controlled validators).

## LTP analogue

`OptimisticBridgeChallenge` (LTP-A-006 Option E) explicitly uses
**three independent resolution paths**:

| Path | Function | Gate | Source |
|------|----------|------|--------|
| A | `resolveChallenge` | onlyAdmin | OptimisticBridgeChallenge.sol:197 |
| B | `resolveChallengeByArbiter` | only `arbiter` (NOT admin) | :300-304 |
| C | `resolveByTimeDecay` | anyone after grace period | :328-345 |

The path-separation defense: even if EITHER admin OR arbiter is
compromised, the bridge has a working resolution path. Plus, if
both keys are compromised but the attackers hold them
passively (do-nothing), the time-decay path lets any caller
finalize after grace.

| ID | Defense | Source |
|----|---------|--------|
| D1 | `setArbiter` rejects `arbiter == admin` | OptimisticBridgeChallenge.sol:282 |
| D2 | `setArbiter` is `onlyAdmin` | :281 |
| D3 | `setZKVerifier` is `onlyAdmin` | :357 |
| D4 | `setResolutionGracePeriod` enforces 24h floor (cannot shrink path C to a no-op) | :288-294 |
| D5 | `resolveChallengeByArbiter` rejects admin and other callers (path separation enforced) | :304 |
| D6 | `resolveByTimeDecay` requires grace period elapsed | :332-335 |

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| Forge unit | `contracts/test/security/historical/SCN_017_LayerZero_DVN.t.sol` | D1×2 (admin-as-arbiter rejected; rejection persists after first arbiter set), D2, D3, D4×3 (below-floor / at-floor / non-admin), D5×2 (admin and attacker both rejected from arbiter path), D6×2 (before-grace reverts; after-grace succeeds) |

## How to run

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_017_*' -vvv
```

## Cross-references

- **SCN-003** (Poly Network keeper-escalation) — broader
  `onlyAdmin` privilege-boundary defenses
- **SCN-004** (Orbit multisig subversion) — threshold-of-signers
- **SCN-016** (Cypher pause-bypass) — sibling governance defense

## Findings opened

None expected. Path-separation + verifier-set governance
defenses pre-exist as LTP-A-006 Option E.
