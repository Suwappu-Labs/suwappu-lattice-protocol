# SCN-016 — Cypher Protocol pause bypass via upgrade

**Status.** VERIFIED-GREEN expected.
**Layer.** 4 — Governance.
**Historical incident.** Cypher Protocol, Aug 2023, ~\$1M.
**LTP-A-* link.** [LTP-A-018](../../internal/SECURITY_AUDIT_2026-05-15.md)
(pause has no timelock) + [LTP-A-009](../../internal/SECURITY_AUDIT_2026-05-15.md)
(production-Timelock delay floor).

## What happened (Cypher)

Cypher Protocol detected an exploit and paused the contract.
The attacker then triggered an upgrade path that the team had
not anticipated would survive the pause, and continued draining
post-pause. The loss was small in dollar terms (~\$1M) but the
pattern is illustrative: **a pause is only as strong as every
governance path that could lift it.**

Root primitive: **pause + upgrade are co-governing controls**.
If one can bypass the other, the pause is theater.

## LTP analogue

`LTPAnchorRegistry`:

- `pause()` and `unpause()` — both `onlyAdmin`
  (LTPAnchorRegistry.sol:137-146).
- `_authorizeUpgrade()` (UUPS hook) — also `onlyAdmin`
  (LTPAnchorRegistry.sol:153).
- The `paused` storage slot is inherited storage; UUPS upgrade
  preserves it across implementation swaps.

The defense is **same-gate co-control**: an attacker would
need admin to either pause or upgrade. In production, ADMIN
IS the `TimelockController`, which adds a 24h+ delay per
`DeployMainnet.s.sol:43-48` (SCN-019).

| ID | Defense | Source |
|----|---------|--------|
| U1 | `pause()` is `onlyAdmin` | LTPAnchorRegistry.sol:137 |
| U2 | `unpause()` is `onlyAdmin` | :143 |
| U3 | `_authorizeUpgrade()` is `onlyAdmin` (same gate as pause) | :153 |
| U4 | `paused` storage slot survives UUPS upgrade | structural (storage layout) |
| U5 | Attacker cannot use upgrade to bypass pause (combined) | U1+U3 |

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| Forge unit | `contracts/test/security/historical/SCN_016_PauseUpgradeBypass.t.sol` | U1, U2, U3, U4 (paused-survives-upgrade), U5 (combined) |

## How to run

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_016_*' -vvv
```

## Cross-references

- **SCN-003** (Poly Network keeper-escalation) — broader
  `onlyAdmin` privilege-boundary defenses
- **SCN-018** (Parity init protection) — sibling defense:
  `_disableInitializers` prevents init-on-impl
- **SCN-019** (Timelock-delay floor) — adds the 24h delay
  in production deployments

## Findings opened

None expected. Same-gate co-control pre-exists.
