# SCN-019 — Production-Timelock delay floor

**Status.** VERIFIED-GREEN expected.
**Layer.** 4 — Governance.
**Historical incident.** Cypher Protocol, Aug 2023, ~\$1M
(pause-bypass via near-zero-delay Timelock; sibling to SCN-016).
**LTP-A-* link.** [LTP-A-009](../../../SECURITY_AUDIT_2026-05-15.md)
(production-Timelock delay un-asserted).

## What happened (Cypher Protocol Timelock angle)

Cypher Protocol shipped with a near-zero-delay TimelockController.
When the team paused after detecting an exploit, the attacker
scheduled and immediately executed a malicious upgrade through
the Timelock — the delay was too short to give honest governance
a reaction window.

Root primitive: **the Timelock's minimum delay is the WHOLE
defense.** A near-zero delay turns the TimelockController into a
cosmetic wrapper around `call()`.

## LTP analogue

`contracts/script/DeployMainnet.s.sol:48` enforces:

```solidity
require(timelockDelay >= 24 hours,
        "mainnet requires timelock >= 24 hours");
```

The defense is at DEPLOY time — the OZ `TimelockController`
itself has no minimum (any positive uint256 is accepted). Like
SCN-009's deploy-policy Byzantine floor for the multisig
threshold, the protection lives in the deploy script.

| ID | Defense | Source |
|----|---------|--------|
| F1 | DeployMainnet rejects `timelockDelay < 24 hours` | DeployMainnet.s.sol:48 |
| F2 | (Documented boundary) OZ TimelockController itself accepts any non-negative delay — the deploy-policy floor IS the defense | TimelockController.sol (external dep) |

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| Forge unit + fuzz | `contracts/test/security/historical/SCN_019_TimelockFloor.t.sol` | F1×5 (boundary cases at 0 / 1 / below-24h / exactly-24h / 48h) + 2 fuzz (over below-floor and over above-floor ranges), F2×2 (OZ TimelockController accepts low delay — documents that the contract layer has no Byzantine floor; the deploy-policy floor IS the defense) |

The test uses the **SCN-009 wrapper pattern**: replicate the
`require(timelockDelay >= 24 hours)` predicate as a pure
Solidity helper and pin it via assertion + fuzz. Forge can't
`vm.envUint` arbitrary deploy-script paths in a unit test, but
the predicate IS the defense, and pinning the predicate is
sufficient.

## How to run

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_019_*' -vvv
```

## Cross-references

- **SCN-009** (Harmony low-threshold) — same deploy-policy
  pattern for the multisig Byzantine floor
- **SCN-016** (Cypher pause-bypass) — sibling Cypher defense at
  the contract layer
- **OPERATOR_RUNBOOK §13** — production deploy checklist that
  enforces this floor

## Findings opened

None. Deploy-policy floor pre-exists.
