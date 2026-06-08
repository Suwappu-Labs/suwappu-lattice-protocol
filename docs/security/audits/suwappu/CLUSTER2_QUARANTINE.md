# Cluster-2 Quarantine — LTPMultiSig-dependent test suites

**Date:** 2026-06-08. **Status:** quarantined (skipped), tracked for re-targeting.

## Why

`LTPMultiSig` was **deprecated in C6** (commit `313fa74`) — its constructor now
`revert`s with *"LTPMultiSig: DEPRECATED. Deploy Gnosis Safe 1.4.1 for production."*
Production governance moved to **Gnosis Safe 1.4.1 + TimelockController**. The
contract's own NatSpec documents two critical defects (1-of-N auto-confirm+execute,
no execution timelock), so it is genuinely unsafe and ships nowhere.

Every test that does `new LTPMultiSig(...)` therefore reverts at `setUp`, leaving
`make contracts-secaudit` **RED at baseline** — the gate couldn't run.

## Decision (advisor-backed)

These suites are **skipped via `vm.skip(true)`**, not revived against the dead
contract. Reviving them green would make CI assert *production multisig
attack-resistance* for a contract that is deprecated and unsafe — a hollow green
that reads as coverage it isn't. Skipping is honest: a skipped test makes no
claim. Each carries an inline comment pointing here.

## Quarantined suites

| Suite | File | Class | Subject |
|---|---|---|---|
| `SCN004_Orbit_MultisigSubversion` | `test/security/historical/SCN_004_Orbit_MultisigSubversion.t.sol` | **subject** | Orbit-hack multisig subversion |
| `SCN004_Invariant` | `test/security/historical/SCN_004_Orbit_MultisigSubversion.invariant.t.sol` | **subject** | Orbit invariant |
| `SCN008_Ronin_ActiveSetCollapse` | `test/security/historical/SCN_008_Ronin_ActiveSetCollapse.t.sol` | **subject** | Ronin-hack active-set/threshold collapse |
| `SCN009_Harmony_LowThreshold` | `test/security/historical/SCN_009_Harmony_LowThreshold.t.sol` | **subject** | Harmony-hack low threshold |
| `MultiSigTest` | `test/LTPAnchorRegistry.t.sol` | **subject** | LTPMultiSig behaviour directly |
| `MultiSigErrorReportTest` | `test/LTPAnchorRegistry.t.sol` | **subject** | LTPMultiSig error reporting |
| `TimelockGovernanceTest` | `test/LTPAnchorRegistry.t.sol` | incidental | registry timelock governance (multisig is the proposer scaffold) |

Also: `test/echidna/SCN_004_OrbitEchidna.sol` instantiates `LTPMultiSig` — it is not
run by `forge test` (Echidna is not yet wired into secaudit) but must be re-targeted
with the rest.

`test/L2ForkTest.t.sol` is **not** quarantined here — it already self-skips when
`BASE_SEPOLIA_RPC_URL` is unset.

## Restore path (tracked, not done here)

1. **Subject suites** (SCN_004/008/009, `MultiSig*`): re-target a live **Gnosis Safe
   1.4.1** deployment (or a faithful Safe test harness) and re-encode the
   Orbit/Ronin/Harmony attacks against it. That is the only thing that legitimately
   restores *production* multisig attack-resistance coverage.
2. **Incidental** (`TimelockGovernanceTest`, the echidna harness): the multisig is
   only a proposer/admin scaffold — re-point to the Safe (or a minimal mock
   threshold-multisig) so the registry/timelock coverage returns without claiming
   to test LTPMultiSig.

Until then these scenarios are **uncovered**; do not read the green secaudit run as
covering them.
