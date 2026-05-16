# SCN-004 — Orbit Chain multisig threshold subversion

**Status.** VERIFIED-GREEN (defenses hold; CI verifies).
**Layer.** 1 — Smart-contract input validation / access control.
**Historical incident.** Orbit Bridge, 1 Jan 2024, ~$82M.
**LTP-A-* link.** [LTP-A-002 / LTP-A-008](../../../SECURITY_AUDIT_2026-05-15.md).

## What happened (Orbit Chain)

Orbit Bridge ran a 7-of-10 validator multisig on its Klaytn ↔
Ethereum bridge contract. Public reports indicate that:

1. A subset of validator keys were compromised over time.
2. Combined with weak verification on stored validator signatures
   (specifics disputed in public sources), the attacker assembled
   enough valid signatures to authorize a withdrawal of ~$82M.

Root primitive: **advertised N-of-M multisig threshold collapses
when M-effective (the number of distinct, secure, uncompromised
keys) falls below N.** The bug surface is "anything that lets a
sub-threshold quorum execute" — key reuse across chains, weak
signature storage, fake validator additions, or simple key
compromise.

## LTP analogue

LTP's governance multisig `LTPMultiSig` is the gate to the Registry's
admin role. The Orbit-equivalent claim is **"no transaction executes
unless `confirmations >= threshold`, and that threshold (and owner
set) can only change via a multisig-confirmed `changeThreshold` /
`addOwner` / `removeOwner` call."**

| ID  | Defense | Source line | Revert error |
|-----|---------|-------------|---------------|
| M1  | `executeTransaction` requires `confirmations >= threshold` | LTPMultiSig.sol:168 | `InsufficientConfirmations` |
| M2  | `onlyOwner` gates submit / confirm / revoke / execute | :88, :113, :134, :144, :161 | `NotOwner` |
| M3  | `addOwner`, `removeOwner`, `changeThreshold` are `onlySelf` (callable only via the multisig itself) | :185, :194, :218 | `OnlySelf` |
| M4  | Constructor rejects `threshold == 0` or `threshold > owners.length` | :67-69 | `InvalidThreshold` |
| M5  | Double-confirmation rejected | :249 | `TxAlreadyConfirmed` |
| M6  | `revokeConfirmation` lowers the count; replaying execute reverts | structural + M1 | `InsufficientConfirmations` |

## Note on deploy-script threshold (LTP-A-002 FIXED-IN-SOURCE)

`LTPMultiSig` itself supports arbitrary `(owners, threshold)`. The
LTP-A-002 audit-finding called out the **deploy script's default**
of 2-of-2, which is too low for mainnet. The fix is in
`DeployMainnet.s.sol`. This scenario does not re-test the deploy
script — it confirms the contract's defenses hold regardless of
how it's parameterized.

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| Forge unit + fuzz | `contracts/test/security/historical/SCN_004_Orbit_MultisigSubversion.t.sol` | M1-M6 explicit (11 tests) + property fuzz over arbitrary non-owner callers |
| Forge invariant | `contracts/test/security/historical/SCN_004_Orbit_MultisigSubversion.invariant.t.sol` | T1 no-execute-below-threshold, T2 threshold-stable, T3 owner-set-stable |
| Echidna properties | `contracts/test/echidna/SCN_004_OrbitEchidna.sol` | S1 threshold-never-drifts, S2 owner-set-stable; inline `assert(false)` on every successful attacker call |

## How to run

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_004_*' -vvv
cd contracts && echidna . --contract SCN_004_OrbitEchidna --config echidna.yaml
```

## Findings opened

None expected. Threshold + ownership gates pre-exist.
