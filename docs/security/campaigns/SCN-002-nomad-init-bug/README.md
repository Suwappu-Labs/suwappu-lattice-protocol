# SCN-002 — Nomad init-bug "any message valid"

**Status.** VERIFIED-GREEN (defenses hold; CI verifies).
**Layer.** 1 — Smart-contract input validation.
**Historical incident.** Nomad bridge, 1 Aug 2022, $190M.
**LTP-A-* link.** [LTP-A-003](../../../SECURITY_AUDIT_2026-05-15.md)
("Zero-hash anchor auto-trust" — INFO severity; the defenses below
already block the Nomad-class flow).

## What happened (Nomad)

In a routine upgrade, Nomad's `Replica.sol` `initialize()` set:

```solidity
confirmedRoots[bytes32(0)] = 1;
```

This made the **zero hash** a "confirmed root". `prove()`'s logic was:

```solidity
if (confirmedRoots[_root] == 0) return false;
```

Because the zero hash was now non-zero in the map, ANY message whose
computed root defaulted to `bytes32(0)` (which a crafted empty input
would produce) passed the check and was treated as pre-verified. The
fix: never pre-trust the sentinel.

Root primitive: **initializer set a default trust value that
effectively whitelisted any input matching the sentinel.**

## LTP analogue

LTP's `LTPAnchorRegistry._anchor()` rejects every zero-valued primary
input at the boundary:

| ID  | Defense | Source line | Revert error |
|-----|---------|-------------|---------------|
| Z1  | `anchorDigest != bytes32(0)` | `LTPAnchorRegistry.sol:524` | `ZeroDigest` |
| Z2  | `entityIdHash != bytes32(0)` | `:525, :230` | `ZeroEntityId` |
| Z3  | `merkleRoot != bytes32(0)` | `:526` | `ZeroMerkleRoot` |
| Z4  | `signerVkHash != bytes32(0)` | `:527, :231, :282` | `ZeroSignerVk` |
| Z5  | `policyHash == bytes32(0)` is BY-DESIGN sentinel ("no on-chain policy") — must NOT short-circuit other defenses | `:528` | n/a |
| Z6  | `initialize()` is `initializer`-modified on the proxy; `_disableInitializers()` on impl prevents re-init | `:97, :104` | OZ `InvalidInitialization` |
| Z7  | `_anchors[bytes32(0)].anchoredAt` is never written (no path stores under the zero digest) | structural | n/a |

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| Forge unit + fuzz | `contracts/test/security/historical/SCN_002_Nomad_InitBug.t.sol` | Z1-Z7 explicit + fuzz: any zero among the 4 primary inputs always reverts |
| Forge invariant | `contracts/test/security/historical/SCN_002_Nomad_InitBug.invariant.t.sol` | N1 zero-digest-never-anchored, N2 no-zero-primary-input-accepted |
| Echidna properties | `contracts/test/echidna/SCN_002_NomadEchidna.sol` | Q1/Q2 mirror N1/N2; inline `assert` on every accepted anchor |

## How to run

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_002_*' -vvv
cd contracts && echidna . --contract SCN_002_NomadEchidna --config echidna.yaml
```

## Findings opened

None expected. All defenses pre-exist.
