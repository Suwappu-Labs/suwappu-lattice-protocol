# SCN-001 — Wormhole signature-verification skip

**Status.** VERIFIED-GREEN (defense holds).
**Layer.** 1 — Smart-contract input validation.
**Historical incident.** Wormhole bridge, 2 Feb 2022, $326M.
**LTP-A-* link.** [LTP-A-001](../../../SECURITY_AUDIT_2026-05-15.md#ltp-a-001--on-chain-anchoring-trusts-off-chain-bls-verification-wormhole-class)
(BY-DESIGN). The on-chain defense compensates for the deliberate
no-on-chain-ML-DSA-verification design.

## What happened (Wormhole)

The Wormhole Token Bridge on Solana accepted "verify signatures" calls
that referenced a `sysvar instructions` account but did not validate
that the supplied account was the real sysvar. The attacker supplied a
counterfeit instructions account whose data was crafted to look like a
prior `verify_signatures` instruction had run. With the spoofed
verification signal in place, the attacker called
`complete_native_with_payload` and minted 120,000 wETH on Solana
without holding the corresponding ETH, then bridged $326M out before
the team patched.

Root primitive: **the program trusted an input that it should have
been deriving or validating itself**.

## LTP analogue

`LTPAnchorRegistry.anchor()` (and `batchAnchor`, `anchorWithBinding`)
performs **no on-chain ML-DSA verification** by design. The contract
header at `contracts/src/LTPAnchorRegistry.sol:13` calls this out
explicitly: "Thin on-chain, thick off-chain." The off-chain relayer
verifies the entity owner's signature; the on-chain contract trusts
that the caller passed pre-verified input.

This is the same architectural shape as the Wormhole bug — except
LTP makes the choice explicit and pairs it with on-chain access
gating. The defenses that compensate:

| ID  | Defense | Source line | Revert error |
|-----|---------|-------------|---------------|
| D1  | `authorizedSigners[signerVkHash]` must be true | `LTPAnchorRegistry.sol:536-538` | `UnauthorizedSigner` |
| D2  | Signer expiry (LTP-A-030 grace period) not elapsed | `:239-242` | `UnauthorizedSigner` |
| D3  | `_anchors[anchorDigest].anchoredAt == 0` | `:531-533` | `AlreadyAnchored` |
| D4  | Entity-signer binding (first-write-wins) | `:540-549` | `NotEntitySigner` |
| D5  | Sequence monotonicity | `:551-555` | `SequenceTooLow` |
| D6  | Temporal expiry `block.timestamp < validUntil` | `:557-560` | `Expired` |
| D7  | State-machine `_isValidTransition` | `:562-567` | `InvalidStateTransition` |
| D8  | `targetChainId` stamped from `block.chainid` | `:577` | (no revert; storage-time invariant) |
| D9  | `whenNotPaused` | `:169, 192, 228` | `ContractPaused` |

## What this scenario verifies

A red-team replay of the Wormhole pattern against LTP cannot land an
anchor unless every defense above holds. The test pack pins each
defense and a property-level fuzz/invariant claim.

## Test pack

| Test type | Path | What it asserts |
|---|---|---|
| Forge unit + fuzz | `contracts/test/security/historical/SCN_001_Wormhole_AnchorRegistry.t.sol` | D1, D3, D4, D5, D6, D8, D9 each revert on the expected input; fuzz layer asserts no unauthorized-VK path lands an anchor |
| Forge invariant | `contracts/test/security/historical/SCN_001_Wormhole_AnchorRegistry.invariant.t.sol` | I1 no-unauthorized-anchor; I2 chain-id-stamp; I3 sequence-monotone — across handler-bounded stateful sequences |
| Echidna properties | `contracts/test/echidna/SCN_001_WormholeEchidna.sol` | P1/P2/P3 mirror I1/I2/I3 in Echidna's assertion + view-property modes |

## How to run

```bash
# Unit + fuzz + invariant (all forge):
cd contracts && forge test --match-path 'test/security/historical/SCN_001_*' -vvv

# Echidna (requires `brew install echidna` or trailofbits/echidna container):
cd contracts && echidna . --contract SCN_001_WormholeEchidna --config echidna.yaml
```

## Evidence

See [`test-evidence.md`](test-evidence.md) for commit refs and CI run
URLs. See [`threat-intel.md`](threat-intel.md) for the historical
sources cited.

## Findings opened

None. All defenses held on first run; no new LTP-A-* finding
required.
