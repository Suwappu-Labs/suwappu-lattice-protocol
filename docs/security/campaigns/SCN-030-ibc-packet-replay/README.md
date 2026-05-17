# SCN-030 — Cosmos IBC-class packet replay

**Status.** VERIFIED-GREEN via existing replay-rejection defenses.
**Layer.** 7 — Off-chain infrastructure (cross-chain message replay).
**Historical pattern.** Theoretical class — Cosmos IBC has a
documented packet-replay risk that the protocol's
sequence-number plus commitment design rejects. The class also
applies to bridge contracts that don't maintain a per-message
identifier.
**LTP-A-* link.** [LTP-A-008](../../../SECURITY_AUDIT_2026-05-15.md)
(cross-chain anchor replay — INFO severity, defenses pre-existed).

## What happens in this class

A cross-chain message handler accepts a (signature, payload)
pair and processes it. The attacker:

1. Observes a legitimate cross-chain message.
2. Replays the same (signature, payload) — either on the same
   chain or on a different chain — to trigger the action a
   second time.

Defenses:

1. **Per-message identifier replay rejection.** Once a message
   ID has been processed, reject any further submission with
   the same ID.
2. **Chain-specific binding.** Include the destination chain
   ID in the signed payload so cross-chain replay fails
   verification.
3. **Sequence-number monotonicity.** Per-sender sequence
   numbers must increase strictly; replaying an old sequence
   reverts.

## LTP analogue

LTP's `LTPAnchorRegistry._anchor()` (lines 530-577) implements
all three:

| ID | Defense | Source |
|----|---------|--------|
| IBC1 | `_anchors[anchorDigest].anchoredAt != 0` → `AlreadyAnchored` | LTPAnchorRegistry.sol:531-533 |
| IBC2 | `targetChainId` is stamped from `block.chainid`, NOT caller-supplied — cross-chain replay would fail because the destination chain's record wouldn't match | :577 |
| IBC3 | `signerSequences[vk]` is strictly monotonic; replay of an older sequence reverts with `SequenceTooLow` | :551-555 |

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| **None new.** | Already pinned by SCN-001 (Wormhole) defenses D3, D5, D8. | `contracts/test/security/historical/SCN_001_Wormhole_AnchorRegistry.t.sol` (`test_D3_replay_rejected`, `test_D5_stale_sequence_rejected`, `test_D8_target_chain_stamped_from_block_chainid`) |
| Stateful invariant | Existing `SCN_001_Wormhole_AnchorRegistry.invariant.t.sol::invariant_chain_id_stamp` + `invariant_sequence_monotone` | Same file |

SCN-030 is a **cross-reference / awareness doc** — the defense
was already executable as part of the SCN-001 batch. This file
documents the IBC-class threat model + maps it to existing
tests for FedRAMP evidence.

## How to verify

```bash
cd contracts && forge test --match-test test_D3_replay_rejected -vvv
cd contracts && forge test --match-test test_D5_stale_sequence_rejected -vvv
cd contracts && forge test --match-test test_D8_target_chain_stamped_from_block_chainid -vvv
cd contracts && forge test --match-test invariant_chain_id_stamp -vvv
cd contracts && forge test --match-test invariant_sequence_monotone -vvv
```

## Cross-references

- **SCN-001** (Wormhole signature-skip) — pinned D3, D5, D8;
  this scenario references those tests directly
- **LTP-A-008** — covered by these defenses
- **OPERATOR_RUNBOOK §11** (monitoring) — would alert on
  unusual `AlreadyAnchored` or `SequenceTooLow` revert rates

## Findings opened

None. Cross-chain replay defenses pre-exist and are pinned by
SCN-001. R-4 Layer 7 closes here.
