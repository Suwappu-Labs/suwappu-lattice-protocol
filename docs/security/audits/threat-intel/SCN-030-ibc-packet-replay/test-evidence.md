# SCN-030 — Test evidence

## Existing test coverage (no new tests required)

| Test | File | Property |
|---|---|---|
| `test_D3_replay_rejected` | `contracts/test/security/historical/SCN_001_Wormhole_AnchorRegistry.t.sol` | Per-message replay rejection |
| `test_D5_stale_sequence_rejected` | same | Sequence monotonicity |
| `test_D8_target_chain_stamped_from_block_chainid` | same | Chain-id stamping |
| `invariant_chain_id_stamp` | `contracts/test/security/historical/SCN_001_Wormhole_AnchorRegistry.invariant.t.sol` | I2 stateful |
| `invariant_sequence_monotone` | same | I3 stateful |

## No new test artifacts

The defense pre-exists. SCN-030 is documentation-only — a
cross-reference to the SCN-001 tests for FedRAMP evidence + a
mapping to the IBC-spec threat model.

## How to verify

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_001_*' -vvv
```
