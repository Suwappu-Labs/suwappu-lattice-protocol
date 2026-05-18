# SCN-001 — Test evidence

Populated as the test pack runs.

## Forge unit + fuzz

| Test | Status | Notes |
|---|---|---|
| `test_D1_unauthorized_signer_rejected` | _pending first run_ | Defense D1 |
| `test_D1_unauthorized_signer_rejected_legitimate_caller` | _pending first run_ | Defense D1 (caller-independence) |
| `test_D3_replay_rejected` | _pending first run_ | Defense D3 |
| `test_D4_foreign_signer_cannot_overwrite_entity_binding` | _pending first run_ | Defense D4 |
| `test_D5_stale_sequence_rejected` | _pending first run_ | Defense D5 |
| `test_D6_expired_anchor_rejected` | _pending first run_ | Defense D6 |
| `test_D8_target_chain_stamped_from_block_chainid` | _pending first run_ | Defense D8 |
| `test_D9_paused_rejects_anchor` | _pending first run_ | Defense D9 |
| `testFuzz_unauthorized_signer_always_reverts` | _pending first run_ | Fuzz over D1 |

## Forge invariant

| Invariant | Status | Notes |
|---|---|---|
| `invariant_no_unauthorized_anchor` | _pending first run_ | I1 |
| `invariant_chain_id_stamp` | _pending first run_ | I2 |
| `invariant_sequence_monotone` | _pending first run_ | I3 |

## Echidna

| Property | Status | Notes |
|---|---|---|
| `echidna_no_unauthorized_anchor` (P1) | _pending first run_ | Mirrors I1 |
| `echidna_chain_id_stamp` (P2) | _pending first run_ | Mirrors I2 |
| `echidna_sequence_monotone` (P3) | _pending first run_ | Mirrors I3 |
| inline `assert(authBefore)` in `tryAnchor` | _pending first run_ | P1 enforcement at write-time |

## Run commands

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_001_*' -vvv
cd contracts && echidna . --contract SCN_001_WormholeEchidna --config echidna.yaml
```

## CI run URLs

_(populated after the PR opens — links to the GitHub Actions runs)_
