# SCN-009 — Test evidence

## Forge unit + fuzz

| Test | Status | Notes |
|---|---|---|
| `test_H1_constructor_accepts_2_of_5` | _pending first CI run_ | H1 — contract has no Byzantine floor |
| `test_H1_constructor_accepts_1_of_5` | _pending first CI run_ | H1 — boundary |
| `test_H2_byzantine_floor_for_5_owners_is_3` | _pending first CI run_ | H2 — Harmony's 2-of-5 fails mainnet floor |
| `test_H2_byzantine_floor_for_9_owners_is_5` | _pending first CI run_ | H2 — Ronin's 5-of-9 just passes |
| `test_H2_byzantine_floor_strictly_greater_than_half` | _pending first CI run_ | H2 — property over N |
| `testFuzz_H2_floor_rejects_under_half_threshold` | _pending first CI run_ | H2 — fuzz |
| `test_H3_one_compromised_of_5_blocked_at_2_threshold` | _pending first CI run_ | H3 — under-quorum |
| `test_H3_two_compromised_of_5_can_execute_by_design` | _pending first CI run_ | H3 — documents the Harmony scenario |
| `test_H3_byzantine_floor_blocks_same_2_key_compromise` | _pending first CI run_ | H3 — proves H2 prevents it |

## Run commands

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_009_*' -vvv
```
