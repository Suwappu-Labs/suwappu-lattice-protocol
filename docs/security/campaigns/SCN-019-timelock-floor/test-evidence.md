# SCN-019 — Test evidence

## Forge unit + fuzz

| Test | Status | Notes |
|---|---|---|
| `test_F1_floor_rejects_zero_delay` | _pending first CI run_ | F1 |
| `test_F1_floor_rejects_one_second` | _pending first CI run_ | F1 (Cypher exact shape) |
| `test_F1_floor_rejects_below_24h` | _pending first CI run_ | F1 |
| `test_F1_floor_accepts_exactly_24h` | _pending first CI run_ | F1 boundary |
| `test_F1_floor_accepts_recommended_48h` | _pending first CI run_ | F1 |
| `testFuzz_F1_floor_rejects_below_24h` | _pending first CI run_ | F1 fuzz |
| `testFuzz_F1_floor_accepts_at_or_above_24h` | _pending first CI run_ | F1 fuzz |
| `test_F2_oz_timelock_accepts_low_delay_at_contract_layer` | _pending first CI run_ | F2 (documents boundary) |
| `test_F2_oz_timelock_accepts_floor_delay` | _pending first CI run_ | F2 (happy path) |

## Run commands

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_019_*' -vvv
```
