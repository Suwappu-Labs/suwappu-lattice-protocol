# SCN-004 — Test evidence

## Forge unit + fuzz

| Test | Status | Notes |
|---|---|---|
| `test_M1_execute_below_threshold_reverts` | _pending first CI run_ | M1 |
| `test_M2_non_owner_cannot_submit` | _pending first CI run_ | M2 (submit) |
| `test_M2_non_owner_cannot_confirm` | _pending first CI run_ | M2 (confirm) |
| `test_M2_non_owner_cannot_revoke` | _pending first CI run_ | M2 (revoke) |
| `test_M2_non_owner_cannot_execute` | _pending first CI run_ | M2 (execute) |
| `test_M3_owner_cannot_unilaterally_change_threshold` | _pending first CI run_ | M3 |
| `test_M3_owner_cannot_unilaterally_add_owner` | _pending first CI run_ | M3 |
| `test_M3_owner_cannot_unilaterally_remove_owner` | _pending first CI run_ | M3 |
| `test_M3_attacker_cannot_change_threshold` | _pending first CI run_ | M3 |
| `test_M4_constructor_rejects_zero_threshold` | _pending first CI run_ | M4 |
| `test_M4_constructor_rejects_threshold_above_owners` | _pending first CI run_ | M4 |
| `test_M4_constructor_rejects_empty_owners` | _pending first CI run_ | M4 |
| `test_M5_double_confirm_rejected` | _pending first CI run_ | M5 |
| `test_M6_revoke_drops_below_threshold` | _pending first CI run_ | M6 |
| `testFuzz_arbitrary_non_owner_blocked` | _pending first CI run_ | Property fuzz |

## Forge invariant

| Invariant | Status | Notes |
|---|---|---|
| `invariant_no_execute_below_threshold` | _pending first CI run_ | T1 |
| `invariant_threshold_stable` | _pending first CI run_ | T2 |
| `invariant_owner_set_stable` | _pending first CI run_ | T3 |

## Echidna

| Property | Status | Notes |
|---|---|---|
| `echidna_threshold_never_drifts` (S1) | _pending first manual run_ | Mirrors T2 |
| `echidna_owner_set_stable` (S2) | _pending first manual run_ | Mirrors T3 |
| inline `assert(false)` on every successful attacker call | _pending first manual run_ | Write-time enforcement |

## Run commands

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_004_*' -vvv
cd contracts && echidna . --contract SCN_004_OrbitEchidna --config echidna.yaml
```
