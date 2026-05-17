# SCN-017 — Test evidence

## Forge unit

| Test | Status | Notes |
|---|---|---|
| `test_D1_setArbiter_rejects_admin_as_arbiter` | _pending first CI run_ | D1 |
| `test_D1_setArbiter_rejects_admin_after_arbiter_change` | _pending first CI run_ | D1 persistence |
| `test_D2_non_admin_cannot_setArbiter` | _pending first CI run_ | D2 |
| `test_D3_non_admin_cannot_setZKVerifier` | _pending first CI run_ | D3 |
| `test_D4_setResolutionGracePeriod_rejects_below_floor` | _pending first CI run_ | D4 |
| `test_D4_setResolutionGracePeriod_accepts_at_floor` | _pending first CI run_ | D4 boundary |
| `test_D4_setResolutionGracePeriod_non_admin_rejected` | _pending first CI run_ | D4 access |
| `test_D5_admin_cannot_call_arbiter_path` | _pending first CI run_ | D5 path separation |
| `test_D5_attacker_cannot_call_arbiter_path` | _pending first CI run_ | D5 access |
| `test_D6_time_decay_before_grace_reverts` | _pending first CI run_ | D6 |
| `test_D6_time_decay_after_grace_succeeds` | _pending first CI run_ | D6 happy path |

## Run commands

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_017_*' -vvv
```
