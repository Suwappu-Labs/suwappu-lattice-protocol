# SCN-016 — Test evidence

## Forge unit

| Test | Status | Notes |
|---|---|---|
| `test_U1_non_admin_cannot_pause` | _pending first CI run_ | U1 |
| `test_U2_non_admin_cannot_unpause` | _pending first CI run_ | U2 |
| `test_U3_non_admin_cannot_upgrade` | _pending first CI run_ | U3 |
| `test_U4_paused_state_survives_upgrade` | _pending first CI run_ | U4 |
| `test_U5_attacker_cannot_use_upgrade_to_bypass_pause` | _pending first CI run_ | U5 combined |

## Run commands

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_016_*' -vvv
```
