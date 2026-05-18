# SCN-015 — Test evidence

## Forge unit

| Test | Status | Notes |
|---|---|---|
| `test_G1_grace_rotation_records_expiry` | _pending first CI run_ | G1 |
| `test_G2_atomic_rotation_revokes_old_key` | _pending first CI run_ | G2 |
| `test_G3_old_key_works_inside_grace_via_transitionState` | _pending first CI run_ | G3 |
| `test_G4_old_key_rejected_after_grace_via_transitionState` | _pending first CI run_ | G4 |
| `test_G5_old_key_works_inside_grace_via_anchor` | _pending first CI run_ | G5 (LTP-A-031 side) |
| `test_G6_old_key_rejected_after_grace_via_anchor` | _pending first CI run_ | G6 — regression for LTP-A-031 fix |
| `test_G_new_key_works_inside_and_outside_grace` | _pending first CI run_ | edge case |
| `test_G_grace_cap_at_7_days` | _pending first CI run_ | argument bound |

## Findings opened

- **LTP-A-031** (HIGH) — `_anchor()` ignored `signerExpiresAt`.
  Linear GLO-832. Fix at `LTPAnchorRegistry.sol:541-549`. SCN-015
  test G6 is the regression.

## Run commands

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_015_*' -vvv
```
