# SCN-005 — Test evidence

## Forge unit + fuzz

| Test | Status | Notes |
|---|---|---|
| `test_E1_E3_reentry_during_resolveChallenge_blocked` | _pending first CI run_ | E1+E3 cross-path re-entry |
| `test_E2_status_set_before_transfer_in_finalizeWindow` | _pending first CI run_ | E2 CEI ordering |
| `test_E4_same_digest_replay_rejected` | _pending first CI run_ | E4 status-precondition replay block |

## Forge invariant

| Invariant | Status | Notes |
|---|---|---|
| `invariant_no_double_payout` | _pending first CI run_ | X1 |
| `invariant_status_terminal_monotone` | _pending first CI run_ | X2 |

## Echidna

| Property | Status | Notes |
|---|---|---|
| `echidna_no_successful_reentry` (Y1) | _pending first manual run_ | Harness arms re-entry during finalizeWindow |
| inline `assert(!reentrySucceeded)` | _pending first manual run_ | Write-time check after each armed call |
| `echidna_balance_non_negative` (Y2 baseline) | _pending first manual run_ | Sanity |

## Run commands

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_005_*' -vvv
cd contracts && echidna . --contract SCN_005_PenpieEchidna --config echidna.yaml
```
