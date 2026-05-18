# SCN-008 — Test evidence

## Forge unit + fuzz

| Test | Status | Notes |
|---|---|---|
| `test_R1_submit_confirmation_credits_only_msg_sender` | _pending first CI run_ | R1 |
| `test_R2_confirm_credits_only_msg_sender` | _pending first CI run_ | R2 (legit) |
| `test_R2_attacker_cannot_relay_a_confirmation` | _pending first CI run_ | R2 (attacker-relay attempt) |
| `test_R3_execute_counts_only_recorded_confirmations` | _pending first CI run_ | R3 |
| `test_R4_unknown_selector_reverts_no_fallback` | _pending first CI run_ | R4 (specific selector) |
| `testFuzz_R4_no_fallback_for_arbitrary_selectors` | _pending first CI run_ | R4 (fuzz) |
| `test_compromised_single_owner_cannot_execute` | _pending first CI run_ | end-to-end scenario |

## Run commands

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_008_*' -vvv
```
