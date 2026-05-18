# SCN-007 — Test evidence

## Forge unit + fuzz

| Test | Status | Notes |
|---|---|---|
| `test_T1_malicious_payload_only_emitted_not_dispatched` | _pending first CI run_ | T1 — emit-only |
| `testFuzz_T1_arbitrary_payload_emitted_safely` | _pending first CI run_ | T1 — property fuzz over arbitrary bytes |
| `test_T3_user_cannot_change_verification_mode` | _pending first CI run_ | T3 — mode is admin-only |
| `test_T5_verifier_dispatch_target_is_immutable` | _pending first CI run_ | T5 — challengeContract fixed |

## Run commands

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_007_*' -vvv
```
