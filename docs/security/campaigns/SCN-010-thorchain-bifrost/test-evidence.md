# SCN-010 — Test evidence

## pytest

| Test | Status | Notes |
|---|---|---|
| `test_B1_aggregate_verify_rejects_length_mismatch_pks_too_few` | _pending first CI run_ | B1 |
| `test_B1_aggregate_verify_rejects_length_mismatch_msgs_too_few` | _pending first CI run_ | B1 |
| `test_B2_aggregate_verify_rejects_short_signature` | _pending first CI run_ | B2 |
| `test_B2_aggregate_verify_rejects_long_signature` | _pending first CI run_ | B2 |
| `test_B3_aggregate_verify_rejects_tampered_message` | _pending first CI run_ | B3 |
| `test_B3_aggregate_verify_rejects_swapped_pk` | _pending first CI run_ | B3 |
| `test_B4_aggregate_verify_rejects_random_bytes_signature` | _pending first CI run_ | B4 |
| `test_B4_aggregate_verify_rejects_unrelated_aggregate` | _pending first CI run_ | B4 |
| `test_B5_fast_aggregate_verify_rejects_extra_unrelated_pk` | _pending first CI run_ | B5 |
| `test_B5_fast_aggregate_verify_rejects_swapped_pk` | _pending first CI run_ | B5 |
| `test_B6_aggregate_verify_empty_lists_does_not_return_true` | _pending first CI run_ | B6 |
| `test_B7_per_signer_verify_rejects_message_tamper` | _pending first CI run_ | B7 |

## Run commands

```bash
pip install -e '.[dev]'  # py_ecc / blst
pytest tests/security/historical/test_scn_010_thorchain_bifrost.py -v
```
