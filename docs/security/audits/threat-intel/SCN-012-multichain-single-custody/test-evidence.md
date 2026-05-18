# SCN-012 — Test evidence

## pytest

| Test | Status | Notes |
|---|---|---|
| `test_C1_combine_below_threshold_raises` | _pending first CI run_ | C1 |
| `test_C2_single_partial_does_not_verify_as_full_signature` | _pending first CI run_ | C2 |
| `test_C3_combining_threshold_partials_produces_valid_signature` | _pending first CI run_ | C3 exact |
| `test_C3_combining_more_than_threshold_also_valid` | _pending first CI run_ | C3 over-threshold |
| `test_C5_same_participant_double_counted_does_not_verify` | _pending first CI run_ | C5 |
| `test_single_custody_holder_cannot_unilaterally_sign` | _pending first CI run_ | end-to-end single-custody scenario |

## Run commands

```bash
pip install -e '.[dev]'
pytest tests/security/historical/test_scn_012_multichain.py -v
```
