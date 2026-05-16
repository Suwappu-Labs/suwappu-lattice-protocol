# SCN-011 — Test evidence

## pytest

| Test | Status | Notes |
|---|---|---|
| `test_L1_software_hsm_refuses_production_when_explicitly_selected` | _pending first CI run_ | L1 prod refuse |
| `test_L1_software_hsm_allowed_outside_production` | _pending first CI run_ | L1 dev/CI allow |
| `test_L1_software_hsm_allowed_production_with_different_provider` | _pending first CI run_ | L1 boundary |
| `test_L2_HSMBackend_abstract_interface_has_no_export_method` | _pending first CI run_ | L2 |
| `test_L3_sign_unknown_key_id_raises` | _pending first CI run_ | L3 |
| `test_L4_sign_with_kem_key_raises_typeerror` | _pending first CI run_ | L4 |
| `test_L4_kem_decaps_with_dsa_key_raises_typeerror` | _pending first CI run_ | L4 |
| `test_L5_destroy_key_returns_true_then_false` | _pending first CI run_ | L5 |
| `test_L5_destroyed_key_cannot_sign` | _pending first CI run_ | L5 |
| `test_L7_generate_dsa_keypair_rejects_duplicate_key_id` | _pending first CI run_ | L7 |
| `test_L7_generate_kem_keypair_rejects_duplicate_key_id` | _pending first CI run_ | L7 |
| `test_L7_generate_dsa_and_kem_share_same_id_space` | _pending first CI run_ | L7 cross-type |
| `test_L8_has_key_distinguishes_present_vs_absent` | _pending first CI run_ | L8 |

## Run commands

```bash
pip install -e '.[dev]'
pytest tests/security/historical/test_scn_011_lazarus_hsm.py -v
```
