# SCN-029 — Test evidence

## pytest

| Test | Status | Notes |
|---|---|---|
| `test_GR1_max_receive_message_length_present` | _pending first CI run_ | GR1 |
| `test_GR2_max_send_message_length_present` | _pending first CI run_ | GR2 |
| `test_GR1_GR2_message_caps_at_4_mib` | _pending first CI run_ | GR1+GR2 value |
| `test_GR3_max_concurrent_streams_present` | _pending first CI run_ | GR3 |
| `test_GR3_concurrent_streams_finite_and_low` | _pending first CI run_ | GR3 value |
| `test_GR4_thread_pool_default_capped` | _pending first CI run_ | GR4 |
| `test_GR_options_passed_to_grpc_server` | _pending first CI run_ | defense-in-depth |

## Run commands

```bash
pip install -e '.[dev]'
pytest tests/security/historical/test_scn_029_grpc_limits.py -v
```
