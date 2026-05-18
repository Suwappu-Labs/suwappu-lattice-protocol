# SCN-028 — Test evidence

## pytest

| Test | Status | Notes |
|---|---|---|
| `test_GW1_default_host_is_loopback` | _pending first CI run_ | GW1 |
| `test_GW1_default_host_is_not_zero_zero_zero_zero` | _pending first CI run_ | GW1 anti-test |
| `test_GW2_explicit_public_bind_opt_in` | _pending first CI run_ | GW2 |
| `test_GW2_specific_interface_opt_in` | _pending first CI run_ | GW2 |
| `test_GW3_port_override` | _pending first CI run_ | GW3 |
| `test_GW3_default_port_is_8000` | _pending first CI run_ | GW3 |

## Run commands

```bash
pip install -e '.[dev]'
pytest tests/security/historical/test_scn_028_gateway_bind.py -v
```
