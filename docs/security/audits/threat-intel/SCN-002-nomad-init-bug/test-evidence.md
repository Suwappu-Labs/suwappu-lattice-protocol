# SCN-002 — Test evidence

## Forge unit + fuzz

| Test | Status | Notes |
|---|---|---|
| `test_Z1_zero_anchor_digest_rejected` | _pending first CI run_ | Z1 |
| `test_Z2_zero_entity_id_rejected` | _pending first CI run_ | Z2 |
| `test_Z3_zero_merkle_root_rejected` | _pending first CI run_ | Z3 |
| `test_Z4_zero_signer_vk_rejected` | _pending first CI run_ | Z4 |
| `test_Z5_zero_policy_hash_accepted_but_other_defenses_still_run` | _pending first CI run_ | Z5 |
| `test_Z6_initializer_cannot_be_recalled_on_proxy` | _pending first CI run_ | Z6 (proxy) |
| `test_Z6_initializer_cannot_be_called_on_implementation` | _pending first CI run_ | Z6 (impl) |
| `test_Z7_zero_digest_record_never_populated` | _pending first CI run_ | Z7 |
| `testFuzz_any_zero_primary_input_reverts` | _pending first CI run_ | Property fuzz |

## Forge invariant

| Invariant | Status | Notes |
|---|---|---|
| `invariant_zero_digest_never_anchored` | _pending first CI run_ | N1 |
| `invariant_no_zero_primary_input_accepted` | _pending first CI run_ | N2 |

## Echidna

| Property | Status | Notes |
|---|---|---|
| `echidna_zero_digest_never_anchored` (Q1) | _pending first manual run_ | Mirrors N1 |
| `echidna_no_zero_primary_input_accepted` (Q2) | _pending first manual run_ | Mirrors N2 |
| inline `assert` in `tryAnchor` | _pending first manual run_ | Q2 write-time enforcement |

## Run commands

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_002_*' -vvv
cd contracts && echidna . --contract SCN_002_NomadEchidna --config echidna.yaml
```
