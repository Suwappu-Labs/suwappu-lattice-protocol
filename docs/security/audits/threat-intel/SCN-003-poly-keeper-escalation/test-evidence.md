# SCN-003 — Test evidence

## Forge unit + fuzz

| Test | Status | Notes |
|---|---|---|
| `test_P1_registerSigner_rejects_attacker` | _pending first CI run_ | P1 |
| `test_P2_revokeSigner_rejects_attacker` | _pending first CI run_ | P2 |
| `test_P3_rotateSigner_rejects_attacker` | _pending first CI run_ | P3 |
| `test_P4_rotateSignerWithGrace_rejects_attacker` | _pending first CI run_ | P4 |
| `test_P5_reassignEntitySigner_rejects_attacker` | _pending first CI run_ | P5 |
| `test_P6_setBindingDisputeVerifier_rejects_attacker` | _pending first CI run_ | P6 |
| `test_P7_disputeBinding_rejects_non_verifier` | _pending first CI run_ | P7 (incl. admin) |
| `test_P8_transferAdmin_rejects_attacker` | _pending first CI run_ | P8 |
| `test_P9_pause_unpause_reject_attacker` | _pending first CI run_ | P9 |
| `test_P10_anchor_with_unregistered_signer_does_not_register_it` | _pending first CI run_ | P10 |
| `testFuzz_arbitrary_caller_cannot_invoke_admin_functions` | _pending first CI run_ | Property fuzz |
| `testFuzz_arbitrary_caller_cannot_dispute_binding` | _pending first CI run_ | Property fuzz |

## Forge invariant

| Invariant | Status | Notes |
|---|---|---|
| `invariant_admin_monopoly_on_signers` | _pending first CI run_ | K1 |
| `invariant_admin_never_silently_changes` | _pending first CI run_ | K2 |

## Echidna

| Property | Status | Notes |
|---|---|---|
| `echidna_admin_never_moves` (R1) | _pending first manual run_ | Mirrors K2 |
| `echidna_only_seed_vk_authorized` (R2) | _pending first manual run_ | Mirrors K1 (post-condition) |
| inline `assert(false)` on every attacker path | _pending first manual run_ | Write-time enforcement |

## Run commands

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_003_*' -vvv
cd contracts && echidna . --contract SCN_003_PolyEchidna --config echidna.yaml
```
