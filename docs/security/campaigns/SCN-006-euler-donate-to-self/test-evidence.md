# SCN-006 — Test evidence

## Forge unit

| Test | Status | Notes |
|---|---|---|
| `test_V1_bare_eth_call_reverts_no_receive` | _pending first CI run_ | V1 — no receive() |
| `test_V1_call_with_random_selector_reverts` | _pending first CI run_ | V1 — no fallback() |
| `test_V2_openWindow_accounts_for_value` | _pending first CI run_ | V2 — operator bond |
| `test_V2_submitChallenge_accounts_for_value` | _pending first CI run_ | V2 — challenger bond |
| `test_V3_selfdestruct_donation_creates_detectable_drift` | _pending first CI run_ | V3 — drift detectable |

## Pre-existing forge invariant (reused)

| Invariant | Status | File |
|---|---|---|
| `invariant_bonds_conserved` | covered by existing audit work | `contracts/test/invariant/OptimisticBridgeChallenge.invariant.t.sol` |

## Run commands

```bash
cd contracts && forge test --match-path 'test/security/historical/SCN_006_*' -vvv
cd contracts && forge test --match-test invariant_bonds_conserved -vvv
```
