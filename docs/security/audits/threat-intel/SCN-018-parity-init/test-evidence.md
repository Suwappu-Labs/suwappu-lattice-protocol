# SCN-018 — Test evidence

## Existing test coverage (no new tests required)

| Test | File:Line | Status |
|---|---|---|
| `test_implementationCannotBeInitialized` | `contracts/test/LTPAnchorRegistry.t.sol:843` | Pre-existing; pinned by previous audit. Will run in CI as part of standard Forge Tests job. |
| SCN-002 Z6 (`test_Z6_initializer_cannot_be_recalled_on_proxy`, `test_Z6_initializer_cannot_be_called_on_implementation`) | `contracts/test/security/historical/SCN_002_Nomad_InitBug.t.sol` | Already pinned in R-2. |

## No new test artifacts

This scenario is documentation-only. The defense pre-exists and
is already exercised by:
1. The pre-existing audit test (line 843).
2. The SCN-002 Z6 sub-tests (this campaign).

## How to verify

```bash
cd contracts && forge test --match-test test_implementationCannotBeInitialized -vvv
cd contracts && forge test --match-path 'test/security/historical/SCN_002_*' --match-test test_Z6 -vvv
```
