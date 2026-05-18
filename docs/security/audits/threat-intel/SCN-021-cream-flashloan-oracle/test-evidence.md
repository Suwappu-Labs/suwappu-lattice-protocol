# SCN-021 — Test evidence

Structurally-N/A.

## Verification commands

```bash
grep -rnE "flashLoan|flash_loan|EIP3156|IERC3156|onFlashLoan|\
           executeOperation|FlashLoanReceiver" contracts/src/
# Expected: no matches

grep -rnE "flashloan|flash_loan" src/ltp/
# Expected: no matches

# Plus SCN-020's oracle verification
grep -rnE "oracle|getPrice|priceFeed|chainlink|aggregator|\
           getRoundData|latestAnswer" contracts/src/
# Expected: no matches
```

## Documentation deliverables

| Deliverable | Status | Location |
|---|---|---|
| Scenario README + threat-intel | this commit | `docs/security/audits/threat-intel/SCN-021-cream-flashloan-oracle/` |

## Adjacent test coverage

The "bonds must be self-funded" property is pinned by:
- SCN-006 V2 (`test_V2_openWindow_accounts_for_value` /
  `test_V2_submitChallenge_accounts_for_value`)
- `invariant_bonds_conserved` (existing audit-tier invariant)
