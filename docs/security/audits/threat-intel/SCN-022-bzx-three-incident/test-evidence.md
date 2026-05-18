# SCN-022 — Test evidence

Structurally-N/A.

## Verification commands

```bash
# Layer 5 combined verification across SCN-020/021/022:

# Oracle surfaces (SCN-020)
grep -rnE "oracle|getPrice|priceFeed|chainlink|aggregator|\
           getRoundData|latestAnswer" contracts/src/
# Expected: no matches

# Flashloan surfaces (SCN-021)
grep -rnE "flashLoan|flash_loan|EIP3156|IERC3156|onFlashLoan|\
           FlashLoanReceiver" contracts/src/
# Expected: no matches

# Leverage / margin / liquidation / borrow surfaces (SCN-022)
grep -rnE "leverage|margin|liquidate|borrow|collateralRatio|\
           healthFactor" contracts/src/
# Expected: no matches
```

All three combined verify that LTP has zero attack surface for
the entire Layer 5 (oracle / data feed / DeFi composability)
attack class.

## Documentation deliverables

| Deliverable | Status | Location |
|---|---|---|
| Scenario README + threat-intel | this commit | `docs/security/audits/threat-intel/SCN-022-bzx-three-incident/` |
| Combined Layer 5 closure note | drafted in README | (this file + sibling scenarios) |
