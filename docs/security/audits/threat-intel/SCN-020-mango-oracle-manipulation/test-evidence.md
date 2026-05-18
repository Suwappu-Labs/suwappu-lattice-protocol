# SCN-020 — Test evidence

Structurally-N/A: no on-chain price-oracle surface in LTP.

## Verification commands

```bash
# Solidity side
grep -rnE "oracle|getPrice|priceFeed|chainlink|aggregator|\
           getRoundData|latestAnswer" contracts/src/
# Expected: no matches

# Python SDK side
grep -rnE "^(def |class ).*(oracle|price)" src/ltp/
# Expected: no matches
```

Both should return zero matches. If a future commit adds any
match, this scenario becomes ACTIVE and requires the design
hardening described in the README ("Future considerations").

## Documentation deliverables

| Deliverable | Status | Location |
|---|---|---|
| Scenario README + threat-intel | this commit | `docs/security/audits/threat-intel/SCN-020-mango-oracle-manipulation/` |
| Future-feature design constraints | drafted in README | (will move to a design-decision doc when an oracle feature is proposed) |
