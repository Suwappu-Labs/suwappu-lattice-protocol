# SCN-021 — Cream Finance flashloan + oracle manipulation

**Status.** STRUCTURALLY-N/A. LTP has no flashloan source AND no on-chain price oracle.
**Layer.** 5 — Oracle / data feed.
**Historical incident.** Cream Finance, 27 Oct 2021, ~\$130M.
**LTP-A-* link.** None directly. Documentation deliverable.

## What happened (Cream)

The attacker used flashloans from MakerDAO + AAVE + Curve to
borrow ~\$1.5B in stablecoins atomically. They:

1. Deposited the flash-borrowed assets as collateral on Cream.
2. Repeatedly traded between yUSDVault-style price-per-share
   oracles (Cream used `getPricePerFullShare()` from the
   underlying vault as the oracle).
3. By manipulating vault state inside the flashloan call,
   they inflated the price-per-share reading.
4. Borrowed against the inflated collateral.
5. Repaid the flashloans, exited with the difference.

Two orthogonal primitives combined:
- **Flashloan** — atomic, very-large-capital access in a single
  transaction.
- **Manipulable oracle** — price-per-share computed from
  manipulable on-chain vault state.

Either alone is survivable. **The composition is what made it
catastrophic.**

## LTP analogue

LTP has neither primitive:

| Primitive | LTP status |
|---|---|
| Flashloan source | LTP exposes no `flashLoan(token, amount, data)` or equivalent. Bonds in OptimisticBridgeChallenge must be funded from the caller's own balance. |
| Price oracle | None — covered by SCN-020. |

Even if a hypothetical attacker could obtain a flashloan from
an external source (Aave, MakerDAO), the flashloan capital
cannot be used to manipulate LTP state in a way that produces
extractable value, because LTP makes no on-chain economic
decisions that depend on caller-controllable market state.

## Verification commands

```bash
# Solidity: any flashloan surface?
grep -rnE "flashLoan|flash_loan|EIP3156|IERC3156|onFlashLoan|\
           executeOperation|FlashLoanReceiver" contracts/src/
# Expected: no matches

# Python: any flashloan reference?
grep -rnE "flashloan|flash_loan" src/ltp/
# Expected: no matches

# Plus SCN-020's verification: no oracle surface
grep -rnE "oracle|getPrice|priceFeed|chainlink|aggregator|\
           getRoundData|latestAnswer" contracts/src/
# Expected: no matches
```

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| **None.** | _structural_ | LTP has neither primitive that Cream combined. |

## Cross-references

- **SCN-006** (Euler donate-to-self) — pins
  OptimisticBridgeChallenge has no donation surface; bonds
  must come from caller's balance
- **SCN-020** (Mango oracle manipulation) — sibling
  structurally-N/A finding for the oracle half
- **SCN-022** (bZx three-incident pattern) — sibling
  structurally-N/A finding for the bond-pricing flow

## Findings opened

None. Scenario is structurally-N/A.
