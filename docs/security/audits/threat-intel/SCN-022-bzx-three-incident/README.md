# SCN-022 — bZx three-incident pattern

**Status.** STRUCTURALLY-N/A. LTP has no leverage / margin / bond-priced surface.
**Layer.** 5 — Oracle / data feed (and composability).
**Historical incidents.** bZx / Fulcrum, 2020-2021, three major
incidents (~\$1M, ~\$8M, ~\$55M cumulatively).
**LTP-A-* link.** None directly. Documentation deliverable.

## What happened (bZx)

bZx was a leverage / margin protocol. Three incidents in
sequence exposed different facets of the same underlying class:

1. **Feb 14, 2020 (\$350k)** — flashloan + Uniswap oracle
   manipulation. The attacker used a flashloan to inflate the
   sUSD/ETH price on the Uniswap pool that bZx used as its
   oracle, then opened a leveraged position against the
   manipulated price.

2. **Feb 18, 2020 (\$650k)** — Kyber-via-Uniswap oracle
   manipulation, same general primitive: trade volume in the
   underlying market shifted bZx's view of the asset price.

3. **Sep 14, 2020 (~\$8M)** — duplicate-collateral bug where
   the contract incremented one variable but failed to
   increment its mirror, letting the attacker withdraw twice
   what they had deposited.

4. **Nov 5, 2021 (~\$55M)** — Polygon-deployment private-key
   compromise (the operator-tier failure mode, covered by
   SCN-011 / SCN-012 layer).

The first three are the "DeFi composability / oracle" cluster.
Each shares the primitive that **bZx made an economic decision
(margin call, liquidation, borrow availability) based on a
price source the attacker could shift atomically.**

## LTP analogue

LTP has **none of bZx's surfaces**:

| bZx surface | LTP equivalent |
|---|---|
| Leverage / margin positions | None |
| Liquidation logic | None |
| Borrowing against collateral | None |
| Asset-price oracle for collateral valuation | None (SCN-020) |
| Atomic flashloan source | None (SCN-021) |
| Duplicate-collateral accounting | None — bonds are pure ETH, not multi-asset positions |

The bZx primitive — "economic decision based on manipulable
price during a single atomic transaction" — has no on-chain
target in LTP.

## Verification

Combined verification across SCN-020/021/022:

```bash
# No oracle (SCN-020)
grep -rnE "oracle|getPrice|priceFeed|chainlink|aggregator|\
           getRoundData|latestAnswer" contracts/src/

# No flashloan (SCN-021)
grep -rnE "flashLoan|flash_loan|EIP3156|IERC3156|onFlashLoan|\
           FlashLoanReceiver" contracts/src/

# No leverage / margin (SCN-022)
grep -rnE "leverage|margin|liquidate|borrow|collateralRatio|\
           healthFactor" contracts/src/

# All three expected: no matches
```

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| **None.** | _structural_ | LTP has none of bZx's surfaces. |

## Cross-references

- **SCN-020** (Mango oracle manipulation) — oracle side
- **SCN-021** (Cream flashloan+oracle) — flashloan side
- **SCN-011** (Lazarus HSM) — the bZx Nov 2021 Polygon
  private-key compromise is covered by this layer

## Findings opened

None. SCN-020/021/022 together establish that the entire
"DeFi composability + oracle manipulation" attack class has
zero on-chain target in LTP. Layer 5 (oracle / data feed) is
effectively closed by structural absence.

This closes the "oracle/data-feed" portion of R-4. Next: Layer 6
(frontend / supply chain — SCN-023..026).
