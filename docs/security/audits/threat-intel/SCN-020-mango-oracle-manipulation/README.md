# SCN-020 — Mango Markets oracle manipulation

**Status.** STRUCTURALLY-N/A. LTP has no internal price oracle.
**Layer.** 5 — Oracle / data feed.
**Historical incident.** Mango Markets, 11 Oct 2022, ~\$116M.
**LTP-A-* link.** None directly. Documentation deliverable.

## What happened (Mango)

Avraham Eisenberg used \$10M of capital to:

1. Open a large MNGO/USDC perp position on Mango.
2. Spot-buy MNGO on thinly-traded markets (FTX, Ascendex, Mango
   spot) to push the spot price ~10x in minutes.
3. Mango's oracle pulled from those very spot markets, so the
   on-protocol MNGO "price" inflated 10x.
4. With his perp position now showing massive unrealized PnL,
   he borrowed ~\$116M of other assets against the inflated
   collateral.
5. Withdrew the borrowed assets to a separate account.
6. The MNGO price collapsed back; his perp position became
   worthless but the borrowed assets were gone.

Root primitive: **a protocol's collateral pricing pulled from a
manipulable spot market**. The oracle was an honest mirror of
market price — but the market itself could be moved by the
attacker.

(Eisenberg later argued in court that "it was just a market
trade." The Southern District of New York disagreed. He was
convicted in April 2024 on fraud and market-manipulation charges.)

## LTP analogue

**LTP has no internal price oracle.** Verified by full-repo grep:

```bash
$ grep -rnE "oracle|getPrice|priceFeed|chainlink|aggregator|\
              getRoundData|latestAnswer" contracts/src/
(no matches)

$ grep -rnE "^(def |class ).*(oracle|price)" src/ltp/
(no matches)
```

The Mango primitive — "manipulable price feed used as
collateral valuation" — has **no on-chain target** in LTP.

## What COULD constitute an oracle surface (and doesn't)

For completeness, here's the audit chain a reviewer might
expect to find an oracle in:

| Possible surface | LTP design choice |
|---|---|
| Bond valuation in `OptimisticBridgeChallenge` | Bonds are denominated in native ETH; no conversion to USD or other asset is performed on-chain |
| Cross-chain message validation | Validates Merkle proofs / ML-DSA signatures, not asset prices |
| Reward / slashing economics | Off-chain (the gateway VM); not collateral-priced on-chain |
| ZK proof verification | Verifies cryptographic proofs, not market state |

The architectural choice "no on-chain collateral pricing" is
**by design** — LTP is a bridge / state-anchoring protocol, not
a lending or perp protocol. Oracle attacks against LTP-the-
contract are structurally impossible because the surface they
target does not exist.

## What IS in scope (very narrow)

The only "external data" LTP consumes at the contract layer is
the caller-supplied `merkleRoot` / `policyHash` in anchor
submissions. These are NOT prices and they are NOT subject to
market manipulation; they are content-addressed identifiers.
The defenses against malicious content-addressing are:

- SCN-001 (Wormhole) — signature-verification gate
- SCN-002 (Nomad) — no zero-value sentinel auto-trust
- SCN-003 (Poly Network) — no caller-supplied dispatch

## Future considerations

If LTP ever adds a feature that consumes external pricing (e.g.,
a future fee mechanism denominated in USD, or cross-chain bond
collateral in a non-ETH asset), this scenario would become
ACTIVE and would require:

- Chainlink / Pyth / RedStone aggregation across N independent
  feeds
- TWAP (time-weighted) windows of at least 30 minutes
- A circuit breaker: reject any single update that diverges
  >X% from the prior TWAP
- A pause mechanism that fires automatically on extreme
  divergence

These would be designed against MITRE / Trail of Bits oracle-
attack patterns. Documented here as **future-feature design
constraints** rather than current defenses.

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| **None.** | _structural_ | No on-chain price-oracle surface exists in LTP. The grep above is the verification; CI's existing Slither + solhint runs would flag any future addition of an oracle without a corresponding hardening review. |

## Cross-references

- **SCN-021** (Cream flashloan + oracle) — same primitive
  applied to a flashloan composability surface; same
  structurally-N/A finding for LTP
- **SCN-022** (bZx three-incident pattern) — same primitive
  applied to bond-pricing flows; same structurally-N/A
  finding for LTP

## Findings opened

None. Scenario is structurally-N/A. Documented for FedRAMP
evidence and for future reviewers.
