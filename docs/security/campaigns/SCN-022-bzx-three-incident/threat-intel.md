# SCN-022 — Threat intelligence sources

Historical incidents: **bZx / Fulcrum exploits, 2020-2021.**

Four distinct incidents in the project's history; SCN-022 covers
the three that share the DeFi-composability/oracle primitive.
The fourth (Nov 2021 Polygon private-key compromise) is covered
by the layer-3 trust-boundary scenarios (SCN-011 family).

## Primary sources

- **bZx team post-mortems** for each incident (Feb 14, Feb 18,
  Sep 14 2020).
- **Patch PRs** in the bZx monorepo closing each path.

## Secondary technical analyses

- **PeckShield** — early breakdowns of the Feb 2020 incidents.
- **samczsun** — Sep 2020 duplicate-collateral analysis.
- **SlowMist** — incident reports.
- **Quantstamp / OpenZeppelin** — retrospectives on the
  composability primitive that bZx's Feb 2020 incidents
  popularized.

## Root primitive

A protocol makes an economic decision (margin call, liquidation
threshold, borrow availability) based on a price source that
can be moved by the same caller in the same atomic transaction.

Defenses against this composition class:

1. **No on-chain economic decisions based on caller-shiftable
   state.** This is the structural defense LTP applies — the
   contract makes no leverage / margin / borrow decisions at
   all.

2. **TWAP oracles** with windows long enough that flashloan-
   scale movements can't shift the average.

3. **Independent oracle aggregation** (Chainlink + Pyth +
   RedStone) so manipulating one feed isn't enough.

4. **Circuit breakers** that pause on extreme price divergence.

5. **Mutual-exclusion of flashloan + state-changing operations**
   in the same transaction.

LTP applies defense (1) by architectural choice. The other four
become relevant only if LTP ever adds an economic decision
surface (it currently doesn't).

## Mapping to LTP

LTP is a bridge / state-anchoring protocol. None of bZx's
attack surfaces (leverage, margin, liquidation, borrow,
collateral-priced oracle) exist on-chain. Bonds in
OptimisticBridgeChallenge are pure native ETH escrow with
zero pricing logic.

This closes Layer 5 (oracle / data feed) of the campaign by
structural absence across all three sibling scenarios
(SCN-020, SCN-021, SCN-022).

## Date of last verification

2026-05-17 — SCN-022 added under R-4.
