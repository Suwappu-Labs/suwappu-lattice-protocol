# SCN-020 — Threat intelligence sources

Historical incident: **Mango Markets exploit, 11 October 2022, ~\$116M.**

## Primary sources

- **Mango Markets DAO post-mortem** — published on the Mango
  governance forum within hours of the exploit.
- **Court filings, United States v. Eisenberg, S.D.N.Y.** —
  criminal case 22-cr-417. Eisenberg's defense argued the
  exploit was "legitimate market activity"; the court rejected
  this in April 2024.
- **FBI / DOJ press releases** on the prosecution.

## Secondary technical analyses

- **Chainalysis** — fund-tracing through the cross-chain bridges
  Eisenberg used.
- **Mango DAO governance proposals** — including the
  "agreement-to-return" proposal Eisenberg himself voted for
  using the stolen MNGO tokens.
- **Halborn / SlowMist** — independent technical breakdowns of
  the oracle-manipulation mechanism.

## Root primitive

A protocol's collateral pricing pulled from manipulable spot
markets. The oracle was an honest mirror of market price — but
the market itself could be moved by the attacker with $10M of
capital, producing leverage that allowed extraction of $116M.

Related incidents that share this primitive:
- Cream Finance (Oct 2021, ~\$130M) — flashloan + oracle manipulation
- bZx / Fulcrum (2020-2021, multiple) — repeated oracle/flashloan
  composability bugs
- Compound DAI margin call event (2020) — oracle reported wrong
  DAI price during dYdX flash mint
- Inverse Finance (Apr 2022, ~\$15M) — TWAP manipulation on Sushi
- Various Curve-pool oracle exploits

## Mapping to LTP

LTP has no on-chain price oracle. The defense is structural
absence, verified by repo-wide grep (see scenario README).

The Mango primitive cannot apply to LTP because:
1. LTP holds no collateral that requires USD-denominated
   pricing — bonds are native ETH.
2. LTP makes no leverage / borrowing decisions on-chain.
3. LTP consumes no external market-data feeds at the contract
   layer.

## Date of last verification

2026-05-17 — SCN-020 added under R-4.
