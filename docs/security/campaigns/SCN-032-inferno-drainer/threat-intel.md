# SCN-032 — Threat intelligence sources

Historical pattern: **Inferno Drainer + successor wallet-drainer kits, 2022-2024, cumulative ~\$80M+ extracted.**

## Primary references

- **ScamSniffer monthly reports** — quantitative wallet-drainer
  loss tracking.
- **Inferno Drainer law-enforcement takedown announcements**
  (late 2023) — partial team apprehension; successor kits
  immediately replaced them.

## Secondary technical analyses

- **MetaMask / Coinbase Wallet engineering blogs** — drainer-
  detection heuristics that wallet UIs have adopted.
- **Blockaid / Pocket Universe / Wallet Guard** — third-party
  drainer-detection vendors.
- **ChainAbuse** — community-reported drainer URL database.

## Root primitive

Phishing-as-a-service: a kit operator provides drainer JS to
"affiliates" who handle look-alike-domain hosting and traffic
acquisition. The economic model spreads attack capability
across many low-skilled actors, making take-downs harder.

Defenses cluster into:

1. **End-user education** — recognize signs of phishing.
2. **Wallet-UI hardening** — pre-transaction simulation, drainer-
   list blocking, anomaly detection on approval transactions.
3. **Protocol-side brand protection** — defensive domain
   registration, takedown procedures, clear "we will never
   X" policies.
4. **Operator hygiene** — separate signing browser, no
   general browsing on a signing machine.

## Mapping to LTP

LTP itself isn't a drainer target today (no dApp), but the
operator team and future integrators are. SCN-032 covers the
defensive-readiness side via tabletop drill.

## Date of last verification

2026-05-17 — SCN-032 scaffolded under R-5.
