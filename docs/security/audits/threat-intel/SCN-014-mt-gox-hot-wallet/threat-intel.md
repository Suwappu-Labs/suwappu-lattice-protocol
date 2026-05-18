# SCN-014 — Threat intelligence sources

Historical incident: **Mt Gox sustained hot-wallet drain, 2011-2014, ~650k BTC.**

## Primary sources

- **Mark Karpeles testimony** in the Japanese bankruptcy
  proceedings, 2014-2016.
- **Mt Gox bankruptcy trustee reports** — public filings.
- **WizSec independent investigation** —
  detailed reconstruction of the drain timeline from
  on-chain analysis.

## Secondary technical analyses

- **Kim Nilsson (WizSec)** — multi-year forensic timeline of
  the drain. The canonical reconstruction.
- **Chainalysis** — retroactive on-chain tracing of the
  Mt Gox theft addresses.
- **The Wall Street Journal / Reuters** — 2014-era reporting
  on the bankruptcy and timeline.

## Root primitive

Operator-controlled hot wallet with:

1. No balance ceiling (could drain to zero).
2. No reconciliation against expected baseline (drift could
   accumulate unnoticed for years).
3. Insider risk: at least one drain path appears to have
   required operator-side knowledge / cooperation.
4. Unencrypted key material at one historical point.

This pattern recurs in exchange-tier custody failures:
- KuCoin (Sep 2020, $281M) — hot-wallet compromise
- Bitfinex (Aug 2016, ~120k BTC) — hot-wallet drain
- DMM Bitcoin (May 2024, $305M) — operator-environment
  compromise enabling drain (Lazarus, see SCN-011)
- WazirX (Jul 2024, $230M) — Liminal Custody multisig
  with insufficient guardian independence

## Mapping to LTP

LTP does not run an exchange-tier hot wallet. The OptimisticBridge-
Challenge contract is the only ETH-bearing contract and is gated
by per-challenge bond conservation (SCN-006). The off-chain
gateway VM's RPC submission account IS analogous to a hot wallet
for gas purposes — its defenses (MG1-MG4 in README) are
operational policy, not contract code.

## Date of last verification

2026-05-17 — SCN-014 documented under R-3.
