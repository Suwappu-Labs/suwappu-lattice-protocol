# SCN-021 — Threat intelligence sources

Historical incident: **Cream Finance exploit, 27 October 2021, ~\$130M.**

This was Cream's THIRD major incident in 2021 (Feb ~\$37M, Aug
~\$19M, Oct ~\$130M); SCN-021 covers the October incident
specifically since it cleanly combined flashloan + oracle
primitives.

## Primary sources

- **Cream Finance post-mortem** — Medium / project blog.
- **Patch PR** in the Cream monorepo removing the vulnerable
  oracle path.

## Secondary technical analyses

- **PeckShield** — call-trace breakdown of the flashloan +
  oracle composition.
- **SlowMist** — incident report.
- **Halborn / Trail of Bits** — retrospectives on flashloan-
  resistant oracle design.

## Root primitive

Two orthogonal primitives composed atomically:

1. **Flashloan** — atomic access to very-large capital that
   must be repaid in the same transaction.
2. **Manipulable on-chain oracle** — a price source whose
   value depends on caller-controllable state (vault
   balances, AMM reserves, supply/demand ratios).

Defenses against the composition are:

- **Don't expose flashloan surfaces** when not needed for
  protocol UX.
- **Use TWAP** (time-weighted) over enough blocks that
  flashloan-scale movements can't shift the average.
- **Aggregate independent oracles** (Chainlink + Pyth +
  RedStone) — the attacker would need to manipulate all
  feeds simultaneously.
- **Circuit breakers** that pause on >X% divergence.

## Mapping to LTP

LTP has neither primitive. It has no flashloan source (bonds
must be self-funded) AND no on-chain price oracle (verified by
grep). The composition cannot apply.

## Date of last verification

2026-05-17 — SCN-021 added under R-4.
