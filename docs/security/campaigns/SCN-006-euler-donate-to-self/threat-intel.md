# SCN-006 — Threat intelligence sources

Historical incident: **Euler Finance exploit, 13 March 2023, ~$197M (later recovered).**

## Primary sources

- **Euler Labs post-mortem** —
  https://medium.com/euler-xyz/euler-protocol-statement-on-the-13th-march-2023-attack-25aa2ad6dc06
- **Patch PR** in Euler's monorepo introducing donation-time debt
  check.

## Secondary technical analyses

- **OpenZeppelin / Halborn writeups** — root-cause walkthroughs.
- **Rekt News** — https://rekt.news/euler-rekt/
- **Mudit Gupta** — technical breakdown of the donateToReserves +
  self-liquidation chain.

## Root primitive

A write path mutated protocol-wide accounting totals without
maintaining the per-account invariant. The general lesson:
**any function that adjusts protocol-level state must also
update the per-actor state it depends on.** Donation/contribution
functions are the canonical surface where this gets missed.

Related incidents:
- Compound (2021): `COMP` distribution accounting that double-
  credited certain accounts after a governance proposal.
- bZx / Fulcrum (multiple): oracle + flashloan combinations
  that effectively let an attacker "donate" price to themselves.
- Beanstalk (2022): governance vote-weight accounting bypass.

## Mapping to LTP

LTP's accounting surface is the bond escrow in
`OptimisticBridgeChallenge`. The Euler-equivalent attack requires
a donation path; LTP has none (no `receive()`, no `fallback()`,
no `donate` function). The only ETH-receiving entrypoints are
`openWindow` and `submitChallenge`, both of which update bond
state atomically with receipt.

The residual force-deposit primitive (selfdestruct) is detected
by the existing `invariant_bonds_conserved` strict-equality
check.

## Date of last verification

2026-05-16 — SCN-006 added under R-2.
