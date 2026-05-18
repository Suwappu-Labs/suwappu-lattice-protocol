# SCN-001 — Threat intelligence sources

Historical incident: **Wormhole Token Bridge exploit, 2 February 2022, $326M.**

## Primary sources

- **Certus One / Wormhole post-mortem** (project team) —
  https://medium.com/wormhole-foundation/wormhole-incident-report-02-02-22-ad9b8f21eec6
  (archive snapshot recommended; project blogs move).
- **Wormhole patch PR** introducing the sysvar-instructions account
  check — search GitHub `wormhole-foundation/wormhole` for the 2022-02
  Solana bridge fix.

## Secondary technical analyses

- **Samczsun thread + breakdown** — root-cause walk-through within
  hours of the exploit; archived on Twitter (`samczsun`).
- **Kudelski Security analysis** — independent reproduction of the
  `verify_signatures` spoofing primitive.
- **Rekt News** — https://rekt.news/wormhole-rekt/
- **Immunefi report** — accompanying bounty-context publication.

## Root primitive

The Solana program trusted an account it should have validated. The
"have signatures been verified?" signal was derived from caller-
supplied account data rather than from a hard-coded canonical
account address.

In bridge-design terms this is a **fraud-proof-substrate trust
boundary** failure: the contract relied on an off-chain (or off-
program) verification step but accepted unauthenticated evidence of
that step having occurred.

## Mapping to LTP

LTP makes the same architectural choice (no on-chain ML-DSA
verification, deliberate; see LTP-A-001 BY-DESIGN). Where Wormhole
left the trust-boundary exposed via a spoofable account, LTP gates
the on-chain path via `authorizedSigners[signerVkHash]` membership
plus seven additional defenses (D1-D9 in `README.md`). The
defensive companion is `OptimisticBridgeChallenge.finalizeUnchallenged()`
(see LTP-A-006) which removes the admin-monopoly resolver and lets
anyone close an unchallenged window.

## Date of last verification

2026-05-16 — SCN-001 added under PR for R-2.
