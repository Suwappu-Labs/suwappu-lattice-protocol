# SCN-002 — Threat intelligence sources

Historical incident: **Nomad Bridge exploit, 1 August 2022, ~$190M.**

## Primary sources

- **Nomad post-mortem** (project team) —
  https://medium.com/nomad-xyz-blog/nomad-bridge-hack-root-cause-analysis-875ad2e5aacd
  (archive snapshot recommended).
- **Patch PR** in `nomad-xyz/monorepo` removing the zero-hash trust
  default — referenced in the post-mortem.

## Secondary technical analyses

- **samczsun thread** — minutes-old root-cause walkthrough.
- **Paradigm research** — "Anatomy of the Nomad Hack" (paradigm.xyz).
- **Rekt News** — https://rekt.news/nomad-rekt/
- **Trail of Bits** — retrospective on initializer-time invariants.

## Root primitive

A routine upgrade set `confirmedRoots[bytes32(0)] = 1` in the Replica
contract's initializer, making the zero hash a "verified root".
`prove()` then accepted any message whose root defaulted to
`bytes32(0)`. Structural lesson: **never pre-trust a sentinel value
at initialization time.**

This is a class of "init-time default" bug shared with several other
incidents. The general defense is **zero-value rejection at function
boundaries** combined with **initializer one-shot enforcement**.

## Mapping to LTP

LTP rejects bytes32(0) for every primary input in `_anchor()` (lines
524-527), `transitionState()` (230-231), `registerSigner()` (282),
`rotateSigner()` (321), and `_anchorWithBinding()` (342-343). The
`policyHash == bytes32(0)` sentinel is intentionally allowed but
documented as "no on-chain policy enforced" — and the test pack
verifies it does NOT short-circuit replay or sequence defenses.

The OpenZeppelin `Initializable` pattern (`_disableInitializers()`
in the implementation constructor + `initializer` modifier on
`initialize()`) ensures `initialize()` runs exactly once on the
proxy and never on the implementation directly.

## Date of last verification

2026-05-16 — SCN-002 added under R-2.
