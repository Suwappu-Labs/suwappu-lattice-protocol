# SCN-015 — Threat intelligence sources

This scenario covers a **structural class** of bug rather than a
single named incident — post-compromise key rotation across
multiple historical bridges has shipped with the "rotated-out
key keeps working in some forgotten path" failure mode.

## Adjacent historical incidents

- **Multichain (Jul 2023, ~\$125M)** — after the founder's
  detention, the team's attempted key-rotation across multiple
  validator addresses was incomplete; some addresses continued
  draining for weeks. See SCN-012.
- **Ronin post-fix (2024 secondary incident, ~\$12M)** — after
  the 2022 rotation, a re-issued operator key was front-run by
  an MEV bot.
- **Various Multisig key-rotation bugs** — in the broader
  ecosystem (Cosmos chains, Polygon plasma bridge, etc.) where
  the rotation logic touched one path but not its parallel.

## Primary sources

- **Vitalik Buterin's "anti-correlated signers" writing** —
  Discusses the operational difficulty of true key rotation in
  distributed signer sets. (Original URL has moved; search
  "Vitalik Buterin anti-correlated signers" for the current
  location.)
- **Trail of Bits "Audit of a Key Rotation"** — generic
  retrospective on rotation-bug failure modes.

## Root primitive

Authority is checked in MULTIPLE code paths. A rotation that
clears one path but not the other leaves residual authority on
the rotated-out key. The defense is **consistency-of-check**:
every code path that checks `is this signer authorized?` MUST
also check `is this signer's grace period over?`.

## Mapping to LTP

LTP's `LTPAnchorRegistry` has two signer-authorization paths:
`transitionState()` and `_anchor()`. Before LTP-A-031 fix,
the former checked `signerExpiresAt` and the latter did not.
The exact failure mode described above.

The fix at `LTPAnchorRegistry.sol:541-549` mirrors
`transitionState()`'s check, achieving consistency. SCN-015's
test G6 is the regression test for the fix.

## Date of last verification

2026-05-17 — SCN-015 added under R-3 (one-shot batch). LTP-A-031
surfaced during authoring; fix and test landed in same commit.
