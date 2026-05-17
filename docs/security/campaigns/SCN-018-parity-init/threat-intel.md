# SCN-018 — Threat intelligence sources

Historical incidents:
- **Parity Multisig Wallet bug, 19 July 2017, ~\$30M stolen**
  (three high-balance multisigs drained).
- **Parity Multisig Wallet "accidental kill", 6 November 2017,
  ~\$280M permanently frozen** (devops199 called `kill()` on
  the library, destroying the delegatecall target for all
  dependent instances).

## Primary sources

- **Parity Technologies post-mortems** (two separate documents,
  one per incident).
- **Ethereum Foundation post-incident statements** — covering
  both the technical mechanism and the broader implications for
  upgradable-contract design.

## Secondary technical analyses

- **OpenZeppelin "Parity Hack Explained"** — the canonical
  technical breakdown.
- **Trail of Bits** — retrospectives on `_disableInitializers`
  and the UUPS pattern that followed.
- **ConsenSys Diligence** — broader analysis of "init-on-impl"
  as a class.

## Root primitive

Two distinct primitives:

1. **Uninitialized implementation / library contract.** A
   contract whose `initialize` function is not gated against
   being called by anyone, anywhere. Anyone can claim
   ownership.
2. **`selfdestruct` in upgradable infrastructure.** Even with
   correct ownership, `selfdestruct` removes the bytecode and
   breaks all downstream `delegatecall` consumers.

Modern UUPS-pattern contracts address both:
- `_disableInitializers()` in the implementation constructor
  prevents direct initialization.
- Avoid `selfdestruct` entirely in upgradable code; rely on
  `_authorizeUpgrade` for governance over the implementation
  pointer.

## Mapping to LTP

LTP's `LTPAnchorRegistry` follows the modern UUPS pattern:
- Constructor calls `_disableInitializers()` (line 97).
- `initialize` has the `initializer` modifier (line 104).
- No `selfdestruct` anywhere in the contract.
- Upgrade authorization via `_authorizeUpgrade(newImpl)`
  `onlyAdmin` (line 153) — see SCN-016 for the upgrade-vs-pause
  co-control.

The defense pre-dates the campaign. SCN-018 ties the historical
incident to LTP's existing defense for future auditors.

## Date of last verification

2026-05-17 — SCN-018 cross-reference doc added under R-3.
