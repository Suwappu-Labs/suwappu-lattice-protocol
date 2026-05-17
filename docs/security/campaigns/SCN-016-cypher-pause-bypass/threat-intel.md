# SCN-016 — Threat intelligence sources

Historical incident: **Cypher Protocol exploit, 7 August 2023, ~\$1M.**

## Primary sources

- **Cypher Protocol post-mortem** — published shortly after the
  incident on the team's Twitter / Mirror.
- **Patch / upgrade** restoring the pause primitive's integrity.

## Secondary technical analyses

- **SlowMist** — Solana program upgrade-bypass analysis.
- **Rekt News** coverage (excluded from lychee per the
  established pattern; search "Cypher Protocol rekt" for the
  current location).
- **Halborn / Trail of Bits** retrospectives on
  pause + upgrade co-governance.

## Root primitive

Pause and upgrade are **co-governing controls**: if one can lift
or bypass the other, the pause is illusory. The structural
defense is *same-gate co-control* — both operations require the
same authority (admin / governance multisig / timelock), so an
attacker who could lift one could have lifted the other directly.

This class also includes:
- Several Solana programs that allowed `upgrade_authority` to
  override pauses.
- Various Ethereum proxy patterns where the proxy admin's
  authority over upgrades was decoupled from the implementation's
  pause gate.

## Mapping to LTP

LTP's `LTPAnchorRegistry` co-controls pause and upgrade behind
`onlyAdmin`. In production the admin is the
`TimelockController`, which adds a 24h delay per `DeployMainnet`
(SCN-019). An attacker who somehow gained admin would still face
the delay before either operation took effect.

## Date of last verification

2026-05-17 — SCN-016 added under R-3.
