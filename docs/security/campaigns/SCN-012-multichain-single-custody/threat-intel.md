# SCN-012 — Threat intelligence sources

Historical incident: **Multichain (Anyswap) collapse, May–July 2023, ~\$125M cumulative drain.**

## Primary sources

- **Multichain team communications** — sparse public statements
  on the project's X/Twitter and Discord during the May–July
  2023 window. The team disbanded shortly after; the archived
  statements are the canonical record of what was acknowledged.
- **Chinese authorities** — public statements confirming the
  founder/CEO detention.

## Secondary technical analyses

- **Chainalysis** — fund-tracing through Multichain's MPC-managed
  addresses.
- **Rekt News** — https://rekt.news/multichain-rekt/
- **PeckShield / SlowMist** — early-warning analyses of the
  unusual on-chain activity preceding the public acknowledgement.
- **Halborn** — retrospective on MPC-based custody and the
  "shared but not really" failure mode.

## Root primitive

Multichain advertised an MPC-managed multi-validator setup. In
practice, the cryptographic shares were held by a single
operational principal — the founder/CEO. When that principal
became unavailable (detention), the organization could not act
collectively despite the cryptographic infrastructure ostensibly
supporting collective control.

The structural lesson: **the cryptographic threshold is only as
strong as the operational distribution of the shares**. A 3-of-5
MPC where all 5 shares live on devices controlled by one
individual is operationally 1-of-1.

This pattern recurs:
- Multichain (May 2023) — single principal
- HTX / Sun's Heco era (Nov 2023) — operational hygiene
  collapse under one entity
- DMM Bitcoin (May 2024) — single-environment compromise
- WazirX (Jul 2024) — Liminal Custody multisig where the
  guardian set lacked independence

## Mapping to LTP

LTP's threshold-signing module
(`src/ltp/execution/committee/dkg/threshold_signing.py`) generates
shares via a real DKG protocol, with each participant's share
held by a distinct cryptographic identity. The contract-tier
multisig (LTPMultiSig + DeployMainnet's Byzantine floor) is the
second orthogonal layer.

The "operational distribution of shares" is documented in
`OPERATOR_RUNBOOK.md` (key custody policy) and is tested via the
tabletop drills planned for R-5 (SCN-031, SCN-032, SCN-033).

This scenario file pins ONLY the cryptographic layer — that no
combination of fewer-than-threshold shares or duplicate shares
can produce a valid signature.

## Date of last verification

2026-05-17 — SCN-012 added under R-3.
