# SCN-008 — Threat intelligence sources

Historical incident: **Ronin Bridge exploit, 23 March 2022, ~$625M.**

## Primary sources

- **Ronin Network post-mortem** (Sky Mavis) —
  https://roninblockchain.substack.com/p/community-alert-ronin-validators
- **Patch PRs** removing the Axie DAO gas-relayer trust and
  rotating all 9 validator keys.

## Secondary technical analyses

- **Chainalysis attribution** — DPRK / Lazarus Group attribution
  via post-exploit fund movement.
- **Rekt News** — https://rekt.news/ronin-rekt/
- **CertiK / Halborn / Trail of Bits** — retrospectives on the
  social-engineering + delegated-signature primitive.
- **DOJ press release (2022-04-14)** — Treasury sanctions on the
  exploit wallet, attributing to Lazarus.

## Root primitive

A multisig's effective threshold collapsed because:

1. **Inactive signers** in the nominal set didn't lower M-effective
   when the relationship ended. The contract had no concept of
   "active" vs "inactive"; off-chain operations did, but they
   weren't reflected on-chain.
2. **Proxy / gas-relayer flow** let one signing key produce
   signatures attributable to a different validator. The
   on-chain instance had no way to distinguish "Sky Mavis signed
   for Axie DAO" from "Axie DAO signed for itself."

Lazarus then compromised the 4 Sky-Mavis-controlled keys (via a
fake-LinkedIn-recruiter payload delivered as a PDF) and abused
the still-active gas-relayer flow to manufacture the 5th
signature.

Same primitive in different shape: Harmony Horizon (Jun 2022,
2-of-5 compromised — SCN-009), Multichain (Jul 2023, single-
custody collapse — SCN-012), DMM Bitcoin (May 2024, exchange-
side compromise), WazirX (Jul 2024, Liminal Custody multisig
compromise).

## Mapping to LTP

LTPMultiSig has no proxy-signing surface. Every confirmation is
gated by `msg.sender == owner`. There is no `permit`,
`executeWithSig`, or gas-relayer entrypoint. The deployed
instance on SUWAPPU Testnet runs the same bytecode (verified via
`docs/DEPLOYED_CONTRACTS.md`).

The operator-tier hardening for sustained key compromise
(HSM custody, active-set monitoring, regular rotation) is
covered by LTP-A-004 and the operator runbook — see SCN-011
(Lazarus-tier sustained key compromise) for the operational
analogue.

## Date of last verification

2026-05-16 — SCN-008 added under R-3.
