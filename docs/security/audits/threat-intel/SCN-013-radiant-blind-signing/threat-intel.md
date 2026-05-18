# SCN-013 — Threat intelligence sources

Historical incident: **Radiant Capital exploit, 16 October 2024, ~\$58M.**

## Primary sources

- **Radiant Capital post-mortem** —
  https://medium.com/@RadiantCapital/radiant-capital-incident-update-e56d8c23829e
  Detailed walk-through of the attack, including the malware
  injection vector and the blind-signing failure mode.
- **Patch / response**: validator rotation, pause, and external
  audit of the operator security posture.

## Secondary technical analyses

- **Mandiant** — Lazarus attribution and TTP analysis for the
  malware family used (a Mac-targeting variant of the
  TraderTraitor / AppleJeus toolkit).
- **SlowMist** — incident report focusing on the EIP-712
  signature-substitution primitive.
- **CertiK** — analysis of the executeTransactions() drain path.

## Root primitive

The operator trusted the wallet UI to display what was actually
being signed. The malware did NOT need to extract the hardware-
wallet seed; it only needed to manipulate what the operator
saw between Safe / wallet UI and the Ledger device. Three
signers in a 3-of-11 multisig confirmed substituted
transactions without realizing.

Two contributing factors specific to Radiant:
1. **Blind signing was acceptable in policy.** When the wallet
   UI couldn't fully decode an EIP-712 cross-chain message, the
   operator was allowed to confirm via raw-hash display.
2. **No independent verification step.** No second-device
   recomputation of the safeTxHash before confirmation.

The general failure mode shows up in any signing flow where:
- the SIGNED bytes are not what the OPERATOR thinks they're
  signing, and
- there is no second source of truth that the operator can
  cross-check against.

Related incidents that share elements of this primitive:
- Wintermute hot-wallet compromise (Sep 2022) — Profanity-
  generated vanity address keys.
- Multiple "address-poisoning" attacks against retail signers.
- Various Ledger Connect Kit / npm supply-chain attacks
  (SCN-026 will cover this class).

## Mapping to LTP

LTP has no direct on-chain primitive for this class — the attack
target is the human signer, not the contract. The defense lives
in operational policy: never blind-sign mainnet, pre-verify on
a separate device, treat malware-on-host as an active incident.

The campaign deliverable is a new section §13.5 of
`docs/OPERATOR_RUNBOOK.md` ("Hardware-wallet signing protocol")
to be drafted with the operator team during the R-5 drill.

## Date of last verification

2026-05-17 — SCN-013 documentation added under R-3.
