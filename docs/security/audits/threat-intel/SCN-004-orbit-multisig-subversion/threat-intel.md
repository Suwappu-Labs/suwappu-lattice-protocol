# SCN-004 — Threat intelligence sources

Historical incident: **Orbit Bridge exploit, 1 January 2024, ~$82M.**

## Primary sources

- **Ozys / Orbit Chain announcements** (project team) — initial
  public statements via the team's X/Twitter and Medium accounts.
- **Klaytn / Ethereum block explorers** — on-chain trace of the
  drain transactions.

## Secondary technical analyses

- **Rekt News** — https://rekt.news/orbit-bridge-rekt/
- **SlowMist analysis** — independent reproduction of the
  cross-chain message construction and signature collection.
- **Chainalysis crypto crime report (Q1 2024)** — DPRK
  attribution discussion.

## Root primitive

A multisig (7-of-10) signed validator approvals for cross-chain
withdrawals. The attacker assembled enough valid signatures to
clear the 7-signature threshold. Public details about HOW remain
partially disputed — possibilities range from straightforward key
compromise (most likely Lazarus tooling) to reuse of stored
signatures or weaknesses in signature-domain separation.

Structurally, every multisig-threshold subversion incident
(Orbit, Ronin, Harmony) reduces to the same lesson: **the
advertised N-of-M is only as strong as the weakest M keys in
custody.** Defenses against this class are:

- Concrete signer threshold checked on every execute path
- Owner-set and threshold mutation gated by the multisig itself
- HSM-protected key custody (operator-tier control)
- Active-set monitoring (Ronin's failure: 4 of 9 keys were inactive)

## Mapping to LTP

The contract-layer claim is straightforward: `LTPMultiSig` never
executes a transaction with `confirmations < threshold`, never
permits a unilateral threshold change, and rejects every non-
owner caller. The operator-layer claim (HSM custody, active-set
monitoring) is addressed separately — see LTP-A-004 and the
OPERATOR_RUNBOOK key-rotation procedure.

## Date of last verification

2026-05-16 — SCN-004 added under R-2.
