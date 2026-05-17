# SCN-013 — Radiant Capital blind-signing

**Status.** DOCUMENTATION-COMPLETE. Live drill deferred to R-5 with operator consent.
**Layer.** 3 — Key management (operator-tier).
**Historical incident.** Radiant Capital, 16 Oct 2024, ~\$58M.
**LTP-A-* link.** [LTP-A-004](../../../SECURITY_AUDIT_2026-05-15.md)
(single-custody operator signing key) + a new operator-runbook
addition for hardware-wallet blind-signing policy.

## What happened (Radiant)

Radiant Capital ran a 3-of-11 multisig on Arbitrum / BNB Chain.
The attacker (Lazarus, per Mandiant attribution) used a months-
long social-engineering campaign to deliver a Mac-malware payload
to multiple signers. The malware did NOT extract the hardware-
wallet keys (which is hard). Instead it manipulated **what the
hardware wallet displayed to the operator**:

1. The operator initiates a legitimate transaction in Safe / wallet UI.
2. The transaction is forwarded to the Ledger hardware wallet.
3. Most Ledger devices show a transaction summary that the
   operator confirms by pressing a physical button.
4. For complex EIP-712 / cross-chain messages, many UIs fall back
   to "blind signing" — the device shows raw hex / hash, not a
   human-readable transaction summary.
5. The malware intercepted the transaction bytes between the host
   and the Ledger, and substituted a different transaction (with
   the same EIP-712 hash prefix that the operator was checking).
6. The operator confirmed the displayed summary, but the device
   signed the swapped transaction.

Three signers fell for this in sequence. The transaction
authorized an `executeTransactions()` call that drained the
bridge.

Root primitive: **the operator trusted the wallet UI to display
what was actually being signed.** Blind signing — accepting a
"sign this hash" prompt without independent verification of the
underlying intent — is the failure mode.

## LTP analogue

LTP has no direct on-chain analogue for SCN-013 — this is purely
an operator-tier attack against the human-in-the-loop signing
flow. The defense lives in operational policy. The recommended
additions to `docs/OPERATOR_RUNBOOK.md`:

### Operator-policy additions (drafted)

**O1. Never blind-sign on mainnet.**
If the wallet UI cannot display a fully-decoded transaction
summary on the Ledger device, abort. Do not proceed with "sign
this hash."

**O2. Pre-verify transaction bytes on a separate device.**
Before initiating any multisig confirmation, compute the
`safeTxHash` (or equivalent) on a clean device — air-gapped if
the operation is high-value — and confirm it matches the hash
shown on the Ledger. This catches host-malware substitution.

**O3. Use Wallet-Connect via a dedicated signing browser.**
The browser used for multisig confirmation should be a
dedicated, isolated profile / VM / device. No general
browsing, no extensions, no other dApps.

**O4. Independent transaction-summary verification.**
For deployments through the Timelock (24h delay), the second
signer should INDEPENDENTLY reconstruct the queued
transaction's payload from the contract source + the human-
described intent, and compute its hash. Compare to the
Timelock event's `id` field.

**O5. Treat malware-discovery as an active incident.**
If any signer's host shows signs of compromise (unexpected
processes, unfamiliar dialogs, transactions that look
different than initiated), STOP the in-flight transaction
proposal and rotate the affected signer's hardware wallet to
a fresh seed on clean hardware. Treat the in-flight proposal
as compromised regardless of whether it has been confirmed.

These policies should be merged into `OPERATOR_RUNBOOK.md` §13
(production deploy checklist) as a new sub-section §13.5
"Hardware-wallet signing protocol" — to be drafted with the
operator team during the live drill.

## Test pack

| Test type | Path | What it pins |
|---|---|---|
| **No pytest / forge tests.** | _structural_ | The attack surface is human-in-the-loop UX; there is no contract-level or SDK-level primitive to test. |

The verification path is **a live operator drill** — the
campaign plan's "tabletop (operator runbook drill)" — which is
deferred to R-5 with operator sign-off per the campaign charter
(SECURITY_TESTING.md §3).

## Cross-references

- **SCN-011** (Lazarus HSM trust boundary) — the cryptographic
  layer this scenario's UX issue sits above
- **SCN-012** (Multichain single-custody) — operational
  distribution of signing authority
- **SCN-031** (Ronin fake-recruiter LinkedIn DM) — the initial-
  access primitive that delivered the Radiant malware
- **OPERATOR_RUNBOOK §13** — production deploy checklist; will
  gain §13.5 from this scenario's drill

## Findings opened

No code findings. One **operator-runbook gap** identified: no
explicit blind-signing policy. This will be authored
collaboratively with the operator team during the R-5 drill.
