# SCN-003 — Threat intelligence sources

Historical incident: **Poly Network cross-chain bridge exploit, 10 August 2021, ~$611M.**

## Primary sources

- **Poly Network post-mortem** —
  https://medium.com/poly-network/poly-network-incident-report-2021-08-10-2a40e2f0e9fa
  (archive snapshot recommended).
- **Patch** removing the keeper-rotation path from the cross-chain
  message handler — referenced in the post-mortem.

## Secondary technical analyses

- **Mudit Gupta technical breakdown** —
  https://mudit.blog/poly-network-largest-defi-hack/
  Walks through `verifyHeaderAndExecuteTx` →
  `_executeCrossChainTx` → `putCurEpochConPubKeyBytes`.
- **Rekt News** — https://rekt.news/polynetwork-rekt/
- **SlowMist analysis** — independent reproduction of the cross-
  chain message construction.
- **Samczsun thread** — early triage.

## Root primitive

A cross-chain message handler treated `(target, method, args)` from
caller-supplied data as an instruction to execute. The contract
forwarded the call without checking the target was outside the
privileged set. Effectively the privilege boundary moved into
caller data, where it could be controlled by anyone able to
construct a valid cross-chain message envelope.

The structural lesson: **privilege boundaries belong in
`msg.sender` checks (or onchain-only context), never in caller-
supplied target / method fields.**

Related incidents that share this primitive include several
governance-token-bridge bugs (chainsafe-class), and the broader
class of "delegatecall to user-supplied address" bugs.

## Mapping to LTP

LTP has no generic-forwarder. Every privileged function in
`LTPAnchorRegistry` is gated by `msg.sender` against a concrete
role — `onlyAdmin` or `bindingDisputeVerifier`. The Poly-equivalent
attack collapses to "non-privileged caller invokes a privileged
function", which every defense rejects.

The audit's BY-DESIGN trust assumption for LTP-A-001 — "thin
on-chain, thick off-chain" — depends on these privilege gates
being airtight. SCN-003 is the executable proof that they are.

## Date of last verification

2026-05-16 — SCN-003 added under R-2.
