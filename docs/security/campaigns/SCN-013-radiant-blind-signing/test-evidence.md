# SCN-013 — Test evidence

This scenario has no code-level test pack. The attack surface is
human-in-the-loop UX; verification requires a live operator
drill, deferred to R-5 with operator consent.

## Documentation deliverables

| Deliverable | Status | Location |
|---|---|---|
| Scenario README + threat-intel | this commit | `docs/security/campaigns/SCN-013-radiant-blind-signing/` |
| Operator-runbook §13.5 (Hardware-wallet signing protocol) | drafted in README, formalization deferred | `docs/OPERATOR_RUNBOOK.md` (future) |
| Live tabletop drill transcript | deferred to R-5 | `transcript.md` in this directory (will be added) |

## Operator-policy items pinned

- O1: Never blind-sign on mainnet.
- O2: Pre-verify transaction bytes on a separate device.
- O3: Use Wallet-Connect via a dedicated signing browser.
- O4: Independent transaction-summary verification.
- O5: Treat malware-discovery as an active incident.

See README for details.
