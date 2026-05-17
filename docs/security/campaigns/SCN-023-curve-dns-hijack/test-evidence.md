# SCN-023 — Test evidence

No LTP dApp domain exists today; structurally-N/A. Policy items
C1-C6 captured in the scenario README for future activation.

## Documentation deliverables

| Deliverable | Status | Location |
|---|---|---|
| Scenario README + threat-intel | this commit | `docs/security/campaigns/SCN-023-curve-dns-hijack/` |
| C1-C6 policy items | drafted in README | will move to OPERATOR_RUNBOOK §13.7 when a dApp is added |

## Activation trigger

This scenario becomes ACTIVE when LTP first hosts a customer-
facing dApp domain. At that point:

1. The C1-C6 policies must be in place BEFORE the domain goes
   live.
2. A new `dapp-frontend-deploy-checklist.md` should be added
   to `docs/`.
3. An external DNS-monitoring service should be wired up.
4. The C1-C6 items should move into OPERATOR_RUNBOOK §13.7.
