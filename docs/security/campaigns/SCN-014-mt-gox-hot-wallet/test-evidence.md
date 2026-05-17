# SCN-014 — Test evidence

Structurally-N/A: LTP has no on-chain hot-wallet primitive.

## Documentation deliverables

| Deliverable | Status | Location |
|---|---|---|
| Scenario README + threat-intel | this commit | `docs/security/campaigns/SCN-014-mt-gox-hot-wallet/` |
| Operator policy items MG1-MG4 | drafted in README; formalization deferred | future `OPERATOR_RUNBOOK.md` §11, §13.6 |

## Adjacent test coverage

The relevant defenses are already pinned elsewhere:

| Defense | Pinned by |
|---|---|
| OptimisticBridgeChallenge has no `receive()` / `fallback()` | SCN-006 V1 |
| Bond conservation (no drift between balance and tracked bonds) | `contracts/test/invariant/OptimisticBridgeChallenge.invariant.t.sol::invariant_bonds_conserved` |
| HSM trust boundary | SCN-011 L1-L8 |
| Threshold-signing for operator-key custody | SCN-012 C1-C5 |
