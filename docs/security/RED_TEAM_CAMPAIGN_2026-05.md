# LTP Red-Team Campaign — May 2026

**Authorization.** This campaign operates under
[`/SECURITY_TESTING.md`](../../SECURITY_TESTING.md). All scenarios are
defensive regression tests authored against LTP's own code in
isolated environments.

**Status.** Phase R-1 (Charter + Foundation) — IN PROGRESS as of
2026-05-16.

**Plan reference.** Approved plan:
`/Users/mongolraider/.claude/plans/tingly-wondering-pike.md` (local).

## Objective

The merged [`SECURITY_AUDIT_2026-05-15.md`](../SECURITY_AUDIT_2026-05-15.md)
maps ~10 historical bridge hacks to LTP-A-001…LTP-A-030 in §28. The
mapping is theoretical; this campaign turns it executable.

Each historical incident becomes a **defensive regression test**: the
test replays the abstract attack pattern against the corresponding
LTP surface, and the test **passes** if LTP rejects the attack. A
test that fails on first run is a new finding — we open
LTP-A-031, LTP-A-032, … in `SECURITY_AUDIT_2026-05-15.md`, write the
fix, and re-run until the test goes green.

## Methodology

Adapted from TIBER-EU and MITRE ATT&CK, compressed for a single
protocol:

1. **Threat intelligence.** Start from a documented post-mortem
   (project blog, Rekt News, SlowMist, Trail of Bits, court filing).
   No speculation.
2. **Pattern abstraction.** Reduce the incident to its primitive
   (e.g., "signature-count check skipped", "validator key
   compromised", "frontend served by attacker CDN").
3. **LTP surface mapping.** Find the analogous function call, RPC
   endpoint, signing path, or operator workflow in LTP.
4. **Defensive-test authoring.** Write a `forge` / `pytest` test
   that replays the abstract pattern against the LTP surface and
   asserts the defense fires.
5. **Red → green loop.** Test passes → record evidence. Test
   fails → open finding, write patch, re-run.
6. **Evidence collection.** Per-scenario directory at
   `docs/security/campaigns/SCN-XXX-<slug>/` (README, threat-intel
   citations, test-evidence, remediation, optional transcript).

## Phases

| Phase | Scope | Status |
|---|---|---|
| R-1 | Charter + foundation (this file, charter doc, dir skeleton) | IN PROGRESS |
| R-2 | Layer 1 (contract input validation) — scenarios 1-7 | PLANNED |
| R-3 | Layer 2-4 (signing, key, governance) — scenarios 8-19 | PLANNED |
| R-4 | Layer 5-7 (oracle, frontend, infra) — scenarios 20-30 | PLANNED |
| R-5 | Layer 8 (social-engineering tabletops) — scenarios 31-33 | PLANNED |
| R-6 | Wrap-up + back-link to audit doc | PLANNED |

## Scenario roster

The full layered roster lives in
[`campaigns/README.md`](campaigns/README.md). Each row links to its
per-scenario evidence directory once that scenario enters R-2 through
R-5.

## Findings produced

This table accumulates as scenarios complete. Empty during R-1.

| Finding | Scenario | Severity | Linear | Remediation PR | Status |
|---|---|---|---|---|---|
| _(none yet — R-1 in progress)_ | — | — | — | — | — |

## Final report

Populated at R-6 close. Contains:

- Total scenarios run / passed / failed-then-fixed / deferred
- Aggregate test-suite size (LOC) and CI runtime
- Residual risks explicitly accepted (with rationale)
- Update to `SECURITY_AUDIT_2026-05-15.md` §28 to cite the new test
  files for each historical-incident row

## Cross-references

- [`/SECURITY_TESTING.md`](../../SECURITY_TESTING.md) — charter
- [`SECURITY_AUDIT_2026-05-15.md`](../SECURITY_AUDIT_2026-05-15.md) §28
  — historical-incident → LTP-A-* mapping (the source for this campaign)
- [`THREAT_MODEL.md`](../THREAT_MODEL.md) — protocol threat model
- [`FORMAL_VERIFICATION_STATUS.md`](../FORMAL_VERIFICATION_STATUS.md)
  — machine-checked surface
- [`OPERATOR_RUNBOOK.md`](../OPERATOR_RUNBOOK.md) — tabletop scenarios
  produce updates here
- [`CORRIDOR_INTEGRATION.md`](../CORRIDOR_INTEGRATION.md) — wire-format
  invariants
