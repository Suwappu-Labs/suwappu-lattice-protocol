# LTP Red-Team Campaign — May 2026

**Authorization.** This campaign operates under
[`/SECURITY_TESTING.md`](../../SECURITY_TESTING.md). All scenarios are
defensive regression tests authored against LTP's own code in
isolated environments.

**Status.** COMPLETE as of 2026-05-17. R-1 through R-4 closed
with all contract-tier and infra-tier defenses verified. R-5
(social-engineering tabletops) scaffolded; live drills deferred
to operator-team consent. **One real bug surfaced and fixed:
LTP-A-031** (`_anchor()` ignored `signerExpiresAt`).

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
| R-1 | Charter + foundation (this file, charter doc, dir skeleton) | ✓ CLOSED (PR #12) |
| R-2 | Layer 1 (contract input validation) — scenarios 1-7 | ✓ CLOSED (PRs #13, #14, #15, #16, #17, #18, #19) |
| R-3 | Layer 2-4 (signing, key, governance) — scenarios 8-19 | ✓ CLOSED (PRs #20, #21, #22, #23, #24, #25, #26) |
| R-4 | Layer 5-7 (oracle, frontend, infra) — scenarios 20-30 | ✓ CLOSED (PR #27) |
| R-5 | Layer 8 (social-engineering tabletops) — scenarios 31-33 | SCAFFOLDED — live drills pending operator consent |
| R-6 | Wrap-up + back-link to audit doc | ✓ CLOSED (this commit) |

## Scenario roster

The full layered roster lives in
[`campaigns/README.md`](campaigns/README.md). Each row links to its
per-scenario evidence directory once that scenario enters R-2 through
R-5.

## Findings produced

| Finding | Scenario | Severity | Linear | Remediation PR | Status |
|---|---|---|---|---|---|
| **LTP-A-031** | SCN-015 (Signer-rotation grace race) | HIGH | [GLO-832](https://linear.app/globalsettlement/issue/GLO-832) | [PR #26](https://github.com/GlobalSettlementNetwork/gsx-lattice-protocol/pull/26) — commit `577e80f` | ✓ REMEDIATED-GREEN |

**One real finding surfaced + fixed across the entire 33-scenario
campaign.** `LTPAnchorRegistry._anchor()` checked
`authorizedSigners[signerVkHash]` but did NOT check
`signerExpiresAt[signerVkHash]`, contrary to its doc-comment.
`transitionState()` correctly checked expiry. The two paths
diverged; a rotated-out key continued to satisfy `anchor()`
indefinitely after the grace window. Fix at
`LTPAnchorRegistry.sol:541-549` mirrors `transitionState`'s
check. SCN-015 test G6 is the regression test.

## Final report

### Scenario outcomes

| Outcome | Count | Examples |
|---|---|---|
| VERIFIED-GREEN (defense pre-existed, regression test pinned) | 20 | SCN-001 Wormhole, SCN-002 Nomad, SCN-003 Poly, SCN-004 Orbit, SCN-005 Penpie, SCN-006 Euler, SCN-007 THORChain, SCN-008 Ronin, SCN-009 Harmony, SCN-010 BLS, SCN-011 HSM, SCN-012 Multichain, SCN-016 Pause-upgrade, SCN-017 LayerZero, SCN-019 Timelock, SCN-024 Vyper, SCN-026 Ledger Connect Kit, SCN-028 Gateway bind, SCN-029 gRPC limits, SCN-030 IBC replay |
| REMEDIATED-GREEN (test surfaced bug, fix landed same branch) | 1 | **SCN-015 (Signer-rotation grace; LTP-A-031)** |
| STRUCTURALLY-N/A (attack surface doesn't exist in LTP) | 5 | SCN-014 Mt Gox, SCN-018 Parity, SCN-020 Mango, SCN-021 Cream, SCN-022 bZx |
| PARTIAL / DOC-ONLY (defense lives in policy not code; no on-chain surface today) | 4 | SCN-013 Radiant, SCN-023 Curve DNS, SCN-025 Badger Cloudflare, SCN-027 Mixin cloud |
| SCAFFOLDED — live drill deferred (operator consent gate) | 3 | SCN-031 Ronin recruiter, SCN-032 Inferno Drainer, SCN-033 Heco OPSEC |
| **TOTAL** | **33** | |

### Aggregate test-suite size

- **Forge tests added:** ~70 across 9 new files in
  `contracts/test/security/historical/SCN_*.t.sol`
- **Forge invariants added:** 8 (3 SCN-001, 2 SCN-002, 2
  SCN-003, 1 SCN-005) plus 1 reused (`invariant_bonds_conserved`)
- **Echidna harnesses added:** 5 (SCN-001..005)
- **pytest tests added:** ~50 across 5 new files in
  `tests/security/historical/test_scn_*.py`
- **Docs added:** ~100 markdown files across 30 campaign
  directories under `docs/security/campaigns/`
- **Contract code changed:** 5 LOC patch to
  `LTPAnchorRegistry.sol:541-549` (LTP-A-031 fix)

### Residual risks accepted

| Risk | Acceptance rationale |
|---|---|
| Live tabletop drills (SCN-031..033) not yet executed | Charter requires explicit operator-team consent; scaffolding complete and pre-drill checklist documented. Drills scheduled at operator-team's discretion. |
| SCN-013 / SCN-023 / SCN-025 / SCN-027 operational policies drafted but not yet in `OPERATOR_RUNBOOK.md` | These policies activate when LTP first hosts a dApp or formalizes the operator-team's cloud-account boundary. Tracked in scenario READMEs. |
| Fork-tests deferred (SCN-008 noted possible variant) | Deployed instance runs same bytecode as the local-deploy test target; fork-test adds no new defensive value. |

### Audit doc back-link

`docs/SECURITY_AUDIT_2026-05-15.md` §28 has been updated to
add the LTP-A-031 row alongside LTP-A-001..LTP-A-030. Each row
in the historical-incident → LTP-A-* mapping now cites the
corresponding SCN-XXX directory for executable verification.

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
