# LTP Red-Team Campaign — June 2026

**Theme.** Economic and griefing attacks against the
`OptimisticBridgeChallenge` bond mechanism.

**Authorization.** This campaign operates under
[`/SECURITY_TESTING.md`](../../../../SECURITY_TESTING.md). All scenarios
are defensive regression tests authored against LTP's own code
in isolated environments. Same scope rules as the May 2026
campaign apply.

**Status.** R-1 OPEN (this charter). R-2..R-4 to be scoped on
charter approval.

**Predecessor.** Builds on the [May 2026 campaign](RED_TEAM_CAMPAIGN_2026-05.md)
and its [consolidated report](RED_TEAM_REPORT_2026-05.md) §11
item 2 — "Economic-attack modeling. `OptimisticBridgeChallenge`
has a bond mechanism. Adversarial bond pricing under EIP-1559
fee spikes, or griefing the challenge window, was not exercised."

## Why this campaign now

The May 2026 campaign closed with 33 scenarios verifying that
LTP rejects every known historical bridge-hack pattern. The
report's §11 explicitly named eight unexercised areas; bond
economics was the highest-ROI internal-testable item. This
campaign converts that recommendation into an executable test
pack.

`OptimisticBridgeChallenge` is the only ETH-bearing contract
in LTP today. It implements:

- An open/challenge/resolve state machine with bonds posted
  by both operator (`openWindow`) and challenger
  (`submitChallenge`).
- **Three independent resolution paths** (LTP-A-006 defense):
  admin (`resolveChallenge`), arbiter (`resolveChallengeByArbiter`),
  permissionless time-decay (`resolveByTimeDecay`).
- A ZK fraud-proof path (`finalizeWithFraudProof`) gated to
  `zkVerifier` (admin cannot call — LTP-A-001 defense).
- A ZK validity-proof refund path (`finalizeWithZKProof`).

Six invariants (I1–I6) already pin the bond-conservation,
double-finalize, and path-gating properties. This campaign
extends the test surface in directions the existing invariants
don't reach: **economic adversary scenarios** and
**adversarial transaction ordering**.

## Objective

Each scenario codifies an economic / griefing attack class
against the bond mechanism, then either:

1. Adds a regression test (forge fuzz, forge invariant,
   forge stateful sequence, or fork-sim) that confirms LTP
   rejects the attack — VERIFIED-GREEN; or
2. Identifies a real exploit path and follows the May charter's
   STOP-the-line rule (fix on same branch, open LTP-A-NNN,
   re-test until green) — REMEDIATED-GREEN.

The May charter's prompt-care policy applies unchanged: tests
are defensive verification, not offensive generation.

## Methodology

Same five-step pattern as the May 2026 campaign (TIBER-EU +
MITRE ATT&CK adapted), with one substitution at step 1:

1. **Threat-class input.** Start from a documented economic-
   attack class (Cantor-style mempool front-running,
   EIP-1559-induced incentive inversion, griefing under
   asymmetric cost) and/or LTP-internal threat-model node
   not yet exercised. Cite the post-mortem or paper.
2. **Pattern abstraction.** Reduce to a fuzz / sequence
   primitive (e.g., "many sequential submitChallenge calls
   with minimum bond", "submitChallenge tx ordered ahead of
   resolveChallenge in same block").
3. **LTP surface mapping.** Identify the entrypoint(s) in
   `OptimisticBridgeChallenge.sol` and the bond-state path
   to exercise.
4. **Test authoring.** Write the test as forge unit / fuzz /
   invariant / stateful-sequence (`Handler.sol` pattern, same
   as the existing invariant suite at
   `contracts/test/invariant/OptimisticBridgeChallenge.invariant.t.sol`).
   For EIP-1559 dynamics, use forge's `vm.fee()` and `vm.txGasPrice()`
   to simulate basefee sweeps. No mainnet broadcast.
5. **Red → green loop.** Pass on first run → VERIFIED-GREEN.
   Fail → finding, fix, re-test.

## Scenario roster

Seven scenarios, numbered to continue the unified SCN-XXX
sequence from the May campaign (SCN-001..033). All live under
`docs/security/audits/threat-intel/`.

| # | Attack class | Entrypoint(s) | Test type | Expected outcome |
|---|---|---|---|---|
| **SCN-034** | Challenge-window griefing (mass-spam) | `openWindow` × N + `submitChallenge` × N | forge stateful + fuzz | VERIFIED-GREEN expected (per-digest namespacing + bond floors) |
| **SCN-035** | EIP-1559 fee-spike incentive inversion | `submitChallenge` + `resolveChallenge` cost under variable `basefee` | forge fork-sim with `vm.fee()` sweep | May surface a new LTP-A-* if floor is too low |
| **SCN-036** | Cross-window reentrancy fallback | `resolveChallenge` → recipient fallback → `submitChallenge` on different digest | forge invariant with malicious recipient mock | VERIFIED-GREEN expected (contract-level `nonReentrant`) |
| **SCN-037** | Arbiter front-running (mempool ordering) | `resolveChallenge` vs `resolveChallengeByArbiter` tx ordering | forge stateful (first-resolution-wins) | VERIFIED-GREEN expected (idempotent status lock) |
| **SCN-038** | State-desync race | `submitChallenge` ordered against `resolveChallenge` on STATUS_OPEN | forge sequence fuzz | VERIFIED-GREEN expected (status guard at line 199) |
| **SCN-039** | Bond-asymmetry economic test | `setMinOperatorBond` / `setMinChallengerBond` skew | forge unit + docs | DOCUMENTATION-COMPLETE (governance concern, not a code bug) |
| **SCN-040** | Zero-bond intentionality | `setMinChallengerBond(0)` then `submitChallenge{value:0}` | forge unit + docs | DOCUMENTATION-COMPLETE (intentional admin tunable; pin invariant that zero is symmetric) |

Numbering continues the May campaign so the
`docs/security/audits/threat-intel/SCN-XXX-<slug>/` index stays unified
across all campaigns.

## Phases

| Phase | Scope | Deliverable |
|---|---|---|
| R-1 | Charter + foundation (this file) | PR opened today; landing target same day |
| R-2 | SCN-034..038 — forge invariants + stateful sequence tests | One PR; per-SCN commit |
| R-3 | SCN-035 — EIP-1559 fork-sim (separate because needs `vm.fee()` plumbing) | One PR |
| R-4 | SCN-039, SCN-040 — economic documentation + zero-bond invariant | One PR; closes campaign |
| R-5 | Wrap-up — consolidated audit report addendum + back-link from RED_TEAM_REPORT_2026-05.md §11 item 2 | One PR; closes campaign |

Per-phase PR titles follow the May convention:
`docs(security): R-N — <scope>` for charter/doc PRs,
`test(security): R-N SCN-NNN — <slug>` for test PRs.

## Surface inventory (from R-1 exploration)

Captured from a read of `contracts/src/OptimisticBridgeChallenge.sol`:

**Bond state.** `operatorBond`, `challengerBond` (per Challenge),
`minOperatorBond`, `minChallengerBond` (admin-tunable),
`resolutionGracePeriod` (14 days default; ≥24h floor).

**ETH-moving entrypoints.**

- `openWindow{value}` (line 151) — opener deposits operatorBond.
- `submitChallenge{value}` (line 175) — challenger deposits.
- `resolveChallenge` (line 197) — admin only; pays totalBonds to winner.
- `finalizeWindow` (line 218) — permissionless, refunds unchallenged operator.
- `resolveChallengeByArbiter` (line 300) — arbiter only.
- `resolveByTimeDecay` (line 328) — permissionless after grace.
- `finalizeWithZKProof` (line 366) — admin OR zkVerifier; refunds both.
- `finalizeWithFraudProof` (line 402) — zkVerifier only; admin gated out.

**Existing invariants** (`contracts/test/invariant/OptimisticBridgeChallenge.invariant.t.sol`):

- I1 `invariant_bonds_conserved` — contract balance equals
  sum of unsettled bonds.
- I2 `invariant_no_double_finalization`.
- I3 `invariant_fraud_proof_gated_to_verifier`.
- I5 `invariant_arbiter_path_gated`.
- I6 `invariant_time_decay_respects_grace`.

**Pre-existing findings touching bonds:**

- [LTP-A-006](SECURITY_AUDIT_2026-05-15.md) (CRITICAL, closed)
  — admin-monopoly resolver; three-path defense added.
- [LTP-A-001](SECURITY_AUDIT_2026-05-15.md) (CRITICAL, closed)
  — ZK fraud-proof gated to verifier, admin out.

## Per-scenario directory template

Same as May:

```
docs/security/audits/threat-intel/SCN-XXX-<slug>/
├── README.md          # economic class + LTP mapping
├── threat-intel.md    # citations (≥2 — economic-attack papers
│                      # / EIP-1559 fee analysis / mempool studies)
├── test-evidence.md   # commit refs, CI run URLs, gas data
├── remediation.md     # only if a finding opens
```

For SCN-034..038, the test artifacts go under
`contracts/test/security/historical/` (consistent with May)
even though the threat class is economic rather than
historical-incident-driven. The directory name is a
historical artifact; renaming is out of scope for this
campaign.

## Out of scope

- **Cryptographic primitive review.** ML-KEM / ML-DSA wrapper
  audit is a separate workstream (May report §11 item 5).
- **Formal verification.** Halmos / hevm symbolic execution
  is a separate workstream (May report §11 item 1).
- **Cross-repo wire parity.** Separate workstream (May report
  §11 item — implicit; see `2-patterns/gsx-cross-repo-wire-parity`).
- **Live mainnet broadcasts.** Fork-sim only.
- **Bond-floor governance review.** `setMinOperatorBond` /
  `setMinChallengerBond` admin policy is documented but not
  re-litigated here.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| SCN-035 surfaces a real economic finding requiring a contract change | Charter STOP-the-line rule applies: fix on same branch, open LTP-A-NNN, re-test until green. Same flow as LTP-A-031 in SCN-015. |
| Forge `vm.fee()` plumbing for EIP-1559 sweep proves harder than expected | Isolate SCN-035 to its own phase (R-3) so SCN-034/036/037/038 are not blocked. |
| Invariant tests collide with existing handler state machine | Author SCN scenarios as **new** invariants in `contracts/test/security/historical/SCN_034_*.invariant.t.sol` rather than extending the existing handler. |
| Campaign perceived as repeating May 2026 | This campaign exercises **economic** attack classes; May exercised **historical-incident** patterns. The threat-class taxonomy is orthogonal. |

## Verification

R-1 closes when:

1. This charter merges to `main`.
2. [`SECURITY_TESTING.md`](../../../../SECURITY_TESTING.md) references
   the new campaign alongside the May one.
3. [`RED_TEAM_REPORT_2026-05.md`](RED_TEAM_REPORT_2026-05.md) §11
   item 2 is annotated "Active campaign: see
   `RED_TEAM_CAMPAIGN_2026-06.md`."

R-2..R-5 each close on the same gate as May: all ETP CI jobs +
Docs CI green; per-scenario evidence directories populated;
scenario index in `../threat-intel/README.md` updated.

## Cross-references

- [`/SECURITY_TESTING.md`](../../../../SECURITY_TESTING.md) — charter
- [`RED_TEAM_CAMPAIGN_2026-05.md`](RED_TEAM_CAMPAIGN_2026-05.md) — predecessor
- [`RED_TEAM_REPORT_2026-05.md`](RED_TEAM_REPORT_2026-05.md) §11 item 2 — recommendation that spawned this campaign
- [`SECURITY_AUDIT_2026-05-15.md`](SECURITY_AUDIT_2026-05-15.md) — LTP-A-006 and LTP-A-001 (the bond-mechanism findings already closed)
- [`THREAT_MODEL.md`](../../../THREAT_MODEL.md) — protocol threat model
- [`../threat-intel/README.md`](../threat-intel/README.md) — unified SCN-XXX index
