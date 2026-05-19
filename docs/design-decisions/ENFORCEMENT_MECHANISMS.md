# Enforcement Mechanisms: Future-Proof Design

**Status:** Proposal
**Date:** 2026-03-13
**Authors:** LTP Core Team
**Relates to:** Whitepaper §5.2, §5.3, §5.4, §5.5, Open Questions 6 & 8

---

## Context

LTP's current enforcement layer provides:
- **Progressive slashing** (1% → 5% → 15% → 30% + eviction) in `economics.py`
- **Correlation penalty** (Ethereum-inspired, up to 3x multiplier)
- **Burst audit challenges** (time-bounded storage proofs) in `commitment.py`
- **Offense decay** (rehabilitation after 30 days clean behavior)
- **7-day slashing grace period** with reversal capability

These mechanisms are solid for a v1 system. However, the whitepaper itself
acknowledges two critical gaps:

1. **Open Question 6:** The storage proof challenge-response (§5.2.2) is a
   statistical deterrent, not a cryptographic guarantee. A node with a
   co-located proxy 5ms away defeats the time bound.
2. **Open Question 8:** Slashing is hardcoded to audit failures. Future
   enforcement may need custom conditions (data withholding, censorship,
   incorrect oracle feeds).

This document proposes seven enforcement mechanisms that address these gaps
while remaining future-proof across the protocol's lifecycle.

```mermaid
flowchart TD
    subgraph Now["Immediate"]
        FV["Formal Verification\nInvariants"]
        PDP["PDP Storage\nProofs"]
    end

    subgraph Growth["Growth Phase"]
        PS["Programmable\nSlashing"]
        MEV["MEV-Protected\nEnforcement"]
    end

    subgraph Maturity["Maturity Phase"]
        ISD["Intersubjective\nDisputes"]
        VDF["VDF-Enhanced\nAudits"]
    end

    PD["Progressive\nDecentralization"] --> Now & Growth & Maturity
    FV --> PDP
    PDP --> PS
    PS --> MEV
    MEV --> ISD
    ISD --> VDF
```

---

## Mechanism 1: Proof of Data Possession (PDP) Storage Proofs

### Problem

LTP's current burst challenge is a statistical deterrent (whitepaper §5.2.2):

```
P(catch outsourcing node) ≈ P(RTT_fetch + shard_size/bandwidth > T)
```

A node with a co-located proxy 5ms away trivially passes a T=50ms bound.
The whitepaper explicitly acknowledges this limitation.

### Solution

Adopt a **Proof of Data Possession (PDP)** model, inspired by Filecoin's
PDP mechanism (shipped mainnet May 2025). PDP provides cryptographic proof
of storage without sealing overhead:

- **160 bytes per challenge** regardless of dataset size
- **No sealing required** — data stays raw and accessible (unlike PoRep)
- **Supports mutable collections** (add/delete/modify)
- Verification is compact and on-chain verifiable

### Design

```
StorageProofStrategy (enum):
  BURST_CHALLENGE  — Current time-bounded burst challenges (statistical)
  PDP              — Proof of Data Possession (cryptographic)
  HYBRID           — PDP with burst challenge fallback

PDP Challenge Protocol:
  1. Verifier selects random subset of shard indices
  2. For each index, generates a random coefficient
  3. Node computes: tag = H(shard_data[index] || coefficient) for each
  4. Node aggregates: aggregate_proof = combine(tags)
  5. Verifier checks aggregate_proof against known commitments
  6. Result: cryptographic guarantee of possession (not just statistical)

PDP Proof Record:
  - challenge_epoch: int        # When challenged
  - proof_bytes: bytes          # 160-byte compact proof
  - indices_challenged: int     # Number of indices sampled
  - verification_result: bool   # Pass/fail
  - response_time_ms: float     # For latency monitoring
```

### Why This Is Future-Proof

- PDP scales O(1) per challenge regardless of dataset size (160 bytes)
- No sealing ceremony means data stays hot and retrievable
- The 2025 IACR paper (2025/887) formally proves succinctness and
  non-malleability are necessary and sufficient for adaptive security
- Compatible with both Monad L1 (native precompile) and Ethereum L2
  (SNARK verification contract)

### Implementation Path

- Default to `PDP` on Monad L1 backend (native precompile support)
- Default to `HYBRID` on Ethereum L2 backend (PDP + burst as fallback)
- Keep `BURST_CHALLENGE` on local backend (testing, no proof overhead)

---

## Mechanism 2: Programmable Slashing Conditions

### Problem

Current slashing is hardcoded to audit failures in `compute_slash()`.
New enforcement rules (data withholding, latency violations, censorship)
require protocol upgrades to the economics engine itself.

### Solution

Follow EigenLayer's **programmable slashing** model (went live April 2025):

```
SlashingCondition (abstract interface):
  - condition_id: str              # Unique identifier
  - evaluate(evidence: bytes) → SlashResult
  - stake_allocation_bps: int      # Basis points of total stake at risk
  - description: str               # Human-readable description

SlashResult:
  - violated: bool
  - severity: SlashingTier
  - evidence_hash: str
  - explanation: str

Built-in conditions:
  - AuditFailureCondition          # Current behavior (3 strikes → eviction)
  - DataWithholdingCondition       # Node refuses valid fetch requests
  - LatencyDegradationCondition    # Sustained latency above threshold
  - ProofFailureCondition          # Failed PDP proof verification

Unique Stake Allocation:
  - Operators allocate specific stake percentages per condition
  - Prevents cascading slashing across unrelated violations
  - 14-day delay on allocation changes prevents escape
```

### Why This Is Future-Proof

- New enforcement rules deploy as new `SlashingCondition` implementations
- No protocol upgrade required for new condition types
- Pattern survived EigenLayer's scaling to $15B+ TVL
- Unique Stake Allocation prevents systemic risk contagion

### Key Safety Mechanisms

| Mechanism | Purpose |
|-----------|---------|
| 14-day allocation change delay | Prevents escape from impending slashing |
| Minimum allocation per condition | Ensures meaningful economic deterrent |
| Condition registry | Prevents duplicate or conflicting conditions |
| Veto committee (Bootstrap/Growth) | Governance backstop during early phases |

---

## Mechanism 3: Intersubjective Dispute Resolution

### Problem

Some violations cannot be proven on-chain but are obvious to reasonable
observers: selective data withholding, degraded-but-not-failed service,
censorship of specific entities.

### Solution

Adopt EigenLayer's **intersubjective forking** mechanism for the MATURITY
phase:

```
IntersubjectiveDispute:
  - dispute_id: str
  - challenger: str               # Node ID raising the dispute
  - target: str                   # Node ID accused
  - evidence_uri: str             # Off-chain evidence location
  - dispute_bond: int             # Minimum bond to prevent spam
  - resolution: DisputeResolution # PENDING / UPHELD / REJECTED
  - votes_for: int                # Stake-weighted votes to uphold
  - votes_against: int            # Stake-weighted votes to reject
  - voting_deadline_epoch: int    # Resolution deadline
  - slash_if_upheld: int          # Amount to slash if upheld

DisputeResolution process:
  1. Challenger posts dispute + bond (minimum 1% of target's stake)
  2. Voting period opens (168 epochs = 7 days)
  3. Token holders vote (stake-weighted)
  4. If upheld (>66% stake-weighted majority):
     - Target is slashed per dispute specification
     - Challenger's bond is returned + 10% reward
  5. If rejected:
     - Challenger's bond is burned (anti-spam)
     - Target is unaffected
```

### When to Implement

| Phase | Enforcement Model |
|-------|------------------|
| Bootstrap | Foundation can directly evict (permissioned) |
| Growth | Programmable slashing conditions (objective) |
| Maturity | Intersubjective disputes added (subjective) |

### Why This Is Future-Proof

- Solves the fundamental limitation that not everything is on-chain provable
- Fork-and-slash creates Schelling point without centralized adjudication
- Bonds prevent spam; supermajority threshold prevents tyranny of majority
- Only activates at Maturity when token distribution is sufficiently
  decentralized

---

## Mechanism 4: VDF-Enhanced Audit Timing

### Problem

The time bound T in burst challenges is calibrated against network RTT
but has no cryptographic guarantee. It relies on the gap between an
outsourcing node's re-fetch latency and T, which is deployment-specific.

### Solution

Use a **Verifiable Delay Function** as part of the audit challenge:

```
VDF-Enhanced Challenge Protocol:
  Challenge: (entity_id, shard_index, nonce, vdf_difficulty)
  Response:  (
    shard_proof: H(ciphertext || nonce),
    vdf_output: bytes,
    vdf_proof: bytes
  )

Verification:
  1. Verify VDF proof (< 1ms verification time)
  2. Check VDF output matches expected difficulty
  3. Verify shard_proof against known-good hash
  4. Total: cryptographic timing guarantee + storage proof

VDFConfig:
  - difficulty: int          # Sequential steps required (~50ms)
  - construction: str        # "pietrzak" | "wesolowski" | "class_group"
  - group_params: bytes      # Group parameters (RSA modulus or discriminant)
  - enabled: bool            # Feature flag for gradual rollout
```

### Constructions Evaluated

| Construction | Setup | PQ-Safe | Maturity |
|-------------|-------|---------|----------|
| Pietrzak (RSA) | Trusted | No | Production |
| Wesolowski (RSA) | Trusted | No | Production |
| Class groups | Trustless | Partial | Research |
| Isogeny-based | Trustless | Yes | Experimental |

### Why This Is Future-Proof

- VDFs provide physics-based timing (sequential computation is fundamentally
  bound by clock cycles) rather than network-distance assumptions
- Newer isogeny-based constructions may offer post-quantum resistance
- Verification is O(1) regardless of difficulty parameter
- Can be combined with PDP for defense-in-depth

### Caveats

- RSA-based VDFs require trusted setup
- Class group security is less studied than RSA
- Hardware acceleration could shift difficulty calibration
- **Recommendation:** Mark as EXPERIMENTAL; deploy alongside PDP, not instead of

---

## Mechanism 5: MEV-Protected Enforcement

### Problem

On Ethereum L2, slashing transactions can be MEV-targeted:
- Validators front-run slashes to extract value
- Challengers' dispute transactions are censored
- Enforcement ordering is manipulated for profit

### Solution

Layer three MEV protection mechanisms:

```
1. Encrypted Enforcement Submissions:
   - Challenge/dispute submissions encrypted until block inclusion
   - Prevents front-running of enforcement transactions
   - Uses commit-reveal: H(evidence) in block N, evidence in block N+1

2. Epoch-Based Batch Slashing:
   - Accumulate slashing evidence per epoch
   - Execute all slashes as a batch with uniform processing
   - Prevents ordering games within the enforcement pipeline
   - Already partially implemented via 168-epoch grace period

3. Meta-Enforcement:
   - Operators caught manipulating enforcement tx ordering are slashed
   - Additional SlashingCondition: EnforcementManipulation
   - Requires proof of ordering manipulation (on-chain attestation)
```

### Why This Is Future-Proof

- Encrypted mempools are becoming standard (Flashbots SUAVE, MEV-Share)
- Epoch-based batching naturally integrates with LTP's existing epoch model
- Defense-in-depth: no single mechanism is sufficient alone
- Meta-enforcement creates recursive deterrence

---

## Mechanism 6: Formal Verification Invariants

### Problem

As slashing becomes programmable and handles larger economic stakes, bugs
in enforcement logic could slash honest operators or fail to slash
malicious ones. Traditional testing cannot cover all state combinations.

### Solution

Define formally verifiable invariants for the enforcement layer:

```
Safety Properties (no false positives):
  INV-S1: A node is only slashed if evaluate(evidence) returned violated=True
          for at least one registered SlashingCondition.
  INV-S2: A node that passes all audits and PDP proofs in an epoch cannot
          have its offense_count incremented in that epoch.
  INV-S3: A reversed PendingSlash never results in stake deduction.
  INV-S4: total_slashed ≤ stake (a node cannot be slashed below zero).

Liveness Properties (no false negatives):
  INV-L1: A node with 3+ consecutive audit failures will be evicted within
          max(3, eviction_offense_threshold) offense increments.
  INV-L2: A finalized PendingSlash always results in stake deduction
          (no path skips execution).
  INV-L3: Offense decay cannot reduce offense_count below 0.

Uniqueness Properties:
  INV-U1: The same offense event cannot produce two PendingSlash entries
          for the same node in the same epoch.
  INV-U2: A PendingSlash can only transition: PENDING → FINALIZED or
          PENDING → REVERSED (no other transitions).

Correlation Properties:
  INV-C1: correlation_multiplier ∈ [1.0, max_correlation_multiplier]
          for all valid inputs.
  INV-C2: An isolated offense (concurrent_slashed_stake = 0) always
          results in multiplier = 1.0 (no correlation penalty).

Economic Properties:
  INV-E1: Fee split components always sum to the input fee
          (no rounding loss beyond 1 wei).
  INV-E2: Vested rewards are monotonically claimable (claimable_at(t+1) ≥
          claimable_at(t) for all t).
```

### Implementation Approach

| Method | Scope | Tool |
|--------|-------|------|
| Property-based testing | Python invariants | Hypothesis |
| Model checking | State machine transitions | Spin/Promela |
| Theorem proving | Core slashing logic | Lean 4 |
| Runtime assertions | Production enforcement | assert + monitoring |

### Why This Is Future-Proof

- Mathematical guarantees are timeless — they don't degrade with new attacks
- FMBC 2025 demonstrated Lean 4 mechanization of fraud proof games
- Property-based testing catches edge cases traditional tests miss
- Runtime assertions catch violations in production before damage spreads

---

## Mechanism 7: Progressive Decentralization of Enforcement

### Problem

No protocol launches fully decentralized. Enforcement must evolve from
centralized (foundation control) to autonomous (protocol-governed).

### Solution

Codify enforcement transitions into irreversible smart contract triggers:

```
Phase Transitions:

BOOTSTRAP → GROWTH (epoch 4,320):
  - Foundation retains veto power over slashing
  - Minimum 3 independent operators required
  - Trigger: epoch ≥ bootstrap_end_epoch AND active_nodes ≥ min_genesis_nodes
  - Irreversible: foundation cannot re-enter bootstrap mode

GROWTH → MATURITY (epoch 17,520):
  - Foundation veto power revoked (irreversible capability drop)
  - Intersubjective disputes activated
  - Programmable slashing fully autonomous
  - Trigger: epoch ≥ growth_end_epoch AND
             validator_concentration_hhi < 2500 AND
             token_distribution_gini < 0.65
  - Irreversible: governance cannot restore veto power

MATURITY:
  - Governance minimization — reduce DAO powers over time
  - Enforcement fully autonomous (code-is-law + intersubjective backstop)
  - Only upgradeable via supermajority token vote (>75%)
```

```mermaid
stateDiagram-v2
    [*] --> Bootstrap
    Bootstrap --> Growth: epoch >= 4320\nAND nodes >= min_genesis
    Growth --> Maturity: epoch >= 17520\nAND HHI < 2500\nAND Gini < 0.65

    state Bootstrap {
        [*] --> B: Foundation veto active
    }
    state Growth {
        [*] --> G: Programmable slashing
    }
    state Maturity {
        [*] --> M: Fully autonomous
    }
```

### Decentralization Metrics

| Metric | Bootstrap | Growth | Maturity |
|--------|-----------|--------|----------|
| Operator count | ≥ 5 | ≥ 20 | ≥ 100 |
| HHI (validator concentration) | Any | < 5000 | < 2500 |
| Gini (token distribution) | Any | < 0.80 | < 0.65 |
| Governance participation | N/A | > 5% | > 15% |
| Foundation veto | Yes | Yes | **No** |

### Why This Is Future-Proof

- Automated triggers make decentralization irreversible and verifiable
- Metrics-based transitions prevent premature decentralization
- Foundation veto in early phases protects against catastrophic bugs
- Governance minimization reduces attack surface over time

---

## Comparison Matrix

| Mechanism | Phase | Effort | Impact | Gap Addressed |
|-----------|-------|--------|--------|---------------|
| PDP Storage Proofs | Growth | Medium | Critical | Open Question 6 |
| Programmable Slashing | Growth | Medium | High | Extensibility |
| Intersubjective Disputes | Maturity | High | High | Subjective violations |
| VDF-Enhanced Audits | Maturity | High | Medium | Timing guarantees |
| MEV-Protected Enforcement | Growth (L2) | Low | Medium | Enforcement gaming |
| Formal Verification | Now | Low | Critical | Correctness |
| Progressive Decentralization | All | Low | High | Trust evolution |

---

## Implementation

All mechanisms are implemented in `src/ltp/enforcement.py` behind the
existing `CommitmentBackend` abstraction:

```
src/ltp/
├── enforcement.py       # New: enforcement mechanisms module
├── economics.py         # Updated: programmable slashing integration
├── commitment.py        # Updated: PDP proof strategy
└── backends/
    ├── base.py          # Updated: enforcement backend interface
    └── ...
```

Usage:
```python
from ltp.enforcement import (
    StorageProofStrategy,
    SlashingConditionRegistry,
    AuditFailureCondition,
    DataWithholdingCondition,
    IntersubjectiveDispute,
    VDFConfig,
    EnforcementInvariants,
    DecentralizationMetrics,
)

# Configure enforcement
registry = SlashingConditionRegistry()
registry.register(AuditFailureCondition(stake_allocation_bps=5000))
registry.register(DataWithholdingCondition(stake_allocation_bps=3000))

# Evaluate evidence
result = registry.evaluate("audit_failure", evidence_bytes)
if result.violated:
    slash_amount = engine.compute_slash_for_condition(node, result)

# Check invariants
invariants = EnforcementInvariants(engine)
assert invariants.check_safety(node, epoch)
```

Tests: `tests/test_enforcement.py` — comprehensive coverage of all
seven mechanisms including edge cases and invariant verification.

---

## Recommendation

**Immediate (P0):**
- Implement formal verification invariants (low effort, prevents catastrophic bugs)
- Implement PDP storage proof strategy (closes biggest enforcement gap)

**Growth Phase (P1):**
- Deploy programmable slashing interface
- Add MEV-protected batch slashing for L2 deployments

**Maturity Phase (P2):**
- Activate intersubjective dispute resolution
- Deploy VDF-enhanced audits (experimental, alongside PDP)

**Continuous:**
- Progressive decentralization metrics enforced at phase transitions
