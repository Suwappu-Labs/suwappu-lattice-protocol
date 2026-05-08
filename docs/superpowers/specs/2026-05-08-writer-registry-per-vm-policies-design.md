# Spec C2: Writer Registry + Per-VM Policies

**Author:** Javier Calderon Jr, CTO — Global Settlement (GSX)
**Date:** 2026-05-08
**Status:** Approved
**Depends on:** Spec C1 (BLS Primitives + Key Management)
**Prepares for:** Spec C3 (TBD — committee formation / consensus participation)

---

## 1. Overview

Spec C2 adds writer authorization and per-VM policy enforcement to the ETP execution layer. Currently, the `TransactionRouter` dispatches transactions by VM tag byte with zero authorization checks. Any entity can submit transactions to any VM. C2 closes this gap by introducing:

- A **Writer Registry** that enrolls and manages writer identities with a 6-state lifecycle
- **Per-VM configurable policies** that control what each writer can do on each VM
- A **layered enforcement gate** — universal checks at the router, per-VM checks at the executor
- **RBAC governance** with custom role creation scoped by identity tier and VM
- **Emergency recovery** mechanisms for GSX team intervention

The design is a hybrid: universal writer gating provides a baseline, per-VM policies allow customization, and an optional `WriterAuthorizer` protocol gives VMs full custom control when needed.

---

## 2. Writer Identity Model

A `WriterIdentity` wraps either a `KeyPair` (ML-DSA) or `BLSIdentity` (from Spec C1) into a unified credential type. This is the unit of enrollment in the registry.

### 2.1 Identity Tiers

```python
class IdentityTier(Enum):
    MLDSA = "mldsa"          # Full ML-DSA KeyPair — highest tier
    BLS = "bls"              # BLS-only identity — lower tier
    COMPOSITE = "composite"  # KeyPair + BLS — highest tier (same capabilities as MLDSA)
```

- **MLDSA:** Writer registered with a `KeyPair` (ML-DSA signing key). Full post-quantum identity.
- **BLS:** Writer registered with a `BLSIdentity` only. Restricted by default, upgradeable per-VM.
- **COMPOSITE:** Writer registered with a `KeyPair` that includes BLS keys (`with_bls=True`). Gets the same default capabilities as MLDSA.

Tier is derived automatically from the keys presented at registration.

### 2.2 WriterIdentity

```python
class WriterIdentity:
    tier: IdentityTier
    fingerprint: bytes           # Unique identity hash — registry key and audit trail
    mldsa_vk: Optional[bytes]   # Present for MLDSA/COMPOSITE tiers
    bls_pk: Optional[bytes]     # Present for BLS/COMPOSITE tiers
```

- `fingerprint` is computed using `bls_fingerprint()` for BLS tier, `composite_fingerprint()` for COMPOSITE, or SHA3-256 of the ML-DSA verification key for MLDSA tier.
- Fingerprint is the canonical identity — used as the registry key, in audit logs, and for policy lookups.

---

## 3. Writer Lifecycle & State Machine

### 3.1 States

| State | Can Transact | Entry Condition |
|-------|-------------|-----------------|
| PENDING | No | Self-registration |
| PROBATION | Yes, restricted | Sponsor approval (N-of-M existing writers) |
| ACTIVE | Yes, full | Admin approval, or probation period completed |
| SUSPENDED | No | Violation, admin action, rate limit breach |
| EXPIRED | No | Time-bound access lapsed |
| REVOKED | No | Permanent removal — cannot re-register same identity |

### 3.2 State Diagram

```
PENDING ──→ ACTIVE ──→ SUSPENDED ──→ REVOKED
   │           ↑           ↑
   ↓           │           │
PROBATION ─────┘       EXPIRED ──→ REVOKED
                          ↑
                       ACTIVE
```

### 3.3 Valid Transitions

| From | To | Trigger |
|------|-----|---------|
| PENDING | PROBATION | Sponsor threshold met |
| PENDING | ACTIVE | Admin approval |
| PENDING | REVOKED | Admin rejection |
| PROBATION | ACTIVE | Probation period elapsed, no violations |
| PROBATION | SUSPENDED | Violation during probation |
| PROBATION | REVOKED | Serious violation during probation |
| ACTIVE | SUSPENDED | Violation, admin action |
| ACTIVE | EXPIRED | Time-bound access lapses |
| ACTIVE | REVOKED | Permanent ban, voluntary exit |
| SUSPENDED | ACTIVE | Reinstatement by admin |
| SUSPENDED | REVOKED | Escalation |
| EXPIRED | ACTIVE | Renewal |
| EXPIRED | REVOKED | Cleanup / admin decision |

Each transition is recorded with a timestamp, actor fingerprint (or "system"), from-state, to-state, and reason string. The implementation follows the same valid-transitions-dict pattern used by `EntityState` in `src/ltp/anchor.py`.

---

## 4. Writer Registry

The `WriterRegistry` manages writer enrollment, state transitions, and audit trails. It contains no policy evaluation logic.

### 4.1 Approval Paths

```python
class ApprovalPath(Enum):
    ADMIN = "admin"       # Direct admin approval → ACTIVE
    SPONSOR = "sponsor"   # N-of-M sponsor vouches → PROBATION
    SELF = "self"         # Self-registration → PENDING (no approval yet)
```

### 4.2 TransitionEntry

```python
class TransitionEntry:
    timestamp: int             # When the transition occurred (ms)
    from_state: WriterState
    to_state: WriterState
    actor_fp: bytes            # Who triggered (admin fp, sponsor fp, or b"system")
    reason: str                # Human-readable reason
    is_emergency: bool = False # Tagged True for emergency interventions (Section 8)
```

### 4.3 WriterRecord

```python
class WriterRecord:
    identity: WriterIdentity
    state: WriterState                   # Current lifecycle state
    approval_path: ApprovalPath          # How this writer was approved
    enrolled_at: int                     # Timestamp (ms)
    approved_at: Optional[int]           # When activated
    approved_by: Optional[bytes]         # Admin fingerprint or "sponsors"
    sponsors: list[bytes]                # Fingerprints of sponsoring writers
    probation_until: Optional[int]       # Epoch when probation ends
    expires_at: Optional[int]            # Epoch when access expires (0 = never)
    suspension_reason: Optional[str]
    transition_log: list[TransitionEntry]  # Full audit trail
```

### 4.4 Core Operations

| Operation | Signature | Behavior |
|-----------|-----------|----------|
| `enroll` | `(identity) → WriterRecord` | Creates PENDING record. Validates identity (correct key sizes, not already registered, not previously revoked). |
| `approve` | `(fingerprint, admin_fp) → WriterRecord` | Admin path: PENDING → ACTIVE. |
| `sponsor` | `(fingerprint, sponsor_fp) → WriterRecord` | Adds sponsor. When threshold met: PENDING → PROBATION. Sponsors must be ACTIVE writers. |
| `promote` | `(fingerprint) → WriterRecord` | System call: PROBATION → ACTIVE when probation period elapses. |
| `suspend` | `(fingerprint, reason, actor_fp)` | ACTIVE/PROBATION → SUSPENDED. |
| `reinstate` | `(fingerprint, actor_fp)` | SUSPENDED → ACTIVE. |
| `revoke` | `(fingerprint, reason, actor_fp)` | Any non-REVOKED → REVOKED. Permanent. |
| `renew` | `(fingerprint, actor_fp)` | EXPIRED → ACTIVE. |
| `check_expirations` | `(current_epoch)` | Batch scan: ACTIVE writers past `expires_at` → EXPIRED. |
| `lookup` | `(fingerprint) → Optional[WriterRecord]` | Read-only lookup. |
| `active_writers` | `() → list[WriterRecord]` | All ACTIVE + PROBATION writers. |

### 4.5 Registry Configuration

```python
class RegistryConfig:
    sponsor_threshold: int = 2        # How many sponsors needed for PROBATION
    probation_epochs: int = 10        # How long probation lasts
    default_expiry_epochs: int = 0    # Default time-bound access (0 = no expiry)
```

Records are stored in a dict keyed by fingerprint. Every mutation appends to `transition_log` with timestamp, actor, from-state, to-state, and reason.

---

## 5. Registry Governance & Roles

### 5.1 Built-in Role Hierarchy

| Role | Authority |
|------|-----------|
| Owner | Full control — config, role management, admin delegation, all writer operations |
| Admin | Writer lifecycle operations — approve, reject, suspend, revoke, reinstate |
| Sponsor | Vouch for pending writers only |

### 5.2 Custom Roles with Scoped Permissions

The Owner can create custom roles with permissions scoped to specific identity tiers and/or VMs.

```python
class RegistryAction(Enum):
    APPROVE = "approve"
    REJECT = "reject"
    SUSPEND = "suspend"
    REINSTATE = "reinstate"
    REVOKE = "revoke"
    CONFIGURE_POLICY = "configure_policy"
    SET_RATE_LIMIT = "set_rate_limit"
    MANAGE_ALLOWLIST = "manage_allowlist"
    MANAGE_DENYLIST = "manage_denylist"

class ScopedPermission:
    action: RegistryAction
    tier_scope: Optional[set[IdentityTier]]  # None = all tiers
    vm_scope: Optional[set[int]]             # None = all VMs

class RegistryRole:
    name: str
    permissions: list[ScopedPermission]
    is_builtin: bool
```

### 5.3 Example Custom Roles

- **"EVM Operator"** — can approve/suspend BLS-tier writers for EVM (vm_tag=0x01) only
- **"UTXO Admin"** — can approve/suspend/revoke any tier for Bitcoin VM (vm_tag=0x50) only
- **"Rate Limit Manager"** — can set rate limits on any VM but cannot approve/revoke writers
- **"BLS Tier Reviewer"** — can approve/reject BLS-tier writers across all VMs but cannot touch MLDSA/COMPOSITE tier

### 5.4 Role Assignment

```python
class RoleAssignment:
    role: RegistryRole
    assignee_fp: bytes          # Fingerprint of the role holder
    assigned_by: bytes          # Owner fingerprint
    assigned_at: int            # Timestamp
    expires_at: Optional[int]   # Time-bound delegation (0 = permanent)
```

Only the Owner can create roles, assign roles, and modify the built-in role hierarchy's configuration (sponsor threshold, probation epochs, etc.). Role assignments are time-bound and auditable. The existing `RBACManager` in `src/ltp/compliance.py` follows a similar pattern — C2 uses the same approach scoped to writer registry operations.

---

## 6. Per-VM Writer Policy (Declarative 8-Knob)

The default policy engine. VMs that don't need custom authorization logic declare a `VMWriterPolicy` and the engine evaluates it.

### 6.1 Operation Types

```python
class OperationType(Enum):
    TRANSFER = "transfer"
    DEPLOY = "deploy"
    CALL = "call"
    STATE_MODIFY = "state_modify"
    STATE_READ = "state_read"
```

### 6.2 VMWriterPolicy

```python
class VMWriterPolicy:
    vm_tag: int

    # Knob 1: Allowed identity tiers
    allowed_tiers: set[IdentityTier]               # Default: {MLDSA, COMPOSITE, BLS}

    # Knob 2: Operation permissions per tier
    tier_operations: dict[IdentityTier, set[OperationType]]
    # Default: MLDSA/COMPOSITE → all ops, BLS → {TRANSFER, STATE_READ}

    # Knob 3: Rate limits
    max_txs_per_epoch: dict[IdentityTier, int]     # 0 = unlimited
    # Default: MLDSA/COMPOSITE → 0, BLS → 1000

    # Knob 4: Stake requirements
    min_stake: dict[IdentityTier, int]             # Per-tier minimum stake (0 = none)
    # Default: all → 0

    # Knob 5: Writer cap
    max_writers: int                                # 0 = unlimited
    # Default: 0

    # Knob 6: Gas/fee multiplier per tier
    fee_multiplier: dict[IdentityTier, float]      # 1.0 = standard
    # Default: all → 1.0

    # Knob 7: Allowlist/denylist
    allowlist: Optional[set[bytes]]                # None = allow all authorized writers
    denylist: set[bytes]                           # Always checked, empty by default

    # Knob 8: Time-bound access
    default_access_epochs: int                     # 0 = no expiry
    # Default: 0
```

### 6.3 Evaluation Order (Short-Circuit)

1. Is the writer's tier in `allowed_tiers`? No → reject
2. Is the writer on `denylist`? Yes → reject
3. Is `allowlist` set and writer not on it? → reject
4. Does the writer's tier have permission for this `OperationType`? No → reject
5. Has the writer exceeded `max_txs_per_epoch`? Yes → reject
6. Does the writer meet `min_stake` for their tier? No → reject
7. Is the `max_writers` cap reached (for new writers)? Yes → reject
8. Pass → return `fee_multiplier` for the writer's tier

Each VM gets a `VMWriterPolicy` instance. If a VM doesn't configure one, a sensible default policy is applied.

### 6.4 Probation Override

When a writer is in PROBATION state, the policy engine automatically applies tighter constraints regardless of the VM policy:

- Halved rate limits
- No DEPLOY operations
- Doubled fee multiplier

These probation modifiers are configurable at the registry level via `RegistryConfig`.

---

## 7. WriterAuthorizer Protocol (Custom VM Override)

The escape hatch for VMs that need authorization logic beyond the 8-knob declarative policy.

### 7.1 Protocol Definition

```python
class AuthorizationResult:
    allowed: bool
    reason: Optional[str]              # Human-readable rejection reason
    fee_multiplier: float = 1.0        # Custom fee adjustment
    metadata: Optional[dict] = None    # VM-specific audit data

class WriterAuthorizer(Protocol):
    def authorize_writer(
        self,
        writer: WriterRecord,
        operation: OperationType,
        tx_bytes: bytes,
    ) -> AuthorizationResult:
        """Evaluate whether this writer can perform this operation on this VM."""
        ...

    def on_writer_state_change(
        self,
        writer: WriterRecord,
        old_state: WriterState,
        new_state: WriterState,
    ) -> None:
        """Optional hook: VM reacts to writer lifecycle changes."""
        ...
```

### 7.2 Resolution Order

```
executor implements WriterAuthorizer?
    YES → call executor.authorize_writer(writer, op, tx)
    NO  → evaluate against VM's VMWriterPolicy (Section 6)
```

### 7.3 Contract

- The router-level `WriterGate` always runs first. By the time `authorize_writer` is called, the writer is guaranteed to be ACTIVE or PROBATION with a valid identity.
- The VM authorizer does NOT re-check lifecycle state or identity validity. It only answers: "given a valid, active writer — can they do this specific thing on my VM?"
- If a VM implements `WriterAuthorizer`, its `VMWriterPolicy` is ignored entirely — the protocol takes full ownership. No mixing of declarative + custom for the same VM.

### 7.4 Example Use Cases

- **Custom EVM authorizer:** Contract deployment whitelists, gas price floors, calldata size limits
- **Simple UTXO VM:** Skips the protocol, uses declarative `VMWriterPolicy` instead
- **Institutional VM:** Custom KYC/compliance checks before allowing writes

---

## 8. Recovery & Emergency Intervention

When the GSX team needs to intervene — compromised keys, broken authorizers, misconfigured policies, or urgent security events.

### 8.1 Emergency Actions

```python
class EmergencyAction(Enum):
    FREEZE_REGISTRY = "freeze_registry"         # Halt all writer operations
    FREEZE_VM = "freeze_vm"                     # Halt a single VM's writers
    BYPASS_AUTHORIZER = "bypass_authorizer"     # Force VM back to declarative policy
    FORCE_REVOKE = "force_revoke"               # Revoke writer ignoring role checks
    ROLLBACK_POLICY = "rollback_policy"         # Revert VM policy to previous version
    ROTATE_OWNER = "rotate_owner"               # Transfer ownership to new identity
    OVERRIDE_DISPATCH = "override_dispatch"     # Allow/block specific tx manually
```

### 8.2 Emergency Intervention Record

```python
class EmergencyIntervention:
    action: EmergencyAction
    actor_fp: bytes                # Who initiated
    reason: str                    # Mandatory audit reason
    timestamp: int
    scope: Optional[int]           # vm_tag if scoped, None if global
    auto_expires: Optional[int]    # Epoch when intervention auto-lifts (0 = manual only)
```

### 8.3 Scenario Matrix

| Scenario | Intervention |
|----------|-------------|
| Custom WriterAuthorizer has a bug, rejecting all writers | `BYPASS_AUTHORIZER` — forces VM to fall back to its `VMWriterPolicy` until the authorizer is fixed |
| Writer's keys compromised | `FORCE_REVOKE` — immediate revocation bypassing normal role checks |
| VM policy misconfigured, blocking legitimate traffic | `ROLLBACK_POLICY` — revert to the last known-good policy snapshot |
| Active security incident across the network | `FREEZE_REGISTRY` — halts all writer dispatching globally |
| Single VM under attack | `FREEZE_VM` — halt one VM's writer operations without affecting others |
| Owner keys compromised | `ROTATE_OWNER` — requires M-of-N recovery keys |
| Need to allow a specific critical transaction through during a freeze | `OVERRIDE_DISPATCH` — one-shot manual allow/block |

### 8.4 Recovery Key Quorum

At registry creation, an M-of-N recovery quorum is established (e.g., 3-of-5 recovery keys held by the GSX team). This quorum can:

- Execute `ROTATE_OWNER` to transfer ownership
- Execute `FREEZE_REGISTRY` / `FREEZE_VM` in emergencies
- Lift a freeze when the Owner is unavailable

Recovery keys are ML-DSA identities (post-quantum secure), stored separately from operational keys. The recovery quorum cannot approve writers, modify policies, or perform normal operations — only emergency actions.

### 8.5 Policy Versioning

Every `VMWriterPolicy` mutation creates a snapshot. `ROLLBACK_POLICY` reverts to a previous snapshot by version number. History is append-only — snapshots are never deleted.

### 8.6 Audit

All emergency interventions are logged to the same `transition_log` as writer state changes, tagged with `is_emergency=True`. This gives a complete audit trail of when the GSX team intervened, why, and what they did.

---

## 9. WriterGate (Layered Enforcement)

The integration layer that wires writer authorization into the existing execution pipeline.

### 9.1 Pipeline Change

**Current flow (no auth):**
```
Consensus → TransactionRouter.execute_batch() → VMRegistry.get(tag) → executor.execute(payload)
```

**New flow with WriterGate:**
```
Consensus → TransactionRouter.execute_batch()
                ↓
           WriterGate.pre_dispatch(writer_fp, tx_bytes)
                ↓ (universal checks)
           VMRegistry.get(tag) → executor
                ↓
           WriterGate.vm_authorize(writer, executor, op, tx_bytes)
                ↓ (per-VM: custom authorizer or declarative policy)
           executor.execute(payload)
```

### 9.2 WriterGate Interface

```python
class DispatchDecision:
    allowed: bool
    reason: Optional[str]
    fee_multiplier: float = 1.0
    writer_record: Optional[WriterRecord]

class WriterGate:
    registry: WriterRegistry
    policies: dict[int, VMWriterPolicy]        # vm_tag → policy
    emergency: EmergencyState                   # Current freeze/bypass state

    def pre_dispatch(self, writer_fp: bytes, tx_bytes: bytes) -> DispatchDecision:
        """Universal checks — runs before any VM dispatch."""
        # 1. Is registry frozen? → reject
        # 2. Look up writer by fingerprint → not found? → reject
        # 3. Is writer ACTIVE or PROBATION? → no? → reject
        # 4. Is the target VM frozen? → reject
        # 5. Is there an OVERRIDE_DISPATCH for this tx? → apply it
        # Return writer_record for downstream use

    def vm_authorize(
        self, writer: WriterRecord, executor: ExecutionModel,
        operation: OperationType, tx_bytes: bytes
    ) -> DispatchDecision:
        """Per-VM checks — runs after universal gate passes."""
        # 1. Is authorizer bypassed for this VM? → use declarative policy
        # 2. Does executor implement WriterAuthorizer? → delegate
        # 3. Fall back to VMWriterPolicy evaluation (Section 6)
```

### 9.3 Transaction Identity Binding

Each transaction in an `OrderedBatch` is prefixed with the writer's fingerprint:

```
[writer_fp (32 bytes)] [vm_tag (1 byte)] [payload]
```

The router strips the writer fingerprint before dispatch, just like it currently strips the VM tag byte. The `OrderedBatch` format stays the same (`transactions: list[bytes]`), but the byte layout of each entry gains the 32-byte fingerprint prefix.

### 9.4 Rate Limit Tracking

The `WriterGate` maintains a per-writer, per-VM transaction counter that resets each epoch. When `execute_batch` is called, counters are checked against the policy's `max_txs_per_epoch` before dispatch.

### 9.5 Backward Compatibility

The `WriterGate` is optional. If the `TransactionRouter` is constructed without a `WriterGate`, it behaves exactly as today (no auth checks). This preserves all existing tests and allows incremental adoption.

---

## 10. File Structure

### 10.1 New Files

```
src/ltp/execution/
├── writer.py              # WriterIdentity, IdentityTier, WriterState, WriterRecord, TransitionEntry
├── writer_registry.py     # WriterRegistry — enrollment, state transitions, lookup
├── writer_policy.py       # VMWriterPolicy, PolicyEngine, probation modifiers
├── writer_auth.py         # WriterAuthorizer protocol, AuthorizationResult, DispatchDecision
├── writer_gate.py         # WriterGate — universal + per-VM enforcement
├── writer_roles.py        # RegistryAction, ScopedPermission, RegistryRole, RoleAssignment
├── writer_recovery.py     # EmergencyAction, EmergencyIntervention, recovery quorum
├── writer_config.py       # RegistryConfig — thresholds, probation params, modifiers
├── writer_epoch.py        # Epoch-driven operations — rate limits, expiration, auto-promotion
```

### 10.2 Modified Files

| File | Change |
|------|--------|
| `src/ltp/execution/types.py` | Add `OperationType` enum |
| `src/ltp/execution/router.py` | `TransactionRouter.__init__` gains optional `writer_gate` param; `execute_batch` calls gate checks when present |
| `src/ltp/execution/__init__.py` | Export new public types |

### 10.3 Test Files

```
tests/
├── test_writer.py              # WriterIdentity, WriterState, WriterRecord
├── test_writer_roles.py        # RBAC — roles, scoped permissions, assignment
├── test_writer_registry.py     # Enrollment, state transitions, sponsor flow
├── test_writer_policy.py       # PolicyEngine, 8-knob evaluation, probation modifiers
├── test_writer_auth.py         # WriterAuthorizer protocol, custom VM authorizer
├── test_writer_gate.py         # Layered enforcement, universal + per-VM
├── test_writer_recovery.py     # Emergency actions, policy rollback, recovery quorum
├── test_writer_epoch.py        # Rate limit rollover, expiration, auto-promotion
├── test_writer_e2e.py          # Full flow: enroll → approve → transact → suspend
```

### 10.4 Dependency Direction

```
writer.py ← writer_config.py
    ↑
writer_roles.py
    ↑
writer_registry.py ← writer_epoch.py
    ↑
writer_policy.py (+ types.py)
    ↑
writer_auth.py
    ↑
writer_gate.py ← writer_recovery.py
    ↑
router.py (modified)
```

Everything flows downward. `writer.py` depends on nothing. `writer_gate.py` depends on everything. No circular imports.

---

## 11. Integration with C1 and Forward to C3

### 11.1 C1 → C2 Integration Points

| C1 Component | C2 Usage |
|-------------|----------|
| `BLSIdentity` | Accepted as writer credential for BLS tier enrollment |
| `KeyPair.to_bls_identity()` | COMPOSITE tier detection |
| `bls_fingerprint()` / `composite_fingerprint()` | Used as `WriterIdentity.fingerprint` |
| `DOMAIN_BLS_ATTEST` | ACTIVE writers with BLS keys flagged as committee-eligible (C3 input) |

### 11.2 C2 Prepares for C3

- Tracks which active writers hold BLS keys (committee-eligible flag)
- Records writer history and standing (input to validator reputation/selection)
- Provides `on_writer_state_change` hook for consensus layer reactivity
- `WriterRecord.transition_log` serves as on-chain-anchoring candidate for writer reputation

### 11.3 What C2 Explicitly Does NOT Do

- No committee formation or validator selection logic
- No consensus protocol changes
- No attestation workflow changes (C1's `AttestationEngine` stays as-is)
- No on-chain anchoring of writer records

C2 is purely the authorization and policy layer. It answers "who can write, where, and under what conditions."

---

## 12. Testing Strategy

### 12.1 Key Test Scenarios

| Test | What It Proves |
|------|---------------|
| Enroll with KeyPair → MLDSA tier | Identity type detection |
| Enroll with BLSIdentity → BLS tier | Identity type detection |
| Enroll with composite KeyPair → COMPOSITE tier | Identity type detection |
| Sponsor flow: 2-of-3 sponsors → PROBATION | Sponsor threshold logic |
| Admin approve → ACTIVE (skips PROBATION) | Admin fast-path |
| PROBATION auto-promote after N epochs | Epoch-driven promotion |
| BLS writer attempts DEPLOY on default policy → reject | Tier-based operation gating |
| BLS writer DEPLOY on VM with equal-access policy → allow | Per-VM override (option A capacity) |
| Custom WriterAuthorizer rejects → fallback NOT used | Protocol takes full ownership |
| BYPASS_AUTHORIZER → declarative policy used | Emergency recovery |
| FREEZE_REGISTRY → all dispatches rejected | Global freeze |
| FREEZE_VM → only that VM rejected | Scoped freeze |
| Policy rollback to previous version | Snapshot/versioning |
| ROTATE_OWNER with M-of-N quorum | Recovery key governance |
| Custom role with tier+VM scoping approves writer | RBAC scoped permissions |
| Custom role without permission → action rejected | RBAC enforcement |
| Rate limit exceeded → reject, epoch rollover → reset | Epoch-based rate limiting |
| Router without WriterGate → passthrough | Backward compatibility |
| Full E2E: enroll → sponsor → probation → promote → transact → expire → renew | Complete lifecycle |

### 12.2 Property-Based Tests (Hypothesis)

- Any valid writer in ACTIVE/PROBATION state can pass universal gate checks
- No writer in PENDING/SUSPENDED/EXPIRED/REVOKED can pass universal gate checks
- Policy evaluation is deterministic — same inputs always produce same result
- All state transitions produce valid states (no invalid state reachable)
- Role permission scoping is monotonic — removing a permission never grants access

### 12.3 Regression

All existing tests (2,983 as of Spec C1 completion) must continue passing. The optional `WriterGate` parameter on `TransactionRouter` ensures zero impact on existing code.
