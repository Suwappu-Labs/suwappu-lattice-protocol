# Writer Registry + Per-VM Policies Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add writer authorization and per-VM policy enforcement to the ETP execution layer, gating transaction dispatch through the TransactionRouter with a 6-state writer lifecycle, RBAC governance, declarative policies, custom VM authorizer protocol, and emergency recovery.

**Architecture:** Layered enforcement — universal writer checks at the router level (identity valid? writer active? VM frozen?), then per-VM policy checks at the executor level (declarative 8-knob policy OR custom `WriterAuthorizer` protocol). Writer identity wraps either ML-DSA `KeyPair` or BLS `BLSIdentity` into a unified `WriterIdentity` type with three tiers (MLDSA, BLS, COMPOSITE). All modules live under `src/ltp/execution/` following existing package conventions.

**Tech Stack:** Python 3.12+, dataclasses, Enum, Protocol (typing), pytest + Hypothesis, existing LTP primitives (SHA3-256 via `canonical_hash_bytes`, KeyPair, BLSIdentity)

**Spec:** `docs/superpowers/specs/2026-05-08-writer-registry-per-vm-policies-design.md`

---

## File Structure

### New files (under `src/ltp/execution/`)

| File | Responsibility |
|------|---------------|
| `writer.py` | Data model: `IdentityTier`, `WriterState`, `WriterIdentity`, `WriterRecord`, `TransitionEntry`, `ApprovalPath`, state machine transitions |
| `writer_config.py` | `RegistryConfig` and `ProbationModifiers` — all tunable parameters |
| `writer_roles.py` | RBAC: `RegistryAction`, `ScopedPermission`, `RegistryRole`, `RoleAssignment`, permission checking |
| `writer_registry.py` | `WriterRegistry` — enrollment, approval, sponsorship, state transitions, lookup |
| `writer_policy.py` | `VMWriterPolicy`, `PolicyEngine` — declarative 8-knob policy evaluation |
| `writer_auth.py` | `WriterAuthorizer` protocol, `AuthorizationResult`, `DispatchDecision` |
| `writer_recovery.py` | `EmergencyAction`, `EmergencyIntervention`, `EmergencyState`, policy snapshots |
| `writer_epoch.py` | `EpochTracker` — rate limits, expiration checks, probation auto-promotion |
| `writer_gate.py` | `WriterGate` — universal + per-VM layered enforcement |

### Modified files

| File | Change |
|------|--------|
| `src/ltp/execution/types.py` | Add `OperationType` enum |
| `src/ltp/execution/router.py` | Add optional `writer_gate` param to `TransactionRouter` |
| `src/ltp/execution/__init__.py` | Export new public types |

### Test files (under `tests/`)

| File | Coverage |
|------|----------|
| `tests/test_writer.py` | Identity tiers, state machine, writer records |
| `tests/test_writer_roles.py` | RBAC roles, scoped permissions, assignment |
| `tests/test_writer_registry.py` | Enrollment, approval, sponsorship, state transitions |
| `tests/test_writer_policy.py` | 8-knob policy evaluation, probation overrides |
| `tests/test_writer_auth.py` | WriterAuthorizer protocol, custom authorizer |
| `tests/test_writer_gate.py` | Layered enforcement, universal + per-VM |
| `tests/test_writer_recovery.py` | Emergency actions, policy rollback, recovery quorum |
| `tests/test_writer_epoch.py` | Rate limits, expiration, auto-promotion |
| `tests/test_writer_e2e.py` | Full lifecycle integration test |

---

### Task 1: Writer Data Model

**Files:**
- Create: `src/ltp/execution/writer.py`
- Test: `tests/test_writer.py`

- [ ] **Step 1: Write failing tests for IdentityTier and WriterState**

```python
"""Tests for Writer data model (Spec C2 §2–3)."""

import time
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st


class TestIdentityTier:
    def test_three_tiers_exist(self):
        from src.ltp.execution.writer import IdentityTier
        assert IdentityTier.MLDSA.value == "mldsa"
        assert IdentityTier.BLS.value == "bls"
        assert IdentityTier.COMPOSITE.value == "composite"

    def test_tier_count(self):
        from src.ltp.execution.writer import IdentityTier
        assert len(IdentityTier) == 3


class TestWriterState:
    def test_six_states_exist(self):
        from src.ltp.execution.writer import WriterState
        assert WriterState.PENDING.value == "pending"
        assert WriterState.PROBATION.value == "probation"
        assert WriterState.ACTIVE.value == "active"
        assert WriterState.SUSPENDED.value == "suspended"
        assert WriterState.EXPIRED.value == "expired"
        assert WriterState.REVOKED.value == "revoked"

    def test_state_count(self):
        from src.ltp.execution.writer import WriterState
        assert len(WriterState) == 6

    def test_transactable_states(self):
        from src.ltp.execution.writer import WriterState, TRANSACTABLE_STATES
        assert WriterState.ACTIVE in TRANSACTABLE_STATES
        assert WriterState.PROBATION in TRANSACTABLE_STATES
        assert WriterState.PENDING not in TRANSACTABLE_STATES
        assert WriterState.SUSPENDED not in TRANSACTABLE_STATES
        assert WriterState.EXPIRED not in TRANSACTABLE_STATES
        assert WriterState.REVOKED not in TRANSACTABLE_STATES


class TestWriterTransitions:
    def test_valid_transition_count(self):
        from src.ltp.execution.writer import VALID_WRITER_TRANSITIONS
        assert len(VALID_WRITER_TRANSITIONS) == 13

    def test_pending_to_probation_valid(self):
        from src.ltp.execution.writer import WriterState, validate_writer_transition
        ok, msg = validate_writer_transition(WriterState.PENDING, WriterState.PROBATION)
        assert ok is True
        assert msg == ""

    def test_pending_to_active_valid(self):
        from src.ltp.execution.writer import WriterState, validate_writer_transition
        ok, msg = validate_writer_transition(WriterState.PENDING, WriterState.ACTIVE)
        assert ok is True

    def test_pending_to_revoked_valid(self):
        from src.ltp.execution.writer import WriterState, validate_writer_transition
        ok, msg = validate_writer_transition(WriterState.PENDING, WriterState.REVOKED)
        assert ok is True

    def test_probation_to_active_valid(self):
        from src.ltp.execution.writer import WriterState, validate_writer_transition
        ok, _ = validate_writer_transition(WriterState.PROBATION, WriterState.ACTIVE)
        assert ok is True

    def test_active_to_suspended_valid(self):
        from src.ltp.execution.writer import WriterState, validate_writer_transition
        ok, _ = validate_writer_transition(WriterState.ACTIVE, WriterState.SUSPENDED)
        assert ok is True

    def test_suspended_to_active_valid(self):
        from src.ltp.execution.writer import WriterState, validate_writer_transition
        ok, _ = validate_writer_transition(WriterState.SUSPENDED, WriterState.ACTIVE)
        assert ok is True

    def test_expired_to_active_valid(self):
        from src.ltp.execution.writer import WriterState, validate_writer_transition
        ok, _ = validate_writer_transition(WriterState.EXPIRED, WriterState.ACTIVE)
        assert ok is True

    def test_revoked_to_anything_invalid(self):
        from src.ltp.execution.writer import WriterState, validate_writer_transition
        for target in WriterState:
            if target == WriterState.REVOKED:
                continue
            ok, msg = validate_writer_transition(WriterState.REVOKED, target)
            assert ok is False
            assert "invalid transition" in msg

    def test_noop_same_state(self):
        from src.ltp.execution.writer import WriterState, validate_writer_transition
        ok, msg = validate_writer_transition(WriterState.ACTIVE, WriterState.ACTIVE)
        assert ok is False
        assert "no-op" in msg

    def test_active_to_pending_invalid(self):
        from src.ltp.execution.writer import WriterState, validate_writer_transition
        ok, _ = validate_writer_transition(WriterState.ACTIVE, WriterState.PENDING)
        assert ok is False


class TestWriterIdentity:
    def test_from_keypair_mldsa(self):
        from src.ltp.execution.writer import WriterIdentity, IdentityTier
        from src.ltp.keypair import KeyPair
        kp = KeyPair.generate("test-mldsa")
        identity = WriterIdentity.from_keypair(kp)
        assert identity.tier == IdentityTier.MLDSA
        assert identity.mldsa_vk == kp.vk
        assert identity.bls_pk is None
        assert len(identity.fingerprint) == 32

    def test_from_keypair_composite(self):
        from src.ltp.execution.writer import WriterIdentity, IdentityTier
        from src.ltp.keypair import KeyPair
        kp = KeyPair.generate("test-composite", with_bls=True)
        identity = WriterIdentity.from_keypair(kp)
        assert identity.tier == IdentityTier.COMPOSITE
        assert identity.mldsa_vk == kp.vk
        assert identity.bls_pk == kp.bls_pk
        assert len(identity.fingerprint) == 32

    def test_from_bls_identity(self):
        from src.ltp.execution.writer import WriterIdentity, IdentityTier
        from src.ltp.bls_keys import BLSKeyPair
        bls_kp = BLSKeyPair.generate("test-bls")
        bls_id = bls_kp.to_identity()
        identity = WriterIdentity.from_bls_identity(bls_id)
        assert identity.tier == IdentityTier.BLS
        assert identity.bls_pk == bls_id.pk
        assert identity.mldsa_vk is None
        assert identity.fingerprint == bls_id.fingerprint

    def test_different_keypairs_different_fingerprints(self):
        from src.ltp.execution.writer import WriterIdentity
        from src.ltp.keypair import KeyPair
        kp1 = KeyPair.generate("a")
        kp2 = KeyPair.generate("b")
        id1 = WriterIdentity.from_keypair(kp1)
        id2 = WriterIdentity.from_keypair(kp2)
        assert id1.fingerprint != id2.fingerprint

    def test_identity_is_frozen(self):
        from src.ltp.execution.writer import WriterIdentity, IdentityTier
        from src.ltp.keypair import KeyPair
        kp = KeyPair.generate("frozen-test")
        identity = WriterIdentity.from_keypair(kp)
        with pytest.raises(AttributeError):
            identity.tier = IdentityTier.BLS


class TestTransitionEntry:
    def test_entry_fields(self):
        from src.ltp.execution.writer import TransitionEntry, WriterState
        entry = TransitionEntry(
            timestamp=1000,
            from_state=WriterState.PENDING,
            to_state=WriterState.ACTIVE,
            actor_fp=b"\x01" * 32,
            reason="admin approved",
        )
        assert entry.from_state == WriterState.PENDING
        assert entry.to_state == WriterState.ACTIVE
        assert entry.is_emergency is False

    def test_emergency_flag(self):
        from src.ltp.execution.writer import TransitionEntry, WriterState
        entry = TransitionEntry(
            timestamp=1000,
            from_state=WriterState.ACTIVE,
            to_state=WriterState.SUSPENDED,
            actor_fp=b"\x01" * 32,
            reason="emergency freeze",
            is_emergency=True,
        )
        assert entry.is_emergency is True


class TestApprovalPath:
    def test_three_paths(self):
        from src.ltp.execution.writer import ApprovalPath
        assert ApprovalPath.ADMIN.value == "admin"
        assert ApprovalPath.SPONSOR.value == "sponsor"
        assert ApprovalPath.SELF.value == "self"


class TestWriterRecord:
    def test_create_pending_record(self):
        from src.ltp.execution.writer import (
            WriterIdentity, WriterRecord, WriterState, ApprovalPath,
        )
        from src.ltp.keypair import KeyPair
        kp = KeyPair.generate("rec-test")
        identity = WriterIdentity.from_keypair(kp)
        record = WriterRecord(
            identity=identity,
            state=WriterState.PENDING,
            approval_path=ApprovalPath.SELF,
            enrolled_at=1000,
        )
        assert record.state == WriterState.PENDING
        assert record.approved_at is None
        assert record.sponsors == []
        assert record.transition_log == []

    def test_can_transact_active(self):
        from src.ltp.execution.writer import (
            WriterIdentity, WriterRecord, WriterState, ApprovalPath,
        )
        from src.ltp.keypair import KeyPair
        kp = KeyPair.generate("transact-test")
        identity = WriterIdentity.from_keypair(kp)
        record = WriterRecord(
            identity=identity,
            state=WriterState.ACTIVE,
            approval_path=ApprovalPath.ADMIN,
            enrolled_at=1000,
        )
        assert record.can_transact is True

    def test_cannot_transact_pending(self):
        from src.ltp.execution.writer import (
            WriterIdentity, WriterRecord, WriterState, ApprovalPath,
        )
        from src.ltp.keypair import KeyPair
        kp = KeyPair.generate("no-transact")
        identity = WriterIdentity.from_keypair(kp)
        record = WriterRecord(
            identity=identity,
            state=WriterState.PENDING,
            approval_path=ApprovalPath.SELF,
            enrolled_at=1000,
        )
        assert record.can_transact is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_writer.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.ltp.execution.writer'`

- [ ] **Step 3: Implement writer.py**

```python
"""Writer data model — identity, lifecycle states, records (Spec C2 §2–3).

Defines the core types consumed by all other writer_* modules.
No business logic — pure data structures and state validation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from ..primitives import canonical_hash_bytes
from ..bls_keys import BLSIdentity, bls_fingerprint, composite_fingerprint

__all__ = [
    "IdentityTier",
    "WriterState",
    "VALID_WRITER_TRANSITIONS",
    "TRANSACTABLE_STATES",
    "validate_writer_transition",
    "TransitionEntry",
    "WriterIdentity",
    "ApprovalPath",
    "WriterRecord",
]


class IdentityTier(Enum):
    """Writer identity tiers based on credential type."""
    MLDSA = "mldsa"
    BLS = "bls"
    COMPOSITE = "composite"


class WriterState(Enum):
    """Writer lifecycle states (Spec C2 §3.1)."""
    PENDING = "pending"
    PROBATION = "probation"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    EXPIRED = "expired"
    REVOKED = "revoked"


TRANSACTABLE_STATES: frozenset[WriterState] = frozenset({
    WriterState.ACTIVE,
    WriterState.PROBATION,
})


VALID_WRITER_TRANSITIONS: frozenset[tuple[WriterState, WriterState]] = frozenset({
    # Enrollment paths
    (WriterState.PENDING, WriterState.PROBATION),   # Sponsor threshold met
    (WriterState.PENDING, WriterState.ACTIVE),       # Admin approval
    (WriterState.PENDING, WriterState.REVOKED),      # Admin rejection
    # Probation resolution
    (WriterState.PROBATION, WriterState.ACTIVE),     # Probation completed
    (WriterState.PROBATION, WriterState.SUSPENDED),  # Violation during probation
    (WriterState.PROBATION, WriterState.REVOKED),    # Serious violation
    # Active writer events
    (WriterState.ACTIVE, WriterState.SUSPENDED),     # Violation / admin action
    (WriterState.ACTIVE, WriterState.EXPIRED),       # Time-bound access lapsed
    (WriterState.ACTIVE, WriterState.REVOKED),       # Permanent ban / voluntary exit
    # Recovery paths
    (WriterState.SUSPENDED, WriterState.ACTIVE),     # Reinstatement
    (WriterState.SUSPENDED, WriterState.REVOKED),    # Escalation
    (WriterState.EXPIRED, WriterState.ACTIVE),       # Renewal
    (WriterState.EXPIRED, WriterState.REVOKED),      # Cleanup
})


def validate_writer_transition(
    current: WriterState,
    target: WriterState,
) -> tuple[bool, str]:
    """Check if a writer state transition is valid.

    Follows the same pattern as anchor/state.py validate_transition.
    Returns: (True, "") if valid, (False, reason) if invalid.
    """
    if current == target:
        return False, f"no-op transition: {current.value} -> {target.value}"
    if (current, target) in VALID_WRITER_TRANSITIONS:
        return True, ""
    return False, f"invalid transition: {current.value} -> {target.value}"


@dataclass(frozen=True)
class TransitionEntry:
    """Immutable audit record of a writer state transition."""
    timestamp: int
    from_state: WriterState
    to_state: WriterState
    actor_fp: bytes
    reason: str
    is_emergency: bool = False


@dataclass(frozen=True)
class WriterIdentity:
    """Unified writer credential wrapping KeyPair or BLSIdentity (Spec C2 §2)."""
    tier: IdentityTier
    fingerprint: bytes
    mldsa_vk: Optional[bytes] = None
    bls_pk: Optional[bytes] = None

    @classmethod
    def from_keypair(cls, kp) -> WriterIdentity:
        """Create from a KeyPair. Detects COMPOSITE vs MLDSA tier."""
        if kp.bls_pk is not None:
            return cls(
                tier=IdentityTier.COMPOSITE,
                fingerprint=composite_fingerprint(kp.vk, kp.bls_pk),
                mldsa_vk=kp.vk,
                bls_pk=kp.bls_pk,
            )
        return cls(
            tier=IdentityTier.MLDSA,
            fingerprint=canonical_hash_bytes(kp.vk),
            mldsa_vk=kp.vk,
        )

    @classmethod
    def from_bls_identity(cls, bls_id: BLSIdentity) -> WriterIdentity:
        """Create from a standalone or derived BLSIdentity."""
        return cls(
            tier=IdentityTier.BLS,
            fingerprint=bls_id.fingerprint,
            bls_pk=bls_id.pk,
        )


class ApprovalPath(Enum):
    """How a writer was approved for enrollment."""
    ADMIN = "admin"
    SPONSOR = "sponsor"
    SELF = "self"


@dataclass
class WriterRecord:
    """Mutable record tracking a writer's lifecycle in the registry."""
    identity: WriterIdentity
    state: WriterState
    approval_path: ApprovalPath
    enrolled_at: int
    approved_at: Optional[int] = None
    approved_by: Optional[bytes] = None
    sponsors: list[bytes] = field(default_factory=list)
    probation_until: Optional[int] = None
    expires_at: Optional[int] = None
    suspension_reason: Optional[str] = None
    transition_log: list[TransitionEntry] = field(default_factory=list)

    @property
    def can_transact(self) -> bool:
        """Whether this writer can submit transactions."""
        return self.state in TRANSACTABLE_STATES
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_writer.py -v`
Expected: All 25 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/writer.py tests/test_writer.py
git commit -m "feat(writer): add writer data model — identity tiers, state machine, records (C2 §2–3)"
```

---

### Task 2: Registry Config

**Files:**
- Create: `src/ltp/execution/writer_config.py`
- Test: `tests/test_writer.py` (append to existing)

- [ ] **Step 1: Write failing tests for RegistryConfig**

Append to `tests/test_writer.py`:

```python
class TestRegistryConfig:
    def test_defaults(self):
        from src.ltp.execution.writer_config import RegistryConfig
        cfg = RegistryConfig()
        assert cfg.sponsor_threshold == 2
        assert cfg.probation_epochs == 10
        assert cfg.default_expiry_epochs == 0

    def test_custom_config(self):
        from src.ltp.execution.writer_config import RegistryConfig
        cfg = RegistryConfig(sponsor_threshold=3, probation_epochs=20, default_expiry_epochs=100)
        assert cfg.sponsor_threshold == 3
        assert cfg.probation_epochs == 20
        assert cfg.default_expiry_epochs == 100

    def test_probation_modifiers_defaults(self):
        from src.ltp.execution.writer_config import ProbationModifiers
        mods = ProbationModifiers()
        assert mods.rate_limit_divisor == 2
        assert mods.fee_multiplier_factor == 2.0
        assert mods.blocked_operations == frozenset({"deploy"})

    def test_config_has_probation_modifiers(self):
        from src.ltp.execution.writer_config import RegistryConfig
        cfg = RegistryConfig()
        assert cfg.probation_modifiers is not None
        assert cfg.probation_modifiers.rate_limit_divisor == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_writer.py::TestRegistryConfig -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement writer_config.py**

```python
"""Registry configuration — tunable parameters for writer enrollment (Spec C2 §4.5)."""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["RegistryConfig", "ProbationModifiers"]


@dataclass(frozen=True)
class ProbationModifiers:
    """Constraints applied to writers in PROBATION state (Spec C2 §6.4)."""
    rate_limit_divisor: int = 2            # Halve the VM's rate limit
    fee_multiplier_factor: float = 2.0     # Double the fee multiplier
    blocked_operations: frozenset[str] = frozenset({"deploy"})  # Deny these ops


@dataclass(frozen=True)
class RegistryConfig:
    """Global configuration for the WriterRegistry."""
    sponsor_threshold: int = 2
    probation_epochs: int = 10
    default_expiry_epochs: int = 0         # 0 = no expiry
    probation_modifiers: ProbationModifiers = field(default_factory=ProbationModifiers)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_writer.py -v`
Expected: All tests PASS (25 from Task 1 + 4 new)

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/writer_config.py tests/test_writer.py
git commit -m "feat(writer): add RegistryConfig and ProbationModifiers (C2 §4.5)"
```

---

### Task 3: RBAC Roles

**Files:**
- Create: `src/ltp/execution/writer_roles.py`
- Test: `tests/test_writer_roles.py`

- [ ] **Step 1: Write failing tests**

```python
"""Tests for Writer RBAC roles and scoped permissions (Spec C2 §5)."""

import pytest


class TestRegistryAction:
    def test_nine_actions(self):
        from src.ltp.execution.writer_roles import RegistryAction
        assert len(RegistryAction) == 9
        assert RegistryAction.APPROVE.value == "approve"
        assert RegistryAction.CONFIGURE_POLICY.value == "configure_policy"
        assert RegistryAction.MANAGE_DENYLIST.value == "manage_denylist"


class TestScopedPermission:
    def test_unrestricted_permission(self):
        from src.ltp.execution.writer_roles import ScopedPermission, RegistryAction
        perm = ScopedPermission(action=RegistryAction.APPROVE)
        assert perm.tier_scope is None  # all tiers
        assert perm.vm_scope is None    # all VMs

    def test_scoped_to_tier_and_vm(self):
        from src.ltp.execution.writer_roles import ScopedPermission, RegistryAction
        from src.ltp.execution.writer import IdentityTier
        perm = ScopedPermission(
            action=RegistryAction.APPROVE,
            tier_scope={IdentityTier.BLS},
            vm_scope={0x01},
        )
        assert IdentityTier.BLS in perm.tier_scope
        assert 0x01 in perm.vm_scope

    def test_matches_unrestricted(self):
        from src.ltp.execution.writer_roles import ScopedPermission, RegistryAction
        from src.ltp.execution.writer import IdentityTier
        perm = ScopedPermission(action=RegistryAction.APPROVE)
        assert perm.matches(RegistryAction.APPROVE, IdentityTier.BLS, 0x01) is True
        assert perm.matches(RegistryAction.APPROVE, IdentityTier.MLDSA, 0x20) is True

    def test_matches_scoped(self):
        from src.ltp.execution.writer_roles import ScopedPermission, RegistryAction
        from src.ltp.execution.writer import IdentityTier
        perm = ScopedPermission(
            action=RegistryAction.APPROVE,
            tier_scope={IdentityTier.BLS},
            vm_scope={0x01},
        )
        assert perm.matches(RegistryAction.APPROVE, IdentityTier.BLS, 0x01) is True
        assert perm.matches(RegistryAction.APPROVE, IdentityTier.MLDSA, 0x01) is False
        assert perm.matches(RegistryAction.APPROVE, IdentityTier.BLS, 0x20) is False
        assert perm.matches(RegistryAction.SUSPEND, IdentityTier.BLS, 0x01) is False

    def test_matches_no_vm_context(self):
        """Actions like APPROVE don't require VM scope — pass vm_tag=None."""
        from src.ltp.execution.writer_roles import ScopedPermission, RegistryAction
        from src.ltp.execution.writer import IdentityTier
        perm = ScopedPermission(action=RegistryAction.APPROVE)
        assert perm.matches(RegistryAction.APPROVE, IdentityTier.BLS, None) is True


class TestRegistryRole:
    def test_custom_role(self):
        from src.ltp.execution.writer_roles import (
            RegistryRole, ScopedPermission, RegistryAction,
        )
        from src.ltp.execution.writer import IdentityTier
        role = RegistryRole(
            name="evm-operator",
            permissions=[
                ScopedPermission(
                    action=RegistryAction.APPROVE,
                    tier_scope={IdentityTier.BLS},
                    vm_scope={0x01},
                ),
                ScopedPermission(
                    action=RegistryAction.SUSPEND,
                    tier_scope={IdentityTier.BLS},
                    vm_scope={0x01},
                ),
            ],
            is_builtin=False,
        )
        assert role.has_permission(RegistryAction.APPROVE, IdentityTier.BLS, 0x01)
        assert not role.has_permission(RegistryAction.APPROVE, IdentityTier.MLDSA, 0x01)
        assert not role.has_permission(RegistryAction.REVOKE, IdentityTier.BLS, 0x01)


class TestBuiltinRoles:
    def test_owner_role(self):
        from src.ltp.execution.writer_roles import builtin_owner, RegistryAction
        from src.ltp.execution.writer import IdentityTier
        owner = builtin_owner()
        assert owner.is_builtin is True
        # Owner can do anything
        for action in RegistryAction:
            for tier in IdentityTier:
                assert owner.has_permission(action, tier, 0x01)

    def test_admin_role(self):
        from src.ltp.execution.writer_roles import builtin_admin, RegistryAction
        from src.ltp.execution.writer import IdentityTier
        admin = builtin_admin()
        assert admin.is_builtin is True
        # Admin can approve/suspend/revoke but not configure policy
        assert admin.has_permission(RegistryAction.APPROVE, IdentityTier.BLS, None)
        assert admin.has_permission(RegistryAction.SUSPEND, IdentityTier.BLS, None)
        assert admin.has_permission(RegistryAction.REVOKE, IdentityTier.BLS, None)
        assert not admin.has_permission(RegistryAction.CONFIGURE_POLICY, IdentityTier.BLS, None)

    def test_sponsor_role(self):
        from src.ltp.execution.writer_roles import builtin_sponsor, RegistryAction
        from src.ltp.execution.writer import IdentityTier
        sponsor = builtin_sponsor()
        assert sponsor.is_builtin is True
        # Sponsor can only approve (vouch)
        assert sponsor.has_permission(RegistryAction.APPROVE, IdentityTier.BLS, None)
        assert not sponsor.has_permission(RegistryAction.SUSPEND, IdentityTier.BLS, None)


class TestRoleAssignment:
    def test_assignment_fields(self):
        from src.ltp.execution.writer_roles import RoleAssignment, builtin_admin
        assignment = RoleAssignment(
            role=builtin_admin(),
            assignee_fp=b"\xaa" * 32,
            assigned_by=b"\xbb" * 32,
            assigned_at=1000,
        )
        assert assignment.expires_at is None
        assert assignment.assignee_fp == b"\xaa" * 32

    def test_assignment_expired(self):
        from src.ltp.execution.writer_roles import RoleAssignment, builtin_admin
        assignment = RoleAssignment(
            role=builtin_admin(),
            assignee_fp=b"\xaa" * 32,
            assigned_by=b"\xbb" * 32,
            assigned_at=1000,
            expires_at=5,
        )
        assert assignment.is_active(current_epoch=4) is True
        assert assignment.is_active(current_epoch=5) is False
        assert assignment.is_active(current_epoch=6) is False

    def test_permanent_assignment(self):
        from src.ltp.execution.writer_roles import RoleAssignment, builtin_admin
        assignment = RoleAssignment(
            role=builtin_admin(),
            assignee_fp=b"\xaa" * 32,
            assigned_by=b"\xbb" * 32,
            assigned_at=1000,
            expires_at=None,
        )
        assert assignment.is_active(current_epoch=999999) is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_writer_roles.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement writer_roles.py**

```python
"""Writer RBAC — roles, scoped permissions, assignment (Spec C2 §5)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .writer import IdentityTier

__all__ = [
    "RegistryAction",
    "ScopedPermission",
    "RegistryRole",
    "RoleAssignment",
    "builtin_owner",
    "builtin_admin",
    "builtin_sponsor",
]


class RegistryAction(Enum):
    """Actions that can be performed on the writer registry."""
    APPROVE = "approve"
    REJECT = "reject"
    SUSPEND = "suspend"
    REINSTATE = "reinstate"
    REVOKE = "revoke"
    CONFIGURE_POLICY = "configure_policy"
    SET_RATE_LIMIT = "set_rate_limit"
    MANAGE_ALLOWLIST = "manage_allowlist"
    MANAGE_DENYLIST = "manage_denylist"


@dataclass(frozen=True)
class ScopedPermission:
    """A permission scoped to specific identity tiers and/or VMs."""
    action: RegistryAction
    tier_scope: Optional[frozenset[IdentityTier]] = None  # None = all tiers
    vm_scope: Optional[frozenset[int]] = None              # None = all VMs

    def __init__(self, action: RegistryAction,
                 tier_scope: Optional[set[IdentityTier]] = None,
                 vm_scope: Optional[set[int]] = None):
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "tier_scope",
                           frozenset(tier_scope) if tier_scope is not None else None)
        object.__setattr__(self, "vm_scope",
                           frozenset(vm_scope) if vm_scope is not None else None)

    def matches(self, action: RegistryAction,
                tier: Optional[IdentityTier] = None,
                vm_tag: Optional[int] = None) -> bool:
        """Check if this permission covers the given action/tier/vm."""
        if self.action != action:
            return False
        if self.tier_scope is not None and tier is not None:
            if tier not in self.tier_scope:
                return False
        if self.vm_scope is not None and vm_tag is not None:
            if vm_tag not in self.vm_scope:
                return False
        return True


@dataclass(frozen=True)
class RegistryRole:
    """A named role with a set of scoped permissions."""
    name: str
    permissions: tuple[ScopedPermission, ...]
    is_builtin: bool

    def __init__(self, name: str,
                 permissions: list[ScopedPermission] | tuple[ScopedPermission, ...],
                 is_builtin: bool):
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "permissions",
                           tuple(permissions) if isinstance(permissions, list) else permissions)
        object.__setattr__(self, "is_builtin", is_builtin)

    def has_permission(self, action: RegistryAction,
                       tier: Optional[IdentityTier] = None,
                       vm_tag: Optional[int] = None) -> bool:
        """Check if this role grants the given action for the tier/vm context."""
        return any(p.matches(action, tier, vm_tag) for p in self.permissions)


@dataclass(frozen=True)
class RoleAssignment:
    """Binds a role to a specific writer identity."""
    role: RegistryRole
    assignee_fp: bytes
    assigned_by: bytes
    assigned_at: int
    expires_at: Optional[int] = None

    def is_active(self, current_epoch: int) -> bool:
        """Check if this assignment is still valid."""
        if self.expires_at is None:
            return True
        return current_epoch < self.expires_at


def builtin_owner() -> RegistryRole:
    """Owner role — full control over everything."""
    all_perms = [ScopedPermission(action=a) for a in RegistryAction]
    return RegistryRole(name="owner", permissions=all_perms, is_builtin=True)


def builtin_admin() -> RegistryRole:
    """Admin role — writer lifecycle operations only."""
    admin_actions = [
        RegistryAction.APPROVE,
        RegistryAction.REJECT,
        RegistryAction.SUSPEND,
        RegistryAction.REINSTATE,
        RegistryAction.REVOKE,
    ]
    perms = [ScopedPermission(action=a) for a in admin_actions]
    return RegistryRole(name="admin", permissions=perms, is_builtin=True)


def builtin_sponsor() -> RegistryRole:
    """Sponsor role — can only vouch for pending writers."""
    perms = [ScopedPermission(action=RegistryAction.APPROVE)]
    return RegistryRole(name="sponsor", permissions=perms, is_builtin=True)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_writer_roles.py -v`
Expected: All 13 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/writer_roles.py tests/test_writer_roles.py
git commit -m "feat(writer): add RBAC roles with scoped permissions (C2 §5)"
```

---

### Task 4: Writer Registry

**Files:**
- Create: `src/ltp/execution/writer_registry.py`
- Test: `tests/test_writer_registry.py`

- [ ] **Step 1: Write failing tests**

```python
"""Tests for WriterRegistry — enrollment, approval, state transitions (Spec C2 §4)."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st


def _make_mldsa_identity():
    from src.ltp.execution.writer import WriterIdentity
    from src.ltp.keypair import KeyPair
    kp = KeyPair.generate("reg-test")
    return WriterIdentity.from_keypair(kp)


def _make_bls_identity():
    from src.ltp.execution.writer import WriterIdentity
    from src.ltp.bls_keys import BLSKeyPair
    bls_kp = BLSKeyPair.generate("reg-bls")
    return bls_kp.to_identity(), WriterIdentity.from_bls_identity(bls_kp.to_identity())


def _make_registry(sponsor_threshold=2, probation_epochs=10):
    from src.ltp.execution.writer_registry import WriterRegistry
    from src.ltp.execution.writer_config import RegistryConfig
    cfg = RegistryConfig(
        sponsor_threshold=sponsor_threshold,
        probation_epochs=probation_epochs,
    )
    return WriterRegistry(config=cfg)


class TestEnrollment:
    def test_enroll_creates_pending_record(self):
        from src.ltp.execution.writer import WriterState, ApprovalPath
        reg = _make_registry()
        identity = _make_mldsa_identity()
        record = reg.enroll(identity, timestamp=1000)
        assert record.state == WriterState.PENDING
        assert record.approval_path == ApprovalPath.SELF
        assert record.enrolled_at == 1000
        assert len(record.transition_log) == 0

    def test_enroll_lookup(self):
        reg = _make_registry()
        identity = _make_mldsa_identity()
        reg.enroll(identity, timestamp=1000)
        found = reg.lookup(identity.fingerprint)
        assert found is not None
        assert found.identity.fingerprint == identity.fingerprint

    def test_enroll_duplicate_rejected(self):
        reg = _make_registry()
        identity = _make_mldsa_identity()
        reg.enroll(identity, timestamp=1000)
        with pytest.raises(ValueError, match="already registered"):
            reg.enroll(identity, timestamp=2000)

    def test_enroll_revoked_identity_rejected(self):
        reg = _make_registry()
        identity = _make_mldsa_identity()
        reg.enroll(identity, timestamp=1000)
        reg.approve(identity.fingerprint, admin_fp=b"\x01" * 32, timestamp=2000)
        reg.revoke(identity.fingerprint, reason="ban", actor_fp=b"\x01" * 32, timestamp=3000)
        with pytest.raises(ValueError, match="previously revoked"):
            reg.enroll(identity, timestamp=4000)

    def test_enroll_bls_identity(self):
        from src.ltp.execution.writer import IdentityTier
        reg = _make_registry()
        _, identity = _make_bls_identity()
        record = reg.enroll(identity, timestamp=1000)
        assert record.identity.tier == IdentityTier.BLS


class TestAdminApproval:
    def test_approve_pending_to_active(self):
        from src.ltp.execution.writer import WriterState
        reg = _make_registry()
        identity = _make_mldsa_identity()
        reg.enroll(identity, timestamp=1000)
        record = reg.approve(identity.fingerprint, admin_fp=b"\x01" * 32, timestamp=2000)
        assert record.state == WriterState.ACTIVE
        assert record.approved_at == 2000
        assert record.approved_by == b"\x01" * 32
        assert len(record.transition_log) == 1

    def test_approve_nonexistent_raises(self):
        reg = _make_registry()
        with pytest.raises(KeyError):
            reg.approve(b"\xff" * 32, admin_fp=b"\x01" * 32, timestamp=1000)

    def test_approve_already_active_raises(self):
        reg = _make_registry()
        identity = _make_mldsa_identity()
        reg.enroll(identity, timestamp=1000)
        reg.approve(identity.fingerprint, admin_fp=b"\x01" * 32, timestamp=2000)
        with pytest.raises(ValueError, match="invalid transition"):
            reg.approve(identity.fingerprint, admin_fp=b"\x01" * 32, timestamp=3000)


class TestSponsorFlow:
    def test_single_sponsor_not_enough(self):
        from src.ltp.execution.writer import WriterState
        reg = _make_registry(sponsor_threshold=2)
        identity = _make_mldsa_identity()
        reg.enroll(identity, timestamp=1000)
        record = reg.sponsor(identity.fingerprint, sponsor_fp=b"\xaa" * 32, timestamp=2000)
        assert record.state == WriterState.PENDING
        assert len(record.sponsors) == 1

    def test_threshold_met_transitions_to_probation(self):
        from src.ltp.execution.writer import WriterState, ApprovalPath
        reg = _make_registry(sponsor_threshold=2)
        identity = _make_mldsa_identity()
        reg.enroll(identity, timestamp=1000)
        reg.sponsor(identity.fingerprint, sponsor_fp=b"\xaa" * 32, timestamp=2000)
        record = reg.sponsor(identity.fingerprint, sponsor_fp=b"\xbb" * 32, timestamp=3000)
        assert record.state == WriterState.PROBATION
        assert record.approval_path == ApprovalPath.SPONSOR
        assert len(record.sponsors) == 2
        assert record.probation_until is not None

    def test_duplicate_sponsor_ignored(self):
        reg = _make_registry(sponsor_threshold=2)
        identity = _make_mldsa_identity()
        reg.enroll(identity, timestamp=1000)
        reg.sponsor(identity.fingerprint, sponsor_fp=b"\xaa" * 32, timestamp=2000)
        record = reg.sponsor(identity.fingerprint, sponsor_fp=b"\xaa" * 32, timestamp=3000)
        assert len(record.sponsors) == 1


class TestStateTransitions:
    def test_suspend_active_writer(self):
        from src.ltp.execution.writer import WriterState
        reg = _make_registry()
        identity = _make_mldsa_identity()
        reg.enroll(identity, timestamp=1000)
        reg.approve(identity.fingerprint, admin_fp=b"\x01" * 32, timestamp=2000)
        record = reg.suspend(
            identity.fingerprint, reason="violation",
            actor_fp=b"\x01" * 32, timestamp=3000,
        )
        assert record.state == WriterState.SUSPENDED
        assert record.suspension_reason == "violation"

    def test_reinstate_suspended_writer(self):
        from src.ltp.execution.writer import WriterState
        reg = _make_registry()
        identity = _make_mldsa_identity()
        reg.enroll(identity, timestamp=1000)
        reg.approve(identity.fingerprint, admin_fp=b"\x01" * 32, timestamp=2000)
        reg.suspend(identity.fingerprint, reason="test", actor_fp=b"\x01" * 32, timestamp=3000)
        record = reg.reinstate(identity.fingerprint, actor_fp=b"\x01" * 32, timestamp=4000)
        assert record.state == WriterState.ACTIVE

    def test_revoke_is_permanent(self):
        from src.ltp.execution.writer import WriterState
        reg = _make_registry()
        identity = _make_mldsa_identity()
        reg.enroll(identity, timestamp=1000)
        reg.approve(identity.fingerprint, admin_fp=b"\x01" * 32, timestamp=2000)
        record = reg.revoke(
            identity.fingerprint, reason="ban",
            actor_fp=b"\x01" * 32, timestamp=3000,
        )
        assert record.state == WriterState.REVOKED
        with pytest.raises(ValueError, match="invalid transition"):
            reg.reinstate(identity.fingerprint, actor_fp=b"\x01" * 32, timestamp=4000)

    def test_renew_expired_writer(self):
        from src.ltp.execution.writer import WriterState
        reg = _make_registry()
        identity = _make_mldsa_identity()
        reg.enroll(identity, timestamp=1000)
        reg.approve(identity.fingerprint, admin_fp=b"\x01" * 32, timestamp=2000)
        # Manually expire
        record = reg.lookup(identity.fingerprint)
        record.expires_at = 5
        reg.check_expirations(current_epoch=5)
        record = reg.lookup(identity.fingerprint)
        assert record.state == WriterState.EXPIRED
        record = reg.renew(identity.fingerprint, actor_fp=b"\x01" * 32, timestamp=6000)
        assert record.state == WriterState.ACTIVE

    def test_promote_probation_to_active(self):
        from src.ltp.execution.writer import WriterState
        reg = _make_registry(sponsor_threshold=1, probation_epochs=5)
        identity = _make_mldsa_identity()
        reg.enroll(identity, timestamp=1000)
        reg.sponsor(identity.fingerprint, sponsor_fp=b"\xaa" * 32, timestamp=2000)
        record = reg.lookup(identity.fingerprint)
        assert record.state == WriterState.PROBATION
        record = reg.promote(identity.fingerprint, timestamp=3000)
        assert record.state == WriterState.ACTIVE


class TestAuditTrail:
    def test_transitions_logged(self):
        reg = _make_registry()
        identity = _make_mldsa_identity()
        reg.enroll(identity, timestamp=1000)
        reg.approve(identity.fingerprint, admin_fp=b"\x01" * 32, timestamp=2000)
        reg.suspend(identity.fingerprint, reason="test", actor_fp=b"\x01" * 32, timestamp=3000)
        record = reg.lookup(identity.fingerprint)
        assert len(record.transition_log) == 2
        assert record.transition_log[0].reason == "admin approved"
        assert record.transition_log[1].reason == "test"


class TestActiveWriters:
    def test_active_writers_list(self):
        reg = _make_registry()
        id1 = _make_mldsa_identity()
        id2 = _make_mldsa_identity()
        reg.enroll(id1, timestamp=1000)
        reg.enroll(id2, timestamp=1000)
        reg.approve(id1.fingerprint, admin_fp=b"\x01" * 32, timestamp=2000)
        active = reg.active_writers()
        assert len(active) == 1
        assert active[0].identity.fingerprint == id1.fingerprint
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_writer_registry.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement writer_registry.py**

```python
"""WriterRegistry — enrollment, approval, state transitions (Spec C2 §4)."""

from __future__ import annotations

from typing import Optional

from .writer import (
    ApprovalPath, TransitionEntry, WriterIdentity, WriterRecord,
    WriterState, TRANSACTABLE_STATES, validate_writer_transition,
)
from .writer_config import RegistryConfig

__all__ = ["WriterRegistry"]


class WriterRegistry:
    """Central enrollment authority for writer identities.

    Manages writer records and state transitions. Contains no
    policy evaluation logic — that lives in writer_policy.py.
    """

    def __init__(self, config: Optional[RegistryConfig] = None) -> None:
        self._config = config or RegistryConfig()
        self._records: dict[bytes, WriterRecord] = {}
        self._revoked: set[bytes] = set()

    @property
    def config(self) -> RegistryConfig:
        return self._config

    def enroll(self, identity: WriterIdentity, timestamp: int) -> WriterRecord:
        """Register a new writer in PENDING state."""
        fp = identity.fingerprint
        if fp in self._revoked:
            raise ValueError(f"identity {fp.hex()[:16]} previously revoked")
        if fp in self._records:
            raise ValueError(f"identity {fp.hex()[:16]} already registered")
        record = WriterRecord(
            identity=identity,
            state=WriterState.PENDING,
            approval_path=ApprovalPath.SELF,
            enrolled_at=timestamp,
        )
        self._records[fp] = record
        return record

    def lookup(self, fingerprint: bytes) -> Optional[WriterRecord]:
        """Read-only lookup by fingerprint."""
        return self._records.get(fingerprint)

    def _get(self, fingerprint: bytes) -> WriterRecord:
        record = self._records.get(fingerprint)
        if record is None:
            raise KeyError(f"writer {fingerprint.hex()[:16]} not found")
        return record

    def _transition(self, fingerprint: bytes, target: WriterState,
                    actor_fp: bytes, reason: str, timestamp: int,
                    is_emergency: bool = False) -> WriterRecord:
        record = self._get(fingerprint)
        ok, msg = validate_writer_transition(record.state, target)
        if not ok:
            raise ValueError(msg)
        entry = TransitionEntry(
            timestamp=timestamp,
            from_state=record.state,
            to_state=target,
            actor_fp=actor_fp,
            reason=reason,
            is_emergency=is_emergency,
        )
        record.transition_log.append(entry)
        record.state = target
        if target == WriterState.REVOKED:
            self._revoked.add(fingerprint)
        return record

    def approve(self, fingerprint: bytes, admin_fp: bytes,
                timestamp: int) -> WriterRecord:
        """Admin approval: PENDING → ACTIVE."""
        record = self._transition(
            fingerprint, WriterState.ACTIVE, admin_fp, "admin approved", timestamp,
        )
        record.approval_path = ApprovalPath.ADMIN
        record.approved_at = timestamp
        record.approved_by = admin_fp
        return record

    def sponsor(self, fingerprint: bytes, sponsor_fp: bytes,
                timestamp: int) -> WriterRecord:
        """Add a sponsor. If threshold met: PENDING → PROBATION."""
        record = self._get(fingerprint)
        if record.state != WriterState.PENDING:
            raise ValueError(f"can only sponsor PENDING writers, got {record.state.value}")
        if sponsor_fp in record.sponsors:
            return record  # duplicate sponsor, no-op
        record.sponsors.append(sponsor_fp)
        if len(record.sponsors) >= self._config.sponsor_threshold:
            self._transition(
                fingerprint, WriterState.PROBATION, sponsor_fp,
                f"sponsor threshold met ({len(record.sponsors)}/{self._config.sponsor_threshold})",
                timestamp,
            )
            record.approval_path = ApprovalPath.SPONSOR
            record.approved_at = timestamp
            record.approved_by = b"sponsors"
            record.probation_until = self._config.probation_epochs
        return record

    def promote(self, fingerprint: bytes, timestamp: int) -> WriterRecord:
        """System call: PROBATION → ACTIVE after probation period."""
        return self._transition(
            fingerprint, WriterState.ACTIVE, b"system",
            "probation completed", timestamp,
        )

    def suspend(self, fingerprint: bytes, reason: str,
                actor_fp: bytes, timestamp: int) -> WriterRecord:
        """Suspend a writer: ACTIVE/PROBATION → SUSPENDED."""
        record = self._transition(
            fingerprint, WriterState.SUSPENDED, actor_fp, reason, timestamp,
        )
        record.suspension_reason = reason
        return record

    def reinstate(self, fingerprint: bytes, actor_fp: bytes,
                  timestamp: int) -> WriterRecord:
        """Reinstate a suspended writer: SUSPENDED → ACTIVE."""
        record = self._transition(
            fingerprint, WriterState.ACTIVE, actor_fp, "reinstated", timestamp,
        )
        record.suspension_reason = None
        return record

    def revoke(self, fingerprint: bytes, reason: str,
               actor_fp: bytes, timestamp: int) -> WriterRecord:
        """Permanently revoke a writer. Cannot re-register."""
        return self._transition(
            fingerprint, WriterState.REVOKED, actor_fp, reason, timestamp,
        )

    def renew(self, fingerprint: bytes, actor_fp: bytes,
              timestamp: int) -> WriterRecord:
        """Renew an expired writer: EXPIRED → ACTIVE."""
        return self._transition(
            fingerprint, WriterState.ACTIVE, actor_fp, "renewed", timestamp,
        )

    def check_expirations(self, current_epoch: int) -> list[bytes]:
        """Batch scan: ACTIVE writers past expires_at → EXPIRED."""
        expired = []
        for fp, record in self._records.items():
            if (record.state == WriterState.ACTIVE
                    and record.expires_at is not None
                    and record.expires_at > 0
                    and current_epoch >= record.expires_at):
                self._transition(
                    fp, WriterState.EXPIRED, b"system",
                    f"access expired at epoch {record.expires_at}",
                    current_epoch,
                )
                expired.append(fp)
        return expired

    def active_writers(self) -> list[WriterRecord]:
        """Return all writers in ACTIVE or PROBATION state."""
        return [r for r in self._records.values() if r.state in TRANSACTABLE_STATES]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_writer_registry.py -v`
Expected: All 18 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/writer_registry.py tests/test_writer_registry.py
git commit -m "feat(writer): add WriterRegistry — enrollment, approval, state machine (C2 §4)"
```

---

### Task 5: OperationType + Policy Engine

**Files:**
- Modify: `src/ltp/execution/types.py`
- Create: `src/ltp/execution/writer_policy.py`
- Test: `tests/test_writer_policy.py`

- [ ] **Step 1: Write failing tests**

```python
"""Tests for per-VM writer policy and PolicyEngine (Spec C2 §6)."""

import pytest


class TestOperationType:
    def test_five_operations(self):
        from src.ltp.execution.types import OperationType
        assert len(OperationType) == 5
        assert OperationType.TRANSFER.value == "transfer"
        assert OperationType.DEPLOY.value == "deploy"
        assert OperationType.CALL.value == "call"
        assert OperationType.STATE_MODIFY.value == "state_modify"
        assert OperationType.STATE_READ.value == "state_read"


class TestVMWriterPolicyDefaults:
    def test_default_allows_all_tiers(self):
        from src.ltp.execution.writer_policy import VMWriterPolicy
        from src.ltp.execution.writer import IdentityTier
        policy = VMWriterPolicy(vm_tag=0x01)
        assert IdentityTier.MLDSA in policy.allowed_tiers
        assert IdentityTier.BLS in policy.allowed_tiers
        assert IdentityTier.COMPOSITE in policy.allowed_tiers

    def test_default_bls_restricted_ops(self):
        from src.ltp.execution.writer_policy import VMWriterPolicy
        from src.ltp.execution.writer import IdentityTier
        from src.ltp.execution.types import OperationType
        policy = VMWriterPolicy(vm_tag=0x01)
        bls_ops = policy.tier_operations[IdentityTier.BLS]
        assert OperationType.TRANSFER in bls_ops
        assert OperationType.STATE_READ in bls_ops
        assert OperationType.DEPLOY not in bls_ops

    def test_default_mldsa_all_ops(self):
        from src.ltp.execution.writer_policy import VMWriterPolicy
        from src.ltp.execution.writer import IdentityTier
        from src.ltp.execution.types import OperationType
        policy = VMWriterPolicy(vm_tag=0x01)
        mldsa_ops = policy.tier_operations[IdentityTier.MLDSA]
        assert len(mldsa_ops) == len(OperationType)


class TestPolicyEvaluation:
    def _make_active_record(self, tier_str="mldsa"):
        from src.ltp.execution.writer import (
            WriterIdentity, WriterRecord, WriterState, ApprovalPath, IdentityTier,
        )
        tier = IdentityTier(tier_str)
        identity = WriterIdentity(
            tier=tier, fingerprint=b"\xaa" * 32,
            mldsa_vk=b"\x01" * 32 if tier_str != "bls" else None,
            bls_pk=b"\x02" * 48 if tier_str != "mldsa" else None,
        )
        return WriterRecord(
            identity=identity, state=WriterState.ACTIVE,
            approval_path=ApprovalPath.ADMIN, enrolled_at=1000,
        )

    def test_mldsa_deploy_allowed(self):
        from src.ltp.execution.writer_policy import VMWriterPolicy, PolicyEngine
        from src.ltp.execution.types import OperationType
        policy = VMWriterPolicy(vm_tag=0x01)
        engine = PolicyEngine()
        record = self._make_active_record("mldsa")
        result = engine.evaluate(record, OperationType.DEPLOY, policy)
        assert result.allowed is True

    def test_bls_deploy_rejected(self):
        from src.ltp.execution.writer_policy import VMWriterPolicy, PolicyEngine
        from src.ltp.execution.types import OperationType
        policy = VMWriterPolicy(vm_tag=0x01)
        engine = PolicyEngine()
        record = self._make_active_record("bls")
        result = engine.evaluate(record, OperationType.DEPLOY, policy)
        assert result.allowed is False
        assert "operation not permitted" in result.reason

    def test_bls_transfer_allowed(self):
        from src.ltp.execution.writer_policy import VMWriterPolicy, PolicyEngine
        from src.ltp.execution.types import OperationType
        policy = VMWriterPolicy(vm_tag=0x01)
        engine = PolicyEngine()
        record = self._make_active_record("bls")
        result = engine.evaluate(record, OperationType.TRANSFER, policy)
        assert result.allowed is True

    def test_denylist_blocks(self):
        from src.ltp.execution.writer_policy import VMWriterPolicy, PolicyEngine
        from src.ltp.execution.types import OperationType
        policy = VMWriterPolicy(vm_tag=0x01, denylist={b"\xaa" * 32})
        engine = PolicyEngine()
        record = self._make_active_record("mldsa")
        result = engine.evaluate(record, OperationType.TRANSFER, policy)
        assert result.allowed is False
        assert "denylist" in result.reason

    def test_allowlist_blocks_unlisted(self):
        from src.ltp.execution.writer_policy import VMWriterPolicy, PolicyEngine
        from src.ltp.execution.types import OperationType
        policy = VMWriterPolicy(vm_tag=0x01, allowlist={b"\xbb" * 32})
        engine = PolicyEngine()
        record = self._make_active_record("mldsa")
        result = engine.evaluate(record, OperationType.TRANSFER, policy)
        assert result.allowed is False
        assert "allowlist" in result.reason

    def test_tier_not_allowed(self):
        from src.ltp.execution.writer_policy import VMWriterPolicy, PolicyEngine
        from src.ltp.execution.writer import IdentityTier
        from src.ltp.execution.types import OperationType
        policy = VMWriterPolicy(vm_tag=0x01, allowed_tiers={IdentityTier.MLDSA})
        engine = PolicyEngine()
        record = self._make_active_record("bls")
        result = engine.evaluate(record, OperationType.TRANSFER, policy)
        assert result.allowed is False
        assert "tier" in result.reason

    def test_rate_limit_exceeded(self):
        from src.ltp.execution.writer_policy import VMWriterPolicy, PolicyEngine
        from src.ltp.execution.writer import IdentityTier
        from src.ltp.execution.types import OperationType
        policy = VMWriterPolicy(
            vm_tag=0x01,
            max_txs_per_epoch={
                IdentityTier.MLDSA: 1,
                IdentityTier.COMPOSITE: 1,
                IdentityTier.BLS: 1,
            },
        )
        engine = PolicyEngine()
        record = self._make_active_record("mldsa")
        result1 = engine.evaluate(record, OperationType.TRANSFER, policy, tx_count=0)
        assert result1.allowed is True
        result2 = engine.evaluate(record, OperationType.TRANSFER, policy, tx_count=1)
        assert result2.allowed is False
        assert "rate limit" in result2.reason

    def test_fee_multiplier_returned(self):
        from src.ltp.execution.writer_policy import VMWriterPolicy, PolicyEngine
        from src.ltp.execution.writer import IdentityTier
        from src.ltp.execution.types import OperationType
        policy = VMWriterPolicy(
            vm_tag=0x01,
            fee_multiplier={
                IdentityTier.MLDSA: 1.5,
                IdentityTier.COMPOSITE: 1.5,
                IdentityTier.BLS: 2.0,
            },
        )
        engine = PolicyEngine()
        record = self._make_active_record("mldsa")
        result = engine.evaluate(record, OperationType.TRANSFER, policy)
        assert result.fee_multiplier == 1.5

    def test_equal_access_policy(self):
        """VM configures equal capabilities for all tiers (option A capacity)."""
        from src.ltp.execution.writer_policy import VMWriterPolicy, PolicyEngine
        from src.ltp.execution.writer import IdentityTier
        from src.ltp.execution.types import OperationType
        all_ops = set(OperationType)
        policy = VMWriterPolicy(
            vm_tag=0x01,
            tier_operations={
                IdentityTier.MLDSA: all_ops,
                IdentityTier.COMPOSITE: all_ops,
                IdentityTier.BLS: all_ops,
            },
        )
        engine = PolicyEngine()
        record = self._make_active_record("bls")
        result = engine.evaluate(record, OperationType.DEPLOY, policy)
        assert result.allowed is True


class TestProbationOverride:
    def _make_probation_record(self):
        from src.ltp.execution.writer import (
            WriterIdentity, WriterRecord, WriterState, ApprovalPath, IdentityTier,
        )
        identity = WriterIdentity(
            tier=IdentityTier.MLDSA, fingerprint=b"\xaa" * 32,
            mldsa_vk=b"\x01" * 32,
        )
        return WriterRecord(
            identity=identity, state=WriterState.PROBATION,
            approval_path=ApprovalPath.SPONSOR, enrolled_at=1000,
        )

    def test_probation_blocks_deploy(self):
        from src.ltp.execution.writer_policy import VMWriterPolicy, PolicyEngine
        from src.ltp.execution.types import OperationType
        from src.ltp.execution.writer_config import RegistryConfig
        policy = VMWriterPolicy(vm_tag=0x01)
        engine = PolicyEngine(config=RegistryConfig())
        record = self._make_probation_record()
        result = engine.evaluate(record, OperationType.DEPLOY, policy)
        assert result.allowed is False
        assert "probation" in result.reason

    def test_probation_doubles_fee(self):
        from src.ltp.execution.writer_policy import VMWriterPolicy, PolicyEngine
        from src.ltp.execution.types import OperationType
        from src.ltp.execution.writer_config import RegistryConfig
        policy = VMWriterPolicy(vm_tag=0x01)
        engine = PolicyEngine(config=RegistryConfig())
        record = self._make_probation_record()
        result = engine.evaluate(record, OperationType.TRANSFER, policy)
        assert result.allowed is True
        assert result.fee_multiplier == 2.0  # default 1.0 * probation factor 2.0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_writer_policy.py -v`
Expected: FAIL

- [ ] **Step 3: Add OperationType to types.py**

Add after the `BatchResult` class in `src/ltp/execution/types.py`:

```python
class OperationType(Enum):
    """Types of operations a writer can perform on a VM (Spec C2 §6.1)."""
    TRANSFER = "transfer"
    DEPLOY = "deploy"
    CALL = "call"
    STATE_MODIFY = "state_modify"
    STATE_READ = "state_read"
```

Add `from enum import Enum` to the imports at the top of the file.

- [ ] **Step 4: Implement writer_policy.py**

```python
"""Per-VM writer policy — declarative 8-knob evaluation (Spec C2 §6)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .types import OperationType
from .writer import IdentityTier, WriterRecord, WriterState
from .writer_config import ProbationModifiers, RegistryConfig

__all__ = ["VMWriterPolicy", "PolicyEngine", "PolicyResult"]


def _default_tier_operations() -> dict[IdentityTier, set[OperationType]]:
    all_ops = set(OperationType)
    return {
        IdentityTier.MLDSA: all_ops,
        IdentityTier.COMPOSITE: all_ops,
        IdentityTier.BLS: {OperationType.TRANSFER, OperationType.STATE_READ},
    }


def _default_rate_limits() -> dict[IdentityTier, int]:
    return {
        IdentityTier.MLDSA: 0,
        IdentityTier.COMPOSITE: 0,
        IdentityTier.BLS: 1000,
    }


def _default_fee_multipliers() -> dict[IdentityTier, float]:
    return {t: 1.0 for t in IdentityTier}


def _default_stakes() -> dict[IdentityTier, int]:
    return {t: 0 for t in IdentityTier}


@dataclass
class VMWriterPolicy:
    """Declarative per-VM policy with 8 configurable knobs."""
    vm_tag: int
    allowed_tiers: set[IdentityTier] = field(
        default_factory=lambda: set(IdentityTier))
    tier_operations: dict[IdentityTier, set[OperationType]] = field(
        default_factory=_default_tier_operations)
    max_txs_per_epoch: dict[IdentityTier, int] = field(
        default_factory=_default_rate_limits)
    min_stake: dict[IdentityTier, int] = field(
        default_factory=_default_stakes)
    max_writers: int = 0
    fee_multiplier: dict[IdentityTier, float] = field(
        default_factory=_default_fee_multipliers)
    allowlist: Optional[set[bytes]] = None
    denylist: set[bytes] = field(default_factory=set)
    default_access_epochs: int = 0


@dataclass(frozen=True)
class PolicyResult:
    """Result of policy evaluation."""
    allowed: bool
    reason: Optional[str] = None
    fee_multiplier: float = 1.0


class PolicyEngine:
    """Evaluates a WriterRecord against a VMWriterPolicy (Spec C2 §6.3)."""

    def __init__(self, config: Optional[RegistryConfig] = None) -> None:
        self._config = config or RegistryConfig()

    def evaluate(self, record: WriterRecord, operation: OperationType,
                 policy: VMWriterPolicy, tx_count: int = 0,
                 writer_count: int = 0, stake: int = 0) -> PolicyResult:
        """Short-circuit evaluation of the 8-knob policy."""
        tier = record.identity.tier
        fp = record.identity.fingerprint

        # Knob 1: Allowed tiers
        if tier not in policy.allowed_tiers:
            return PolicyResult(allowed=False, reason=f"tier {tier.value} not allowed")

        # Knob 7a: Denylist
        if fp in policy.denylist:
            return PolicyResult(allowed=False, reason="writer on denylist")

        # Knob 7b: Allowlist
        if policy.allowlist is not None and fp not in policy.allowlist:
            return PolicyResult(allowed=False, reason="writer not on allowlist")

        # Probation override: block certain operations
        if record.state == WriterState.PROBATION:
            mods = self._config.probation_modifiers
            if operation.value in mods.blocked_operations:
                return PolicyResult(
                    allowed=False,
                    reason=f"operation {operation.value} blocked during probation",
                )

        # Knob 2: Operation permissions per tier
        tier_ops = policy.tier_operations.get(tier, set())
        if operation not in tier_ops:
            return PolicyResult(
                allowed=False,
                reason=f"operation {operation.value} not permitted for tier {tier.value}",
            )

        # Knob 3: Rate limits
        limit = policy.max_txs_per_epoch.get(tier, 0)
        if record.state == WriterState.PROBATION:
            mods = self._config.probation_modifiers
            if limit > 0:
                limit = max(1, limit // mods.rate_limit_divisor)
        if limit > 0 and tx_count >= limit:
            return PolicyResult(
                allowed=False,
                reason=f"rate limit exceeded ({tx_count}/{limit})",
            )

        # Knob 4: Stake requirements
        min_req = policy.min_stake.get(tier, 0)
        if min_req > 0 and stake < min_req:
            return PolicyResult(
                allowed=False,
                reason=f"insufficient stake ({stake}/{min_req})",
            )

        # Knob 5: Writer cap
        if policy.max_writers > 0 and writer_count >= policy.max_writers:
            return PolicyResult(
                allowed=False,
                reason=f"writer cap reached ({writer_count}/{policy.max_writers})",
            )

        # Knob 6: Fee multiplier
        base_fee = policy.fee_multiplier.get(tier, 1.0)
        if record.state == WriterState.PROBATION:
            mods = self._config.probation_modifiers
            base_fee *= mods.fee_multiplier_factor

        return PolicyResult(allowed=True, fee_multiplier=base_fee)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_writer_policy.py -v`
Expected: All 13 tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/ltp/execution/types.py src/ltp/execution/writer_policy.py tests/test_writer_policy.py
git commit -m "feat(writer): add VMWriterPolicy and PolicyEngine with 8-knob evaluation (C2 §6)"
```

---

### Task 6: WriterAuthorizer Protocol

**Files:**
- Create: `src/ltp/execution/writer_auth.py`
- Test: `tests/test_writer_auth.py`

- [ ] **Step 1: Write failing tests**

```python
"""Tests for WriterAuthorizer protocol (Spec C2 §7)."""

import pytest


class TestAuthorizationResult:
    def test_allowed(self):
        from src.ltp.execution.writer_auth import AuthorizationResult
        result = AuthorizationResult(allowed=True)
        assert result.allowed is True
        assert result.reason is None
        assert result.fee_multiplier == 1.0
        assert result.metadata is None

    def test_rejected_with_reason(self):
        from src.ltp.execution.writer_auth import AuthorizationResult
        result = AuthorizationResult(allowed=False, reason="not authorized")
        assert result.allowed is False
        assert result.reason == "not authorized"


class TestDispatchDecision:
    def test_allowed_decision(self):
        from src.ltp.execution.writer_auth import DispatchDecision
        decision = DispatchDecision(allowed=True, fee_multiplier=1.5)
        assert decision.allowed is True
        assert decision.writer_record is None

    def test_rejected_decision(self):
        from src.ltp.execution.writer_auth import DispatchDecision
        decision = DispatchDecision(allowed=False, reason="frozen")
        assert decision.reason == "frozen"


class TestWriterAuthorizerProtocol:
    def test_custom_authorizer_implements_protocol(self):
        from src.ltp.execution.writer_auth import WriterAuthorizer, AuthorizationResult
        from src.ltp.execution.writer import (
            WriterIdentity, WriterRecord, WriterState, ApprovalPath, IdentityTier,
        )
        from src.ltp.execution.types import OperationType

        class StrictEVMAuthorizer:
            vm_tag = 0x01
            vm_name = "strict-evm"
            family = "account"

            def authorize_writer(self, writer, operation, tx_bytes):
                if operation == OperationType.DEPLOY:
                    return AuthorizationResult(allowed=False, reason="deploy disabled")
                return AuthorizationResult(allowed=True)

            def on_writer_state_change(self, writer, old_state, new_state):
                pass

        auth = StrictEVMAuthorizer()
        assert isinstance(auth, WriterAuthorizer)

    def test_custom_authorizer_rejects_deploy(self):
        from src.ltp.execution.writer_auth import AuthorizationResult
        from src.ltp.execution.writer import (
            WriterIdentity, WriterRecord, WriterState, ApprovalPath, IdentityTier,
        )
        from src.ltp.execution.types import OperationType

        class StrictEVMAuthorizer:
            def authorize_writer(self, writer, operation, tx_bytes):
                if operation == OperationType.DEPLOY:
                    return AuthorizationResult(allowed=False, reason="deploy disabled")
                return AuthorizationResult(allowed=True)

            def on_writer_state_change(self, writer, old_state, new_state):
                pass

        identity = WriterIdentity(
            tier=IdentityTier.MLDSA, fingerprint=b"\xaa" * 32,
            mldsa_vk=b"\x01" * 32,
        )
        record = WriterRecord(
            identity=identity, state=WriterState.ACTIVE,
            approval_path=ApprovalPath.ADMIN, enrolled_at=1000,
        )
        auth = StrictEVMAuthorizer()
        result = auth.authorize_writer(record, OperationType.DEPLOY, b"\x01test")
        assert result.allowed is False
        assert result.reason == "deploy disabled"

        result = auth.authorize_writer(record, OperationType.TRANSFER, b"\x01test")
        assert result.allowed is True

    def test_non_authorizer_not_instance(self):
        from src.ltp.execution.writer_auth import WriterAuthorizer

        class PlainExecutor:
            pass

        assert not isinstance(PlainExecutor(), WriterAuthorizer)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_writer_auth.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement writer_auth.py**

```python
"""WriterAuthorizer protocol — custom VM override (Spec C2 §7)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable

from .types import OperationType
from .writer import WriterRecord, WriterState

__all__ = [
    "AuthorizationResult",
    "DispatchDecision",
    "WriterAuthorizer",
]


@dataclass(frozen=True)
class AuthorizationResult:
    """Result from a custom VM WriterAuthorizer."""
    allowed: bool
    reason: Optional[str] = None
    fee_multiplier: float = 1.0
    metadata: Optional[dict] = None


@dataclass(frozen=True)
class DispatchDecision:
    """Result from the WriterGate dispatch check."""
    allowed: bool
    reason: Optional[str] = None
    fee_multiplier: float = 1.0
    writer_record: Optional[WriterRecord] = None


@runtime_checkable
class WriterAuthorizer(Protocol):
    """Protocol for VMs that implement custom writer authorization.

    When an executor implements this protocol, the PolicyEngine is
    bypassed entirely — the VM takes full ownership of authorization.
    """

    def authorize_writer(
        self,
        writer: WriterRecord,
        operation: OperationType,
        tx_bytes: bytes,
    ) -> AuthorizationResult: ...

    def on_writer_state_change(
        self,
        writer: WriterRecord,
        old_state: WriterState,
        new_state: WriterState,
    ) -> None: ...
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_writer_auth.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/writer_auth.py tests/test_writer_auth.py
git commit -m "feat(writer): add WriterAuthorizer protocol for custom VM authorization (C2 §7)"
```

---

### Task 7: Emergency Recovery

**Files:**
- Create: `src/ltp/execution/writer_recovery.py`
- Test: `tests/test_writer_recovery.py`

- [ ] **Step 1: Write failing tests**

```python
"""Tests for emergency recovery and policy versioning (Spec C2 §8)."""

import pytest


class TestEmergencyAction:
    def test_seven_actions(self):
        from src.ltp.execution.writer_recovery import EmergencyAction
        assert len(EmergencyAction) == 7
        assert EmergencyAction.FREEZE_REGISTRY.value == "freeze_registry"
        assert EmergencyAction.ROTATE_OWNER.value == "rotate_owner"


class TestEmergencyState:
    def test_initial_state_not_frozen(self):
        from src.ltp.execution.writer_recovery import EmergencyState
        state = EmergencyState()
        assert state.is_registry_frozen is False
        assert state.is_vm_frozen(0x01) is False

    def test_freeze_registry(self):
        from src.ltp.execution.writer_recovery import EmergencyState
        state = EmergencyState()
        state.freeze_registry(actor_fp=b"\x01" * 32, reason="security incident", timestamp=1000)
        assert state.is_registry_frozen is True
        assert len(state.interventions) == 1

    def test_unfreeze_registry(self):
        from src.ltp.execution.writer_recovery import EmergencyState
        state = EmergencyState()
        state.freeze_registry(actor_fp=b"\x01" * 32, reason="test", timestamp=1000)
        state.unfreeze_registry(actor_fp=b"\x01" * 32, timestamp=2000)
        assert state.is_registry_frozen is False

    def test_freeze_vm(self):
        from src.ltp.execution.writer_recovery import EmergencyState
        state = EmergencyState()
        state.freeze_vm(vm_tag=0x01, actor_fp=b"\x01" * 32, reason="attack", timestamp=1000)
        assert state.is_vm_frozen(0x01) is True
        assert state.is_vm_frozen(0x20) is False

    def test_unfreeze_vm(self):
        from src.ltp.execution.writer_recovery import EmergencyState
        state = EmergencyState()
        state.freeze_vm(vm_tag=0x01, actor_fp=b"\x01" * 32, reason="test", timestamp=1000)
        state.unfreeze_vm(vm_tag=0x01, actor_fp=b"\x01" * 32, timestamp=2000)
        assert state.is_vm_frozen(0x01) is False

    def test_bypass_authorizer(self):
        from src.ltp.execution.writer_recovery import EmergencyState
        state = EmergencyState()
        assert state.is_authorizer_bypassed(0x01) is False
        state.bypass_authorizer(vm_tag=0x01, actor_fp=b"\x01" * 32, reason="bug", timestamp=1000)
        assert state.is_authorizer_bypassed(0x01) is True

    def test_clear_bypass(self):
        from src.ltp.execution.writer_recovery import EmergencyState
        state = EmergencyState()
        state.bypass_authorizer(vm_tag=0x01, actor_fp=b"\x01" * 32, reason="bug", timestamp=1000)
        state.clear_bypass(vm_tag=0x01, actor_fp=b"\x01" * 32, timestamp=2000)
        assert state.is_authorizer_bypassed(0x01) is False


class TestPolicySnapshots:
    def test_snapshot_and_rollback(self):
        from src.ltp.execution.writer_recovery import PolicySnapshotStore
        from src.ltp.execution.writer_policy import VMWriterPolicy
        from src.ltp.execution.writer import IdentityTier
        store = PolicySnapshotStore()
        policy_v1 = VMWriterPolicy(vm_tag=0x01)
        store.snapshot(0x01, policy_v1, timestamp=1000)
        policy_v2 = VMWriterPolicy(vm_tag=0x01, allowed_tiers={IdentityTier.MLDSA})
        store.snapshot(0x01, policy_v2, timestamp=2000)
        assert store.version_count(0x01) == 2
        rolled_back = store.rollback(0x01, version=0)
        assert IdentityTier.BLS in rolled_back.allowed_tiers  # v1 had all tiers

    def test_rollback_invalid_version(self):
        from src.ltp.execution.writer_recovery import PolicySnapshotStore
        store = PolicySnapshotStore()
        with pytest.raises(KeyError):
            store.rollback(0x01, version=0)

    def test_snapshots_append_only(self):
        from src.ltp.execution.writer_recovery import PolicySnapshotStore
        from src.ltp.execution.writer_policy import VMWriterPolicy
        store = PolicySnapshotStore()
        store.snapshot(0x01, VMWriterPolicy(vm_tag=0x01), timestamp=1000)
        store.snapshot(0x01, VMWriterPolicy(vm_tag=0x01), timestamp=2000)
        store.snapshot(0x01, VMWriterPolicy(vm_tag=0x01), timestamp=3000)
        assert store.version_count(0x01) == 3


class TestRecoveryQuorum:
    def test_quorum_not_met(self):
        from src.ltp.execution.writer_recovery import RecoveryQuorum
        quorum = RecoveryQuorum(
            recovery_keys=[b"\x01" * 32, b"\x02" * 32, b"\x03" * 32],
            threshold=2,
        )
        quorum.add_vote(b"\x01" * 32)
        assert quorum.is_met() is False

    def test_quorum_met(self):
        from src.ltp.execution.writer_recovery import RecoveryQuorum
        quorum = RecoveryQuorum(
            recovery_keys=[b"\x01" * 32, b"\x02" * 32, b"\x03" * 32],
            threshold=2,
        )
        quorum.add_vote(b"\x01" * 32)
        quorum.add_vote(b"\x02" * 32)
        assert quorum.is_met() is True

    def test_invalid_key_rejected(self):
        from src.ltp.execution.writer_recovery import RecoveryQuorum
        quorum = RecoveryQuorum(
            recovery_keys=[b"\x01" * 32, b"\x02" * 32],
            threshold=2,
        )
        with pytest.raises(ValueError, match="not a recovery key"):
            quorum.add_vote(b"\xff" * 32)

    def test_reset_clears_votes(self):
        from src.ltp.execution.writer_recovery import RecoveryQuorum
        quorum = RecoveryQuorum(
            recovery_keys=[b"\x01" * 32, b"\x02" * 32],
            threshold=2,
        )
        quorum.add_vote(b"\x01" * 32)
        quorum.reset()
        assert quorum.is_met() is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_writer_recovery.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement writer_recovery.py**

```python
"""Emergency recovery — freeze, bypass, rollback, quorum (Spec C2 §8)."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .writer_policy import VMWriterPolicy

__all__ = [
    "EmergencyAction",
    "EmergencyIntervention",
    "EmergencyState",
    "PolicySnapshotStore",
    "RecoveryQuorum",
]


class EmergencyAction(Enum):
    """Emergency intervention types."""
    FREEZE_REGISTRY = "freeze_registry"
    FREEZE_VM = "freeze_vm"
    BYPASS_AUTHORIZER = "bypass_authorizer"
    FORCE_REVOKE = "force_revoke"
    ROLLBACK_POLICY = "rollback_policy"
    ROTATE_OWNER = "rotate_owner"
    OVERRIDE_DISPATCH = "override_dispatch"


@dataclass(frozen=True)
class EmergencyIntervention:
    """Audit record for an emergency action."""
    action: EmergencyAction
    actor_fp: bytes
    reason: str
    timestamp: int
    scope: Optional[int] = None
    auto_expires: Optional[int] = None


class EmergencyState:
    """Tracks active emergency interventions."""

    def __init__(self) -> None:
        self._registry_frozen: bool = False
        self._frozen_vms: set[int] = set()
        self._bypassed_authorizers: set[int] = set()
        self.interventions: list[EmergencyIntervention] = []

    @property
    def is_registry_frozen(self) -> bool:
        return self._registry_frozen

    def is_vm_frozen(self, vm_tag: int) -> bool:
        return vm_tag in self._frozen_vms

    def is_authorizer_bypassed(self, vm_tag: int) -> bool:
        return vm_tag in self._bypassed_authorizers

    def _log(self, action: EmergencyAction, actor_fp: bytes,
             reason: str, timestamp: int, scope: Optional[int] = None) -> None:
        self.interventions.append(EmergencyIntervention(
            action=action, actor_fp=actor_fp, reason=reason,
            timestamp=timestamp, scope=scope,
        ))

    def freeze_registry(self, actor_fp: bytes, reason: str, timestamp: int) -> None:
        self._registry_frozen = True
        self._log(EmergencyAction.FREEZE_REGISTRY, actor_fp, reason, timestamp)

    def unfreeze_registry(self, actor_fp: bytes, timestamp: int) -> None:
        self._registry_frozen = False
        self._log(EmergencyAction.FREEZE_REGISTRY, actor_fp, "unfrozen", timestamp)

    def freeze_vm(self, vm_tag: int, actor_fp: bytes, reason: str, timestamp: int) -> None:
        self._frozen_vms.add(vm_tag)
        self._log(EmergencyAction.FREEZE_VM, actor_fp, reason, timestamp, scope=vm_tag)

    def unfreeze_vm(self, vm_tag: int, actor_fp: bytes, timestamp: int) -> None:
        self._frozen_vms.discard(vm_tag)
        self._log(EmergencyAction.FREEZE_VM, actor_fp, "unfrozen", timestamp, scope=vm_tag)

    def bypass_authorizer(self, vm_tag: int, actor_fp: bytes,
                          reason: str, timestamp: int) -> None:
        self._bypassed_authorizers.add(vm_tag)
        self._log(EmergencyAction.BYPASS_AUTHORIZER, actor_fp, reason, timestamp, scope=vm_tag)

    def clear_bypass(self, vm_tag: int, actor_fp: bytes, timestamp: int) -> None:
        self._bypassed_authorizers.discard(vm_tag)
        self._log(EmergencyAction.BYPASS_AUTHORIZER, actor_fp, "cleared", timestamp, scope=vm_tag)


@dataclass(frozen=True)
class _PolicySnapshot:
    version: int
    policy: VMWriterPolicy
    timestamp: int


class PolicySnapshotStore:
    """Append-only policy version history for rollback support."""

    def __init__(self) -> None:
        self._snapshots: dict[int, list[_PolicySnapshot]] = {}

    def snapshot(self, vm_tag: int, policy: VMWriterPolicy, timestamp: int) -> int:
        if vm_tag not in self._snapshots:
            self._snapshots[vm_tag] = []
        version = len(self._snapshots[vm_tag])
        self._snapshots[vm_tag].append(_PolicySnapshot(
            version=version,
            policy=copy.deepcopy(policy),
            timestamp=timestamp,
        ))
        return version

    def rollback(self, vm_tag: int, version: int) -> VMWriterPolicy:
        if vm_tag not in self._snapshots:
            raise KeyError(f"no snapshots for vm_tag 0x{vm_tag:02X}")
        snapshots = self._snapshots[vm_tag]
        if version < 0 or version >= len(snapshots):
            raise KeyError(f"invalid version {version} for vm_tag 0x{vm_tag:02X}")
        return copy.deepcopy(snapshots[version].policy)

    def version_count(self, vm_tag: int) -> int:
        return len(self._snapshots.get(vm_tag, []))


class RecoveryQuorum:
    """M-of-N recovery key quorum for emergency owner rotation."""

    def __init__(self, recovery_keys: list[bytes], threshold: int) -> None:
        self._keys = frozenset(recovery_keys)
        self._threshold = threshold
        self._votes: set[bytes] = set()

    def add_vote(self, key_fp: bytes) -> None:
        if key_fp not in self._keys:
            raise ValueError(f"{key_fp.hex()[:16]} not a recovery key")
        self._votes.add(key_fp)

    def is_met(self) -> bool:
        return len(self._votes) >= self._threshold

    def reset(self) -> None:
        self._votes.clear()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_writer_recovery.py -v`
Expected: All 12 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/writer_recovery.py tests/test_writer_recovery.py
git commit -m "feat(writer): add emergency recovery — freeze, bypass, rollback, quorum (C2 §8)"
```

---

### Task 8: Epoch Operations

**Files:**
- Create: `src/ltp/execution/writer_epoch.py`
- Test: `tests/test_writer_epoch.py`

- [ ] **Step 1: Write failing tests**

```python
"""Tests for epoch-driven writer operations (Spec C2 §9.4)."""

import pytest


class TestEpochTracker:
    def test_initial_counts_zero(self):
        from src.ltp.execution.writer_epoch import EpochTracker
        tracker = EpochTracker()
        assert tracker.get_tx_count(b"\xaa" * 32, 0x01) == 0

    def test_increment_count(self):
        from src.ltp.execution.writer_epoch import EpochTracker
        tracker = EpochTracker()
        tracker.increment(b"\xaa" * 32, 0x01, epoch=1)
        assert tracker.get_tx_count(b"\xaa" * 32, 0x01) == 1
        tracker.increment(b"\xaa" * 32, 0x01, epoch=1)
        assert tracker.get_tx_count(b"\xaa" * 32, 0x01) == 2

    def test_epoch_rollover_resets(self):
        from src.ltp.execution.writer_epoch import EpochTracker
        tracker = EpochTracker()
        tracker.increment(b"\xaa" * 32, 0x01, epoch=1)
        tracker.increment(b"\xaa" * 32, 0x01, epoch=1)
        assert tracker.get_tx_count(b"\xaa" * 32, 0x01) == 2
        tracker.advance_epoch(2)
        assert tracker.get_tx_count(b"\xaa" * 32, 0x01) == 0

    def test_separate_vm_counts(self):
        from src.ltp.execution.writer_epoch import EpochTracker
        tracker = EpochTracker()
        tracker.increment(b"\xaa" * 32, 0x01, epoch=1)
        tracker.increment(b"\xaa" * 32, 0x20, epoch=1)
        assert tracker.get_tx_count(b"\xaa" * 32, 0x01) == 1
        assert tracker.get_tx_count(b"\xaa" * 32, 0x20) == 1

    def test_separate_writer_counts(self):
        from src.ltp.execution.writer_epoch import EpochTracker
        tracker = EpochTracker()
        tracker.increment(b"\xaa" * 32, 0x01, epoch=1)
        tracker.increment(b"\xbb" * 32, 0x01, epoch=1)
        assert tracker.get_tx_count(b"\xaa" * 32, 0x01) == 1
        assert tracker.get_tx_count(b"\xbb" * 32, 0x01) == 1


class TestExpirationChecker:
    def test_check_expirations_expires_writers(self):
        from src.ltp.execution.writer_epoch import check_expirations
        from src.ltp.execution.writer_registry import WriterRegistry
        from src.ltp.execution.writer_config import RegistryConfig
        from src.ltp.execution.writer import WriterIdentity, WriterState, IdentityTier
        reg = WriterRegistry(config=RegistryConfig())
        identity = WriterIdentity(
            tier=IdentityTier.MLDSA, fingerprint=b"\xaa" * 32,
            mldsa_vk=b"\x01" * 32,
        )
        reg.enroll(identity, timestamp=1000)
        reg.approve(identity.fingerprint, admin_fp=b"\x01" * 32, timestamp=2000)
        record = reg.lookup(identity.fingerprint)
        record.expires_at = 10
        expired = check_expirations(reg, current_epoch=10)
        assert len(expired) == 1
        assert reg.lookup(identity.fingerprint).state == WriterState.EXPIRED

    def test_no_expirations_when_not_due(self):
        from src.ltp.execution.writer_epoch import check_expirations
        from src.ltp.execution.writer_registry import WriterRegistry
        from src.ltp.execution.writer_config import RegistryConfig
        from src.ltp.execution.writer import WriterIdentity, IdentityTier
        reg = WriterRegistry(config=RegistryConfig())
        identity = WriterIdentity(
            tier=IdentityTier.MLDSA, fingerprint=b"\xaa" * 32,
            mldsa_vk=b"\x01" * 32,
        )
        reg.enroll(identity, timestamp=1000)
        reg.approve(identity.fingerprint, admin_fp=b"\x01" * 32, timestamp=2000)
        record = reg.lookup(identity.fingerprint)
        record.expires_at = 100
        expired = check_expirations(reg, current_epoch=50)
        assert len(expired) == 0


class TestProbationPromoter:
    def test_promote_due_writers(self):
        from src.ltp.execution.writer_epoch import promote_due_probations
        from src.ltp.execution.writer_registry import WriterRegistry
        from src.ltp.execution.writer_config import RegistryConfig
        from src.ltp.execution.writer import WriterIdentity, WriterState, IdentityTier
        reg = WriterRegistry(config=RegistryConfig(sponsor_threshold=1, probation_epochs=5))
        identity = WriterIdentity(
            tier=IdentityTier.MLDSA, fingerprint=b"\xaa" * 32,
            mldsa_vk=b"\x01" * 32,
        )
        reg.enroll(identity, timestamp=1000)
        reg.sponsor(identity.fingerprint, sponsor_fp=b"\xbb" * 32, timestamp=2000)
        assert reg.lookup(identity.fingerprint).state == WriterState.PROBATION
        promoted = promote_due_probations(reg, current_epoch=10, timestamp=3000)
        assert len(promoted) == 1
        assert reg.lookup(identity.fingerprint).state == WriterState.ACTIVE

    def test_no_promote_before_due(self):
        from src.ltp.execution.writer_epoch import promote_due_probations
        from src.ltp.execution.writer_registry import WriterRegistry
        from src.ltp.execution.writer_config import RegistryConfig
        from src.ltp.execution.writer import WriterIdentity, WriterState, IdentityTier
        reg = WriterRegistry(config=RegistryConfig(sponsor_threshold=1, probation_epochs=5))
        identity = WriterIdentity(
            tier=IdentityTier.MLDSA, fingerprint=b"\xaa" * 32,
            mldsa_vk=b"\x01" * 32,
        )
        reg.enroll(identity, timestamp=1000)
        reg.sponsor(identity.fingerprint, sponsor_fp=b"\xbb" * 32, timestamp=2000)
        promoted = promote_due_probations(reg, current_epoch=3, timestamp=3000)
        assert len(promoted) == 0
        assert reg.lookup(identity.fingerprint).state == WriterState.PROBATION
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_writer_epoch.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement writer_epoch.py**

```python
"""Epoch-driven operations — rate limits, expiration, promotion (Spec C2 §9.4)."""

from __future__ import annotations

from collections import defaultdict

from .writer import WriterState
from .writer_registry import WriterRegistry

__all__ = ["EpochTracker", "check_expirations", "promote_due_probations"]


class EpochTracker:
    """Per-writer, per-VM transaction counter with epoch rollover."""

    def __init__(self) -> None:
        self._counts: dict[tuple[bytes, int], int] = defaultdict(int)
        self._current_epoch: int = 0

    def increment(self, writer_fp: bytes, vm_tag: int, epoch: int) -> None:
        if epoch != self._current_epoch:
            self.advance_epoch(epoch)
        self._counts[(writer_fp, vm_tag)] += 1

    def get_tx_count(self, writer_fp: bytes, vm_tag: int) -> int:
        return self._counts.get((writer_fp, vm_tag), 0)

    def advance_epoch(self, new_epoch: int) -> None:
        self._counts.clear()
        self._current_epoch = new_epoch


def check_expirations(registry: WriterRegistry, current_epoch: int) -> list[bytes]:
    """Expire ACTIVE writers past their expires_at epoch."""
    return registry.check_expirations(current_epoch)


def promote_due_probations(registry: WriterRegistry, current_epoch: int,
                           timestamp: int) -> list[bytes]:
    """Promote PROBATION writers whose probation period has elapsed."""
    promoted = []
    for record in registry.active_writers():
        if (record.state == WriterState.PROBATION
                and record.probation_until is not None
                and current_epoch >= record.probation_until):
            registry.promote(record.identity.fingerprint, timestamp=timestamp)
            promoted.append(record.identity.fingerprint)
    return promoted
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_writer_epoch.py -v`
Expected: All 9 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/writer_epoch.py tests/test_writer_epoch.py
git commit -m "feat(writer): add epoch tracker — rate limits, expiration, auto-promotion (C2 §9.4)"
```

---

### Task 9: WriterGate

**Files:**
- Create: `src/ltp/execution/writer_gate.py`
- Test: `tests/test_writer_gate.py`

- [ ] **Step 1: Write failing tests**

```python
"""Tests for WriterGate — layered enforcement (Spec C2 §9)."""

import pytest


def _make_gate():
    from src.ltp.execution.writer_gate import WriterGate
    from src.ltp.execution.writer_registry import WriterRegistry
    from src.ltp.execution.writer_config import RegistryConfig
    from src.ltp.execution.writer_recovery import EmergencyState
    from src.ltp.execution.writer_epoch import EpochTracker
    reg = WriterRegistry(config=RegistryConfig())
    emergency = EmergencyState()
    epoch = EpochTracker()
    gate = WriterGate(registry=reg, emergency=emergency, epoch_tracker=epoch)
    return gate, reg


def _enroll_active(reg, fp=b"\xaa" * 32):
    from src.ltp.execution.writer import WriterIdentity, IdentityTier
    identity = WriterIdentity(
        tier=IdentityTier.MLDSA, fingerprint=fp,
        mldsa_vk=b"\x01" * 32,
    )
    reg.enroll(identity, timestamp=1000)
    reg.approve(fp, admin_fp=b"\x01" * 32, timestamp=2000)
    return identity


class TestPreDispatch:
    def test_active_writer_allowed(self):
        gate, reg = _make_gate()
        _enroll_active(reg)
        # tx format: [writer_fp (32)] [vm_tag (1)] [payload]
        tx = b"\xaa" * 32 + b"\x01" + b"payload"
        decision = gate.pre_dispatch(tx)
        assert decision.allowed is True
        assert decision.writer_record is not None

    def test_unknown_writer_rejected(self):
        gate, reg = _make_gate()
        tx = b"\xff" * 32 + b"\x01" + b"payload"
        decision = gate.pre_dispatch(tx)
        assert decision.allowed is False
        assert "not found" in decision.reason

    def test_pending_writer_rejected(self):
        from src.ltp.execution.writer import WriterIdentity, IdentityTier
        gate, reg = _make_gate()
        identity = WriterIdentity(
            tier=IdentityTier.MLDSA, fingerprint=b"\xaa" * 32,
            mldsa_vk=b"\x01" * 32,
        )
        reg.enroll(identity, timestamp=1000)
        tx = b"\xaa" * 32 + b"\x01" + b"payload"
        decision = gate.pre_dispatch(tx)
        assert decision.allowed is False
        assert "not active" in decision.reason

    def test_frozen_registry_rejected(self):
        gate, reg = _make_gate()
        _enroll_active(reg)
        gate._emergency.freeze_registry(actor_fp=b"\x01" * 32, reason="test", timestamp=1000)
        tx = b"\xaa" * 32 + b"\x01" + b"payload"
        decision = gate.pre_dispatch(tx)
        assert decision.allowed is False
        assert "frozen" in decision.reason

    def test_frozen_vm_rejected(self):
        gate, reg = _make_gate()
        _enroll_active(reg)
        gate._emergency.freeze_vm(vm_tag=0x01, actor_fp=b"\x01" * 32, reason="test", timestamp=1000)
        tx = b"\xaa" * 32 + b"\x01" + b"payload"
        decision = gate.pre_dispatch(tx)
        assert decision.allowed is False
        assert "VM 0x01 frozen" in decision.reason

    def test_probation_writer_allowed(self):
        from src.ltp.execution.writer import WriterIdentity, IdentityTier
        gate, reg = _make_gate()
        identity = WriterIdentity(
            tier=IdentityTier.MLDSA, fingerprint=b"\xaa" * 32,
            mldsa_vk=b"\x01" * 32,
        )
        reg.enroll(identity, timestamp=1000)
        reg.sponsor(identity.fingerprint, sponsor_fp=b"\xbb" * 32, timestamp=2000)
        reg.sponsor(identity.fingerprint, sponsor_fp=b"\xcc" * 32, timestamp=3000)
        tx = b"\xaa" * 32 + b"\x01" + b"payload"
        decision = gate.pre_dispatch(tx)
        assert decision.allowed is True

    def test_short_tx_rejected(self):
        gate, reg = _make_gate()
        tx = b"\xaa" * 32  # no vm tag
        decision = gate.pre_dispatch(tx)
        assert decision.allowed is False
        assert "too short" in decision.reason


class TestVMAuthorize:
    def test_declarative_policy_allows(self):
        from src.ltp.execution.writer_gate import WriterGate
        from src.ltp.execution.writer_policy import VMWriterPolicy
        from src.ltp.execution.types import OperationType
        gate, reg = _make_gate()
        identity = _enroll_active(reg)
        record = reg.lookup(identity.fingerprint)
        policy = VMWriterPolicy(vm_tag=0x01)
        gate.set_policy(0x01, policy)

        class FakeExecutor:
            vm_tag = 0x01
            vm_name = "fake"
            family = "account"

        decision = gate.vm_authorize(record, FakeExecutor(), OperationType.TRANSFER, b"payload")
        assert decision.allowed is True

    def test_custom_authorizer_used(self):
        from src.ltp.execution.writer_gate import WriterGate
        from src.ltp.execution.writer_policy import VMWriterPolicy
        from src.ltp.execution.writer_auth import AuthorizationResult, WriterAuthorizer
        from src.ltp.execution.types import OperationType
        gate, reg = _make_gate()
        identity = _enroll_active(reg)
        record = reg.lookup(identity.fingerprint)

        class CustomAuth:
            vm_tag = 0x01
            vm_name = "custom"
            family = "account"
            def authorize_writer(self, writer, operation, tx_bytes):
                return AuthorizationResult(allowed=False, reason="custom reject")
            def on_writer_state_change(self, writer, old_state, new_state):
                pass

        executor = CustomAuth()
        decision = gate.vm_authorize(record, executor, OperationType.TRANSFER, b"payload")
        assert decision.allowed is False
        assert decision.reason == "custom reject"

    def test_bypass_authorizer_uses_policy(self):
        from src.ltp.execution.writer_gate import WriterGate
        from src.ltp.execution.writer_policy import VMWriterPolicy
        from src.ltp.execution.writer_auth import AuthorizationResult
        from src.ltp.execution.types import OperationType
        gate, reg = _make_gate()
        identity = _enroll_active(reg)
        record = reg.lookup(identity.fingerprint)
        policy = VMWriterPolicy(vm_tag=0x01)
        gate.set_policy(0x01, policy)
        gate._emergency.bypass_authorizer(
            vm_tag=0x01, actor_fp=b"\x01" * 32, reason="bug", timestamp=1000,
        )

        class CustomAuth:
            vm_tag = 0x01
            vm_name = "custom"
            family = "account"
            def authorize_writer(self, writer, operation, tx_bytes):
                return AuthorizationResult(allowed=False, reason="should be bypassed")
            def on_writer_state_change(self, writer, old_state, new_state):
                pass

        executor = CustomAuth()
        decision = gate.vm_authorize(record, executor, OperationType.TRANSFER, b"payload")
        assert decision.allowed is True  # policy allows, authorizer bypassed
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_writer_gate.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement writer_gate.py**

```python
"""WriterGate — layered universal + per-VM enforcement (Spec C2 §9)."""

from __future__ import annotations

from typing import Optional

from .types import OperationType
from .writer import WriterRecord, TRANSACTABLE_STATES
from .writer_auth import AuthorizationResult, DispatchDecision, WriterAuthorizer
from .writer_config import RegistryConfig
from .writer_epoch import EpochTracker
from .writer_policy import PolicyEngine, PolicyResult, VMWriterPolicy
from .writer_recovery import EmergencyState
from .writer_registry import WriterRegistry

__all__ = ["WriterGate"]

# Transaction format: [writer_fp (32 bytes)] [vm_tag (1 byte)] [payload]
WRITER_FP_SIZE = 32


class WriterGate:
    """Layered enforcement gate for the TransactionRouter.

    Layer 1 (pre_dispatch): Universal checks — identity, state, freeze.
    Layer 2 (vm_authorize): Per-VM — custom authorizer OR declarative policy.
    """

    def __init__(
        self,
        registry: WriterRegistry,
        emergency: Optional[EmergencyState] = None,
        epoch_tracker: Optional[EpochTracker] = None,
        config: Optional[RegistryConfig] = None,
    ) -> None:
        self._registry = registry
        self._emergency = emergency or EmergencyState()
        self._epoch = epoch_tracker or EpochTracker()
        self._policies: dict[int, VMWriterPolicy] = {}
        self._engine = PolicyEngine(config=config or registry.config)

    def set_policy(self, vm_tag: int, policy: VMWriterPolicy) -> None:
        """Register a declarative policy for a VM."""
        self._policies[vm_tag] = policy

    def pre_dispatch(self, tx_bytes: bytes) -> DispatchDecision:
        """Universal checks — runs before any VM dispatch.

        Extracts writer fingerprint from the first 32 bytes of tx_bytes.
        """
        if len(tx_bytes) < WRITER_FP_SIZE + 1:
            return DispatchDecision(allowed=False, reason="tx too short for writer gate")

        writer_fp = tx_bytes[:WRITER_FP_SIZE]
        vm_tag = tx_bytes[WRITER_FP_SIZE]

        # 1. Registry frozen?
        if self._emergency.is_registry_frozen:
            return DispatchDecision(allowed=False, reason="registry frozen")

        # 2. Writer exists?
        record = self._registry.lookup(writer_fp)
        if record is None:
            return DispatchDecision(allowed=False, reason="writer not found")

        # 3. Writer active?
        if record.state not in TRANSACTABLE_STATES:
            return DispatchDecision(
                allowed=False,
                reason=f"writer not active (state={record.state.value})",
            )

        # 4. Target VM frozen?
        if self._emergency.is_vm_frozen(vm_tag):
            return DispatchDecision(
                allowed=False,
                reason=f"VM 0x{vm_tag:02X} frozen",
            )

        return DispatchDecision(allowed=True, writer_record=record)

    def vm_authorize(
        self,
        record: WriterRecord,
        executor: object,
        operation: OperationType,
        tx_bytes: bytes,
    ) -> DispatchDecision:
        """Per-VM checks — custom authorizer or declarative policy."""
        vm_tag = getattr(executor, "vm_tag", None)

        # 1. Authorizer bypassed? → use declarative policy
        bypassed = vm_tag is not None and self._emergency.is_authorizer_bypassed(vm_tag)

        # 2. Custom authorizer?
        if not bypassed and isinstance(executor, WriterAuthorizer):
            result: AuthorizationResult = executor.authorize_writer(
                record, operation, tx_bytes,
            )
            return DispatchDecision(
                allowed=result.allowed,
                reason=result.reason,
                fee_multiplier=result.fee_multiplier,
                writer_record=record,
            )

        # 3. Declarative policy
        if vm_tag is not None and vm_tag in self._policies:
            policy = self._policies[vm_tag]
        else:
            policy = VMWriterPolicy(vm_tag=vm_tag or 0x00)

        fp = record.identity.fingerprint
        tx_count = self._epoch.get_tx_count(fp, vm_tag or 0x00)
        result_p: PolicyResult = self._engine.evaluate(
            record, operation, policy, tx_count=tx_count,
        )
        return DispatchDecision(
            allowed=result_p.allowed,
            reason=result_p.reason,
            fee_multiplier=result_p.fee_multiplier,
            writer_record=record,
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_writer_gate.py -v`
Expected: All 10 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/writer_gate.py tests/test_writer_gate.py
git commit -m "feat(writer): add WriterGate — layered universal + per-VM enforcement (C2 §9)"
```

---

### Task 10: Router Integration

**Files:**
- Modify: `src/ltp/execution/router.py`
- Test: run existing tests + `tests/test_writer_gate.py` (add router integration test)

- [ ] **Step 1: Write failing test for router with WriterGate**

Append to `tests/test_writer_gate.py`:

```python
class TestRouterIntegration:
    def test_router_without_gate_passthrough(self):
        """Existing behavior: no gate = no auth checks."""
        from src.ltp.execution.router import TransactionRouter
        from src.ltp.execution.registry import VMRegistry
        from src.ltp.execution.types import OrderedBatch

        class FakeEVM:
            vm_tag = 0x01
            vm_name = "fake-evm"
            family = "account"
            def execute(self, tx_bytes):
                from src.ltp.execution.types import TxResult
                return TxResult.accepted(gas_used=21000)
            def state_root(self):
                return b"\xcc" * 32
            def validate_tx(self, tx_bytes):
                return True
            def query_state(self, query):
                from src.ltp.execution.types import StateResult
                return StateResult.not_found()

        registry = VMRegistry()
        registry.register(FakeEVM())
        router = TransactionRouter(registry)
        batch = OrderedBatch(
            round=1, epoch=0, transactions=[b"\x01hello"],
            leader_authority=0, timestamp_ms=1000, consensus_type="bft",
        )
        result = router.execute_batch(batch)
        assert result.tx_results[0].success is True

    def test_router_with_gate_rejects_unauthorized(self):
        """Gate blocks unknown writer."""
        from src.ltp.execution.router import TransactionRouter
        from src.ltp.execution.registry import VMRegistry
        from src.ltp.execution.types import OrderedBatch

        class FakeEVM:
            vm_tag = 0x01
            vm_name = "fake-evm"
            family = "account"
            def execute(self, tx_bytes):
                from src.ltp.execution.types import TxResult
                return TxResult.accepted(gas_used=21000)
            def state_root(self):
                return b"\xcc" * 32
            def validate_tx(self, tx_bytes):
                return True
            def query_state(self, query):
                from src.ltp.execution.types import StateResult
                return StateResult.not_found()

        gate, reg = _make_gate()
        registry = VMRegistry()
        registry.register(FakeEVM())
        router = TransactionRouter(registry, writer_gate=gate)
        # Unknown writer
        tx = b"\xff" * 32 + b"\x01" + b"payload"
        batch = OrderedBatch(
            round=1, epoch=0, transactions=[tx],
            leader_authority=0, timestamp_ms=1000, consensus_type="bft",
        )
        result = router.execute_batch(batch)
        assert result.tx_results[0].success is False
        assert "writer" in result.tx_results[0].error.lower()

    def test_router_with_gate_allows_authorized(self):
        """Gate passes authorized writer through to executor."""
        from src.ltp.execution.router import TransactionRouter
        from src.ltp.execution.registry import VMRegistry
        from src.ltp.execution.types import OrderedBatch
        from src.ltp.execution.writer_policy import VMWriterPolicy

        class FakeEVM:
            vm_tag = 0x01
            vm_name = "fake-evm"
            family = "account"
            def execute(self, tx_bytes):
                from src.ltp.execution.types import TxResult
                return TxResult.accepted(gas_used=21000)
            def state_root(self):
                return b"\xcc" * 32
            def validate_tx(self, tx_bytes):
                return True
            def query_state(self, query):
                from src.ltp.execution.types import StateResult
                return StateResult.not_found()

        gate, reg = _make_gate()
        _enroll_active(reg)
        gate.set_policy(0x01, VMWriterPolicy(vm_tag=0x01))
        registry = VMRegistry()
        registry.register(FakeEVM())
        router = TransactionRouter(registry, writer_gate=gate)
        tx = b"\xaa" * 32 + b"\x01" + b"payload"
        batch = OrderedBatch(
            round=1, epoch=0, transactions=[tx],
            leader_authority=0, timestamp_ms=1000, consensus_type="bft",
        )
        result = router.execute_batch(batch)
        assert result.tx_results[0].success is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_writer_gate.py::TestRouterIntegration -v`
Expected: FAIL (TransactionRouter doesn't accept writer_gate yet)

- [ ] **Step 3: Modify router.py**

Replace the `TransactionRouter` class in `src/ltp/execution/router.py`:

```python
"""TransactionRouter — tag-based dispatch to VM executors."""

from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from .registry import VMRegistry
from .state_root import MultiVMStateRoot
from .types import BatchResult, OrderedBatch, OperationType, TxResult

if TYPE_CHECKING:
    from .writer_gate import WriterGate


class ExecutorUnavailable(RuntimeError):
    """Raised when a registered VM executor can't produce a state root."""
    pass


# Writer fingerprint prefix size in gated transactions
_WRITER_FP_SIZE = 32


class TransactionRouter:
    """Routes each transaction in an OrderedBatch to the correct executor.

    Execution order is sacred — consensus already ordered these
    transactions. The router executes them sequentially in exactly
    that order.

    When a WriterGate is provided, each transaction is expected to
    be prefixed with a 32-byte writer fingerprint:
        [writer_fp (32)] [vm_tag (1)] [payload]
    The gate checks writer authorization before dispatch.
    Without a gate, the original format is used:
        [vm_tag (1)] [payload]
    """

    def __init__(self, registry: VMRegistry,
                 writer_gate: Optional[WriterGate] = None) -> None:
        self._registry = registry
        self._gate = writer_gate

    def execute_batch(self, batch: OrderedBatch) -> BatchResult:
        """Execute all transactions, then compute multi-VM state root."""
        results: list[TxResult] = []

        for tx_bytes in batch.transactions:
            if len(tx_bytes) == 0:
                results.append(TxResult.rejected("empty_transaction"))
                continue

            if self._gate is not None:
                result = self._execute_gated(tx_bytes)
            else:
                result = self._execute_ungated(tx_bytes)
            results.append(result)

        # Collect state roots from all registered executors
        vm_roots: dict[int, bytes] = {}
        for executor in self._registry.all_executors():
            try:
                root = executor.state_root()
            except Exception as exc:
                raise ExecutorUnavailable(
                    f"executor '{executor.vm_name}' (0x{executor.vm_tag:02X}) "
                    f"unavailable: {exc}"
                ) from exc
            vm_roots[executor.vm_tag] = root

        state_root = MultiVMStateRoot(vm_roots=vm_roots, batch_round=batch.round)

        return BatchResult(
            round=batch.round,
            tx_results=results,
            state_root=state_root,
        )

    def _execute_ungated(self, tx_bytes: bytes) -> TxResult:
        """Original dispatch — no writer authorization."""
        tag = tx_bytes[0]
        payload = tx_bytes[1:]
        executor = self._registry.get(tag)

        if executor is None:
            return TxResult.rejected(f"unknown_vm_tag:0x{tag:02X}")

        try:
            return executor.execute(payload)
        except Exception as exc:
            return TxResult.failed(f"execution_error:{exc}")

    def _execute_gated(self, tx_bytes: bytes) -> TxResult:
        """Gated dispatch — writer authorization required."""
        # Pre-dispatch: universal checks
        decision = self._gate.pre_dispatch(tx_bytes)
        if not decision.allowed:
            return TxResult.rejected(f"writer_gate:{decision.reason}")

        # Strip writer fingerprint, extract tag and payload
        tag = tx_bytes[_WRITER_FP_SIZE]
        payload = tx_bytes[_WRITER_FP_SIZE + 1:]
        executor = self._registry.get(tag)

        if executor is None:
            return TxResult.rejected(f"unknown_vm_tag:0x{tag:02X}")

        # Per-VM authorization
        vm_decision = self._gate.vm_authorize(
            decision.writer_record, executor,
            OperationType.TRANSFER,  # Default; future: infer from payload
            payload,
        )
        if not vm_decision.allowed:
            return TxResult.rejected(f"writer_gate:{vm_decision.reason}")

        try:
            return executor.execute(payload)
        except Exception as exc:
            return TxResult.failed(f"execution_error:{exc}")
```

- [ ] **Step 4: Run all tests to verify nothing is broken**

Run: `pytest tests/test_writer_gate.py -v && pytest tests/test_execution_router.py -v`
Expected: All tests PASS (existing router tests unchanged, new integration tests pass)

- [ ] **Step 5: Run full regression**

Run: `pytest tests/ -x -q`
Expected: All tests pass, 0 failures

- [ ] **Step 6: Commit**

```bash
git add src/ltp/execution/router.py tests/test_writer_gate.py
git commit -m "feat(router): integrate WriterGate — optional layered enforcement (C2 §9)"
```

---

### Task 11: Module Exports

**Files:**
- Modify: `src/ltp/execution/__init__.py`

- [ ] **Step 1: Update execution __init__.py exports**

Add to the imports and `__all__` in `src/ltp/execution/__init__.py`:

```python
from .types import OrderedBatch, BatchResult, TxResult, StateQuery, StateResult, OperationType
from .writer import (
    IdentityTier, WriterState, WriterIdentity, WriterRecord,
    ApprovalPath, TransitionEntry,
    VALID_WRITER_TRANSITIONS, TRANSACTABLE_STATES, validate_writer_transition,
)
from .writer_config import RegistryConfig, ProbationModifiers
from .writer_roles import (
    RegistryAction, ScopedPermission, RegistryRole, RoleAssignment,
    builtin_owner, builtin_admin, builtin_sponsor,
)
from .writer_registry import WriterRegistry as WriterRegistry  # avoid shadow with VMRegistry
from .writer_policy import VMWriterPolicy, PolicyEngine, PolicyResult
from .writer_auth import AuthorizationResult, DispatchDecision, WriterAuthorizer
from .writer_recovery import (
    EmergencyAction, EmergencyIntervention, EmergencyState,
    PolicySnapshotStore, RecoveryQuorum,
)
from .writer_epoch import EpochTracker, check_expirations, promote_due_probations
from .writer_gate import WriterGate
```

Add all new names to the `__all__` list.

- [ ] **Step 2: Verify imports work**

Run: `python -c "from src.ltp.execution import WriterGate, WriterRegistry, VMWriterPolicy, IdentityTier; print('OK')"`
Expected: `OK`

- [ ] **Step 3: Run full regression**

Run: `pytest tests/ -x -q`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/ltp/execution/__init__.py
git commit -m "feat(execution): export writer registry types from execution package (C2 §10)"
```

---

### Task 12: End-to-End Integration Test

**Files:**
- Create: `tests/test_writer_e2e.py`

- [ ] **Step 1: Write E2E test**

```python
"""End-to-end writer lifecycle integration test (Spec C2 §12)."""

import pytest


class FakeEVM:
    """Minimal VM executor for E2E test."""
    vm_tag = 0x01
    vm_name = "fake-evm"
    family = "account"

    def execute(self, tx_bytes):
        from src.ltp.execution.types import TxResult
        return TxResult.accepted(gas_used=21000)

    def state_root(self):
        return b"\xcc" * 32

    def validate_tx(self, tx_bytes):
        return True

    def query_state(self, query):
        from src.ltp.execution.types import StateResult
        return StateResult.not_found()


class TestWriterLifecycleE2E:
    """Full flow: enroll → sponsor → probation → promote → transact → expire → renew."""

    def test_full_lifecycle(self):
        from src.ltp.execution.writer import WriterIdentity, WriterState, IdentityTier
        from src.ltp.execution.writer_config import RegistryConfig
        from src.ltp.execution.writer_registry import WriterRegistry
        from src.ltp.execution.writer_policy import VMWriterPolicy
        from src.ltp.execution.writer_recovery import EmergencyState
        from src.ltp.execution.writer_epoch import EpochTracker, promote_due_probations
        from src.ltp.execution.writer_gate import WriterGate
        from src.ltp.execution.router import TransactionRouter
        from src.ltp.execution.registry import VMRegistry
        from src.ltp.execution.types import OrderedBatch

        # Setup
        config = RegistryConfig(sponsor_threshold=2, probation_epochs=5)
        registry = WriterRegistry(config=config)
        emergency = EmergencyState()
        epoch_tracker = EpochTracker()
        gate = WriterGate(registry=registry, emergency=emergency, epoch_tracker=epoch_tracker)
        gate.set_policy(0x01, VMWriterPolicy(vm_tag=0x01))

        vm_registry = VMRegistry()
        vm_registry.register(FakeEVM())
        router = TransactionRouter(vm_registry, writer_gate=gate)

        # 1. Enroll writer
        from src.ltp.keypair import KeyPair
        kp = KeyPair.generate("e2e-writer", with_bls=True)
        identity = WriterIdentity.from_keypair(kp)
        registry.enroll(identity, timestamp=1000)
        assert registry.lookup(identity.fingerprint).state == WriterState.PENDING

        # 2. Pending writer cannot transact
        tx = identity.fingerprint + b"\x01" + b"hello"
        batch = OrderedBatch(
            round=1, epoch=0, transactions=[tx],
            leader_authority=0, timestamp_ms=1000, consensus_type="bft",
        )
        result = router.execute_batch(batch)
        assert result.tx_results[0].success is False

        # 3. Sponsor (need 2)
        registry.sponsor(identity.fingerprint, sponsor_fp=b"\xaa" * 32, timestamp=2000)
        assert registry.lookup(identity.fingerprint).state == WriterState.PENDING

        registry.sponsor(identity.fingerprint, sponsor_fp=b"\xbb" * 32, timestamp=3000)
        assert registry.lookup(identity.fingerprint).state == WriterState.PROBATION

        # 4. Probation writer can transact (restricted)
        result = router.execute_batch(batch)
        assert result.tx_results[0].success is True

        # 5. Promote after probation period
        promoted = promote_due_probations(registry, current_epoch=10, timestamp=5000)
        assert len(promoted) == 1
        assert registry.lookup(identity.fingerprint).state == WriterState.ACTIVE

        # 6. Active writer transacts
        result = router.execute_batch(batch)
        assert result.tx_results[0].success is True

        # 7. Expire the writer
        record = registry.lookup(identity.fingerprint)
        record.expires_at = 15
        registry.check_expirations(current_epoch=15)
        assert registry.lookup(identity.fingerprint).state == WriterState.EXPIRED

        # 8. Expired writer cannot transact
        result = router.execute_batch(batch)
        assert result.tx_results[0].success is False

        # 9. Renew
        registry.renew(identity.fingerprint, actor_fp=b"\x01" * 32, timestamp=8000)
        assert registry.lookup(identity.fingerprint).state == WriterState.ACTIVE

        # 10. Transacts again
        result = router.execute_batch(batch)
        assert result.tx_results[0].success is True

        # 11. Verify audit trail
        record = registry.lookup(identity.fingerprint)
        assert len(record.transition_log) >= 4  # pending→prob, prob→active, active→expired, expired→active

    def test_three_identity_tiers_all_enroll(self):
        """All three identity tiers can enroll and transact."""
        from src.ltp.execution.writer import WriterIdentity, WriterState, IdentityTier
        from src.ltp.execution.writer_config import RegistryConfig
        from src.ltp.execution.writer_registry import WriterRegistry
        from src.ltp.keypair import KeyPair
        from src.ltp.bls_keys import BLSKeyPair

        registry = WriterRegistry(config=RegistryConfig())

        # MLDSA tier
        kp_mldsa = KeyPair.generate("mldsa-e2e")
        id_mldsa = WriterIdentity.from_keypair(kp_mldsa)
        registry.enroll(id_mldsa, timestamp=1000)
        registry.approve(id_mldsa.fingerprint, admin_fp=b"\x01" * 32, timestamp=2000)
        assert registry.lookup(id_mldsa.fingerprint).identity.tier == IdentityTier.MLDSA

        # COMPOSITE tier
        kp_comp = KeyPair.generate("comp-e2e", with_bls=True)
        id_comp = WriterIdentity.from_keypair(kp_comp)
        registry.enroll(id_comp, timestamp=1000)
        registry.approve(id_comp.fingerprint, admin_fp=b"\x01" * 32, timestamp=2000)
        assert registry.lookup(id_comp.fingerprint).identity.tier == IdentityTier.COMPOSITE

        # BLS tier
        bls_kp = BLSKeyPair.generate("bls-e2e")
        id_bls = WriterIdentity.from_bls_identity(bls_kp.to_identity())
        registry.enroll(id_bls, timestamp=1000)
        registry.approve(id_bls.fingerprint, admin_fp=b"\x01" * 32, timestamp=2000)
        assert registry.lookup(id_bls.fingerprint).identity.tier == IdentityTier.BLS

        # All three are active
        active = registry.active_writers()
        assert len(active) == 3

    def test_emergency_freeze_and_recovery(self):
        """Freeze registry, verify rejection, unfreeze, verify recovery."""
        from src.ltp.execution.writer import WriterIdentity, IdentityTier
        from src.ltp.execution.writer_config import RegistryConfig
        from src.ltp.execution.writer_registry import WriterRegistry
        from src.ltp.execution.writer_policy import VMWriterPolicy
        from src.ltp.execution.writer_recovery import EmergencyState
        from src.ltp.execution.writer_epoch import EpochTracker
        from src.ltp.execution.writer_gate import WriterGate
        from src.ltp.execution.router import TransactionRouter
        from src.ltp.execution.registry import VMRegistry
        from src.ltp.execution.types import OrderedBatch

        registry = WriterRegistry(config=RegistryConfig())
        emergency = EmergencyState()
        gate = WriterGate(registry=registry, emergency=emergency, epoch_tracker=EpochTracker())
        gate.set_policy(0x01, VMWriterPolicy(vm_tag=0x01))
        vm_registry = VMRegistry()
        vm_registry.register(FakeEVM())
        router = TransactionRouter(vm_registry, writer_gate=gate)

        identity = WriterIdentity(
            tier=IdentityTier.MLDSA, fingerprint=b"\xaa" * 32,
            mldsa_vk=b"\x01" * 32,
        )
        registry.enroll(identity, timestamp=1000)
        registry.approve(identity.fingerprint, admin_fp=b"\x01" * 32, timestamp=2000)

        tx = identity.fingerprint + b"\x01" + b"payload"
        batch = OrderedBatch(
            round=1, epoch=0, transactions=[tx],
            leader_authority=0, timestamp_ms=1000, consensus_type="bft",
        )

        # Works normally
        result = router.execute_batch(batch)
        assert result.tx_results[0].success is True

        # Freeze
        emergency.freeze_registry(actor_fp=b"\x01" * 32, reason="incident", timestamp=3000)
        result = router.execute_batch(batch)
        assert result.tx_results[0].success is False

        # Unfreeze
        emergency.unfreeze_registry(actor_fp=b"\x01" * 32, timestamp=4000)
        result = router.execute_batch(batch)
        assert result.tx_results[0].success is True
```

- [ ] **Step 2: Run E2E tests**

Run: `pytest tests/test_writer_e2e.py -v`
Expected: All 3 tests PASS

- [ ] **Step 3: Run full regression**

Run: `pytest tests/ -x -q`
Expected: All tests pass (existing 2,983 + ~90 new writer tests), 0 failures

- [ ] **Step 4: Commit**

```bash
git add tests/test_writer_e2e.py
git commit -m "test(writer): add end-to-end writer lifecycle integration tests (C2 §12)"
```

---

## Self-Review

**Spec coverage check:**

| Spec Section | Task(s) |
|-------------|---------|
| §2 Writer Identity Model | Task 1 |
| §3 Writer Lifecycle | Task 1 |
| §4 Writer Registry | Task 4 |
| §4.5 Registry Config | Task 2 |
| §5 Registry Governance & Roles | Task 3 |
| §6 Per-VM Policy | Task 5 |
| §6.4 Probation Override | Task 5 |
| §7 WriterAuthorizer Protocol | Task 6 |
| §8 Emergency Recovery | Task 7 |
| §8.4 Recovery Quorum | Task 7 |
| §8.5 Policy Versioning | Task 7 |
| §9 WriterGate | Task 9 |
| §9.3 Transaction Identity Binding | Task 9, 10 |
| §9.4 Rate Limit Tracking | Task 8 |
| §9.5 Backward Compatibility | Task 10 |
| §10 File Structure | All tasks |
| §11 C1 Integration | Task 1 (from_keypair, from_bls_identity) |
| §12 Testing | Tasks 1–12 |

**Placeholder scan:** No TBD/TODO items. All code blocks are complete.

**Type consistency:** `WriterIdentity`, `WriterRecord`, `WriterState`, `IdentityTier`, `ApprovalPath`, `TransitionEntry`, `RegistryConfig`, `ProbationModifiers`, `VMWriterPolicy`, `PolicyEngine`, `PolicyResult`, `AuthorizationResult`, `DispatchDecision`, `WriterAuthorizer`, `EmergencyState`, `EpochTracker`, `WriterGate` — all consistent across tasks.
