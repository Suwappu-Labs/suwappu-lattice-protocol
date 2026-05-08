"""Tests for emergency recovery primitives (Spec C2 §8).

Covers:
  - EmergencyAction enum (7 values)
  - EmergencyState (freeze / bypass lifecycle + audit trail)
  - PolicySnapshotStore (append-only snapshots + rollback)
  - RecoveryQuorum (threshold voting)
"""

from __future__ import annotations

import pytest

from src.ltp.execution.writer_recovery import (
    EmergencyAction,
    EmergencyIntervention,
    EmergencyState,
    PolicySnapshotStore,
    RecoveryQuorum,
)
from src.ltp.execution.writer_policy import VMWriterPolicy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ACTOR = b"\xde\xad\xbe\xef" * 8   # 32 bytes
_TS    = 1_700_000_000


def _policy(vm_tag: int = 1, max_writers: int = 0) -> VMWriterPolicy:
    return VMWriterPolicy(vm_tag=vm_tag, max_writers=max_writers)


# ---------------------------------------------------------------------------
# TestEmergencyAction
# ---------------------------------------------------------------------------

class TestEmergencyAction:
    """All seven enum members must exist with the correct values."""

    def test_seven_actions_exist(self):
        assert len(EmergencyAction) == 7

    def test_freeze_registry(self):
        assert EmergencyAction.FREEZE_REGISTRY.value == "freeze_registry"

    def test_freeze_vm(self):
        assert EmergencyAction.FREEZE_VM.value == "freeze_vm"

    def test_bypass_authorizer(self):
        assert EmergencyAction.BYPASS_AUTHORIZER.value == "bypass_authorizer"

    def test_force_revoke(self):
        assert EmergencyAction.FORCE_REVOKE.value == "force_revoke"

    def test_rollback_policy(self):
        assert EmergencyAction.ROLLBACK_POLICY.value == "rollback_policy"

    def test_rotate_owner(self):
        assert EmergencyAction.ROTATE_OWNER.value == "rotate_owner"

    def test_override_dispatch(self):
        assert EmergencyAction.OVERRIDE_DISPATCH.value == "override_dispatch"


# ---------------------------------------------------------------------------
# TestEmergencyState
# ---------------------------------------------------------------------------

class TestEmergencyState:
    """EmergencyState lifecycle — freeze, unfreeze, bypass, clear."""

    # ---- initial conditions ------------------------------------------------

    def test_initial_not_frozen(self):
        state = EmergencyState()
        assert state.is_registry_frozen is False

    def test_initial_no_frozen_vms(self):
        state = EmergencyState()
        assert state.is_vm_frozen(1) is False
        assert state.is_vm_frozen(99) is False

    def test_initial_no_bypassed_authorizers(self):
        state = EmergencyState()
        assert state.is_authorizer_bypassed(1) is False

    def test_initial_interventions_empty(self):
        state = EmergencyState()
        assert state.interventions == []

    # ---- registry freeze ---------------------------------------------------

    def test_freeze_registry(self):
        state = EmergencyState()
        state.freeze_registry(_ACTOR, "critical vulnerability", _TS)
        assert state.is_registry_frozen is True

    def test_freeze_registry_logs_intervention(self):
        state = EmergencyState()
        state.freeze_registry(_ACTOR, "critical vulnerability", _TS)
        assert len(state.interventions) == 1
        iv = state.interventions[0]
        assert iv.action is EmergencyAction.FREEZE_REGISTRY
        assert iv.actor_fp == _ACTOR
        assert iv.timestamp == _TS

    # ---- registry unfreeze -------------------------------------------------

    def test_unfreeze_registry(self):
        state = EmergencyState()
        state.freeze_registry(_ACTOR, "test", _TS)
        state.unfreeze_registry(_ACTOR, _TS + 100)
        assert state.is_registry_frozen is False

    def test_unfreeze_registry_appends_intervention(self):
        state = EmergencyState()
        state.freeze_registry(_ACTOR, "test", _TS)
        state.unfreeze_registry(_ACTOR, _TS + 100)
        assert len(state.interventions) == 2

    # ---- VM freeze ---------------------------------------------------------

    def test_freeze_vm(self):
        state = EmergencyState()
        state.freeze_vm(42, _ACTOR, "suspicious activity", _TS)
        assert state.is_vm_frozen(42) is True

    def test_freeze_vm_does_not_affect_other_vms(self):
        state = EmergencyState()
        state.freeze_vm(42, _ACTOR, "suspicious activity", _TS)
        assert state.is_vm_frozen(7) is False

    def test_freeze_vm_logs_scope(self):
        state = EmergencyState()
        state.freeze_vm(42, _ACTOR, "suspicious activity", _TS)
        iv = state.interventions[0]
        assert iv.action is EmergencyAction.FREEZE_VM
        assert iv.scope == 42

    # ---- VM unfreeze -------------------------------------------------------

    def test_unfreeze_vm(self):
        state = EmergencyState()
        state.freeze_vm(42, _ACTOR, "test", _TS)
        state.unfreeze_vm(42, _ACTOR, _TS + 50)
        assert state.is_vm_frozen(42) is False

    def test_unfreeze_vm_appends_intervention(self):
        state = EmergencyState()
        state.freeze_vm(42, _ACTOR, "test", _TS)
        state.unfreeze_vm(42, _ACTOR, _TS + 50)
        assert len(state.interventions) == 2

    # ---- authorizer bypass -------------------------------------------------

    def test_bypass_authorizer(self):
        state = EmergencyState()
        state.bypass_authorizer(5, _ACTOR, "emergency patch", _TS)
        assert state.is_authorizer_bypassed(5) is True

    def test_bypass_authorizer_does_not_affect_other_vms(self):
        state = EmergencyState()
        state.bypass_authorizer(5, _ACTOR, "emergency patch", _TS)
        assert state.is_authorizer_bypassed(99) is False

    def test_bypass_authorizer_logs_intervention(self):
        state = EmergencyState()
        state.bypass_authorizer(5, _ACTOR, "emergency patch", _TS)
        iv = state.interventions[0]
        assert iv.action is EmergencyAction.BYPASS_AUTHORIZER
        assert iv.scope == 5

    # ---- clear bypass ------------------------------------------------------

    def test_clear_bypass(self):
        state = EmergencyState()
        state.bypass_authorizer(5, _ACTOR, "test", _TS)
        state.clear_bypass(5, _ACTOR, _TS + 200)
        assert state.is_authorizer_bypassed(5) is False

    def test_clear_bypass_appends_intervention(self):
        state = EmergencyState()
        state.bypass_authorizer(5, _ACTOR, "test", _TS)
        state.clear_bypass(5, _ACTOR, _TS + 200)
        assert len(state.interventions) == 2


# ---------------------------------------------------------------------------
# TestPolicySnapshots
# ---------------------------------------------------------------------------

class TestPolicySnapshots:
    """PolicySnapshotStore — append-only snapshots and rollback."""

    def test_snapshot_returns_zero_for_first_version(self):
        store = PolicySnapshotStore()
        v = store.snapshot(1, _policy(1), _TS)
        assert v == 0

    def test_snapshot_increments_version(self):
        store = PolicySnapshotStore()
        store.snapshot(1, _policy(1, max_writers=0), _TS)
        v = store.snapshot(1, _policy(1, max_writers=10), _TS + 1)
        assert v == 1

    def test_version_count_reflects_snapshots(self):
        store = PolicySnapshotStore()
        assert store.version_count(1) == 0
        store.snapshot(1, _policy(1), _TS)
        assert store.version_count(1) == 1
        store.snapshot(1, _policy(1), _TS + 1)
        assert store.version_count(1) == 2

    def test_rollback_returns_correct_policy(self):
        store = PolicySnapshotStore()
        p0 = _policy(1, max_writers=0)
        p1 = _policy(1, max_writers=50)
        store.snapshot(1, p0, _TS)
        store.snapshot(1, p1, _TS + 1)

        rolled = store.rollback(1, 0)
        assert rolled.max_writers == 0

        rolled = store.rollback(1, 1)
        assert rolled.max_writers == 50

    def test_rollback_returns_deep_copy(self):
        """Mutating the returned policy must not corrupt the stored snapshot."""
        store = PolicySnapshotStore()
        p = _policy(1, max_writers=5)
        store.snapshot(1, p, _TS)

        copy_a = store.rollback(1, 0)
        copy_a.max_writers = 999

        copy_b = store.rollback(1, 0)
        assert copy_b.max_writers == 5

    def test_rollback_invalid_version_raises_key_error(self):
        store = PolicySnapshotStore()
        store.snapshot(1, _policy(1), _TS)
        with pytest.raises(KeyError):
            store.rollback(1, 99)

    def test_rollback_unknown_vm_tag_raises_key_error(self):
        store = PolicySnapshotStore()
        with pytest.raises(KeyError):
            store.rollback(999, 0)

    def test_snapshots_are_independent_per_vm(self):
        store = PolicySnapshotStore()
        store.snapshot(1, _policy(1, max_writers=1), _TS)
        store.snapshot(2, _policy(2, max_writers=2), _TS)
        store.snapshot(2, _policy(2, max_writers=3), _TS + 1)

        assert store.version_count(1) == 1
        assert store.version_count(2) == 2


# ---------------------------------------------------------------------------
# TestRecoveryQuorum
# ---------------------------------------------------------------------------

class TestRecoveryQuorum:
    """RecoveryQuorum — threshold voting lifecycle."""

    def test_quorum_not_met_initially(self):
        keys = [b"\x01" * 32, b"\x02" * 32, b"\x03" * 32]
        q = RecoveryQuorum(keys, threshold=2)
        assert q.is_met() is False

    def test_quorum_met_when_threshold_reached(self):
        keys = [b"\x01" * 32, b"\x02" * 32, b"\x03" * 32]
        q = RecoveryQuorum(keys, threshold=2)
        q.add_vote(b"\x01" * 32)
        q.add_vote(b"\x02" * 32)
        assert q.is_met() is True

    def test_quorum_met_unanimous(self):
        keys = [b"\xaa" * 32, b"\xbb" * 32]
        q = RecoveryQuorum(keys, threshold=2)
        q.add_vote(b"\xaa" * 32)
        q.add_vote(b"\xbb" * 32)
        assert q.is_met() is True

    def test_duplicate_votes_do_not_double_count(self):
        keys = [b"\x01" * 32, b"\x02" * 32]
        q = RecoveryQuorum(keys, threshold=2)
        q.add_vote(b"\x01" * 32)
        q.add_vote(b"\x01" * 32)   # same key again
        assert q.is_met() is False  # only 1 unique vote

    def test_invalid_key_raises_value_error(self):
        keys = [b"\x01" * 32]
        q = RecoveryQuorum(keys, threshold=1)
        with pytest.raises(ValueError):
            q.add_vote(b"\xff" * 32)

    def test_reset_clears_votes(self):
        keys = [b"\x01" * 32, b"\x02" * 32]
        q = RecoveryQuorum(keys, threshold=2)
        q.add_vote(b"\x01" * 32)
        q.add_vote(b"\x02" * 32)
        assert q.is_met() is True
        q.reset()
        assert q.is_met() is False

    def test_threshold_one_met_after_single_vote(self):
        keys = [b"\xca" * 32, b"\xfe" * 32]
        q = RecoveryQuorum(keys, threshold=1)
        q.add_vote(b"\xca" * 32)
        assert q.is_met() is True
