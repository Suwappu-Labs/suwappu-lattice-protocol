"""Hypothesis property-based tests for C2 writer subsystem.

Covers:
  - WriterState transition validity (no invalid transition ever accepted)
  - infer_operation_type round-trip for all known bytes
  - PolicySnapshotStore version monotonicity
  - RecoveryQuorum threshold invariants
  - EpochTracker monotonic counters
"""

from __future__ import annotations

import pytest
from hypothesis import given, assume, settings
from hypothesis import strategies as st

from src.ltp.execution.writer import (
    WriterState,
    VALID_WRITER_TRANSITIONS,
    validate_writer_transition,
)
from src.ltp.execution.types import OperationType, infer_operation_type
from src.ltp.execution.writer_recovery import (
    PolicySnapshotStore,
    RecoveryQuorum,
)
from src.ltp.execution.writer_policy import VMWriterPolicy
from src.ltp.execution.writer_epoch import EpochTracker


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

writer_states = st.sampled_from(list(WriterState))
operation_bytes = st.integers(min_value=0, max_value=255)
fingerprints = st.binary(min_size=32, max_size=32)
vm_tags = st.integers(min_value=0, max_value=255)
timestamps = st.integers(min_value=0, max_value=2**40)
epochs = st.integers(min_value=1, max_value=10_000)


# ---------------------------------------------------------------------------
# Writer state machine properties
# ---------------------------------------------------------------------------

class TestWriterTransitionProperties:

    @given(src=writer_states, dst=writer_states)
    def test_valid_transitions_match_set(self, src, dst):
        """validate_writer_transition agrees with VALID_WRITER_TRANSITIONS."""
        ok, _ = validate_writer_transition(src, dst)
        if src == dst:
            assert not ok, "self-transitions must be rejected"
        elif (src, dst) in VALID_WRITER_TRANSITIONS:
            assert ok, f"{src.value}→{dst.value} should be valid"
        else:
            assert not ok, f"{src.value}→{dst.value} should be invalid"

    @given(state=writer_states)
    def test_revoked_is_terminal(self, state):
        """No transition out of REVOKED is valid."""
        assume(state != WriterState.REVOKED)
        ok, _ = validate_writer_transition(WriterState.REVOKED, state)
        assert not ok, f"REVOKED→{state.value} must be rejected"

    @given(state=writer_states)
    def test_any_state_can_reach_revoked(self, state):
        """Every non-terminal state can transition to REVOKED."""
        if state == WriterState.REVOKED:
            return
        ok, _ = validate_writer_transition(state, WriterState.REVOKED)
        assert ok, f"{state.value}→REVOKED must be valid"


# ---------------------------------------------------------------------------
# Operation type inference properties
# ---------------------------------------------------------------------------

class TestOperationTypeInferenceProperties:

    @given(byte=st.integers(min_value=0, max_value=4))
    def test_known_bytes_never_return_wrong_type(self, byte):
        """All 5 known op-type bytes map to the correct OperationType."""
        expected = {
            0: OperationType.TRANSFER,
            1: OperationType.DEPLOY,
            2: OperationType.CALL,
            3: OperationType.STATE_MODIFY,
            4: OperationType.STATE_READ,
        }
        result = infer_operation_type(bytes([byte]))
        assert result is expected[byte]

    @given(byte=st.integers(min_value=5, max_value=255))
    def test_unknown_bytes_default_to_transfer(self, byte):
        """Any unrecognised op-type byte defaults to TRANSFER."""
        result = infer_operation_type(bytes([byte]))
        assert result is OperationType.TRANSFER

    @given(payload=st.binary(min_size=0, max_size=256))
    def test_always_returns_valid_operation_type(self, payload):
        """infer_operation_type never raises and always returns an OperationType."""
        result = infer_operation_type(payload)
        assert isinstance(result, OperationType)


# ---------------------------------------------------------------------------
# PolicySnapshotStore properties
# ---------------------------------------------------------------------------

class TestPolicySnapshotProperties:

    @given(n=st.integers(min_value=1, max_value=20))
    def test_versions_are_monotonically_increasing(self, n):
        """snapshot() returns strictly incrementing version numbers."""
        store = PolicySnapshotStore()
        versions = []
        for i in range(n):
            v = store.snapshot(0x01, VMWriterPolicy(vm_tag=0x01, max_writers=i), i)
            versions.append(v)
        assert versions == list(range(n))

    @given(n=st.integers(min_value=1, max_value=20))
    def test_version_count_equals_snapshot_calls(self, n):
        """version_count always reflects the number of snapshot() calls."""
        store = PolicySnapshotStore()
        for i in range(n):
            store.snapshot(0x01, VMWriterPolicy(vm_tag=0x01), i)
        assert store.version_count(0x01) == n

    @given(
        n=st.integers(min_value=1, max_value=15),
        target=st.integers(min_value=0, max_value=14),
    )
    def test_rollback_preserves_snapshot_data(self, n, target):
        """Rolling back to version k returns the policy stored at snapshot k."""
        assume(target < n)
        store = PolicySnapshotStore()
        for i in range(n):
            store.snapshot(0x01, VMWriterPolicy(vm_tag=0x01, max_writers=i * 10), i)
        rolled = store.rollback(0x01, target)
        assert rolled.max_writers == target * 10


# ---------------------------------------------------------------------------
# RecoveryQuorum properties
# ---------------------------------------------------------------------------

class TestRecoveryQuorumProperties:

    @given(n_keys=st.integers(min_value=1, max_value=10),
           threshold=st.integers(min_value=1, max_value=10))
    def test_quorum_needs_threshold_unique_votes(self, n_keys, threshold):
        """Quorum is met iff >= threshold unique votes are collected."""
        assume(threshold <= n_keys)
        keys = [bytes([i]) * 32 for i in range(n_keys)]
        q = RecoveryQuorum(keys, threshold=threshold)
        for i in range(threshold - 1):
            q.add_vote(keys[i])
            assert not q.is_met()
        q.add_vote(keys[threshold - 1])
        assert q.is_met()

    @given(n_keys=st.integers(min_value=1, max_value=10))
    def test_duplicate_votes_do_not_advance_quorum(self, n_keys):
        """Voting with the same key twice doesn't double-count."""
        keys = [bytes([i]) * 32 for i in range(n_keys)]
        q = RecoveryQuorum(keys, threshold=2)
        assume(n_keys >= 2)
        q.add_vote(keys[0])
        q.add_vote(keys[0])  # duplicate
        assert not q.is_met()

    @given(n_keys=st.integers(min_value=1, max_value=10))
    def test_reset_clears_all_progress(self, n_keys):
        """After reset(), the quorum is never met regardless of prior votes."""
        keys = [bytes([i]) * 32 for i in range(n_keys)]
        q = RecoveryQuorum(keys, threshold=1)
        q.add_vote(keys[0])
        assert q.is_met()
        q.reset()
        assert not q.is_met()


# ---------------------------------------------------------------------------
# EpochTracker properties
# ---------------------------------------------------------------------------

class TestEpochTrackerProperties:

    @given(n=st.integers(min_value=1, max_value=50))
    def test_tx_count_equals_increment_calls(self, n):
        """get_tx_count returns exactly the number of increment() calls."""
        tracker = EpochTracker()
        fp = b"\xaa" * 32
        for _ in range(n):
            tracker.increment(fp, 0x01, epoch=1)
        assert tracker.get_tx_count(fp, 0x01) == n

    @given(fp1=fingerprints, fp2=fingerprints)
    def test_counters_are_independent_per_writer(self, fp1, fp2):
        """Incrementing one writer's counter doesn't affect another's."""
        assume(fp1 != fp2)
        tracker = EpochTracker()
        tracker.increment(fp1, 0x01, epoch=1)
        tracker.increment(fp1, 0x01, epoch=1)
        tracker.increment(fp2, 0x01, epoch=1)
        assert tracker.get_tx_count(fp1, 0x01) == 2
        assert tracker.get_tx_count(fp2, 0x01) == 1
