"""Tests for the writer data model (Spec C2 §2–3).

Covers identity tiers, writer state machine, transitions, identity
construction, transition log entries, approval paths, and writer records.
"""

import time

import pytest

from src.ltp.bls_keys import BLSKeyPair
from src.ltp.execution.writer import (
    TRANSACTABLE_STATES,
    VALID_WRITER_TRANSITIONS,
    ApprovalPath,
    IdentityTier,
    TransitionEntry,
    WriterIdentity,
    WriterRecord,
    WriterState,
    validate_writer_transition,
)
from src.ltp.keypair import KeyPair

# ---------------------------------------------------------------------------
# TestIdentityTier
# ---------------------------------------------------------------------------


class TestIdentityTier:
    """IdentityTier enum — three cryptographic identity modes."""

    def test_mldsa_tier_exists(self):
        assert IdentityTier.MLDSA.value == "mldsa"

    def test_bls_tier_exists(self):
        assert IdentityTier.BLS.value == "bls"

    def test_composite_tier_exists(self):
        assert IdentityTier.COMPOSITE.value == "composite"

    def test_tier_count_is_three(self):
        assert len(IdentityTier) == 3


# ---------------------------------------------------------------------------
# TestWriterState
# ---------------------------------------------------------------------------


class TestWriterState:
    """WriterState enum — six lifecycle states."""

    def test_all_six_states_exist(self):
        expected = {"PENDING", "PROBATION", "ACTIVE", "SUSPENDED", "EXPIRED", "REVOKED"}
        assert {s.name for s in WriterState} == expected

    def test_state_count_is_six(self):
        assert len(WriterState) == 6

    def test_transactable_states_are_active_and_probation(self):
        assert TRANSACTABLE_STATES == frozenset({WriterState.ACTIVE, WriterState.PROBATION})

    def test_pending_is_not_transactable(self):
        assert WriterState.PENDING not in TRANSACTABLE_STATES

    def test_suspended_is_not_transactable(self):
        assert WriterState.SUSPENDED not in TRANSACTABLE_STATES

    def test_revoked_is_not_transactable(self):
        assert WriterState.REVOKED not in TRANSACTABLE_STATES


# ---------------------------------------------------------------------------
# TestWriterTransitions
# ---------------------------------------------------------------------------


class TestWriterTransitions:
    """VALID_WRITER_TRANSITIONS frozenset and validate_writer_transition()."""

    def test_transition_count_is_thirteen(self):
        assert len(VALID_WRITER_TRANSITIONS) == 13

    def test_pending_to_probation_is_valid(self):
        ok, msg = validate_writer_transition(WriterState.PENDING, WriterState.PROBATION)
        assert ok is True
        assert msg == ""

    def test_pending_to_active_is_valid(self):
        ok, _ = validate_writer_transition(WriterState.PENDING, WriterState.ACTIVE)
        assert ok is True

    def test_pending_to_revoked_is_valid(self):
        ok, _ = validate_writer_transition(WriterState.PENDING, WriterState.REVOKED)
        assert ok is True

    def test_probation_to_active_is_valid(self):
        ok, _ = validate_writer_transition(WriterState.PROBATION, WriterState.ACTIVE)
        assert ok is True

    def test_active_to_suspended_is_valid(self):
        ok, _ = validate_writer_transition(WriterState.ACTIVE, WriterState.SUSPENDED)
        assert ok is True

    def test_suspended_to_active_is_valid(self):
        ok, _ = validate_writer_transition(WriterState.SUSPENDED, WriterState.ACTIVE)
        assert ok is True

    def test_expired_to_active_is_valid(self):
        ok, _ = validate_writer_transition(WriterState.EXPIRED, WriterState.ACTIVE)
        assert ok is True

    def test_pending_to_expired_is_invalid(self):
        ok, reason = validate_writer_transition(WriterState.PENDING, WriterState.EXPIRED)
        assert ok is False
        assert "invalid transition" in reason

    def test_revoked_to_active_is_invalid(self):
        """REVOKED is terminal — no transitions out."""
        ok, reason = validate_writer_transition(WriterState.REVOKED, WriterState.ACTIVE)
        assert ok is False
        assert "invalid transition" in reason

    def test_revoked_to_pending_is_invalid(self):
        ok, _ = validate_writer_transition(WriterState.REVOKED, WriterState.PENDING)
        assert ok is False

    def test_no_op_transition_returns_false(self):
        ok, reason = validate_writer_transition(WriterState.ACTIVE, WriterState.ACTIVE)
        assert ok is False
        assert "no-op transition" in reason

    def test_no_op_includes_state_name(self):
        ok, reason = validate_writer_transition(WriterState.SUSPENDED, WriterState.SUSPENDED)
        assert "SUSPENDED" in reason

    def test_all_valid_transitions_return_true(self):
        for from_state, to_state in VALID_WRITER_TRANSITIONS:
            ok, msg = validate_writer_transition(from_state, to_state)
            assert ok is True, f"Expected valid: {from_state} → {to_state}, got: {msg}"
            assert msg == ""


# ---------------------------------------------------------------------------
# TestWriterIdentity
# ---------------------------------------------------------------------------


class TestWriterIdentity:
    """WriterIdentity construction from keypairs and BLS identities."""

    def test_from_keypair_mldsa_tier(self):
        kp = KeyPair.generate("writer-mldsa")
        identity = WriterIdentity.from_keypair(kp)
        assert identity.tier == IdentityTier.MLDSA
        assert identity.mldsa_vk == kp.vk
        assert identity.bls_pk is None
        assert len(identity.fingerprint) == 32

    def test_from_keypair_composite_tier(self):
        kp = KeyPair.generate("writer-composite", with_bls=True)
        identity = WriterIdentity.from_keypair(kp)
        assert identity.tier == IdentityTier.COMPOSITE
        assert identity.mldsa_vk == kp.vk
        assert identity.bls_pk == kp.bls_pk
        assert len(identity.fingerprint) == 32

    def test_from_bls_identity(self):
        bls_kp = BLSKeyPair.generate("writer-bls")
        bls_id = bls_kp.to_identity()
        identity = WriterIdentity.from_bls_identity(bls_id)
        assert identity.tier == IdentityTier.BLS
        assert identity.bls_pk == bls_kp.pk
        assert identity.fingerprint == bls_id.fingerprint
        assert identity.mldsa_vk is None

    def test_different_keypairs_produce_different_fingerprints(self):
        kp1 = KeyPair.generate("fp-test-1")
        kp2 = KeyPair.generate("fp-test-2")
        id1 = WriterIdentity.from_keypair(kp1)
        id2 = WriterIdentity.from_keypair(kp2)
        assert id1.fingerprint != id2.fingerprint

    def test_identity_is_frozen(self):
        kp = KeyPair.generate("frozen-identity")
        identity = WriterIdentity.from_keypair(kp)
        with pytest.raises((AttributeError, TypeError)):
            identity.tier = IdentityTier.BLS  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TestTransitionEntry
# ---------------------------------------------------------------------------


class TestTransitionEntry:
    """TransitionEntry frozen dataclass."""

    def test_fields_are_accessible(self):
        now = int(time.time() * 1000)
        actor = b"\xab" * 32
        entry = TransitionEntry(
            timestamp=now,
            from_state=WriterState.PENDING,
            to_state=WriterState.ACTIVE,
            actor_fp=actor,
            reason="initial activation",
        )
        assert entry.timestamp == now
        assert entry.from_state == WriterState.PENDING
        assert entry.to_state == WriterState.ACTIVE
        assert entry.actor_fp == actor
        assert entry.reason == "initial activation"
        assert entry.is_emergency is False

    def test_emergency_flag_can_be_set(self):
        entry = TransitionEntry(
            timestamp=int(time.time() * 1000),
            from_state=WriterState.ACTIVE,
            to_state=WriterState.SUSPENDED,
            actor_fp=b"\x00" * 32,
            reason="emergency suspension",
            is_emergency=True,
        )
        assert entry.is_emergency is True

    def test_transition_entry_is_frozen(self):
        entry = TransitionEntry(
            timestamp=int(time.time() * 1000),
            from_state=WriterState.ACTIVE,
            to_state=WriterState.REVOKED,
            actor_fp=b"\x01" * 32,
            reason="policy violation",
        )
        with pytest.raises((AttributeError, TypeError)):
            entry.reason = "modified"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TestApprovalPath
# ---------------------------------------------------------------------------


class TestApprovalPath:
    """ApprovalPath enum — three approval modes."""

    def test_admin_path_exists(self):
        assert ApprovalPath.ADMIN.value == "admin"

    def test_sponsor_path_exists(self):
        assert ApprovalPath.SPONSOR.value == "sponsor"

    def test_self_path_exists(self):
        assert ApprovalPath.SELF.value == "self"


# ---------------------------------------------------------------------------
# TestWriterRecord
# ---------------------------------------------------------------------------


class TestWriterRecord:
    """WriterRecord mutable dataclass and can_transact property."""

    def _make_identity(self) -> WriterIdentity:
        kp = KeyPair.generate("record-test")
        return WriterIdentity.from_keypair(kp)

    def test_create_pending_record(self):
        identity = self._make_identity()
        now = int(time.time() * 1000)
        record = WriterRecord(
            identity=identity,
            state=WriterState.PENDING,
            approval_path=ApprovalPath.ADMIN,
            enrolled_at=now,
        )
        assert record.state == WriterState.PENDING
        assert record.approval_path == ApprovalPath.ADMIN
        assert record.enrolled_at == now
        assert record.approved_at is None
        assert record.approved_by is None
        assert record.sponsors == []
        assert record.transition_log == []

    def test_can_transact_is_true_when_active(self):
        identity = self._make_identity()
        record = WriterRecord(
            identity=identity,
            state=WriterState.ACTIVE,
            approval_path=ApprovalPath.ADMIN,
            enrolled_at=int(time.time() * 1000),
        )
        assert record.can_transact is True

    def test_can_transact_is_true_when_on_probation(self):
        identity = self._make_identity()
        record = WriterRecord(
            identity=identity,
            state=WriterState.PROBATION,
            approval_path=ApprovalPath.SPONSOR,
            enrolled_at=int(time.time() * 1000),
        )
        assert record.can_transact is True

    def test_cannot_transact_when_pending(self):
        identity = self._make_identity()
        record = WriterRecord(
            identity=identity,
            state=WriterState.PENDING,
            approval_path=ApprovalPath.SELF,
            enrolled_at=int(time.time() * 1000),
        )
        assert record.can_transact is False

    def test_cannot_transact_when_suspended(self):
        identity = self._make_identity()
        record = WriterRecord(
            identity=identity,
            state=WriterState.SUSPENDED,
            approval_path=ApprovalPath.ADMIN,
            enrolled_at=int(time.time() * 1000),
            suspension_reason="policy breach",
        )
        assert record.can_transact is False

    def test_cannot_transact_when_revoked(self):
        identity = self._make_identity()
        record = WriterRecord(
            identity=identity,
            state=WriterState.REVOKED,
            approval_path=ApprovalPath.ADMIN,
            enrolled_at=int(time.time() * 1000),
        )
        assert record.can_transact is False

    def test_transition_log_is_mutable(self):
        identity = self._make_identity()
        record = WriterRecord(
            identity=identity,
            state=WriterState.ACTIVE,
            approval_path=ApprovalPath.ADMIN,
            enrolled_at=int(time.time() * 1000),
        )
        entry = TransitionEntry(
            timestamp=int(time.time() * 1000),
            from_state=WriterState.PENDING,
            to_state=WriterState.ACTIVE,
            actor_fp=b"\xcc" * 32,
            reason="approved",
        )
        record.transition_log.append(entry)
        assert len(record.transition_log) == 1
        assert record.transition_log[0] == entry


# ---------------------------------------------------------------------------
# RegistryConfig + ProbationModifiers (Task 2)
# ---------------------------------------------------------------------------


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
