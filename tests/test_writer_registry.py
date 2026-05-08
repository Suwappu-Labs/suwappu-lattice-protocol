"""Tests for the WriterRegistry (Spec C2 §4).

Covers enrollment, admin approval, sponsorship flow, state transitions,
audit trail integrity, and the active_writers() query.
"""

import pytest

from src.ltp.execution.writer import (
    ApprovalPath,
    WriterState,
)
from src.ltp.execution.writer_config import RegistryConfig
from src.ltp.execution.writer_registry import WriterRegistry


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _make_mldsa_identity():
    """Create a fresh ML-DSA writer identity from a generated KeyPair."""
    from src.ltp.execution.writer import WriterIdentity
    from src.ltp.keypair import KeyPair
    kp = KeyPair.generate("reg-test")
    return WriterIdentity.from_keypair(kp)


def _make_bls_identity():
    """Create a fresh BLS writer identity from a BLSKeyPair."""
    from src.ltp.execution.writer import WriterIdentity
    from src.ltp.bls_keys import BLSKeyPair
    bls_kp = BLSKeyPair.generate("reg-bls-test")
    bls_id = bls_kp.to_identity()
    return WriterIdentity.from_bls_identity(bls_id)


def _registry(sponsor_threshold: int = 2, probation_epochs: int = 10) -> WriterRegistry:
    """Return a WriterRegistry with the given config."""
    config = RegistryConfig(
        sponsor_threshold=sponsor_threshold,
        probation_epochs=probation_epochs,
    )
    return WriterRegistry(config=config)


TS = 1_000_000  # A deterministic base timestamp (milliseconds)


# ---------------------------------------------------------------------------
# TestEnrollment
# ---------------------------------------------------------------------------

class TestEnrollment:
    """enroll() — create a PENDING writer record."""

    def test_enroll_creates_pending_record(self):
        reg = _registry()
        ident = _make_mldsa_identity()
        record = reg.enroll(ident, timestamp=TS)
        assert record.state == WriterState.PENDING

    def test_enrolled_record_retrievable_via_lookup(self):
        reg = _registry()
        ident = _make_mldsa_identity()
        reg.enroll(ident, timestamp=TS)
        found = reg.lookup(ident.fingerprint)
        assert found is not None
        assert found.identity.fingerprint == ident.fingerprint

    def test_lookup_missing_fingerprint_returns_none(self):
        reg = _registry()
        assert reg.lookup(b"\x00" * 32) is None

    def test_duplicate_enrollment_raises_value_error(self):
        reg = _registry()
        ident = _make_mldsa_identity()
        reg.enroll(ident, timestamp=TS)
        with pytest.raises(ValueError, match="already registered"):
            reg.enroll(ident, timestamp=TS + 1)

    def test_revoked_writer_cannot_reenroll(self):
        reg = _registry()
        ident = _make_mldsa_identity()
        admin_fp = b"\xaa" * 32
        reg.enroll(ident, timestamp=TS)
        reg.revoke(ident.fingerprint, reason="test", actor_fp=admin_fp, timestamp=TS + 1)
        with pytest.raises(ValueError, match="previously revoked"):
            reg.enroll(ident, timestamp=TS + 2)

    def test_bls_identity_can_be_enrolled(self):
        reg = _registry()
        ident = _make_bls_identity()
        record = reg.enroll(ident, timestamp=TS)
        assert record.state == WriterState.PENDING
        assert record.identity.fingerprint == ident.fingerprint


# ---------------------------------------------------------------------------
# TestAdminApproval
# ---------------------------------------------------------------------------

class TestAdminApproval:
    """approve() — PENDING → ACTIVE via admin path."""

    def test_approve_transitions_pending_to_active(self):
        reg = _registry()
        ident = _make_mldsa_identity()
        admin_fp = b"\xab" * 32
        reg.enroll(ident, timestamp=TS)
        record = reg.approve(ident.fingerprint, admin_fp=admin_fp, timestamp=TS + 10)
        assert record.state == WriterState.ACTIVE

    def test_approve_sets_approval_metadata(self):
        reg = _registry()
        ident = _make_mldsa_identity()
        admin_fp = b"\xac" * 32
        reg.enroll(ident, timestamp=TS)
        record = reg.approve(ident.fingerprint, admin_fp=admin_fp, timestamp=TS + 10)
        assert record.approved_by == admin_fp
        assert record.approved_at == TS + 10
        assert record.approval_path == ApprovalPath.ADMIN

    def test_approve_nonexistent_fingerprint_raises_key_error(self):
        reg = _registry()
        with pytest.raises(KeyError):
            reg.approve(b"\xff" * 32, admin_fp=b"\x01" * 32, timestamp=TS)

    def test_approve_already_active_raises_value_error(self):
        reg = _registry()
        ident = _make_mldsa_identity()
        admin_fp = b"\xad" * 32
        reg.enroll(ident, timestamp=TS)
        reg.approve(ident.fingerprint, admin_fp=admin_fp, timestamp=TS + 10)
        # Second call must fail — writer is now ACTIVE, not PENDING
        with pytest.raises(ValueError, match="PENDING"):
            reg.approve(ident.fingerprint, admin_fp=admin_fp, timestamp=TS + 20)


# ---------------------------------------------------------------------------
# TestSponsorFlow
# ---------------------------------------------------------------------------

class TestSponsorFlow:
    """sponsor() — collect sponsors until threshold; PENDING → PROBATION."""

    def test_single_sponsor_below_threshold_does_not_transition(self):
        reg = _registry(sponsor_threshold=2)
        ident = _make_mldsa_identity()
        reg.enroll(ident, timestamp=TS)
        sponsor_fp = b"\xba" * 32
        record = reg.sponsor(ident.fingerprint, sponsor_fp=sponsor_fp, timestamp=TS + 1)
        # Below threshold — still PENDING
        assert record.state == WriterState.PENDING
        assert sponsor_fp in record.sponsors

    def test_threshold_met_transitions_to_probation(self):
        reg = _registry(sponsor_threshold=2)
        ident = _make_mldsa_identity()
        reg.enroll(ident, timestamp=TS)
        reg.sponsor(ident.fingerprint, sponsor_fp=b"\xb1" * 32, timestamp=TS + 1)
        record = reg.sponsor(ident.fingerprint, sponsor_fp=b"\xb2" * 32, timestamp=TS + 2)
        assert record.state == WriterState.PROBATION

    def test_duplicate_sponsor_is_silently_ignored(self):
        reg = _registry(sponsor_threshold=3)
        ident = _make_mldsa_identity()
        reg.enroll(ident, timestamp=TS)
        s1 = b"\xbc" * 32
        reg.sponsor(ident.fingerprint, sponsor_fp=s1, timestamp=TS + 1)
        record = reg.sponsor(ident.fingerprint, sponsor_fp=s1, timestamp=TS + 2)
        # Still only one unique sponsor
        assert record.sponsors.count(s1) == 1
        assert record.state == WriterState.PENDING

    def test_sponsor_on_non_pending_writer_raises_value_error(self):
        reg = _registry(sponsor_threshold=2)
        ident = _make_mldsa_identity()
        admin_fp = b"\xbe" * 32
        reg.enroll(ident, timestamp=TS)
        reg.approve(ident.fingerprint, admin_fp=admin_fp, timestamp=TS + 5)
        with pytest.raises(ValueError, match="PENDING"):
            reg.sponsor(ident.fingerprint, sponsor_fp=b"\xbf" * 32, timestamp=TS + 10)

    def test_probation_until_set_on_sponsor_threshold(self):
        reg = _registry(sponsor_threshold=2, probation_epochs=10)
        ident = _make_mldsa_identity()
        reg.enroll(ident, timestamp=TS)
        reg.sponsor(ident.fingerprint, sponsor_fp=b"\xca" * 32, timestamp=TS + 1)
        record = reg.sponsor(ident.fingerprint, sponsor_fp=b"\xcb" * 32, timestamp=TS + 2)
        assert record.probation_until == (TS + 2) + 10


# ---------------------------------------------------------------------------
# TestStateTransitions
# ---------------------------------------------------------------------------

class TestStateTransitions:
    """suspend, reinstate, revoke, renew, promote."""

    def test_suspend_active_writer(self):
        reg = _registry()
        ident = _make_mldsa_identity()
        admin_fp = b"\xda" * 32
        reg.enroll(ident, timestamp=TS)
        reg.approve(ident.fingerprint, admin_fp=admin_fp, timestamp=TS + 1)
        record = reg.suspend(
            ident.fingerprint,
            reason="policy violation",
            actor_fp=admin_fp,
            timestamp=TS + 2,
        )
        assert record.state == WriterState.SUSPENDED
        assert record.suspension_reason == "policy violation"

    def test_reinstate_suspended_writer(self):
        reg = _registry()
        ident = _make_mldsa_identity()
        admin_fp = b"\xdb" * 32
        reg.enroll(ident, timestamp=TS)
        reg.approve(ident.fingerprint, admin_fp=admin_fp, timestamp=TS + 1)
        reg.suspend(ident.fingerprint, reason="test", actor_fp=admin_fp, timestamp=TS + 2)
        record = reg.reinstate(ident.fingerprint, actor_fp=admin_fp, timestamp=TS + 3)
        assert record.state == WriterState.ACTIVE
        assert record.suspension_reason is None

    def test_revoke_is_permanent_terminal_state(self):
        reg = _registry()
        ident = _make_mldsa_identity()
        admin_fp = b"\xdc" * 32
        reg.enroll(ident, timestamp=TS)
        reg.approve(ident.fingerprint, admin_fp=admin_fp, timestamp=TS + 1)
        reg.revoke(
            ident.fingerprint,
            reason="permanent ban",
            actor_fp=admin_fp,
            timestamp=TS + 2,
        )
        record = reg.lookup(ident.fingerprint)
        assert record.state == WriterState.REVOKED
        # Confirm fingerprint added to _revoked set
        assert ident.fingerprint in reg._revoked
        # Re-enrollment blocked
        with pytest.raises(ValueError, match="previously revoked"):
            reg.enroll(ident, timestamp=TS + 10)

    def test_renew_expired_writer_back_to_active(self):
        reg = _registry()
        ident = _make_mldsa_identity()
        admin_fp = b"\xdd" * 32
        reg.enroll(ident, timestamp=TS)
        reg.approve(ident.fingerprint, admin_fp=admin_fp, timestamp=TS + 1)
        # Manually set expires_at so check_expirations triggers
        record = reg.lookup(ident.fingerprint)
        record.expires_at = 5
        expired = reg.check_expirations(current_epoch=5)
        assert ident.fingerprint in expired
        assert record.state == WriterState.EXPIRED
        # Now renew
        reg.renew(ident.fingerprint, actor_fp=admin_fp, timestamp=TS + 10)
        assert record.state == WriterState.ACTIVE

    def test_promote_probation_to_active(self):
        reg = _registry(sponsor_threshold=2)
        ident = _make_mldsa_identity()
        reg.enroll(ident, timestamp=TS)
        reg.sponsor(ident.fingerprint, sponsor_fp=b"\xde" * 32, timestamp=TS + 1)
        reg.sponsor(ident.fingerprint, sponsor_fp=b"\xdf" * 32, timestamp=TS + 2)
        record = reg.lookup(ident.fingerprint)
        assert record.state == WriterState.PROBATION
        reg.promote(ident.fingerprint, timestamp=TS + 3)
        assert record.state == WriterState.ACTIVE

    def test_suspend_probation_writer(self):
        reg = _registry(sponsor_threshold=2)
        ident = _make_mldsa_identity()
        admin_fp = b"\xea" * 32
        reg.enroll(ident, timestamp=TS)
        reg.sponsor(ident.fingerprint, sponsor_fp=b"\xe1" * 32, timestamp=TS + 1)
        reg.sponsor(ident.fingerprint, sponsor_fp=b"\xe2" * 32, timestamp=TS + 2)
        record = reg.suspend(
            ident.fingerprint,
            reason="probation violation",
            actor_fp=admin_fp,
            timestamp=TS + 3,
        )
        assert record.state == WriterState.SUSPENDED


# ---------------------------------------------------------------------------
# TestAuditTrail
# ---------------------------------------------------------------------------

class TestAuditTrail:
    """transition_log entries must be accurate and immutable."""

    def test_enroll_then_approve_logs_one_transition(self):
        reg = _registry()
        ident = _make_mldsa_identity()
        admin_fp = b"\xfa" * 32
        reg.enroll(ident, timestamp=TS)
        reg.approve(ident.fingerprint, admin_fp=admin_fp, timestamp=TS + 1)
        record = reg.lookup(ident.fingerprint)
        assert len(record.transition_log) == 1
        entry = record.transition_log[0]
        assert entry.from_state == WriterState.PENDING
        assert entry.to_state == WriterState.ACTIVE
        assert entry.actor_fp == admin_fp

    def test_sponsor_threshold_logs_transition_with_reason(self):
        reg = _registry(sponsor_threshold=2)
        ident = _make_mldsa_identity()
        reg.enroll(ident, timestamp=TS)
        reg.sponsor(ident.fingerprint, sponsor_fp=b"\xfb" * 32, timestamp=TS + 1)
        s2 = b"\xfc" * 32
        reg.sponsor(ident.fingerprint, sponsor_fp=s2, timestamp=TS + 2)
        record = reg.lookup(ident.fingerprint)
        assert len(record.transition_log) == 1
        entry = record.transition_log[0]
        assert entry.from_state == WriterState.PENDING
        assert entry.to_state == WriterState.PROBATION
        assert "threshold" in entry.reason.lower()

    def test_multi_step_transitions_all_logged(self):
        reg = _registry()
        ident = _make_mldsa_identity()
        admin_fp = b"\xfd" * 32
        reg.enroll(ident, timestamp=TS)
        reg.approve(ident.fingerprint, admin_fp=admin_fp, timestamp=TS + 1)
        reg.suspend(ident.fingerprint, reason="infraction", actor_fp=admin_fp, timestamp=TS + 2)
        reg.reinstate(ident.fingerprint, actor_fp=admin_fp, timestamp=TS + 3)
        record = reg.lookup(ident.fingerprint)
        assert len(record.transition_log) == 3
        states = [(e.from_state, e.to_state) for e in record.transition_log]
        assert states == [
            (WriterState.PENDING,    WriterState.ACTIVE),
            (WriterState.ACTIVE,     WriterState.SUSPENDED),
            (WriterState.SUSPENDED,  WriterState.ACTIVE),
        ]


# ---------------------------------------------------------------------------
# TestActiveWriters
# ---------------------------------------------------------------------------

class TestActiveWriters:
    """active_writers() — returns only ACTIVE and PROBATION writers."""

    def test_returns_empty_list_when_no_writers(self):
        reg = _registry()
        assert reg.active_writers() == []

    def test_pending_writer_not_included(self):
        reg = _registry()
        ident = _make_mldsa_identity()
        reg.enroll(ident, timestamp=TS)
        assert reg.active_writers() == []

    def test_active_writer_is_included(self):
        reg = _registry()
        ident = _make_mldsa_identity()
        admin_fp = b"\x11" * 32
        reg.enroll(ident, timestamp=TS)
        reg.approve(ident.fingerprint, admin_fp=admin_fp, timestamp=TS + 1)
        active = reg.active_writers()
        assert len(active) == 1
        assert active[0].state == WriterState.ACTIVE

    def test_probation_writer_is_included(self):
        reg = _registry(sponsor_threshold=2)
        ident = _make_mldsa_identity()
        reg.enroll(ident, timestamp=TS)
        reg.sponsor(ident.fingerprint, sponsor_fp=b"\x21" * 32, timestamp=TS + 1)
        reg.sponsor(ident.fingerprint, sponsor_fp=b"\x22" * 32, timestamp=TS + 2)
        active = reg.active_writers()
        assert len(active) == 1
        assert active[0].state == WriterState.PROBATION

    def test_suspended_and_revoked_writers_excluded(self):
        reg = _registry()
        ident_a = _make_mldsa_identity()
        ident_b = _make_mldsa_identity()
        admin_fp = b"\x31" * 32
        # Enroll and approve both
        reg.enroll(ident_a, timestamp=TS)
        reg.approve(ident_a.fingerprint, admin_fp=admin_fp, timestamp=TS + 1)
        reg.enroll(ident_b, timestamp=TS)
        reg.approve(ident_b.fingerprint, admin_fp=admin_fp, timestamp=TS + 2)
        # Suspend A, revoke B
        reg.suspend(ident_a.fingerprint, reason="test", actor_fp=admin_fp, timestamp=TS + 3)
        reg.revoke(ident_b.fingerprint, reason="test", actor_fp=admin_fp, timestamp=TS + 4)
        assert reg.active_writers() == []
