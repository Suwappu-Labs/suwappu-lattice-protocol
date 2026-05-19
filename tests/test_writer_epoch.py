"""Tests for epoch-driven writer operations (Spec C2 §9.4).

Covers EpochTracker (per-writer/VM tx counting and epoch rollover),
check_expirations (ACTIVE → EXPIRED batch scan), and
promote_due_probations (PROBATION → ACTIVE on epoch threshold).
"""

import pytest

from src.ltp.execution.writer import IdentityTier, WriterIdentity, WriterState
from src.ltp.execution.writer_config import RegistryConfig
from src.ltp.execution.writer_epoch import (
    EpochTracker,
    check_expirations,
    promote_due_probations,
)
from src.ltp.execution.writer_registry import WriterRegistry

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

_FP = b"\xaa" * 32
_MLDSA_VK = b"\x01" * 32
_ADMIN_FP = b"\xbb" * 32

TS = 1_000_000  # base timestamp (milliseconds)


def _make_identity(fp: bytes = _FP, vk: bytes = _MLDSA_VK) -> WriterIdentity:
    """Fabricate a minimal ML-DSA WriterIdentity."""
    return WriterIdentity(
        tier=IdentityTier.MLDSA,
        fingerprint=fp,
        mldsa_vk=vk,
    )


def _make_active_registry(
    fp: bytes = _FP,
    vk: bytes = _MLDSA_VK,
    sponsor_threshold: int = 2,
    probation_epochs: int = 10,
) -> tuple[WriterRegistry, WriterIdentity]:
    """Return a registry with one ACTIVE writer enrolled and approved."""
    config = RegistryConfig(
        sponsor_threshold=sponsor_threshold,
        probation_epochs=probation_epochs,
    )
    reg = WriterRegistry(config=config)
    ident = _make_identity(fp=fp, vk=vk)
    reg.enroll(ident, timestamp=TS)
    reg.approve(ident.fingerprint, admin_fp=_ADMIN_FP, timestamp=TS + 1)
    return reg, ident


def _make_probation_registry(
    fp: bytes = _FP,
    vk: bytes = _MLDSA_VK,
    sponsor_threshold: int = 2,
    probation_epochs: int = 10,
) -> tuple[WriterRegistry, WriterIdentity]:
    """Return a registry with one PROBATION writer (sponsor threshold met)."""
    config = RegistryConfig(
        sponsor_threshold=sponsor_threshold,
        probation_epochs=probation_epochs,
    )
    reg = WriterRegistry(config=config)
    ident = _make_identity(fp=fp, vk=vk)
    reg.enroll(ident, timestamp=TS)
    # Create two ACTIVE sponsors first
    s1 = _make_identity(fp=b"\xc1" * 32, vk=b"\xd1" * 32)
    reg.enroll(s1, timestamp=TS - 100)
    reg.approve(s1.fingerprint, admin_fp=_ADMIN_FP, timestamp=TS - 99)
    s2 = _make_identity(fp=b"\xc2" * 32, vk=b"\xd2" * 32)
    reg.enroll(s2, timestamp=TS - 100)
    reg.approve(s2.fingerprint, admin_fp=_ADMIN_FP, timestamp=TS - 99)
    reg.sponsor(ident.fingerprint, sponsor_fp=s1.fingerprint, timestamp=TS + 1)
    reg.sponsor(ident.fingerprint, sponsor_fp=s2.fingerprint, timestamp=TS + 2)
    return reg, ident


# ---------------------------------------------------------------------------
# TestEpochTracker
# ---------------------------------------------------------------------------


class TestEpochTracker:
    """EpochTracker — per-(writer, VM) tx counts with epoch rollover."""

    def test_initial_count_is_zero(self):
        tracker = EpochTracker()
        assert tracker.get_tx_count(_FP, vm_tag=1) == 0

    def test_increment_increases_count(self):
        tracker = EpochTracker()
        tracker.increment(_FP, vm_tag=1, epoch=0)
        tracker.increment(_FP, vm_tag=1, epoch=0)
        assert tracker.get_tx_count(_FP, vm_tag=1) == 2

    def test_epoch_rollover_resets_counts(self):
        tracker = EpochTracker()
        tracker.increment(_FP, vm_tag=1, epoch=0)
        tracker.increment(_FP, vm_tag=1, epoch=0)
        assert tracker.get_tx_count(_FP, vm_tag=1) == 2
        # Advance to a new epoch — counts must reset
        tracker.increment(_FP, vm_tag=1, epoch=1)
        assert tracker.get_tx_count(_FP, vm_tag=1) == 1

    def test_separate_vm_tags_tracked_independently(self):
        tracker = EpochTracker()
        tracker.increment(_FP, vm_tag=1, epoch=0)
        tracker.increment(_FP, vm_tag=1, epoch=0)
        tracker.increment(_FP, vm_tag=2, epoch=0)
        assert tracker.get_tx_count(_FP, vm_tag=1) == 2
        assert tracker.get_tx_count(_FP, vm_tag=2) == 1

    def test_separate_writer_fingerprints_tracked_independently(self):
        tracker = EpochTracker()
        fp_a = b"\xaa" * 32
        fp_b = b"\xbb" * 32
        tracker.increment(fp_a, vm_tag=1, epoch=0)
        tracker.increment(fp_a, vm_tag=1, epoch=0)
        tracker.increment(fp_a, vm_tag=1, epoch=0)
        tracker.increment(fp_b, vm_tag=1, epoch=0)
        assert tracker.get_tx_count(fp_a, vm_tag=1) == 3
        assert tracker.get_tx_count(fp_b, vm_tag=1) == 1


# ---------------------------------------------------------------------------
# TestExpirationChecker
# ---------------------------------------------------------------------------


class TestExpirationChecker:
    """check_expirations — batch ACTIVE → EXPIRED on epoch threshold."""

    def test_expires_active_writer_when_epoch_due(self):
        reg, ident = _make_active_registry()
        record = reg.lookup(ident.fingerprint)
        # Set expires_at in the past
        record.expires_at = 50
        expired = check_expirations(reg, current_epoch=50)
        assert ident.fingerprint in expired
        assert record.state == WriterState.EXPIRED

    def test_no_expiration_when_epoch_not_yet_due(self):
        reg, ident = _make_active_registry()
        record = reg.lookup(ident.fingerprint)
        # expires_at is in the future
        record.expires_at = 100
        expired = check_expirations(reg, current_epoch=50)
        assert expired == []
        assert record.state == WriterState.ACTIVE


# ---------------------------------------------------------------------------
# TestProbationPromoter
# ---------------------------------------------------------------------------


class TestProbationPromoter:
    """promote_due_probations — batch PROBATION → ACTIVE on epoch threshold."""

    def test_promotes_probation_writer_when_epoch_due(self):
        reg, ident = _make_probation_registry(probation_epochs=10)
        record = reg.lookup(ident.fingerprint)
        # probation_until is set by sponsor() as timestamp + probation_epochs
        # = (TS + 2) + 10 = TS + 12
        assert record.state == WriterState.PROBATION
        assert record.probation_until is not None
        promoted = promote_due_probations(
            reg, current_epoch=record.probation_until, timestamp=TS + 100
        )
        assert ident.fingerprint in promoted
        assert record.state == WriterState.ACTIVE

    def test_no_promotion_before_probation_due(self):
        reg, ident = _make_probation_registry(probation_epochs=10)
        record = reg.lookup(ident.fingerprint)
        assert record.state == WriterState.PROBATION
        assert record.probation_until is not None
        # Epoch is one before threshold
        promoted = promote_due_probations(
            reg, current_epoch=record.probation_until - 1, timestamp=TS + 100
        )
        assert promoted == []
        assert record.state == WriterState.PROBATION
