"""End-to-end integration tests for committee layer (Spec C3a)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.manager import CommitteeManager
from src.ltp.execution.committee.policy import (
    CommitteePolicy,
    EpochStrategy,
    EvictionMode,
    FloorMode,
    StandbyStrategy,
)
from src.ltp.execution.committee.types import EpochTrigger, EvictionReason
from src.ltp.execution.writer import IdentityTier, WriterIdentity, WriterState
from src.ltp.execution.writer_recovery import EmergencyState
from src.ltp.execution.writer_registry import WriterRegistry

ADMIN_FP = b"\xff" * 32


def _enroll_active(reg, fp_byte, tier=IdentityTier.BLS):
    fp = bytes([fp_byte]) * 32
    bls_pk = bytes([fp_byte]) * 48 if tier in (IdentityTier.BLS, IdentityTier.COMPOSITE) else None
    mldsa_vk = (
        bytes([fp_byte]) * 32 if tier in (IdentityTier.MLDSA, IdentityTier.COMPOSITE) else None
    )
    identity = WriterIdentity(tier=tier, fingerprint=fp, mldsa_vk=mldsa_vk, bls_pk=bls_pk)
    reg.enroll(identity, timestamp=1000 + fp_byte)
    reg.approve(fp, admin_fp=ADMIN_FP, timestamp=2000 + fp_byte)


class TestFullLifecycle:
    """Epoch rotation → eviction → backfill → epoch rotation."""

    def test_full_lifecycle(self):
        reg = WriterRegistry()
        for i in range(1, 6):
            _enroll_active(reg, i, IdentityTier.BLS)
        emergency = EmergencyState()
        policy = CommitteePolicy(
            vm_tag=0x01,
            epoch_length=50,
            max_committee_size=3,
            min_committee_size=2,
            floor_mode=FloorMode.SOFT,
        )
        mgr = CommitteeManager(0x01, policy, reg, emergency)

        # Epoch 1: 3 active, 2 standby
        assert mgr.tick(50, 1000) is True
        assert mgr.epoch == 1
        assert len(mgr.roster.active_members) == 3
        assert len(mgr.roster.standby_members) == 2

        # Suspend an active member — backfill from standby
        active_fp = mgr.roster.active_members[0].writer_fp
        record = reg.lookup(active_fp)
        reg.suspend(active_fp, reason="test", actor_fp=ADMIN_FP, timestamp=2000)
        mgr.on_writer_state_change(record, WriterState.ACTIVE, WriterState.SUSPENDED)
        assert len(mgr.roster.active_members) == 3  # backfilled
        assert len(mgr.roster.standby_members) == 1
        assert not mgr.is_member(active_fp)

        # Epoch 2: roster rebuilt from current registry state
        assert mgr.tick(100, 3000) is True
        assert mgr.epoch == 2
        assert not mgr.is_member(active_fp)

        # History has 2 records
        history = mgr.history()
        assert len(history) == 2


class TestMultiTierCommittee:
    """Committee with mixed tiers, COMPOSITE gets priority."""

    def test_composite_prioritized_over_bls(self):
        reg = WriterRegistry()
        _enroll_active(reg, 1, IdentityTier.BLS)
        _enroll_active(reg, 2, IdentityTier.BLS)
        _enroll_active(reg, 3, IdentityTier.COMPOSITE)
        _enroll_active(reg, 4, IdentityTier.COMPOSITE)
        emergency = EmergencyState()
        policy = CommitteePolicy(vm_tag=0x01, epoch_length=10, max_committee_size=2)
        mgr = CommitteeManager(0x01, policy, reg, emergency)
        mgr.tick(10, 1000)
        tiers = {m.tier for m in mgr.roster.active_members}
        assert tiers == {IdentityTier.COMPOSITE}


class TestEmergencyEpochAdvance:
    """Emergency advance forces committee rotation."""

    def test_emergency_advance_rotates_committee(self):
        reg = WriterRegistry()
        for i in range(1, 4):
            _enroll_active(reg, i)
        emergency = EmergencyState()
        policy = CommitteePolicy(vm_tag=0x01, epoch_strategy=EpochStrategy.MANUAL)
        mgr = CommitteeManager(0x01, policy, reg, emergency)

        assert mgr.tick(9999, 9999) is False
        assert mgr.epoch == 0

        mgr._epoch_mgr.emergency_advance(ADMIN_FP, "breach detected", 5000)
        assert mgr.epoch == 1
        assert mgr.roster is not None
        history = mgr.history()
        assert history[0].trigger is EpochTrigger.EMERGENCY


class TestHardFloorWithRecovery:
    """Hard floor halts, admin advance restores."""

    def test_hard_floor_halt_and_admin_recovery(self):
        reg = WriterRegistry()
        _enroll_active(reg, 1)
        _enroll_active(reg, 2)
        emergency = EmergencyState()
        policy = CommitteePolicy(
            vm_tag=0x01,
            epoch_length=10,
            min_committee_size=2,
            floor_mode=FloorMode.HARD,
        )
        mgr = CommitteeManager(0x01, policy, reg, emergency)
        mgr.tick(10, 1000)
        assert len(mgr.roster.active_members) == 2

        fp = bytes([1]) * 32
        record = reg.lookup(fp)
        reg.revoke(fp, reason="test", actor_fp=ADMIN_FP, timestamp=3000)
        mgr.on_writer_state_change(record, WriterState.ACTIVE, WriterState.REVOKED)
        assert mgr.is_halted

        _enroll_active(reg, 10)
        mgr._epoch_mgr.admin_advance(ADMIN_FP, timestamp=4000)
        assert mgr.epoch == 2
        assert len(mgr.roster.active_members) == 2
