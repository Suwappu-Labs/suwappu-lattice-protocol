"""Tests for EpochManager (Spec C3a §6)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.epoch import EpochManager
from src.ltp.execution.committee.formation import CommitteeFormation
from src.ltp.execution.committee.policy import CommitteePolicy, EpochStrategy
from src.ltp.execution.committee.types import EpochTrigger
from src.ltp.execution.writer import IdentityTier, WriterIdentity
from src.ltp.execution.writer_recovery import EmergencyState
from src.ltp.execution.writer_registry import WriterRegistry

ADMIN_FP = b"\xff" * 32


def _setup(epoch_strategy=EpochStrategy.ROUND_COUNT, epoch_length=100, n_writers=3):
    reg = WriterRegistry()
    for i in range(1, n_writers + 1):
        fp = bytes([i]) * 32
        identity = WriterIdentity(
            tier=IdentityTier.BLS,
            fingerprint=fp,
            bls_pk=bytes([i]) * 48,
        )
        reg.enroll(identity, timestamp=1000 + i)
        reg.approve(fp, admin_fp=ADMIN_FP, timestamp=2000 + i)

    policy = CommitteePolicy(
        vm_tag=0x01,
        epoch_strategy=epoch_strategy,
        epoch_length=epoch_length,
    )
    formation = CommitteeFormation(reg)
    emergency = EmergencyState()
    mgr = EpochManager(0x01, policy, formation, emergency)
    return mgr, reg, emergency


class TestInitialState:
    def test_starts_at_epoch_zero(self):
        mgr, _, _ = _setup()
        assert mgr.current_epoch == 0

    def test_no_roster_before_first_advance(self):
        mgr, _, _ = _setup()
        assert mgr.roster is None

    def test_empty_history(self):
        mgr, _, _ = _setup()
        assert mgr.history == []


class TestRoundCountStrategy:
    def test_no_advance_before_threshold(self):
        mgr, _, _ = _setup(epoch_length=100)
        assert mgr.check_advance(current_round=50, timestamp_ms=5000) is False

    def test_advances_at_threshold(self):
        mgr, _, _ = _setup(epoch_length=100)
        assert mgr.check_advance(current_round=100, timestamp_ms=5000) is True
        assert mgr.current_epoch == 1
        assert mgr.roster is not None
        assert len(mgr.roster.active_members) == 3

    def test_second_epoch_requires_another_epoch_length(self):
        mgr, _, _ = _setup(epoch_length=100)
        mgr.check_advance(current_round=100, timestamp_ms=5000)
        assert mgr.check_advance(current_round=150, timestamp_ms=6000) is False
        assert mgr.check_advance(current_round=200, timestamp_ms=7000) is True
        assert mgr.current_epoch == 2

    def test_history_grows_on_advance(self):
        mgr, _, _ = _setup(epoch_length=100)
        mgr.check_advance(current_round=100, timestamp_ms=5000)
        mgr.check_advance(current_round=200, timestamp_ms=6000)
        assert len(mgr.history) == 2
        assert mgr.history[0].trigger is EpochTrigger.ROUND_COUNT
        assert mgr.history[0].epoch == 1
        assert mgr.history[1].epoch == 2


class TestTimeBasedStrategy:
    def test_advances_at_duration(self):
        mgr, _, _ = _setup(epoch_strategy=EpochStrategy.TIME_BASED, epoch_length=100)
        mgr._policy.epoch_duration_ms = 60_000
        mgr.check_advance(current_round=0, timestamp_ms=0)
        assert mgr.check_advance(current_round=10, timestamp_ms=30_000) is False
        assert mgr.check_advance(current_round=20, timestamp_ms=60_000) is True
        assert mgr.current_epoch == 2
        assert mgr.history[-1].trigger is EpochTrigger.TIME_BASED


class TestManualStrategy:
    def test_check_advance_never_auto_advances(self):
        mgr, _, _ = _setup(epoch_strategy=EpochStrategy.MANUAL, epoch_length=1)
        assert mgr.check_advance(current_round=9999, timestamp_ms=9999) is False
        assert mgr.current_epoch == 0


class TestAdminAdvance:
    def test_admin_advance_works_regardless_of_strategy(self):
        mgr, _, _ = _setup(epoch_strategy=EpochStrategy.MANUAL)
        roster = mgr.admin_advance(actor_fp=ADMIN_FP, timestamp=5000)
        assert mgr.current_epoch == 1
        assert roster is not None
        assert len(mgr.history) == 1
        assert mgr.history[0].trigger is EpochTrigger.ADMIN_SIGNAL


class TestEmergencyAdvance:
    def test_emergency_advance_logs_trigger(self):
        mgr, _, emergency = _setup()
        roster = mgr.emergency_advance(
            actor_fp=ADMIN_FP,
            reason="compromised member",
            timestamp=9000,
        )
        assert mgr.current_epoch == 1
        assert mgr.history[0].trigger is EpochTrigger.EMERGENCY
