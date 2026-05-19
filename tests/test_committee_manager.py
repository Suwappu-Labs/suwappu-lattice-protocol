"""Tests for CommitteeManager coordinator (Spec C3a §9)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.manager import CommitteeManager
from src.ltp.execution.committee.policy import CommitteePolicy, EpochStrategy, FloorMode
from src.ltp.execution.committee.types import CommitteeEvent
from src.ltp.execution.writer import IdentityTier, WriterIdentity, WriterState
from src.ltp.execution.writer_recovery import EmergencyState
from src.ltp.execution.writer_registry import WriterRegistry

ADMIN_FP = b"\xff" * 32


def _setup(n_writers=3, epoch_length=100, **policy_kwargs):
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

    emergency = EmergencyState()
    policy = CommitteePolicy(vm_tag=0x01, epoch_length=epoch_length, **policy_kwargs)
    mgr = CommitteeManager(vm_tag=0x01, policy=policy, registry=reg, emergency=emergency)
    return mgr, reg, emergency


class TestCommitteeManagerBasic:
    def test_tick_advances_epoch(self):
        mgr, _, _ = _setup(epoch_length=100)
        assert mgr.epoch == 0
        assert mgr.tick(100, 5000) is True
        assert mgr.epoch == 1
        assert mgr.roster is not None

    def test_is_member_after_formation(self):
        mgr, _, _ = _setup(epoch_length=100)
        mgr.tick(100, 5000)
        assert mgr.is_member(bytes([1]) * 32) is True
        assert mgr.is_member(bytes([99]) * 32) is False

    def test_tick_no_advance_before_threshold(self):
        mgr, _, _ = _setup(epoch_length=100)
        assert mgr.tick(50, 3000) is False
        assert mgr.epoch == 0


class TestCommitteeManagerEviction:
    def test_on_writer_state_change_evicts_member(self):
        mgr, reg, _ = _setup(epoch_length=100)
        mgr.tick(100, 5000)
        fp = bytes([1]) * 32
        record = reg.lookup(fp)
        mgr.on_writer_state_change(record, WriterState.ACTIVE, WriterState.REVOKED)
        assert not mgr.is_member(fp)

    def test_on_writer_state_change_ignores_non_member(self):
        mgr, reg, _ = _setup(epoch_length=100)
        mgr.tick(100, 5000)
        fp_new = bytes([99]) * 32
        identity = WriterIdentity(
            tier=IdentityTier.BLS,
            fingerprint=fp_new,
            bls_pk=bytes([99]) * 48,
        )
        reg.enroll(identity, timestamp=9000)
        reg.approve(fp_new, admin_fp=ADMIN_FP, timestamp=9001)
        record = reg.lookup(fp_new)
        mgr.on_writer_state_change(record, WriterState.ACTIVE, WriterState.SUSPENDED)
        assert len(mgr.roster.active_members) == 3


class TestCommitteeManagerHalt:
    def test_is_halted_when_hard_floor_breached(self):
        mgr, reg, _ = _setup(
            n_writers=2,
            epoch_length=100,
            min_committee_size=2,
            floor_mode=FloorMode.HARD,
        )
        mgr.tick(100, 5000)
        assert not mgr.is_halted
        fp = bytes([1]) * 32
        record = reg.lookup(fp)
        mgr.on_writer_state_change(record, WriterState.ACTIVE, WriterState.REVOKED)
        assert mgr.is_halted


class TestCommitteeManagerHistory:
    def test_history_tracks_epochs(self):
        mgr, _, _ = _setup(epoch_length=50)
        mgr.tick(50, 1000)
        mgr.tick(100, 2000)
        mgr.tick(150, 3000)
        history = mgr.history()
        assert len(history) == 3
        assert [h.epoch for h in history] == [1, 2, 3]
