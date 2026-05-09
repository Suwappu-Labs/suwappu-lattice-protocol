"""Tests for EvictionHandler (Spec C3a §7)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.eviction import EvictionHandler
from src.ltp.execution.committee.standby import StandbySelector
from src.ltp.execution.committee.types import (
    CommitteeMember,
    CommitteeRole,
    CommitteeRoster,
    CommitteeEvent,
    EvictionReason,
)
from src.ltp.execution.committee.policy import (
    CommitteePolicy,
    EvictionMode,
    FloorMode,
)
from src.ltp.execution.writer import IdentityTier, WriterState


def _member(fp_byte: int, role: CommitteeRole = CommitteeRole.ACTIVE) -> CommitteeMember:
    return CommitteeMember(
        writer_fp=bytes([fp_byte]) * 32,
        bls_pk=bytes([fp_byte]) * 48,
        tier=IdentityTier.BLS,
        joined_epoch=0,
        role=role,
    )


def _roster_with(active_bytes: list[int], standby_bytes: list[int]) -> CommitteeRoster:
    return CommitteeRoster(
        vm_tag=0x01, epoch=1,
        active_members=[_member(b, CommitteeRole.ACTIVE) for b in active_bytes],
        standby_members=[_member(b, CommitteeRole.STANDBY) for b in standby_bytes],
        formed_at=1000, formation_round=100,
    )


TS = 5000


class TestSecurityEviction:
    def test_revoked_writer_evicted_immediately(self):
        policy = CommitteePolicy(vm_tag=0x01)
        sel = StandbySelector(policy)
        handler = EvictionHandler(policy, sel)
        roster = _roster_with([1, 2, 3], [4])
        fp = bytes([1]) * 32
        ev = handler.handle_state_change(roster, fp, WriterState.ACTIVE, WriterState.REVOKED, TS)
        assert ev is not None
        assert ev.reason is EvictionReason.REVOKED
        assert ev.backfill_fp is None
        assert len(roster.active_members) == 2

    def test_revoked_non_member_ignored(self):
        policy = CommitteePolicy(vm_tag=0x01)
        sel = StandbySelector(policy)
        handler = EvictionHandler(policy, sel)
        roster = _roster_with([1, 2], [])
        fp = bytes([99]) * 32
        ev = handler.handle_state_change(roster, fp, WriterState.ACTIVE, WriterState.REVOKED, TS)
        assert ev is None


class TestOperationalEviction:
    def test_suspended_writer_evicted_with_backfill(self):
        policy = CommitteePolicy(vm_tag=0x01)
        sel = StandbySelector(policy)
        handler = EvictionHandler(policy, sel)
        roster = _roster_with([1, 2], [3])
        fp = bytes([1]) * 32
        ev = handler.handle_state_change(roster, fp, WriterState.ACTIVE, WriterState.SUSPENDED, TS)
        assert ev is not None
        assert ev.reason is EvictionReason.SUSPENDED
        assert ev.backfill_fp == bytes([3]) * 32
        assert len(roster.active_members) == 2
        assert len(roster.standby_members) == 0

    def test_expired_writer_evicted_with_backfill(self):
        policy = CommitteePolicy(vm_tag=0x01)
        sel = StandbySelector(policy)
        handler = EvictionHandler(policy, sel)
        roster = _roster_with([1, 2], [3])
        fp = bytes([2]) * 32
        ev = handler.handle_state_change(roster, fp, WriterState.ACTIVE, WriterState.EXPIRED, TS)
        assert ev is not None
        assert ev.reason is EvictionReason.EXPIRED
        assert ev.backfill_fp is not None

    def test_no_backfill_when_standby_empty(self):
        policy = CommitteePolicy(vm_tag=0x01)
        sel = StandbySelector(policy)
        handler = EvictionHandler(policy, sel)
        roster = _roster_with([1, 2], [])
        fp = bytes([1]) * 32
        ev = handler.handle_state_change(roster, fp, WriterState.ACTIVE, WriterState.SUSPENDED, TS)
        assert ev is not None
        assert ev.backfill_fp is None
        assert len(roster.active_members) == 1


class TestEpochBoundaryEviction:
    def test_epoch_boundary_does_not_modify_roster(self):
        policy = CommitteePolicy(
            vm_tag=0x01,
            security_eviction=EvictionMode.EPOCH_BOUNDARY,
        )
        sel = StandbySelector(policy)
        handler = EvictionHandler(policy, sel)
        roster = _roster_with([1, 2], [3])
        fp = bytes([1]) * 32
        ev = handler.handle_state_change(roster, fp, WriterState.ACTIVE, WriterState.REVOKED, TS)
        assert ev is None
        assert len(roster.active_members) == 2
        assert len(handler.pending_evictions) == 1


class TestFloorCheck:
    def test_soft_floor_emits_below_floor_event(self):
        policy = CommitteePolicy(vm_tag=0x01, min_committee_size=3, floor_mode=FloorMode.SOFT)
        sel = StandbySelector(policy)
        handler = EvictionHandler(policy, sel)
        roster = _roster_with([1, 2, 3], [])
        fp = bytes([1]) * 32
        handler.handle_state_change(roster, fp, WriterState.ACTIVE, WriterState.REVOKED, TS)
        assert CommitteeEvent.BELOW_FLOOR in handler.emitted_events

    def test_hard_floor_emits_halted_event(self):
        policy = CommitteePolicy(vm_tag=0x01, min_committee_size=3, floor_mode=FloorMode.HARD)
        sel = StandbySelector(policy)
        handler = EvictionHandler(policy, sel)
        roster = _roster_with([1, 2, 3], [])
        fp = bytes([1]) * 32
        handler.handle_state_change(roster, fp, WriterState.ACTIVE, WriterState.REVOKED, TS)
        assert CommitteeEvent.COMMITTEE_HALTED in handler.emitted_events
        assert handler.is_halted is True

    def test_floor_restored_when_backfill_brings_above_min(self):
        policy = CommitteePolicy(vm_tag=0x01, min_committee_size=2, floor_mode=FloorMode.SOFT)
        sel = StandbySelector(policy)
        handler = EvictionHandler(policy, sel)
        roster = _roster_with([1, 2], [3])
        fp = bytes([1]) * 32
        handler.handle_state_change(roster, fp, WriterState.ACTIVE, WriterState.SUSPENDED, TS)
        assert CommitteeEvent.BELOW_FLOOR not in handler.emitted_events
