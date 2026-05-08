"""Tests for committee core types (Spec C3a §3)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.types import (
    CommitteeRole,
    CommitteeMember,
    CommitteeRoster,
    EpochTrigger,
    EpochRecord,
    EvictionReason,
    EvictionEvent,
    CommitteeEvent,
)
from src.ltp.execution.writer import IdentityTier


class TestCommitteeRole:
    def test_two_roles_exist(self):
        assert len(CommitteeRole) == 2

    def test_active_value(self):
        assert CommitteeRole.ACTIVE.value == "active"

    def test_standby_value(self):
        assert CommitteeRole.STANDBY.value == "standby"


class TestCommitteeMember:
    def test_construction(self):
        m = CommitteeMember(
            writer_fp=b"\xaa" * 32,
            bls_pk=b"\xbb" * 48,
            tier=IdentityTier.COMPOSITE,
            joined_epoch=5,
            role=CommitteeRole.ACTIVE,
        )
        assert m.writer_fp == b"\xaa" * 32
        assert m.bls_pk == b"\xbb" * 48
        assert m.tier is IdentityTier.COMPOSITE
        assert m.joined_epoch == 5
        assert m.role is CommitteeRole.ACTIVE

    def test_is_frozen(self):
        m = CommitteeMember(
            writer_fp=b"\xaa" * 32,
            bls_pk=b"\xbb" * 48,
            tier=IdentityTier.BLS,
            joined_epoch=0,
            role=CommitteeRole.STANDBY,
        )
        with pytest.raises(Exception):
            m.writer_fp = b"\x00" * 32


class TestCommitteeRoster:
    def test_construction(self):
        m1 = CommitteeMember(
            writer_fp=b"\x01" * 32, bls_pk=b"\x01" * 48,
            tier=IdentityTier.BLS, joined_epoch=1, role=CommitteeRole.ACTIVE,
        )
        m2 = CommitteeMember(
            writer_fp=b"\x02" * 32, bls_pk=b"\x02" * 48,
            tier=IdentityTier.MLDSA, joined_epoch=1, role=CommitteeRole.STANDBY,
        )
        roster = CommitteeRoster(
            vm_tag=0x01, epoch=1,
            active_members=[m1], standby_members=[m2],
            formed_at=1000, formation_round=100,
        )
        assert roster.vm_tag == 0x01
        assert len(roster.active_members) == 1
        assert len(roster.standby_members) == 1

    def test_is_mutable(self):
        roster = CommitteeRoster(
            vm_tag=0x01, epoch=1,
            active_members=[], standby_members=[],
            formed_at=1000, formation_round=100,
        )
        m = CommitteeMember(
            writer_fp=b"\x01" * 32, bls_pk=b"\x01" * 48,
            tier=IdentityTier.BLS, joined_epoch=1, role=CommitteeRole.ACTIVE,
        )
        roster.active_members.append(m)
        assert len(roster.active_members) == 1


class TestEpochTrigger:
    def test_four_triggers_exist(self):
        assert len(EpochTrigger) == 4

    def test_values(self):
        assert EpochTrigger.ROUND_COUNT.value == "round_count"
        assert EpochTrigger.ADMIN_SIGNAL.value == "admin_signal"
        assert EpochTrigger.EMERGENCY.value == "emergency"
        assert EpochTrigger.TIME_BASED.value == "time_based"


class TestEpochRecord:
    def test_construction_and_frozen(self):
        roster = CommitteeRoster(
            vm_tag=0x01, epoch=3,
            active_members=[], standby_members=[],
            formed_at=5000, formation_round=500,
        )
        record = EpochRecord(
            vm_tag=0x01, epoch=3, roster=roster,
            trigger=EpochTrigger.ROUND_COUNT,
            previous_epoch=2, timestamp=5000,
        )
        assert record.epoch == 3
        assert record.trigger is EpochTrigger.ROUND_COUNT
        assert record.previous_epoch == 2
        with pytest.raises(Exception):
            record.epoch = 99


class TestEvictionReason:
    def test_four_reasons_exist(self):
        assert len(EvictionReason) == 4

    def test_values(self):
        assert EvictionReason.REVOKED.value == "revoked"
        assert EvictionReason.SUSPENDED.value == "suspended"
        assert EvictionReason.EXPIRED.value == "expired"
        assert EvictionReason.ADMIN.value == "admin"


class TestEvictionEvent:
    def test_construction_with_backfill(self):
        ev = EvictionEvent(
            writer_fp=b"\xaa" * 32, vm_tag=0x01, epoch=5,
            reason=EvictionReason.SUSPENDED,
            backfill_fp=b"\xbb" * 32, timestamp=9000,
        )
        assert ev.backfill_fp == b"\xbb" * 32

    def test_construction_no_backfill(self):
        ev = EvictionEvent(
            writer_fp=b"\xaa" * 32, vm_tag=0x01, epoch=5,
            reason=EvictionReason.REVOKED,
            backfill_fp=None, timestamp=9000,
        )
        assert ev.backfill_fp is None

    def test_is_frozen(self):
        ev = EvictionEvent(
            writer_fp=b"\xaa" * 32, vm_tag=0x01, epoch=5,
            reason=EvictionReason.REVOKED,
            backfill_fp=None, timestamp=9000,
        )
        with pytest.raises(Exception):
            ev.reason = EvictionReason.ADMIN


class TestCommitteeEvent:
    def test_five_events_exist(self):
        assert len(CommitteeEvent) == 5

    def test_values(self):
        assert CommitteeEvent.MEMBER_EVICTED.value == "member_evicted"
        assert CommitteeEvent.MEMBER_BACKFILLED.value == "member_backfilled"
        assert CommitteeEvent.COMMITTEE_HALTED.value == "committee_halted"
        assert CommitteeEvent.BELOW_FLOOR.value == "below_floor"
        assert CommitteeEvent.FLOOR_RESTORED.value == "floor_restored"
