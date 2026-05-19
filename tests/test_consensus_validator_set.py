"""Tests for validator set identity mapping (Spec D1b §2)."""

import pytest

from src.ltp.consensus.validator_set import ValidatorInfo, ValidatorSet
from src.ltp.execution.committee.types import (
    CommitteeMember,
    CommitteeRole,
    CommitteeRoster,
)
from src.ltp.execution.writer import IdentityTier


def _make_roster(n: int, epoch: int = 1) -> CommitteeRoster:
    """Build a CommitteeRoster with n active members."""
    members = [
        CommitteeMember(
            writer_fp=f"validator-{i}".encode(),
            bls_pk=bytes([i]) * 48,
            tier=IdentityTier.COMPOSITE,
            joined_epoch=0,
            role=CommitteeRole.ACTIVE,
        )
        for i in range(n)
    ]
    return CommitteeRoster(
        vm_tag=1,
        epoch=epoch,
        active_members=members,
        standby_members=[],
        formed_at=0,
        formation_round=0,
    )


class TestValidatorInfo:
    """ValidatorInfo frozen dataclass tests."""

    def test_creation(self):
        info = ValidatorInfo(
            writer_fp=b"fp1",
            bls_pk=b"\x01" * 48,
            validator_index=0,
        )
        assert info.writer_fp == b"fp1"
        assert info.validator_index == 0

    def test_frozen(self):
        info = ValidatorInfo(writer_fp=b"fp", bls_pk=b"\x00" * 48, validator_index=0)
        with pytest.raises(AttributeError):
            info.validator_index = 1  # type: ignore[misc]


class TestValidatorSet:
    """ValidatorSet identity mapping and eviction tests."""

    def test_from_roster_builds_correct_set(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        assert vs.epoch == 1
        assert vs.size == 4

    def test_index_for_fp_round_trip(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        fp = b"validator-2"
        idx = vs.index_for(fp)
        assert idx == 2
        assert vs.fp_for(idx) == fp

    def test_bls_pk_for_index(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        assert vs.bls_pk_for(0) == bytes([0]) * 48
        assert vs.bls_pk_for(3) == bytes([3]) * 48

    def test_evict_marks_validator(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        fp = b"validator-1"
        assert vs.is_active(fp) is True
        vs.evict(fp)
        assert vs.is_active(fp) is False
        assert vs.is_evicted(fp) is True

    def test_evict_does_not_change_indices(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        vs.evict(b"validator-1")
        assert vs.index_for(b"validator-0") == 0
        assert vs.index_for(b"validator-2") == 2
        assert vs.index_for(b"validator-3") == 3

    def test_evict_does_not_change_quorum(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        q_before = vs.quorum_threshold
        vs.evict(b"validator-1")
        assert vs.quorum_threshold == q_before

    def test_active_count_decrements_on_eviction(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        assert vs.active_count() == 4
        vs.evict(b"validator-0")
        assert vs.active_count() == 3
        vs.evict(b"validator-2")
        assert vs.active_count() == 2

    def test_evicted_indices_tracking(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        vs.evict(b"validator-1")
        vs.evict(b"validator-3")
        assert vs.evicted_indices() == {1, 3}

    def test_double_eviction_is_idempotent(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        vs.evict(b"validator-1")
        vs.evict(b"validator-1")
        assert vs.active_count() == 3
        assert vs.evicted_indices() == {1}

    def test_unknown_writer_fp_raises_key_error(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        with pytest.raises(KeyError):
            vs.index_for(b"unknown-validator")

    def test_from_roster_empty_roster(self):
        roster = CommitteeRoster(
            vm_tag=1,
            epoch=1,
            active_members=[],
            standby_members=[],
            formed_at=0,
            formation_round=0,
        )
        vs = ValidatorSet.from_roster(roster)
        assert vs.size == 0
        assert vs.active_count() == 0
        assert vs.quorum_threshold == 1

    def test_quorum_n4_gives_q3(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        assert vs.quorum_threshold == 3

    def test_quorum_n7_gives_q5(self):
        roster = _make_roster(7)
        vs = ValidatorSet.from_roster(roster)
        assert vs.quorum_threshold == 5

    def test_members_property_returns_copy(self):
        roster = _make_roster(4)
        vs = ValidatorSet.from_roster(roster)
        members = vs.members
        members.clear()
        assert vs.size == 4
