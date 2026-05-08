"""Tests for StandbySelector (Spec C3a §8)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.standby import StandbySelector, score_member
from src.ltp.execution.committee.types import (
    CommitteeMember,
    CommitteeRole,
    CommitteeRoster,
)
from src.ltp.execution.committee.policy import (
    CommitteePolicy,
    StandbyStrategy,
)
from src.ltp.execution.writer import IdentityTier


def _member(fp_byte: int, tier: IdentityTier = IdentityTier.BLS,
            joined_epoch: int = 0, role: CommitteeRole = CommitteeRole.STANDBY) -> CommitteeMember:
    return CommitteeMember(
        writer_fp=bytes([fp_byte]) * 32,
        bls_pk=bytes([fp_byte]) * 48,
        tier=tier,
        joined_epoch=joined_epoch,
        role=role,
    )


def _roster(active: list[CommitteeMember], standby: list[CommitteeMember]) -> CommitteeRoster:
    return CommitteeRoster(
        vm_tag=0x01, epoch=1,
        active_members=list(active), standby_members=list(standby),
        formed_at=1000, formation_round=100,
    )


class TestScoreMember:
    def test_composite_ranks_highest(self):
        c = _member(1, IdentityTier.COMPOSITE, joined_epoch=5)
        b = _member(2, IdentityTier.BLS, joined_epoch=5)
        m = _member(3, IdentityTier.MLDSA, joined_epoch=5)
        assert score_member(c) > score_member(b) > score_member(m)

    def test_earlier_enrollment_wins_tiebreak(self):
        a = _member(1, IdentityTier.BLS, joined_epoch=1)
        b = _member(2, IdentityTier.BLS, joined_epoch=5)
        assert score_member(a) > score_member(b)


class TestStandbyPriorityQueue:
    def test_picks_highest_scored_standby(self):
        policy = CommitteePolicy(vm_tag=0x01, standby_strategy=StandbyStrategy.PRIORITY_QUEUE)
        sel = StandbySelector(policy)
        s1 = _member(1, IdentityTier.MLDSA)
        s2 = _member(2, IdentityTier.COMPOSITE)
        roster = _roster(active=[], standby=[s1, s2])
        picked = sel.next(roster)
        assert picked is not None
        assert picked.tier is IdentityTier.COMPOSITE

    def test_returns_none_when_empty(self):
        policy = CommitteePolicy(vm_tag=0x01, standby_strategy=StandbyStrategy.PRIORITY_QUEUE)
        sel = StandbySelector(policy)
        roster = _roster(active=[], standby=[])
        assert sel.next(roster) is None


class TestStandbyFIFO:
    def test_picks_first_in_list(self):
        policy = CommitteePolicy(vm_tag=0x01, standby_strategy=StandbyStrategy.FIFO)
        sel = StandbySelector(policy)
        s1 = _member(1, IdentityTier.MLDSA)
        s2 = _member(2, IdentityTier.COMPOSITE)
        roster = _roster(active=[], standby=[s1, s2])
        picked = sel.next(roster)
        assert picked is not None
        assert picked.writer_fp == bytes([1]) * 32


class TestStandbyAdminDesignated:
    def test_picks_first_admin_listed_standby(self):
        fp_a = bytes([0x0A]) * 32
        fp_b = bytes([0x0B]) * 32
        policy = CommitteePolicy(
            vm_tag=0x01,
            standby_strategy=StandbyStrategy.ADMIN_DESIGNATED,
            admin_standby_list=[fp_b, fp_a],
        )
        sel = StandbySelector(policy)
        s_a = _member(0x0A, IdentityTier.BLS)
        s_b = _member(0x0B, IdentityTier.BLS)
        roster = _roster(active=[], standby=[s_a, s_b])
        picked = sel.next(roster)
        assert picked is not None
        assert picked.writer_fp == fp_b

    def test_skips_admin_listed_not_on_standby(self):
        fp_gone = bytes([0xFF]) * 32
        fp_present = bytes([0x01]) * 32
        policy = CommitteePolicy(
            vm_tag=0x01,
            standby_strategy=StandbyStrategy.ADMIN_DESIGNATED,
            admin_standby_list=[fp_gone, fp_present],
        )
        sel = StandbySelector(policy)
        s = _member(0x01, IdentityTier.BLS)
        roster = _roster(active=[], standby=[s])
        picked = sel.next(roster)
        assert picked is not None
        assert picked.writer_fp == fp_present

    def test_returns_none_when_no_admin_match(self):
        policy = CommitteePolicy(
            vm_tag=0x01,
            standby_strategy=StandbyStrategy.ADMIN_DESIGNATED,
            admin_standby_list=[bytes([0xFF]) * 32],
        )
        sel = StandbySelector(policy)
        s = _member(0x01, IdentityTier.BLS)
        roster = _roster(active=[], standby=[s])
        assert sel.next(roster) is None


class TestRank:
    def test_rank_orders_by_score_descending(self):
        policy = CommitteePolicy(vm_tag=0x01, standby_strategy=StandbyStrategy.PRIORITY_QUEUE)
        sel = StandbySelector(policy)
        members = [
            _member(1, IdentityTier.MLDSA, joined_epoch=5),
            _member(2, IdentityTier.COMPOSITE, joined_epoch=5),
            _member(3, IdentityTier.BLS, joined_epoch=1),
        ]
        ranked = sel.rank(members)
        assert ranked[0].tier is IdentityTier.COMPOSITE
        assert ranked[1].tier is IdentityTier.BLS
        assert ranked[2].tier is IdentityTier.MLDSA
