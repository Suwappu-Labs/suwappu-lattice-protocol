"""Hypothesis property-based tests for committee layer (Spec C3a)."""

from __future__ import annotations

from hypothesis import given, assume, settings
from hypothesis import strategies as st

from src.ltp.execution.committee.types import CommitteeMember, CommitteeRole, CommitteeRoster
from src.ltp.execution.committee.standby import StandbySelector, score_member
from src.ltp.execution.committee.formation import CommitteeFormation
from src.ltp.execution.committee.policy import CommitteePolicy, StandbyStrategy
from src.ltp.execution.writer import IdentityTier, WriterIdentity
from src.ltp.execution.writer_registry import WriterRegistry

ADMIN_FP = b"\xff" * 32

tiers = st.sampled_from(list(IdentityTier))
epochs = st.integers(min_value=0, max_value=1000)


class TestScoringProperties:
    @given(tier=tiers, epoch=epochs)
    def test_score_returns_consistent_tuple(self, tier, epoch):
        m = CommitteeMember(
            writer_fp=b"\x01" * 32, bls_pk=b"\x01" * 48,
            tier=tier, joined_epoch=epoch, role=CommitteeRole.ACTIVE,
        )
        s = score_member(m)
        assert isinstance(s, tuple)
        assert len(s) == 2

    @given(e1=epochs, e2=epochs)
    def test_same_tier_earlier_epoch_wins(self, e1, e2):
        assume(e1 != e2)
        m1 = CommitteeMember(
            writer_fp=b"\x01" * 32, bls_pk=b"\x01" * 48,
            tier=IdentityTier.BLS, joined_epoch=e1, role=CommitteeRole.ACTIVE,
        )
        m2 = CommitteeMember(
            writer_fp=b"\x02" * 32, bls_pk=b"\x02" * 48,
            tier=IdentityTier.BLS, joined_epoch=e2, role=CommitteeRole.ACTIVE,
        )
        if e1 < e2:
            assert score_member(m1) > score_member(m2)
        else:
            assert score_member(m2) > score_member(m1)

    def test_tier_ordering_is_composite_bls_mldsa(self):
        c = CommitteeMember(writer_fp=b"\x01"*32, bls_pk=b"\x01"*48,
                            tier=IdentityTier.COMPOSITE, joined_epoch=0, role=CommitteeRole.ACTIVE)
        b = CommitteeMember(writer_fp=b"\x02"*32, bls_pk=b"\x02"*48,
                            tier=IdentityTier.BLS, joined_epoch=0, role=CommitteeRole.ACTIVE)
        m = CommitteeMember(writer_fp=b"\x03"*32, bls_pk=b"\x03"*48,
                            tier=IdentityTier.MLDSA, joined_epoch=0, role=CommitteeRole.ACTIVE)
        assert score_member(c) > score_member(b) > score_member(m)


class TestFormationProperties:
    @given(n=st.integers(min_value=1, max_value=10),
           cap=st.integers(min_value=1, max_value=10))
    def test_active_never_exceeds_cap(self, n, cap):
        reg = WriterRegistry()
        for i in range(1, n + 1):
            fp = bytes([i]) * 32
            identity = WriterIdentity(
                tier=IdentityTier.BLS, fingerprint=fp, bls_pk=bytes([i]) * 48,
            )
            reg.enroll(identity, timestamp=1000 + i)
            reg.approve(fp, admin_fp=ADMIN_FP, timestamp=2000 + i)
        policy = CommitteePolicy(vm_tag=0x01, max_committee_size=cap)
        formation = CommitteeFormation(reg)
        roster = formation.build_roster(policy, epoch=1, round_num=0, timestamp=0)
        assert len(roster.active_members) <= cap

    @given(n=st.integers(min_value=1, max_value=10))
    def test_all_members_are_unique(self, n):
        reg = WriterRegistry()
        for i in range(1, n + 1):
            fp = bytes([i]) * 32
            identity = WriterIdentity(
                tier=IdentityTier.BLS, fingerprint=fp, bls_pk=bytes([i]) * 48,
            )
            reg.enroll(identity, timestamp=1000 + i)
            reg.approve(fp, admin_fp=ADMIN_FP, timestamp=2000 + i)
        policy = CommitteePolicy(vm_tag=0x01)
        formation = CommitteeFormation(reg)
        roster = formation.build_roster(policy, epoch=1, round_num=0, timestamp=0)
        all_fps = [m.writer_fp for m in roster.active_members + roster.standby_members]
        assert len(all_fps) == len(set(all_fps))

    @given(n=st.integers(min_value=1, max_value=10))
    def test_formation_is_deterministic(self, n):
        reg = WriterRegistry()
        for i in range(1, n + 1):
            fp = bytes([i]) * 32
            identity = WriterIdentity(
                tier=IdentityTier.BLS, fingerprint=fp, bls_pk=bytes([i]) * 48,
            )
            reg.enroll(identity, timestamp=1000 + i)
            reg.approve(fp, admin_fp=ADMIN_FP, timestamp=2000 + i)
        policy = CommitteePolicy(vm_tag=0x01, max_committee_size=max(1, n // 2))
        formation = CommitteeFormation(reg)
        r1 = formation.build_roster(policy, epoch=1, round_num=0, timestamp=0)
        r2 = formation.build_roster(policy, epoch=1, round_num=0, timestamp=0)
        fps1 = [m.writer_fp for m in r1.active_members]
        fps2 = [m.writer_fp for m in r2.active_members]
        assert fps1 == fps2
