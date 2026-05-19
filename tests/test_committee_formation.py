"""Tests for CommitteeFormation (Spec C3a §5)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.formation import CommitteeFormation
from src.ltp.execution.committee.policy import CommitteePolicy
from src.ltp.execution.committee.types import CommitteeRole
from src.ltp.execution.writer import (
    IdentityTier,
    WriterIdentity,
    WriterState,
)
from src.ltp.execution.writer_registry import WriterRegistry

ADMIN_FP = b"\xff" * 32


def _enroll_active(
    reg: WriterRegistry, fp_byte: int, tier: IdentityTier = IdentityTier.BLS
) -> None:
    """Enroll and admin-approve a writer with the given fingerprint byte and tier."""
    fp = bytes([fp_byte]) * 32
    bls_pk = bytes([fp_byte]) * 48 if tier in (IdentityTier.BLS, IdentityTier.COMPOSITE) else None
    mldsa_vk = (
        bytes([fp_byte]) * 32 if tier in (IdentityTier.MLDSA, IdentityTier.COMPOSITE) else None
    )
    identity = WriterIdentity(
        tier=tier,
        fingerprint=fp,
        mldsa_vk=mldsa_vk,
        bls_pk=bls_pk,
    )
    reg.enroll(identity, timestamp=1000 + fp_byte)
    reg.approve(fp, admin_fp=ADMIN_FP, timestamp=2000 + fp_byte)


class TestBasicFormation:
    def test_all_eligible_writers_become_active(self):
        reg = WriterRegistry()
        _enroll_active(reg, 1, IdentityTier.BLS)
        _enroll_active(reg, 2, IdentityTier.COMPOSITE)
        policy = CommitteePolicy(vm_tag=0x01)
        formation = CommitteeFormation(reg)
        roster = formation.build_roster(policy, epoch=1, round_num=100, timestamp=5000)
        assert len(roster.active_members) == 2
        assert len(roster.standby_members) == 0
        assert roster.epoch == 1
        assert roster.formation_round == 100

    def test_empty_registry_produces_empty_roster(self):
        reg = WriterRegistry()
        policy = CommitteePolicy(vm_tag=0x01)
        formation = CommitteeFormation(reg)
        roster = formation.build_roster(policy, epoch=0, round_num=0, timestamp=0)
        assert len(roster.active_members) == 0
        assert len(roster.standby_members) == 0


class TestBLSKeyFilter:
    def test_mldsa_only_writer_excluded_when_bls_required(self):
        reg = WriterRegistry()
        _enroll_active(reg, 1, IdentityTier.MLDSA)
        _enroll_active(reg, 2, IdentityTier.BLS)
        policy = CommitteePolicy(vm_tag=0x01, require_bls_key=True)
        formation = CommitteeFormation(reg)
        roster = formation.build_roster(policy, epoch=1, round_num=100, timestamp=5000)
        assert len(roster.active_members) == 1
        assert roster.active_members[0].tier is IdentityTier.BLS

    def test_mldsa_included_when_bls_not_required(self):
        reg = WriterRegistry()
        _enroll_active(reg, 1, IdentityTier.MLDSA)
        policy = CommitteePolicy(vm_tag=0x01, require_bls_key=False)
        formation = CommitteeFormation(reg)
        roster = formation.build_roster(policy, epoch=1, round_num=100, timestamp=5000)
        assert len(roster.active_members) == 1


class TestTierFilter:
    def test_required_tiers_filters_ineligible(self):
        reg = WriterRegistry()
        _enroll_active(reg, 1, IdentityTier.BLS)
        _enroll_active(reg, 2, IdentityTier.COMPOSITE)
        policy = CommitteePolicy(
            vm_tag=0x01,
            required_tiers=frozenset({IdentityTier.COMPOSITE}),
        )
        formation = CommitteeFormation(reg)
        roster = formation.build_roster(policy, epoch=1, round_num=100, timestamp=5000)
        assert len(roster.active_members) == 1
        assert roster.active_members[0].tier is IdentityTier.COMPOSITE


class TestCommitteeCap:
    def test_excess_writers_become_standby(self):
        reg = WriterRegistry()
        _enroll_active(reg, 1, IdentityTier.BLS)
        _enroll_active(reg, 2, IdentityTier.COMPOSITE)
        _enroll_active(reg, 3, IdentityTier.BLS)
        policy = CommitteePolicy(vm_tag=0x01, max_committee_size=2)
        formation = CommitteeFormation(reg)
        roster = formation.build_roster(policy, epoch=1, round_num=100, timestamp=5000)
        assert len(roster.active_members) == 2
        assert len(roster.standby_members) == 1
        tiers = {m.tier for m in roster.active_members}
        assert IdentityTier.COMPOSITE in tiers

    def test_standby_capped_by_max_standby_size(self):
        reg = WriterRegistry()
        for i in range(1, 6):
            _enroll_active(reg, i, IdentityTier.BLS)
        policy = CommitteePolicy(vm_tag=0x01, max_committee_size=2, max_standby_size=1)
        formation = CommitteeFormation(reg)
        roster = formation.build_roster(policy, epoch=1, round_num=100, timestamp=5000)
        assert len(roster.active_members) == 2
        assert len(roster.standby_members) == 1


class TestForceIncludeExclude:
    def test_force_exclude_removes_from_eligible(self):
        reg = WriterRegistry()
        _enroll_active(reg, 1, IdentityTier.BLS)
        _enroll_active(reg, 2, IdentityTier.BLS)
        fp1 = bytes([1]) * 32
        policy = CommitteePolicy(vm_tag=0x01, force_exclude=frozenset({fp1}))
        formation = CommitteeFormation(reg)
        roster = formation.build_roster(policy, epoch=1, round_num=100, timestamp=5000)
        assert len(roster.active_members) == 1
        assert roster.active_members[0].writer_fp != fp1

    def test_force_include_bypasses_tier_filter(self):
        reg = WriterRegistry()
        _enroll_active(reg, 1, IdentityTier.MLDSA)
        _enroll_active(reg, 2, IdentityTier.BLS)
        fp1 = bytes([1]) * 32
        policy = CommitteePolicy(
            vm_tag=0x01,
            require_bls_key=True,
            force_include=frozenset({fp1}),
        )
        formation = CommitteeFormation(reg)
        roster = formation.build_roster(policy, epoch=1, round_num=100, timestamp=5000)
        fps = {m.writer_fp for m in roster.active_members}
        assert fp1 in fps

    def test_force_include_still_requires_transactable(self):
        reg = WriterRegistry()
        fp1 = bytes([1]) * 32
        identity = WriterIdentity(
            tier=IdentityTier.BLS,
            fingerprint=fp1,
            bls_pk=b"\x01" * 48,
        )
        reg.enroll(identity, timestamp=1000)
        # Writer stays PENDING (not transactable)
        policy = CommitteePolicy(vm_tag=0x01, force_include=frozenset({fp1}))
        formation = CommitteeFormation(reg)
        roster = formation.build_roster(policy, epoch=1, round_num=100, timestamp=5000)
        assert len(roster.active_members) == 0


class TestDeterminism:
    def test_same_registry_produces_same_roster(self):
        reg = WriterRegistry()
        for i in range(1, 6):
            _enroll_active(reg, i, IdentityTier.BLS)
        policy = CommitteePolicy(vm_tag=0x01, max_committee_size=3)
        formation = CommitteeFormation(reg)
        r1 = formation.build_roster(policy, epoch=1, round_num=100, timestamp=5000)
        r2 = formation.build_roster(policy, epoch=1, round_num=100, timestamp=5000)
        fps1 = [m.writer_fp for m in r1.active_members]
        fps2 = [m.writer_fp for m in r2.active_members]
        assert fps1 == fps2
