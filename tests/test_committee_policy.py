"""Tests for CommitteePolicy (Spec C3a §4)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.policy import (
    CommitteePolicy,
    EpochStrategy,
    FloorMode,
    StandbyStrategy,
    EvictionMode,
)
from src.ltp.execution.writer import IdentityTier


class TestEpochStrategy:
    def test_three_strategies(self):
        assert len(EpochStrategy) == 3

    def test_values(self):
        assert EpochStrategy.ROUND_COUNT.value == "round_count"
        assert EpochStrategy.TIME_BASED.value == "time_based"
        assert EpochStrategy.MANUAL.value == "manual"


class TestFloorMode:
    def test_two_modes(self):
        assert len(FloorMode) == 2

    def test_values(self):
        assert FloorMode.HARD.value == "hard"
        assert FloorMode.SOFT.value == "soft"


class TestStandbyStrategy:
    def test_three_strategies(self):
        assert len(StandbyStrategy) == 3

    def test_values(self):
        assert StandbyStrategy.PRIORITY_QUEUE.value == "priority_queue"
        assert StandbyStrategy.FIFO.value == "fifo"
        assert StandbyStrategy.ADMIN_DESIGNATED.value == "admin_designated"


class TestEvictionMode:
    def test_three_modes(self):
        assert len(EvictionMode) == 3

    def test_values(self):
        assert EvictionMode.IMMEDIATE.value == "immediate"
        assert EvictionMode.IMMEDIATE_BACKFILL.value == "immediate_backfill"
        assert EvictionMode.EPOCH_BOUNDARY.value == "epoch_boundary"


class TestCommitteePolicy:
    def test_defaults(self):
        p = CommitteePolicy(vm_tag=0x01)
        assert p.epoch_strategy is EpochStrategy.ROUND_COUNT
        assert p.epoch_length == 1000
        assert p.epoch_duration_ms == 0
        assert p.max_committee_size == 0
        assert p.min_committee_size == 1
        assert p.floor_mode is FloorMode.SOFT
        assert p.standby_strategy is StandbyStrategy.PRIORITY_QUEUE
        assert p.max_standby_size == 0
        assert p.admin_standby_list == []
        assert p.required_tiers is None
        assert p.min_epochs_active == 0
        assert p.require_bls_key is True
        assert p.security_eviction is EvictionMode.IMMEDIATE
        assert p.operational_eviction is EvictionMode.IMMEDIATE_BACKFILL
        assert p.require_committee_for_dispatch is False
        assert p.force_include == frozenset()
        assert p.force_exclude == frozenset()

    def test_custom_bridge_policy(self):
        p = CommitteePolicy(
            vm_tag=0x10,
            epoch_length=100,
            max_committee_size=5,
            min_committee_size=3,
            floor_mode=FloorMode.HARD,
            required_tiers=frozenset({IdentityTier.COMPOSITE}),
            standby_strategy=StandbyStrategy.ADMIN_DESIGNATED,
            admin_standby_list=[b"\x01" * 32, b"\x02" * 32],
            require_committee_for_dispatch=True,
        )
        assert p.floor_mode is FloorMode.HARD
        assert p.min_committee_size == 3
        assert p.required_tiers == frozenset({IdentityTier.COMPOSITE})
        assert p.require_committee_for_dispatch is True
        assert len(p.admin_standby_list) == 2

    def test_is_mutable(self):
        p = CommitteePolicy(vm_tag=0x01)
        p.epoch_length = 500
        assert p.epoch_length == 500

    def test_force_include_exclude(self):
        fp1 = b"\xaa" * 32
        fp2 = b"\xbb" * 32
        p = CommitteePolicy(
            vm_tag=0x01,
            force_include=frozenset({fp1}),
            force_exclude=frozenset({fp2}),
        )
        assert fp1 in p.force_include
        assert fp2 in p.force_exclude
