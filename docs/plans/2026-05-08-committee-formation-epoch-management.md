# Committee Formation + Epoch Management (Spec C3a) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the committee formation and epoch management layer as a new subpackage `src/ltp/execution/committee/`, enabling per-VM configurable committees with deterministic selection, epoch-driven rotation, mid-epoch eviction, and standby backfill.

**Architecture:** New subpackage with 6 modules + coordinator. Committee depends on C2's writer layer (one-way). Integration via `on_writer_state_change` hook for eviction, `tick()` heartbeat for epoch advance, opt-in `WriterGate` check for committee-gated dispatch. All roster computation is deterministic — every node produces the same result from the same registry state.

**Tech Stack:** Python 3.12+, pytest, Hypothesis, dataclasses, enums. No new dependencies.

---

## File Structure

**Create:**
- `src/ltp/execution/committee/__init__.py` — public API surface
- `src/ltp/execution/committee/types.py` — CommitteeMember, CommitteeRoster, EpochRecord, EvictionEvent, enums
- `src/ltp/execution/committee/policy.py` — CommitteePolicy dataclass + supporting enums
- `src/ltp/execution/committee/formation.py` — CommitteeFormation (eligibility pipeline + deterministic selection)
- `src/ltp/execution/committee/epoch.py` — EpochManager (epoch lifecycle per VM)
- `src/ltp/execution/committee/eviction.py` — EvictionHandler (mid-epoch removal + floor checks)
- `src/ltp/execution/committee/standby.py` — StandbySelector (3 strategies)

**Create (tests):**
- `tests/test_committee_types.py`
- `tests/test_committee_policy.py`
- `tests/test_committee_formation.py`
- `tests/test_committee_epoch.py`
- `tests/test_committee_eviction.py`
- `tests/test_committee_standby.py`
- `tests/test_committee_manager.py`
- `tests/test_committee_e2e.py`

**Modify:**
- `src/ltp/execution/__init__.py` — add committee exports
- `src/ltp/execution/writer_recovery.py` — add `FORCE_EPOCH_ADVANCE` to EmergencyAction

**Key existing files (read-only reference):**
- `src/ltp/execution/writer.py` — WriterIdentity, WriterRecord, WriterState, IdentityTier, TRANSACTABLE_STATES
- `src/ltp/execution/writer_registry.py` — WriterRegistry.active_writers(), lookup()
- `src/ltp/execution/writer_recovery.py` — EmergencyState, EmergencyAction, RecoveryQuorum
- `src/ltp/execution/writer_epoch.py` — EpochTracker
- `src/ltp/execution/writer_gate.py` — WriterGate
- `src/ltp/execution/writer_policy.py` — VMWriterPolicy (pattern reference for CommitteePolicy)

---

### Task 1: Core Types + Enums

**Files:**
- Create: `src/ltp/execution/committee/__init__.py`
- Create: `src/ltp/execution/committee/types.py`
- Test: `tests/test_committee_types.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_committee_types.py
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


# ---------------------------------------------------------------------------
# CommitteeRole
# ---------------------------------------------------------------------------

class TestCommitteeRole:
    def test_two_roles_exist(self):
        assert len(CommitteeRole) == 2

    def test_active_value(self):
        assert CommitteeRole.ACTIVE.value == "active"

    def test_standby_value(self):
        assert CommitteeRole.STANDBY.value == "standby"


# ---------------------------------------------------------------------------
# CommitteeMember
# ---------------------------------------------------------------------------

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
            m.writer_fp = b"\x00" * 32  # type: ignore[misc]


# ---------------------------------------------------------------------------
# CommitteeRoster
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# EpochTrigger
# ---------------------------------------------------------------------------

class TestEpochTrigger:
    def test_four_triggers_exist(self):
        assert len(EpochTrigger) == 4

    def test_values(self):
        assert EpochTrigger.ROUND_COUNT.value == "round_count"
        assert EpochTrigger.ADMIN_SIGNAL.value == "admin_signal"
        assert EpochTrigger.EMERGENCY.value == "emergency"
        assert EpochTrigger.TIME_BASED.value == "time_based"


# ---------------------------------------------------------------------------
# EpochRecord
# ---------------------------------------------------------------------------

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
            record.epoch = 99  # type: ignore[misc]


# ---------------------------------------------------------------------------
# EvictionReason
# ---------------------------------------------------------------------------

class TestEvictionReason:
    def test_four_reasons_exist(self):
        assert len(EvictionReason) == 4

    def test_values(self):
        assert EvictionReason.REVOKED.value == "revoked"
        assert EvictionReason.SUSPENDED.value == "suspended"
        assert EvictionReason.EXPIRED.value == "expired"
        assert EvictionReason.ADMIN.value == "admin"


# ---------------------------------------------------------------------------
# EvictionEvent
# ---------------------------------------------------------------------------

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
            ev.reason = EvictionReason.ADMIN  # type: ignore[misc]


# ---------------------------------------------------------------------------
# CommitteeEvent
# ---------------------------------------------------------------------------

class TestCommitteeEvent:
    def test_five_events_exist(self):
        assert len(CommitteeEvent) == 5

    def test_values(self):
        assert CommitteeEvent.MEMBER_EVICTED.value == "member_evicted"
        assert CommitteeEvent.MEMBER_BACKFILLED.value == "member_backfilled"
        assert CommitteeEvent.COMMITTEE_HALTED.value == "committee_halted"
        assert CommitteeEvent.BELOW_FLOOR.value == "below_floor"
        assert CommitteeEvent.FLOOR_RESTORED.value == "floor_restored"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_committee_types.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.ltp.execution.committee'`

- [ ] **Step 3: Create the package and implement types**

```python
# src/ltp/execution/committee/__init__.py
"""Committee formation and epoch management (Spec C3a)."""
```

```python
# src/ltp/execution/committee/types.py
"""Core data types for the committee layer (Spec C3a §3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from ..writer import IdentityTier

__all__ = [
    "CommitteeRole",
    "CommitteeMember",
    "CommitteeRoster",
    "EpochTrigger",
    "EpochRecord",
    "EvictionReason",
    "EvictionEvent",
    "CommitteeEvent",
]


class CommitteeRole(str, Enum):
    ACTIVE  = "active"
    STANDBY = "standby"


@dataclass(frozen=True)
class CommitteeMember:
    writer_fp: bytes
    bls_pk: bytes
    tier: IdentityTier
    joined_epoch: int
    role: CommitteeRole


@dataclass
class CommitteeRoster:
    vm_tag: int
    epoch: int
    active_members: list[CommitteeMember]
    standby_members: list[CommitteeMember]
    formed_at: int
    formation_round: int


class EpochTrigger(str, Enum):
    ROUND_COUNT  = "round_count"
    ADMIN_SIGNAL = "admin_signal"
    EMERGENCY    = "emergency"
    TIME_BASED   = "time_based"


@dataclass(frozen=True)
class EpochRecord:
    vm_tag: int
    epoch: int
    roster: CommitteeRoster
    trigger: EpochTrigger
    previous_epoch: int
    timestamp: int


class EvictionReason(str, Enum):
    REVOKED    = "revoked"
    SUSPENDED  = "suspended"
    EXPIRED    = "expired"
    ADMIN      = "admin"


@dataclass(frozen=True)
class EvictionEvent:
    writer_fp: bytes
    vm_tag: int
    epoch: int
    reason: EvictionReason
    backfill_fp: Optional[bytes]
    timestamp: int


class CommitteeEvent(str, Enum):
    MEMBER_EVICTED     = "member_evicted"
    MEMBER_BACKFILLED  = "member_backfilled"
    COMMITTEE_HALTED   = "committee_halted"
    BELOW_FLOOR        = "below_floor"
    FLOOR_RESTORED     = "floor_restored"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_committee_types.py -v`
Expected: All 20 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/committee/__init__.py src/ltp/execution/committee/types.py tests/test_committee_types.py
git commit -m "feat(committee): add core types and enums (C3a §3)"
```

---

### Task 2: Committee Policy

**Files:**
- Create: `src/ltp/execution/committee/policy.py`
- Test: `tests/test_committee_policy.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_committee_policy.py
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


# ---------------------------------------------------------------------------
# Supporting Enums
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# CommitteePolicy
# ---------------------------------------------------------------------------

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_committee_policy.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement CommitteePolicy**

```python
# src/ltp/execution/committee/policy.py
"""Per-VM committee policy configuration (Spec C3a §4)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from ..writer import IdentityTier

__all__ = [
    "EpochStrategy",
    "FloorMode",
    "StandbyStrategy",
    "EvictionMode",
    "CommitteePolicy",
]


class EpochStrategy(str, Enum):
    ROUND_COUNT = "round_count"
    TIME_BASED  = "time_based"
    MANUAL      = "manual"


class FloorMode(str, Enum):
    HARD = "hard"
    SOFT = "soft"


class StandbyStrategy(str, Enum):
    PRIORITY_QUEUE   = "priority_queue"
    FIFO             = "fifo"
    ADMIN_DESIGNATED = "admin_designated"


class EvictionMode(str, Enum):
    IMMEDIATE          = "immediate"
    IMMEDIATE_BACKFILL = "immediate_backfill"
    EPOCH_BOUNDARY     = "epoch_boundary"


@dataclass
class CommitteePolicy:
    """Per-VM committee configuration. Not frozen — updatable by governance."""

    vm_tag: int

    # --- Epoch strategy ---
    epoch_strategy: EpochStrategy = EpochStrategy.ROUND_COUNT
    epoch_length: int = 1000
    epoch_duration_ms: int = 0

    # --- Committee size ---
    max_committee_size: int = 0
    min_committee_size: int = 1
    floor_mode: FloorMode = FloorMode.SOFT

    # --- Standby ---
    standby_strategy: StandbyStrategy = StandbyStrategy.PRIORITY_QUEUE
    max_standby_size: int = 0
    admin_standby_list: list[bytes] = field(default_factory=list)

    # --- Eligibility ---
    required_tiers: Optional[frozenset[IdentityTier]] = None
    min_epochs_active: int = 0
    require_bls_key: bool = True

    # --- Eviction ---
    security_eviction: EvictionMode = EvictionMode.IMMEDIATE
    operational_eviction: EvictionMode = EvictionMode.IMMEDIATE_BACKFILL

    # --- Gate integration ---
    require_committee_for_dispatch: bool = False

    # --- Admin overrides ---
    force_include: frozenset[bytes] = field(default_factory=frozenset)
    force_exclude: frozenset[bytes] = field(default_factory=frozenset)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_committee_policy.py -v`
Expected: All 12 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/committee/policy.py tests/test_committee_policy.py
git commit -m "feat(committee): add CommitteePolicy with per-VM knobs (C3a §4)"
```

---

### Task 3: Standby Selector

**Files:**
- Create: `src/ltp/execution/committee/standby.py`
- Test: `tests/test_committee_standby.py`

Build standby before formation because formation uses the same scoring logic.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_committee_standby.py
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# score_member
# ---------------------------------------------------------------------------

class TestScoreMember:
    def test_composite_ranks_highest(self):
        c = _member(1, IdentityTier.COMPOSITE, joined_epoch=5)
        b = _member(2, IdentityTier.BLS, joined_epoch=5)
        m = _member(3, IdentityTier.MLDSA, joined_epoch=5)
        assert score_member(c) > score_member(b) > score_member(m)

    def test_earlier_enrollment_wins_tiebreak(self):
        a = _member(1, IdentityTier.BLS, joined_epoch=1)
        b = _member(2, IdentityTier.BLS, joined_epoch=5)
        # Earlier joined_epoch = higher priority (lower epoch number is better)
        assert score_member(a) > score_member(b)


# ---------------------------------------------------------------------------
# StandbySelector — PRIORITY_QUEUE
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# StandbySelector — FIFO
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# StandbySelector — ADMIN_DESIGNATED
# ---------------------------------------------------------------------------

class TestStandbyAdminDesignated:
    def test_picks_first_admin_listed_standby(self):
        fp_a = bytes([0x0A]) * 32
        fp_b = bytes([0x0B]) * 32
        policy = CommitteePolicy(
            vm_tag=0x01,
            standby_strategy=StandbyStrategy.ADMIN_DESIGNATED,
            admin_standby_list=[fp_b, fp_a],  # fp_b preferred
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


# ---------------------------------------------------------------------------
# rank()
# ---------------------------------------------------------------------------

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
        # BLS joined_epoch=1 beats MLDSA joined_epoch=5
        assert ranked[1].tier is IdentityTier.BLS
        assert ranked[2].tier is IdentityTier.MLDSA
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_committee_standby.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement StandbySelector**

```python
# src/ltp/execution/committee/standby.py
"""Standby member selection strategies (Spec C3a §8)."""

from __future__ import annotations

from typing import Optional

from .types import CommitteeMember, CommitteeRoster
from .policy import CommitteePolicy, StandbyStrategy
from ..writer import IdentityTier

__all__ = ["StandbySelector", "score_member"]

# Tier priority: COMPOSITE > BLS > MLDSA
_TIER_WEIGHT: dict[IdentityTier, int] = {
    IdentityTier.MLDSA:     1,
    IdentityTier.BLS:       2,
    IdentityTier.COMPOSITE: 3,
}


def score_member(member: CommitteeMember) -> tuple[int, int]:
    """Deterministic scoring: (tier_weight, -joined_epoch).

    Higher tuple = higher priority. Earlier joined_epoch is better
    (negated so lower epoch yields higher score).
    """
    return (_TIER_WEIGHT.get(member.tier, 0), -member.joined_epoch)


class StandbySelector:
    """Selects which standby member fills a vacancy."""

    def __init__(self, policy: CommitteePolicy) -> None:
        self._policy = policy

    def next(self, roster: CommitteeRoster) -> Optional[CommitteeMember]:
        """Return the next standby to promote, or None if standby is empty."""
        if not roster.standby_members:
            return None

        strategy = self._policy.standby_strategy

        if strategy is StandbyStrategy.PRIORITY_QUEUE:
            ranked = self.rank(roster.standby_members)
            return ranked[0] if ranked else None

        if strategy is StandbyStrategy.FIFO:
            return roster.standby_members[0]

        if strategy is StandbyStrategy.ADMIN_DESIGNATED:
            standby_fps = {m.writer_fp: m for m in roster.standby_members}
            for fp in self._policy.admin_standby_list:
                if fp in standby_fps:
                    return standby_fps[fp]
            return None

        return None  # unreachable

    def rank(self, candidates: list[CommitteeMember]) -> list[CommitteeMember]:
        """Order candidates by score descending."""
        return sorted(candidates, key=score_member, reverse=True)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_committee_standby.py -v`
Expected: All 10 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/committee/standby.py tests/test_committee_standby.py
git commit -m "feat(committee): add StandbySelector with 3 strategies (C3a §8)"
```

---

### Task 4: Committee Formation

**Files:**
- Create: `src/ltp/execution/committee/formation.py`
- Test: `tests/test_committee_formation.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_committee_formation.py
"""Tests for CommitteeFormation (Spec C3a §5)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.formation import CommitteeFormation
from src.ltp.execution.committee.types import CommitteeRole
from src.ltp.execution.committee.policy import CommitteePolicy
from src.ltp.execution.writer import (
    IdentityTier,
    WriterIdentity,
    WriterState,
)
from src.ltp.execution.writer_registry import WriterRegistry

ADMIN_FP = b"\xff" * 32


def _enroll_active(reg: WriterRegistry, fp_byte: int,
                   tier: IdentityTier = IdentityTier.BLS) -> None:
    """Enroll and admin-approve a writer with the given fingerprint byte and tier."""
    fp = bytes([fp_byte]) * 32
    bls_pk = bytes([fp_byte]) * 48 if tier in (IdentityTier.BLS, IdentityTier.COMPOSITE) else None
    mldsa_vk = bytes([fp_byte]) * 32 if tier in (IdentityTier.MLDSA, IdentityTier.COMPOSITE) else None
    identity = WriterIdentity(
        tier=tier,
        fingerprint=fp,
        mldsa_vk=mldsa_vk,
        bls_pk=bls_pk,
    )
    reg.enroll(identity, timestamp=1000 + fp_byte)
    reg.approve(fp, admin_fp=ADMIN_FP, timestamp=2000 + fp_byte)


# ---------------------------------------------------------------------------
# Basic formation
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# BLS key requirement
# ---------------------------------------------------------------------------

class TestBLSKeyFilter:
    def test_mldsa_only_writer_excluded_when_bls_required(self):
        reg = WriterRegistry()
        _enroll_active(reg, 1, IdentityTier.MLDSA)  # no BLS key
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


# ---------------------------------------------------------------------------
# Tier filter
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Committee cap + standby
# ---------------------------------------------------------------------------

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
        # COMPOSITE should be active (highest tier priority)
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


# ---------------------------------------------------------------------------
# Force include / exclude
# ---------------------------------------------------------------------------

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
        _enroll_active(reg, 1, IdentityTier.MLDSA)  # normally excluded by require_bls_key
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
        assert fp1 in fps  # force-included despite no BLS key

    def test_force_include_still_requires_transactable(self):
        reg = WriterRegistry()
        fp1 = bytes([1]) * 32
        identity = WriterIdentity(
            tier=IdentityTier.BLS, fingerprint=fp1, bls_pk=b"\x01" * 48,
        )
        reg.enroll(identity, timestamp=1000)
        # Writer stays PENDING (not transactable)
        policy = CommitteePolicy(vm_tag=0x01, force_include=frozenset({fp1}))
        formation = CommitteeFormation(reg)
        roster = formation.build_roster(policy, epoch=1, round_num=100, timestamp=5000)
        assert len(roster.active_members) == 0  # PENDING writer not included


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_committee_formation.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement CommitteeFormation**

```python
# src/ltp/execution/committee/formation.py
"""Committee roster formation from eligible writers (Spec C3a §5)."""

from __future__ import annotations

from .types import CommitteeMember, CommitteeRole, CommitteeRoster
from .policy import CommitteePolicy
from .standby import score_member
from ..writer import IdentityTier, WriterRecord, TRANSACTABLE_STATES
from ..writer_registry import WriterRegistry

__all__ = ["CommitteeFormation"]


class CommitteeFormation:
    """Stateless builder — produces a CommitteeRoster from registry state + policy."""

    def __init__(self, registry: WriterRegistry) -> None:
        self._registry = registry

    def build_roster(
        self,
        policy: CommitteePolicy,
        epoch: int,
        round_num: int,
        timestamp: int,
    ) -> CommitteeRoster:
        """Build a complete roster for a new epoch."""
        # 1. Gather all transactable writers
        candidates = self._registry.active_writers()

        # 2. Split into normal-eligible and force-included
        eligible: list[WriterRecord] = []
        force_included: list[WriterRecord] = []

        for record in candidates:
            fp = record.identity.fingerprint
            if record.state not in TRANSACTABLE_STATES:
                continue
            if fp in policy.force_include:
                force_included.append(record)
                continue
            if fp in policy.force_exclude:
                continue
            if not self._passes_filters(record, policy):
                continue
            eligible.append(record)

        # 3. Force-include: must still be transactable (already checked above)
        all_eligible = eligible + force_included

        # 4. Convert to CommitteeMember and score
        members = [self._to_member(r, epoch) for r in all_eligible]
        members.sort(key=score_member, reverse=True)

        # 5. Split into active and standby
        cap = policy.max_committee_size
        if cap > 0:
            active = members[:cap]
            standby_pool = members[cap:]
        else:
            active = members
            standby_pool = []

        # 6. Cap standby
        if policy.max_standby_size > 0:
            standby_pool = standby_pool[:policy.max_standby_size]

        # 7. Set roles
        active_members = [
            CommitteeMember(
                writer_fp=m.writer_fp, bls_pk=m.bls_pk, tier=m.tier,
                joined_epoch=m.joined_epoch, role=CommitteeRole.ACTIVE,
            )
            for m in active
        ]
        standby_members = [
            CommitteeMember(
                writer_fp=m.writer_fp, bls_pk=m.bls_pk, tier=m.tier,
                joined_epoch=m.joined_epoch, role=CommitteeRole.STANDBY,
            )
            for m in standby_pool
        ]

        return CommitteeRoster(
            vm_tag=policy.vm_tag,
            epoch=epoch,
            active_members=active_members,
            standby_members=standby_members,
            formed_at=timestamp,
            formation_round=round_num,
        )

    def _passes_filters(self, record: WriterRecord, policy: CommitteePolicy) -> bool:
        """Apply eligibility filters 2-4 (BLS key, tier, tenure)."""
        tier = record.identity.tier
        if policy.require_bls_key and tier not in (IdentityTier.BLS, IdentityTier.COMPOSITE):
            return False
        if policy.required_tiers is not None and tier not in policy.required_tiers:
            return False
        # min_epochs_active: count approved transitions as proxy for epochs served
        if policy.min_epochs_active > 0:
            active_transitions = sum(
                1 for e in record.transition_log if e.to_state.value == "active"
            )
            if active_transitions < policy.min_epochs_active:
                return False
        return True

    def _to_member(self, record: WriterRecord, epoch: int) -> CommitteeMember:
        """Convert a WriterRecord to a CommitteeMember."""
        return CommitteeMember(
            writer_fp=record.identity.fingerprint,
            bls_pk=record.identity.bls_pk or b"",
            tier=record.identity.tier,
            joined_epoch=epoch,
            role=CommitteeRole.ACTIVE,  # placeholder, set properly in build_roster
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_committee_formation.py -v`
Expected: All 10 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/committee/formation.py tests/test_committee_formation.py
git commit -m "feat(committee): add CommitteeFormation with eligibility pipeline (C3a §5)"
```

---

### Task 5: Eviction Handler

**Files:**
- Create: `src/ltp/execution/committee/eviction.py`
- Test: `tests/test_committee_eviction.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_committee_eviction.py
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


# ---------------------------------------------------------------------------
# Security eviction (REVOKED → IMMEDIATE, no backfill)
# ---------------------------------------------------------------------------

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
        fp = bytes([99]) * 32  # not on roster
        ev = handler.handle_state_change(roster, fp, WriterState.ACTIVE, WriterState.REVOKED, TS)
        assert ev is None


# ---------------------------------------------------------------------------
# Operational eviction (SUSPENDED → IMMEDIATE_BACKFILL)
# ---------------------------------------------------------------------------

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
        assert len(roster.active_members) == 2  # still 2 (backfilled)
        assert len(roster.standby_members) == 0  # standby consumed

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


# ---------------------------------------------------------------------------
# EPOCH_BOUNDARY mode
# ---------------------------------------------------------------------------

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
        # Deferred — no immediate roster change
        assert ev is None
        assert len(roster.active_members) == 2
        assert len(handler.pending_evictions) == 1


# ---------------------------------------------------------------------------
# Floor checks
# ---------------------------------------------------------------------------

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
        # Evict with backfill — stays at 2 (above min)
        handler.handle_state_change(roster, fp, WriterState.ACTIVE, WriterState.SUSPENDED, TS)
        assert CommitteeEvent.BELOW_FLOOR not in handler.emitted_events
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_committee_eviction.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement EvictionHandler**

```python
# src/ltp/execution/committee/eviction.py
"""Mid-epoch eviction handler (Spec C3a §7)."""

from __future__ import annotations

from typing import Optional

from .types import (
    CommitteeEvent,
    CommitteeMember,
    CommitteeRole,
    CommitteeRoster,
    EvictionEvent,
    EvictionReason,
)
from .policy import CommitteePolicy, EvictionMode, FloorMode
from .standby import StandbySelector
from ..writer import WriterState

__all__ = ["EvictionHandler"]

# Map writer state transitions to eviction categories
_SECURITY_STATES = frozenset({WriterState.REVOKED})
_OPERATIONAL_STATES = frozenset({WriterState.SUSPENDED, WriterState.EXPIRED})

_STATE_TO_REASON: dict[WriterState, EvictionReason] = {
    WriterState.REVOKED:   EvictionReason.REVOKED,
    WriterState.SUSPENDED: EvictionReason.SUSPENDED,
    WriterState.EXPIRED:   EvictionReason.EXPIRED,
}


class EvictionHandler:
    """Handles mid-epoch committee membership changes."""

    def __init__(self, policy: CommitteePolicy, standby_selector: StandbySelector) -> None:
        self._policy = policy
        self._standby = standby_selector
        self._events: list[EvictionEvent] = []
        self._halted: bool = False
        self.pending_evictions: list[tuple[bytes, EvictionReason]] = []
        self.emitted_events: list[CommitteeEvent] = []

    @property
    def is_halted(self) -> bool:
        return self._halted

    def handle_state_change(
        self,
        roster: CommitteeRoster,
        writer_fp: bytes,
        old_state: WriterState,
        new_state: WriterState,
        timestamp: int,
    ) -> Optional[EvictionEvent]:
        """Process a writer state change. Returns EvictionEvent if member was evicted."""
        # Only care about transitions to non-transactable states
        reason = _STATE_TO_REASON.get(new_state)
        if reason is None:
            return None

        # Is this writer on the active roster?
        member_idx = None
        for i, m in enumerate(roster.active_members):
            if m.writer_fp == writer_fp:
                member_idx = i
                break

        if member_idx is None:
            return None  # not a committee member

        # Determine eviction mode
        if new_state in _SECURITY_STATES:
            mode = self._policy.security_eviction
        else:
            mode = self._policy.operational_eviction

        # EPOCH_BOUNDARY: defer
        if mode is EvictionMode.EPOCH_BOUNDARY:
            self.pending_evictions.append((writer_fp, reason))
            return None

        # IMMEDIATE or IMMEDIATE_BACKFILL: remove now
        roster.active_members.pop(member_idx)
        backfill_fp: Optional[bytes] = None

        if mode is EvictionMode.IMMEDIATE_BACKFILL:
            replacement = self._standby.next(roster)
            if replacement is not None:
                roster.standby_members.remove(replacement)
                promoted = CommitteeMember(
                    writer_fp=replacement.writer_fp,
                    bls_pk=replacement.bls_pk,
                    tier=replacement.tier,
                    joined_epoch=replacement.joined_epoch,
                    role=CommitteeRole.ACTIVE,
                )
                roster.active_members.append(promoted)
                backfill_fp = replacement.writer_fp
                self.emitted_events.append(CommitteeEvent.MEMBER_BACKFILLED)

        self.emitted_events.append(CommitteeEvent.MEMBER_EVICTED)

        # Floor check
        self._check_floor(roster)

        event = EvictionEvent(
            writer_fp=writer_fp,
            vm_tag=roster.vm_tag,
            epoch=roster.epoch,
            reason=reason,
            backfill_fp=backfill_fp,
            timestamp=timestamp,
        )
        self._events.append(event)
        return event

    def _check_floor(self, roster: CommitteeRoster) -> None:
        """Check if committee size is below minimum."""
        if len(roster.active_members) >= self._policy.min_committee_size:
            if self._halted:
                self._halted = False
                self.emitted_events.append(CommitteeEvent.FLOOR_RESTORED)
            return

        if self._policy.floor_mode is FloorMode.HARD:
            self._halted = True
            self.emitted_events.append(CommitteeEvent.COMMITTEE_HALTED)
        else:
            self.emitted_events.append(CommitteeEvent.BELOW_FLOOR)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_committee_eviction.py -v`
Expected: All 10 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/committee/eviction.py tests/test_committee_eviction.py
git commit -m "feat(committee): add EvictionHandler with floor enforcement (C3a §7)"
```

---

### Task 6: Epoch Manager

**Files:**
- Create: `src/ltp/execution/committee/epoch.py`
- Test: `tests/test_committee_epoch.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_committee_epoch.py
"""Tests for EpochManager (Spec C3a §6)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.epoch import EpochManager
from src.ltp.execution.committee.formation import CommitteeFormation
from src.ltp.execution.committee.types import EpochTrigger
from src.ltp.execution.committee.policy import CommitteePolicy, EpochStrategy
from src.ltp.execution.writer import IdentityTier, WriterIdentity
from src.ltp.execution.writer_recovery import EmergencyState
from src.ltp.execution.writer_registry import WriterRegistry

ADMIN_FP = b"\xff" * 32


def _setup(epoch_strategy=EpochStrategy.ROUND_COUNT, epoch_length=100,
           n_writers=3):
    reg = WriterRegistry()
    for i in range(1, n_writers + 1):
        fp = bytes([i]) * 32
        identity = WriterIdentity(
            tier=IdentityTier.BLS, fingerprint=fp,
            bls_pk=bytes([i]) * 48,
        )
        reg.enroll(identity, timestamp=1000 + i)
        reg.approve(fp, admin_fp=ADMIN_FP, timestamp=2000 + i)

    policy = CommitteePolicy(
        vm_tag=0x01, epoch_strategy=epoch_strategy, epoch_length=epoch_length,
    )
    formation = CommitteeFormation(reg)
    emergency = EmergencyState()
    mgr = EpochManager(0x01, policy, formation, emergency)
    return mgr, reg, emergency


# ---------------------------------------------------------------------------
# Initial state
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Round-count strategy
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Time-based strategy
# ---------------------------------------------------------------------------

class TestTimeBasedStrategy:
    def test_advances_at_duration(self):
        mgr, _, _ = _setup(epoch_strategy=EpochStrategy.TIME_BASED, epoch_length=100)
        # Set epoch_duration_ms via policy
        mgr._policy.epoch_duration_ms = 60_000  # 60 seconds
        # First check establishes the start timestamp
        mgr.check_advance(current_round=0, timestamp_ms=0)
        # Not enough time
        assert mgr.check_advance(current_round=10, timestamp_ms=30_000) is False
        # Enough time
        assert mgr.check_advance(current_round=20, timestamp_ms=60_000) is True
        assert mgr.current_epoch == 2  # epoch 1 from first check, epoch 2 from second
        assert mgr.history[-1].trigger is EpochTrigger.TIME_BASED


# ---------------------------------------------------------------------------
# Manual strategy
# ---------------------------------------------------------------------------

class TestManualStrategy:
    def test_check_advance_never_auto_advances(self):
        mgr, _, _ = _setup(epoch_strategy=EpochStrategy.MANUAL, epoch_length=1)
        assert mgr.check_advance(current_round=9999, timestamp_ms=9999) is False
        assert mgr.current_epoch == 0


# ---------------------------------------------------------------------------
# Admin advance
# ---------------------------------------------------------------------------

class TestAdminAdvance:
    def test_admin_advance_works_regardless_of_strategy(self):
        mgr, _, _ = _setup(epoch_strategy=EpochStrategy.MANUAL)
        roster = mgr.admin_advance(actor_fp=ADMIN_FP, timestamp=5000)
        assert mgr.current_epoch == 1
        assert roster is not None
        assert len(mgr.history) == 1
        assert mgr.history[0].trigger is EpochTrigger.ADMIN_SIGNAL


# ---------------------------------------------------------------------------
# Emergency advance
# ---------------------------------------------------------------------------

class TestEmergencyAdvance:
    def test_emergency_advance_logs_trigger(self):
        mgr, _, emergency = _setup()
        roster = mgr.emergency_advance(
            actor_fp=ADMIN_FP, reason="compromised member", timestamp=9000,
        )
        assert mgr.current_epoch == 1
        assert mgr.history[0].trigger is EpochTrigger.EMERGENCY
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_committee_epoch.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement EpochManager**

```python
# src/ltp/execution/committee/epoch.py
"""Epoch lifecycle manager (Spec C3a §6)."""

from __future__ import annotations

from typing import Optional

from .types import CommitteeRoster, EpochRecord, EpochTrigger
from .policy import CommitteePolicy, EpochStrategy
from .formation import CommitteeFormation
from ..writer_recovery import EmergencyState

__all__ = ["EpochManager"]


class EpochManager:
    """Per-VM epoch lifecycle. Drives epoch transitions based on configured strategy."""

    def __init__(
        self,
        vm_tag: int,
        policy: CommitteePolicy,
        formation: CommitteeFormation,
        emergency: EmergencyState,
    ) -> None:
        self._vm_tag = vm_tag
        self._policy = policy
        self._formation = formation
        self._emergency = emergency
        self._current_epoch: int = 0
        self._epoch_start_round: int = 0
        self._epoch_start_ts: int = 0
        self._roster: Optional[CommitteeRoster] = None
        self._history: list[EpochRecord] = []

    @property
    def current_epoch(self) -> int:
        return self._current_epoch

    @property
    def roster(self) -> Optional[CommitteeRoster]:
        return self._roster

    @property
    def history(self) -> list[EpochRecord]:
        return list(self._history)

    def check_advance(self, current_round: int, timestamp_ms: int) -> bool:
        """Called every round. Returns True if epoch advanced."""
        strategy = self._policy.epoch_strategy

        if strategy is EpochStrategy.MANUAL:
            return False

        if strategy is EpochStrategy.ROUND_COUNT:
            if current_round - self._epoch_start_round < self._policy.epoch_length:
                return False
        elif strategy is EpochStrategy.TIME_BASED:
            if self._epoch_start_ts == 0 and self._current_epoch == 0:
                # Bootstrap: first call sets the clock and advances to epoch 1
                self._advance(current_round, timestamp_ms, EpochTrigger.ROUND_COUNT)
                return False
            if timestamp_ms - self._epoch_start_ts < self._policy.epoch_duration_ms:
                return False

        trigger = (EpochTrigger.TIME_BASED
                   if strategy is EpochStrategy.TIME_BASED
                   else EpochTrigger.ROUND_COUNT)
        self._advance(current_round, timestamp_ms, trigger)
        return True

    def admin_advance(self, actor_fp: bytes, timestamp: int) -> CommitteeRoster:
        """Governance-forced epoch advance."""
        self._advance(0, timestamp, EpochTrigger.ADMIN_SIGNAL)
        return self._roster

    def emergency_advance(self, actor_fp: bytes, reason: str, timestamp: int) -> CommitteeRoster:
        """Emergency-triggered epoch advance."""
        self._advance(0, timestamp, EpochTrigger.EMERGENCY)
        return self._roster

    def _advance(self, current_round: int, timestamp: int, trigger: EpochTrigger) -> None:
        """Internal: perform the epoch transition."""
        prev_epoch = self._current_epoch
        self._current_epoch += 1

        roster = self._formation.build_roster(
            self._policy, self._current_epoch, current_round, timestamp,
        )
        self._roster = roster

        record = EpochRecord(
            vm_tag=self._vm_tag,
            epoch=self._current_epoch,
            roster=roster,
            trigger=trigger,
            previous_epoch=prev_epoch,
            timestamp=timestamp,
        )
        self._history.append(record)

        self._epoch_start_round = current_round
        self._epoch_start_ts = timestamp
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_committee_epoch.py -v`
Expected: All 11 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/committee/epoch.py tests/test_committee_epoch.py
git commit -m "feat(committee): add EpochManager with 3 strategies (C3a §6)"
```

---

### Task 7: CommitteeManager Coordinator

**Files:**
- Create: `src/ltp/execution/committee/manager.py` (add to subpackage)
- Modify: `src/ltp/execution/committee/__init__.py`
- Test: `tests/test_committee_manager.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_committee_manager.py
"""Tests for CommitteeManager coordinator (Spec C3a §9)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.manager import CommitteeManager
from src.ltp.execution.committee.types import CommitteeEvent
from src.ltp.execution.committee.policy import CommitteePolicy, EpochStrategy, FloorMode
from src.ltp.execution.writer import IdentityTier, WriterIdentity, WriterState
from src.ltp.execution.writer_recovery import EmergencyState
from src.ltp.execution.writer_registry import WriterRegistry

ADMIN_FP = b"\xff" * 32


def _setup(n_writers=3, epoch_length=100, **policy_kwargs):
    reg = WriterRegistry()
    for i in range(1, n_writers + 1):
        fp = bytes([i]) * 32
        identity = WriterIdentity(
            tier=IdentityTier.BLS, fingerprint=fp, bls_pk=bytes([i]) * 48,
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
        # Enroll a new writer not on the committee
        fp_new = bytes([99]) * 32
        identity = WriterIdentity(
            tier=IdentityTier.BLS, fingerprint=fp_new, bls_pk=bytes([99]) * 48,
        )
        reg.enroll(identity, timestamp=9000)
        reg.approve(fp_new, admin_fp=ADMIN_FP, timestamp=9001)
        record = reg.lookup(fp_new)
        # This should not raise or affect the roster
        mgr.on_writer_state_change(record, WriterState.ACTIVE, WriterState.SUSPENDED)
        assert len(mgr.roster.active_members) == 3


class TestCommitteeManagerHalt:
    def test_is_halted_when_hard_floor_breached(self):
        mgr, reg, _ = _setup(
            n_writers=2, epoch_length=100,
            min_committee_size=2, floor_mode=FloorMode.HARD,
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_committee_manager.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement CommitteeManager**

```python
# src/ltp/execution/committee/manager.py
"""CommitteeManager — top-level coordinator (Spec C3a §9)."""

from __future__ import annotations

from typing import Optional

from .types import CommitteeRoster, EpochRecord
from .policy import CommitteePolicy
from .formation import CommitteeFormation
from .epoch import EpochManager
from .eviction import EvictionHandler
from .standby import StandbySelector
from ..writer import WriterRecord, WriterState
from ..writer_recovery import EmergencyState
from ..writer_registry import WriterRegistry

__all__ = ["CommitteeManager"]


class CommitteeManager:
    """Top-level coordinator — one per VM."""

    def __init__(
        self,
        vm_tag: int,
        policy: CommitteePolicy,
        registry: WriterRegistry,
        emergency: EmergencyState,
    ) -> None:
        self._vm_tag = vm_tag
        self._policy = policy
        self._registry = registry
        self._formation = CommitteeFormation(registry)
        self._standby = StandbySelector(policy)
        self._eviction = EvictionHandler(policy, self._standby)
        self._epoch_mgr = EpochManager(vm_tag, policy, self._formation, emergency)

    def on_writer_state_change(
        self,
        writer: WriterRecord,
        old_state: WriterState,
        new_state: WriterState,
    ) -> None:
        """Hook called by WriterRegistry transitions."""
        roster = self._epoch_mgr.roster
        if roster is None:
            return
        self._eviction.handle_state_change(
            roster, writer.identity.fingerprint, old_state, new_state,
            timestamp=0,  # caller should provide real timestamp
        )

    def tick(self, current_round: int, timestamp_ms: int) -> bool:
        """Called every round. Returns True if epoch advanced."""
        return self._epoch_mgr.check_advance(current_round, timestamp_ms)

    @property
    def roster(self) -> Optional[CommitteeRoster]:
        return self._epoch_mgr.roster

    @property
    def epoch(self) -> int:
        return self._epoch_mgr.current_epoch

    @property
    def is_halted(self) -> bool:
        return self._eviction.is_halted

    def is_member(self, writer_fp: bytes) -> bool:
        roster = self._epoch_mgr.roster
        if roster is None:
            return False
        return any(m.writer_fp == writer_fp for m in roster.active_members)

    def history(self) -> list[EpochRecord]:
        return self._epoch_mgr.history
```

- [ ] **Step 4: Update `__init__.py` with full public API**

```python
# src/ltp/execution/committee/__init__.py
"""Committee formation and epoch management (Spec C3a)."""

from .types import (
    CommitteeRole,
    CommitteeMember,
    CommitteeRoster,
    EpochTrigger,
    EpochRecord,
    EvictionReason,
    EvictionEvent,
    CommitteeEvent,
)
from .policy import (
    EpochStrategy,
    FloorMode,
    StandbyStrategy,
    EvictionMode,
    CommitteePolicy,
)
from .formation import CommitteeFormation
from .epoch import EpochManager
from .eviction import EvictionHandler
from .standby import StandbySelector, score_member
from .manager import CommitteeManager

__all__ = [
    # Types
    "CommitteeRole", "CommitteeMember", "CommitteeRoster",
    "EpochTrigger", "EpochRecord",
    "EvictionReason", "EvictionEvent", "CommitteeEvent",
    # Policy
    "EpochStrategy", "FloorMode", "StandbyStrategy", "EvictionMode",
    "CommitteePolicy",
    # Core
    "CommitteeFormation", "EpochManager",
    "EvictionHandler", "StandbySelector", "score_member",
    # Coordinator
    "CommitteeManager",
]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_committee_manager.py -v`
Expected: All 7 tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/ltp/execution/committee/manager.py src/ltp/execution/committee/__init__.py tests/test_committee_manager.py
git commit -m "feat(committee): add CommitteeManager coordinator + full public API (C3a §9)"
```

---

### Task 8: EmergencyAction Extension + Module Exports

**Files:**
- Modify: `src/ltp/execution/writer_recovery.py` — add `FORCE_EPOCH_ADVANCE`
- Modify: `src/ltp/execution/__init__.py` — add committee exports
- Modify: `tests/test_writer_recovery.py` — update enum count assertion
- Test: (existing tests pass, new assertion added)

- [ ] **Step 1: Add FORCE_EPOCH_ADVANCE to EmergencyAction**

In `src/ltp/execution/writer_recovery.py`, add after `CLEAR_OVERRIDE`:

```python
    FORCE_EPOCH_ADVANCE = "force_epoch_advance"
```

- [ ] **Step 2: Update test assertion**

In `tests/test_writer_recovery.py`, change:

```python
    def test_eleven_actions_exist(self):
        assert len(EmergencyAction) == 11
```

to:

```python
    def test_twelve_actions_exist(self):
        assert len(EmergencyAction) == 12
```

And add a new test:

```python
    def test_force_epoch_advance(self):
        assert EmergencyAction.FORCE_EPOCH_ADVANCE.value == "force_epoch_advance"
```

- [ ] **Step 3: Add committee exports to execution __init__.py**

In `src/ltp/execution/__init__.py`, add after the `WriterGate` import block:

```python
# Committee Formation (Spec C3a)
from .committee import (
    CommitteeRole, CommitteeMember, CommitteeRoster,
    EpochTrigger, EpochRecord,
    EvictionReason, EvictionEvent, CommitteeEvent,
    EpochStrategy, FloorMode, StandbyStrategy, EvictionMode,
    CommitteePolicy,
    CommitteeFormation, EpochManager,
    EvictionHandler, StandbySelector,
    CommitteeManager,
)
```

And add to `__all__`:

```python
    # Committee Formation (Spec C3a)
    "CommitteeRole", "CommitteeMember", "CommitteeRoster",
    "EpochTrigger", "EpochRecord",
    "EvictionReason", "EvictionEvent", "CommitteeEvent",
    "EpochStrategy", "FloorMode", "StandbyStrategy", "EvictionMode",
    "CommitteePolicy",
    "CommitteeFormation", "EpochManager",
    "EvictionHandler", "StandbySelector",
    "CommitteeManager",
```

- [ ] **Step 4: Run all tests to verify no regressions**

Run: `pytest tests/test_writer_recovery.py tests/test_committee_*.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/ltp/execution/writer_recovery.py src/ltp/execution/__init__.py tests/test_writer_recovery.py
git commit -m "feat(committee): add FORCE_EPOCH_ADVANCE + execution exports (C3a §10)"
```

---

### Task 9: End-to-End Integration Test

**Files:**
- Create: `tests/test_committee_e2e.py`

- [ ] **Step 1: Write the E2E test**

```python
# tests/test_committee_e2e.py
"""End-to-end integration tests for committee layer (Spec C3a)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.manager import CommitteeManager
from src.ltp.execution.committee.types import EpochTrigger, EvictionReason
from src.ltp.execution.committee.policy import (
    CommitteePolicy,
    EpochStrategy,
    FloorMode,
    EvictionMode,
    StandbyStrategy,
)
from src.ltp.execution.writer import IdentityTier, WriterIdentity, WriterState
from src.ltp.execution.writer_recovery import EmergencyState
from src.ltp.execution.writer_registry import WriterRegistry

ADMIN_FP = b"\xff" * 32


def _enroll_active(reg, fp_byte, tier=IdentityTier.BLS):
    fp = bytes([fp_byte]) * 32
    bls_pk = bytes([fp_byte]) * 48 if tier in (IdentityTier.BLS, IdentityTier.COMPOSITE) else None
    mldsa_vk = bytes([fp_byte]) * 32 if tier in (IdentityTier.MLDSA, IdentityTier.COMPOSITE) else None
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
        # Suspended writer excluded from new roster
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
        # Both active should be COMPOSITE
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

        # Manual strategy — tick never advances
        assert mgr.tick(9999, 9999) is False
        assert mgr.epoch == 0

        # Emergency advance works
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
            vm_tag=0x01, epoch_length=10,
            min_committee_size=2, floor_mode=FloorMode.HARD,
        )
        mgr = CommitteeManager(0x01, policy, reg, emergency)
        mgr.tick(10, 1000)
        assert len(mgr.roster.active_members) == 2

        # Revoke one — drops below floor
        fp = bytes([1]) * 32
        record = reg.lookup(fp)
        reg.revoke(fp, reason="test", actor_fp=ADMIN_FP, timestamp=3000)
        mgr.on_writer_state_change(record, WriterState.ACTIVE, WriterState.REVOKED)
        assert mgr.is_halted

        # Enroll a replacement and admin-advance to recover
        _enroll_active(reg, 10)
        mgr._epoch_mgr.admin_advance(ADMIN_FP, timestamp=4000)
        assert mgr.epoch == 2
        assert len(mgr.roster.active_members) == 2
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `pytest tests/test_committee_e2e.py -v`
Expected: All 5 tests PASS

- [ ] **Step 3: Run full regression**

Run: `pytest tests/ -v --tb=short`
Expected: All tests PASS (3,263 existing + ~80 new committee tests), 0 failures

- [ ] **Step 4: Commit**

```bash
git add tests/test_committee_e2e.py
git commit -m "test(committee): add E2E integration tests (C3a full lifecycle)"
```

---

### Task 10: Hypothesis Property-Based Tests

**Files:**
- Create: `tests/test_committee_hypothesis.py`

- [ ] **Step 1: Write property-based tests**

```python
# tests/test_committee_hypothesis.py
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
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `pytest tests/test_committee_hypothesis.py -v`
Expected: All 6 tests PASS

- [ ] **Step 3: Run full regression**

Run: `pytest tests/ --tb=short`
Expected: All tests PASS, 0 failures

- [ ] **Step 4: Commit**

```bash
git add tests/test_committee_hypothesis.py
git commit -m "test(committee): add Hypothesis property-based tests (C3a)"
```
