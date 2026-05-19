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
    ACTIVE = "active"
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
    ROUND_COUNT = "round_count"
    ADMIN_SIGNAL = "admin_signal"
    EMERGENCY = "emergency"
    TIME_BASED = "time_based"


@dataclass(frozen=True)
class EpochRecord:
    vm_tag: int
    epoch: int
    roster: CommitteeRoster
    trigger: EpochTrigger
    previous_epoch: int
    timestamp: int


class EvictionReason(str, Enum):
    REVOKED = "revoked"
    SUSPENDED = "suspended"
    EXPIRED = "expired"
    ADMIN = "admin"


@dataclass(frozen=True)
class EvictionEvent:
    writer_fp: bytes
    vm_tag: int
    epoch: int
    reason: EvictionReason
    backfill_fp: Optional[bytes]
    timestamp: int


class CommitteeEvent(str, Enum):
    MEMBER_EVICTED = "member_evicted"
    MEMBER_BACKFILLED = "member_backfilled"
    COMMITTEE_HALTED = "committee_halted"
    BELOW_FLOOR = "below_floor"
    FLOOR_RESTORED = "floor_restored"
