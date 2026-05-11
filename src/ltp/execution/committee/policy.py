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

    # --- DKG (Spec C3b) ---
    dkg_threshold: int = 0
    dkg_timeout_rounds: int = 10
    dkg_eager_start_rounds: int = 5
