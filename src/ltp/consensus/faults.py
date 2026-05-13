"""Byzantine fault injection types (Spec D1a §3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class FaultType(Enum):
    """Types of Byzantine behavior a validator can exhibit."""

    HONEST = "honest"
    EQUIVOCATE = "equivocate"
    WITHHOLD = "withhold"
    CRASH = "crash"
    DELAY = "delay"
    CENSOR = "censor"


@dataclass(frozen=True)
class FaultConfig:
    """Configuration for a single fault injection."""

    validator: int
    fault_type: FaultType
    start_round: int
    end_round: int | None = None
    params: dict = field(default_factory=dict)


@dataclass(frozen=True)
class PartitionConfig:
    """Network partition between two groups of validators."""

    group_a: frozenset[int]
    group_b: frozenset[int]
    start_round: int
    duration: int | None = None
