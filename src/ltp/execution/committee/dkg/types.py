"""Core data types for the DKG layer (Spec C3b §2)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

__all__ = [
    "DKGState",
    "DKGPhase",
    "DKGCommitment",
    "DKGShare",
    "DKGComplaint",
    "DKGResult",
    "DKGSessionConfig",
]


class DKGState(str, Enum):
    IDLE        = "idle"
    COMMITTING  = "committing"
    SHARING     = "sharing"
    VERIFYING   = "verifying"
    COMPLAINING = "complaining"
    FINALIZING  = "finalizing"
    COMPLETED   = "completed"
    FAILED      = "failed"


class DKGPhase(str, Enum):
    EAGER  = "eager"
    INLINE = "inline"


@dataclass(frozen=True)
class DKGCommitment:
    dealer_fp: bytes
    feldman_commitments: list[bytes]
    pedersen_commitments: list[bytes]
    round_id: int


@dataclass(frozen=True)
class DKGShare:
    dealer_fp: bytes
    recipient_fp: bytes
    share: int
    blinding_share: int


@dataclass(frozen=True)
class DKGComplaint:
    complainant_fp: bytes
    dealer_fp: bytes
    revealed_share: int
    revealed_blinding: int
    round_id: int


@dataclass(frozen=True)
class DKGResult:
    vm_tag: int
    epoch: int
    group_pk: bytes
    participant_vks: dict[bytes, bytes]
    threshold: int
    qual_set: frozenset[bytes]
    phase: DKGPhase


@dataclass
class DKGSessionConfig:
    vm_tag: int
    epoch: int
    threshold: int
    participants: list[bytes]
    timeout_rounds: int
    start_round: int
