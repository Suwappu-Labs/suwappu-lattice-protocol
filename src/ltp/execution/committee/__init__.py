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

# DKG (Spec C3b)
from .dkg import (
    DKGState, DKGPhase,
    DKGCommitment, DKGShare, DKGComplaint,
    DKGResult, DKGSessionConfig,
    ScalarField, ScalarPoly,
    DKGTransport, FakeDKGTransport,
    DKGKeyRegistry,
)

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
    # DKG (Spec C3b)
    "DKGState", "DKGPhase",
    "DKGCommitment", "DKGShare", "DKGComplaint",
    "DKGResult", "DKGSessionConfig",
    "ScalarField", "ScalarPoly",
    "DKGTransport", "FakeDKGTransport",
    "DKGKeyRegistry",
]
