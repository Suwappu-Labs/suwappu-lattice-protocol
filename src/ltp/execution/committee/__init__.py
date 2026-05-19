"""Committee formation and epoch management (Spec C3a)."""

# DKG (Spec C3b) + Threshold Signing (Spec C3c)
from .dkg import (
    DOMAIN_ATTESTATION,
    DOMAIN_CROSS_VM,
    DOMAIN_STATE_ROOT,
    DKGCommitment,
    DKGComplaint,
    DKGKeyRegistry,
    DKGPhase,
    DKGResult,
    DKGSessionConfig,
    DKGShare,
    DKGState,
    DKGTransport,
    FakeDKGTransport,
    PartialSignature,
    ScalarField,
    ScalarPoly,
    ThresholdSigningKey,
)
from .epoch import EpochManager
from .eviction import EvictionHandler
from .formation import CommitteeFormation
from .manager import CommitteeManager
from .policy import (
    CommitteePolicy,
    EpochStrategy,
    EvictionMode,
    FloorMode,
    StandbyStrategy,
)
from .standby import StandbySelector, score_member
from .types import (
    CommitteeEvent,
    CommitteeMember,
    CommitteeRole,
    CommitteeRoster,
    EpochRecord,
    EpochTrigger,
    EvictionEvent,
    EvictionReason,
)

__all__ = [
    # Types
    "CommitteeRole",
    "CommitteeMember",
    "CommitteeRoster",
    "EpochTrigger",
    "EpochRecord",
    "EvictionReason",
    "EvictionEvent",
    "CommitteeEvent",
    # Policy
    "EpochStrategy",
    "FloorMode",
    "StandbyStrategy",
    "EvictionMode",
    "CommitteePolicy",
    # Core
    "CommitteeFormation",
    "EpochManager",
    "EvictionHandler",
    "StandbySelector",
    "score_member",
    # Coordinator
    "CommitteeManager",
    # DKG (Spec C3b)
    "DKGState",
    "DKGPhase",
    "DKGCommitment",
    "DKGShare",
    "DKGComplaint",
    "DKGResult",
    "DKGSessionConfig",
    "ScalarField",
    "ScalarPoly",
    "DKGTransport",
    "FakeDKGTransport",
    "DKGKeyRegistry",
    # Threshold Signing (Spec C3c)
    "ThresholdSigningKey",
    "PartialSignature",
    "DOMAIN_ATTESTATION",
    "DOMAIN_STATE_ROOT",
    "DOMAIN_CROSS_VM",
]
