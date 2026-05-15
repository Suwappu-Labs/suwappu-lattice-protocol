"""Mysticeti DAG-BFT consensus engine (Specs D1a, D1b)."""

from .types import (
    Block,
    Certificate,
    CommitDecision,
    EquivocationProof,
    RoundState,
)
from .dag_store import DAGStore
from .protocol import MysticetiProtocol
from .commit_rule import (
    evaluate_direct_commit,
    evaluate_indirect_commit,
    collect_causal_history,
)
from .engine import LocalMysticetiEngine, to_ordered_batch
from .faults import FaultType, FaultConfig, PartitionConfig
from .message_bus import MessageBus
from .events import ConsensusEvent, ConsensusEventType
from .validator_set import ValidatorInfo, ValidatorSet
from .bls_certificates import (
    DOMAIN_CONSENSUS_ACK,
    BLSCertificateManager,
    SignedCertificate,
)
from .backend import ConsensusBackend, LocalConsensusBackend
from .committee_sync import CommitteeSync
from .adapter import MysticetiAdapter

__all__ = [
    # D1a: DAG data structures
    "Block",
    "Certificate",
    "CommitDecision",
    "EquivocationProof",
    "RoundState",
    # D1a: Storage
    "DAGStore",
    # D1a: Protocol
    "MysticetiProtocol",
    # D1a: Commit rule
    "evaluate_direct_commit",
    "evaluate_indirect_commit",
    "collect_causal_history",
    # D1a: Engine
    "LocalMysticetiEngine",
    "to_ordered_batch",
    # D1a: Fault injection
    "FaultType",
    "FaultConfig",
    "PartitionConfig",
    # D1a: Message bus
    "MessageBus",
    # D1b: Events
    "ConsensusEvent",
    "ConsensusEventType",
    # D1b: Validator Set
    "ValidatorInfo",
    "ValidatorSet",
    # D1b: BLS Certificates
    "DOMAIN_CONSENSUS_ACK",
    "BLSCertificateManager",
    "SignedCertificate",
    # D1b: Backend
    "ConsensusBackend",
    "LocalConsensusBackend",
    # D1b: Committee Sync
    "CommitteeSync",
    # D1b: Adapter
    "MysticetiAdapter",
]
