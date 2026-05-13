"""Mysticeti DAG-BFT consensus engine (Spec D1a)."""

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

__all__ = [
    # DAG data structures
    "Block",
    "Certificate",
    "CommitDecision",
    "EquivocationProof",
    "RoundState",
    # Storage
    "DAGStore",
    # Protocol
    "MysticetiProtocol",
    # Commit rule
    "evaluate_direct_commit",
    "evaluate_indirect_commit",
    "collect_causal_history",
    # Engine
    "LocalMysticetiEngine",
    "to_ordered_batch",
    # Fault injection
    "FaultType",
    "FaultConfig",
    "PartitionConfig",
    # Message bus
    "MessageBus",
]
