"""Consensus event system (Spec D1b §1)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ConsensusEventType(Enum):
    """Types of consensus-layer events."""

    EPOCH_TRANSITION = "epoch_transition"
    VALIDATOR_EVICTED = "validator_evicted"
    COMMIT_ATTESTED = "commit_attested"
    ENGINE_REBUILT = "engine_rebuilt"
    # D1c: Execution pipeline events
    BATCH_EXECUTED = "batch_executed"
    STATE_ROOT_ATTESTED = "state_root_attested"


@dataclass(frozen=True)
class ConsensusEvent:
    """A single consensus-layer event with typed payload."""

    event_type: ConsensusEventType
    epoch: int
    round: int
    timestamp_ms: int
    payload: dict
