"""Execution-layer event system (Spec D1c §1)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ExecutionEventType(Enum):
    """Types of execution-layer events."""

    LOOP_STARTED = "loop_started"
    LOOP_STOPPED = "loop_stopped"
    FAILURE_THRESHOLD_WARNING = "failure_threshold_warning"
    EXECUTION_HALTED = "execution_halted"
    EPOCH_METRICS_RESET = "epoch_metrics_reset"


@dataclass(frozen=True)
class ExecutionEvent:
    """A single execution-layer event with typed payload."""

    event_type: ExecutionEventType
    round: int
    epoch: int
    timestamp_ms: int
    payload: dict
