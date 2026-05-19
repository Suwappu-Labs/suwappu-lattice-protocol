"""ExecutionMonitor — rolling failure window and halt logic (Spec D1c §5)."""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING

from .execution_events import ExecutionEvent, ExecutionEventType

if TYPE_CHECKING:
    from .execution_config import ExecutionConfig
    from .types import BatchResult

__all__ = ["ExecutionMonitor"]


class ExecutionMonitor:
    """Tracks failure rates across a rolling window and triggers warnings or halt."""

    def __init__(self, config: ExecutionConfig) -> None:
        self._config = config
        self._window: deque[tuple[int, int]] = deque(maxlen=config.failure_window)
        self._total_batches = 0
        self._total_tx_success = 0
        self._total_tx_failure = 0
        self._halt = False

    def record(self, batch_result: BatchResult, catastrophic: bool) -> list[ExecutionEvent]:
        """Record outcome, compute failure rate, emit events."""
        events: list[ExecutionEvent] = []

        successes = sum(1 for r in batch_result.tx_results if r.success)
        failures = sum(1 for r in batch_result.tx_results if not r.success)

        self._window.append((successes, failures))
        self._total_batches += 1
        self._total_tx_success += successes
        self._total_tx_failure += failures

        if catastrophic and self._config.halt_on_catastrophic:
            self._halt = True
            events.append(
                ExecutionEvent(
                    event_type=ExecutionEventType.EXECUTION_HALTED,
                    round=batch_result.round,
                    epoch=0,
                    timestamp_ms=0,
                    payload={
                        "round": batch_result.round,
                        "epoch": 0,
                        "reason": "catastrophic_error",
                        "error": "batch execution raised exception",
                    },
                )
            )

        rate = self.failure_rate()
        if rate > self._config.failure_threshold_pct / 100.0:
            events.append(
                ExecutionEvent(
                    event_type=ExecutionEventType.FAILURE_THRESHOLD_WARNING,
                    round=batch_result.round,
                    epoch=0,
                    timestamp_ms=0,
                    payload={
                        "failure_rate": rate,
                        "threshold": self._config.failure_threshold_pct,
                        "window": self._config.failure_window,
                        "round": batch_result.round,
                    },
                )
            )

        return events

    def should_halt(self) -> bool:
        return self._halt

    def failure_rate(self) -> float:
        total_s = sum(s for s, _ in self._window)
        total_f = sum(f for _, f in self._window)
        total = total_s + total_f
        if total == 0:
            return 0.0
        return total_f / total

    @property
    def total_batches(self) -> int:
        return self._total_batches

    @property
    def total_tx_success(self) -> int:
        return self._total_tx_success

    @property
    def total_tx_failure(self) -> int:
        return self._total_tx_failure

    def reset(self, old_epoch: int, new_epoch: int) -> list[ExecutionEvent]:
        """Reset counters for epoch transition."""
        prev_batches = self._total_batches
        self._window.clear()
        self._total_batches = 0
        self._total_tx_success = 0
        self._total_tx_failure = 0
        self._halt = False

        return [
            ExecutionEvent(
                event_type=ExecutionEventType.EPOCH_METRICS_RESET,
                round=0,
                epoch=new_epoch,
                timestamp_ms=0,
                payload={
                    "old_epoch": old_epoch,
                    "new_epoch": new_epoch,
                    "total_batches_prev": prev_batches,
                },
            )
        ]
