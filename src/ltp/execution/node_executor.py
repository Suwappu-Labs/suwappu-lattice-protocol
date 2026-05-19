"""NodeExecutor — execution pipeline orchestrator (Spec D1c §6)."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from ..consensus.events import ConsensusEvent, ConsensusEventType
from .batch_executor import BatchExecutor
from .execution_config import ExecutionConfig
from .execution_events import ExecutionEvent, ExecutionEventType
from .execution_monitor import ExecutionMonitor
from .state_attestor import AttestationResult, StateAttestor

if TYPE_CHECKING:
    from .attestation import AttestationEngine
    from .consensus import ConsensusAdapter
    from .router import TransactionRouter
    from .types import OrderedBatch

__all__ = ["RoundResult", "NodeExecutor"]


@dataclass(frozen=True)
class RoundResult:
    """Result of executing one consensus round through the full pipeline."""

    batch_result: object  # BatchResult
    attestation: Optional[AttestationResult]
    consensus_events: list[ConsensusEvent]
    execution_events: list[ExecutionEvent]
    round: int
    epoch: int
    halted: bool


class NodeExecutor:
    """Orchestrates BatchExecutor + StateAttestor + ExecutionMonitor."""

    def __init__(
        self,
        consensus: ConsensusAdapter,
        router: TransactionRouter,
        attestation_engine: Optional[AttestationEngine] = None,
        committee_manager: object | None = None,
        config: ExecutionConfig | None = None,
    ) -> None:
        self._consensus = consensus
        self._config = config or ExecutionConfig()
        self._batch_executor = BatchExecutor(router)
        self._state_attestor = StateAttestor(
            attestation_engine,
            committee_manager,
            self._config,
        )
        self._monitor = ExecutionMonitor(self._config)
        self._results: list[RoundResult] = []
        self._consensus_events: list[ConsensusEvent] = []
        self._execution_events: list[ExecutionEvent] = []
        self._running = False
        self._halted = False
        self._loop_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def execute_round(self, batch: OrderedBatch) -> RoundResult:
        """Execute one round through the full pipeline."""
        consensus_events: list[ConsensusEvent] = []
        execution_events: list[ExecutionEvent] = []

        # 1. Execute batch
        batch_result = self._batch_executor.execute(batch)
        catastrophic = self._batch_executor.last_was_catastrophic()

        # 2. Attest state root (skip on catastrophic)
        attestation = None
        if not catastrophic and batch_result.state_root is not None:
            attestation = self._state_attestor.attest(batch_result, batch.epoch)

        # 3. Record in monitor
        monitor_events = self._monitor.record(batch_result, catastrophic)
        execution_events.extend(monitor_events)

        # 4. Tick consensus adapter (if it has tick method — MysticetiAdapter does)
        if hasattr(self._consensus, "tick"):
            adapter_events = self._consensus.tick(batch.round, batch.timestamp_ms)
            consensus_events.extend(adapter_events)

            # Handle epoch transitions
            for evt in adapter_events:
                if evt.event_type == ConsensusEventType.EPOCH_TRANSITION:
                    old_epoch = evt.payload.get("old_epoch", 0)
                    new_epoch = evt.payload.get("new_epoch", 0)
                    reset_events = self._monitor.reset(old_epoch, new_epoch)
                    execution_events.extend(reset_events)

        # 5. Emit BATCH_EXECUTED
        success_count = sum(1 for r in batch_result.tx_results if r.success)
        failure_count = sum(1 for r in batch_result.tx_results if not r.success)
        batch_event = ConsensusEvent(
            event_type=ConsensusEventType.BATCH_EXECUTED,
            epoch=batch.epoch,
            round=batch.round,
            timestamp_ms=batch.timestamp_ms,
            payload={
                "round": batch.round,
                "epoch": batch.epoch,
                "tx_count": len(batch_result.tx_results),
                "success_count": success_count,
                "failure_count": failure_count,
                "state_root": batch_result.state_root.root if batch_result.state_root else None,
            },
        )
        consensus_events.append(batch_event)

        # 6. Emit STATE_ROOT_ATTESTED
        if attestation is not None and attestation.mode != "none":
            attest_event = ConsensusEvent(
                event_type=ConsensusEventType.STATE_ROOT_ATTESTED,
                epoch=batch.epoch,
                round=batch.round,
                timestamp_ms=batch.timestamp_ms,
                payload={
                    "round": batch.round,
                    "epoch": batch.epoch,
                    "state_root": attestation.state_root,
                    "mode": attestation.mode,
                    "bls_signed": attestation.bls_signature is not None,
                },
            )
            consensus_events.append(attest_event)

        # 7. Check halt
        halted = self._monitor.should_halt()
        if halted:
            self._halted = True

        # 8. Store and return
        self._consensus_events.extend(consensus_events)
        self._execution_events.extend(execution_events)

        result = RoundResult(
            batch_result=batch_result,
            attestation=attestation,
            consensus_events=consensus_events,
            execution_events=execution_events,
            round=batch.round,
            epoch=batch.epoch,
            halted=halted,
        )
        self._results.append(result)
        return result

    def run_rounds(self, n: int) -> list[RoundResult]:
        """Synchronous: consume n batches from adapter's stream_batches()."""
        self._consensus.start()
        results = []
        count = 0
        for batch in self._consensus.stream_batches():
            if count >= n or self._halted:
                break
            results.append(self.execute_round(batch))
            count += 1
        self._consensus.stop()
        return results

    def run_loop(self) -> None:
        """Async: pull from stream_batches() in background thread until stop/halt."""
        self._stop_event.clear()

        loop_event = ExecutionEvent(
            event_type=ExecutionEventType.LOOP_STARTED,
            round=self._consensus.current_round(),
            epoch=0,
            timestamp_ms=0,
            payload={"round": self._consensus.current_round(), "epoch": 0},
        )
        self._execution_events.append(loop_event)

        def _loop():
            for batch in self._consensus.stream_batches():
                if self._stop_event.is_set() or self._halted:
                    break
                self.execute_round(batch)

            stop_event = ExecutionEvent(
                event_type=ExecutionEventType.LOOP_STOPPED,
                round=self._consensus.current_round(),
                epoch=0,
                timestamp_ms=0,
                payload={
                    "round": self._consensus.current_round(),
                    "epoch": 0,
                    "total_batches": self._monitor.total_batches,
                },
            )
            self._execution_events.append(stop_event)

        self._loop_thread = threading.Thread(target=_loop, daemon=True)
        self._loop_thread.start()

    def start(self) -> None:
        """Start consensus adapter and run loop."""
        self._consensus.start()
        self._running = True
        self.run_loop()

    def stop(self) -> None:
        """Stop loop and consensus adapter."""
        self._stop_event.set()
        if self._loop_thread is not None:
            self._loop_thread.join(timeout=5.0)
        self._consensus.stop()
        self._running = False

    def submit_transaction(self, tx_bytes: bytes) -> bytes:
        return self._consensus.submit_transaction(tx_bytes)

    def is_running(self) -> bool:
        return self._running

    def is_halted(self) -> bool:
        return self._halted

    def current_round(self) -> int:
        return self._consensus.current_round()

    def event_history(self) -> list:
        """All consensus + execution events."""
        return list(self._consensus_events) + list(self._execution_events)

    def results(self) -> list[RoundResult]:
        return list(self._results)
