"""Consensus backend abstraction (Spec D1b §4)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator

from .engine import LocalMysticetiEngine
from .faults import FaultConfig
from .types import CommitDecision

__all__ = ["ConsensusBackend", "LocalConsensusBackend"]


class ConsensusBackend(ABC):
    """Abstract interface for a consensus engine.

    LocalConsensusBackend wraps the in-process Mysticeti engine.
    Future GrpcConsensusBackend (D2+) will implement the same contract.
    """

    @abstractmethod
    def start(self) -> None: ...

    @abstractmethod
    def stop(self) -> None: ...

    @abstractmethod
    def submit_transactions(self, txs: list[bytes]) -> None: ...

    @abstractmethod
    def advance_round(self) -> int: ...

    @abstractmethod
    def run_rounds(self, n: int) -> list[CommitDecision]: ...

    @abstractmethod
    def stream_commits(self) -> Iterator[CommitDecision]: ...

    @abstractmethod
    def current_round(self) -> int: ...

    @abstractmethod
    def inject_fault(self, fault: FaultConfig) -> None: ...

    @abstractmethod
    def get_validator_count(self) -> int: ...

    @abstractmethod
    def rebuild(self, num_validators: int, fault_tolerance: int | None = None) -> None: ...


class LocalConsensusBackend(ConsensusBackend):
    """Wraps LocalMysticetiEngine. All methods delegate directly."""

    def __init__(
        self,
        num_validators: int,
        fault_tolerance: int | None = None,
        round_timeout_ms: int = 1000,
    ) -> None:
        self._round_timeout_ms = round_timeout_ms
        self._engine = LocalMysticetiEngine(
            num_validators,
            fault_tolerance=fault_tolerance,
            round_timeout_ms=round_timeout_ms,
        )

    def start(self) -> None:
        self._engine.start()

    def stop(self) -> None:
        self._engine.stop()

    def submit_transactions(self, txs: list[bytes]) -> None:
        self._engine.submit_transactions(txs)

    def advance_round(self) -> int:
        return self._engine.advance_round()

    def run_rounds(self, n: int) -> list[CommitDecision]:
        return self._engine.run_rounds(n)

    def stream_commits(self) -> Iterator[CommitDecision]:
        return self._engine.stream_commits()

    def current_round(self) -> int:
        return self._engine._current_round

    def inject_fault(self, fault: FaultConfig) -> None:
        self._engine.inject_fault(fault)

    def get_validator_count(self) -> int:
        return self._engine._n

    def rebuild(self, num_validators: int, fault_tolerance: int | None = None) -> None:
        self._engine = LocalMysticetiEngine(
            num_validators,
            fault_tolerance=fault_tolerance,
            round_timeout_ms=self._round_timeout_ms,
        )
