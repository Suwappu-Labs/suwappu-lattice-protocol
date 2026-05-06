"""ConsensusAdapter protocol and testing implementations."""

from __future__ import annotations

from typing import Iterator, Protocol, runtime_checkable

from .types import OrderedBatch


@runtime_checkable
class ConsensusAdapter(Protocol):
    """Pluggable adapter — one per consensus engine type.

    Consensus sits upstream and delivers ordered transaction batches
    to the ETP execution layer.
    """

    def start(self) -> None: ...

    def stop(self) -> None: ...

    def stream_batches(self) -> Iterator[OrderedBatch]: ...

    def submit_transaction(self, tx_bytes: bytes) -> bytes: ...

    def current_round(self) -> int: ...

    def consensus_type(self) -> str: ...


class FakeConsensusAdapter:
    """Deterministic consensus adapter for testing.

    Yields predetermined batches in order. No threading, no network.
    """

    def __init__(
        self,
        batches: list[OrderedBatch],
        consensus_type: str = "dag",
    ) -> None:
        self._batches = list(batches)
        self._consensus_type = consensus_type
        self._current_round = 0
        self._running = False

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False

    def stream_batches(self) -> Iterator[OrderedBatch]:
        for batch in self._batches:
            self._current_round = batch.round
            yield batch

    def submit_transaction(self, tx_bytes: bytes) -> bytes:
        return b""

    def current_round(self) -> int:
        return self._current_round

    def consensus_type(self) -> str:
        return self._consensus_type
