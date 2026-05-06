"""MoveExecutor — gRPC client to Mysticeti sidecar for Sui Move execution.

The backend parameter abstracts the gRPC connection. In tests, use
FakeMoveBackend. In production, use MysticetiGrpcBackend (which wraps
the grpcio client). This is also the PyO3 FFI swap point — a
PyO3MoveBackend implements the same interface without gRPC.
"""

from __future__ import annotations

from typing import Protocol, Optional

from ..model import VM_TAG_MOVE
from ..types import StateQuery, StateResult, TxResult


class MoveBackend(Protocol):
    """Abstract backend for Move execution — gRPC or FFI."""
    def execute_transaction(self, tx_bytes: bytes) -> tuple[bool, bytes]: ...
    def query_state(self, key: bytes) -> Optional[bytes]: ...
    def get_state_root(self) -> bytes: ...


class MoveExecutor:
    """Sui Move executor — object-based VM (tag 0x10).

    Delegates execution to a MoveBackend (gRPC sidecar or PyO3 FFI).
    """

    vm_tag = VM_TAG_MOVE
    vm_name = "move"
    family = "object"

    def __init__(self, backend: MoveBackend) -> None:
        self._backend = backend

    def execute(self, tx_bytes: bytes) -> TxResult:
        """Execute a Move transaction via the backend."""
        try:
            success, _new_root = self._backend.execute_transaction(tx_bytes)
        except Exception as exc:
            return TxResult.failed(f"move execution error: {exc}")
        if success:
            return TxResult.accepted()
        return TxResult.failed("move execution rejected")

    def state_root(self) -> bytes:
        """Return current 32-byte Move state root from the backend."""
        return self._backend.get_state_root()

    def validate_tx(self, tx_bytes: bytes) -> bool:
        return len(tx_bytes) > 0

    def query_state(self, query: StateQuery) -> StateResult:
        """Query Move object state."""
        try:
            value = self._backend.query_state(query.key)
        except Exception:
            return StateResult.not_found()
        if value is not None:
            return StateResult(data=value, found=True)
        return StateResult.not_found()
