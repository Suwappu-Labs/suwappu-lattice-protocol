"""EVMExecutor — wraps EVM interaction as an ExecutionModel.

This is the stub implementation for Gate 4. It maintains an in-memory
state root that updates on each execute() call. Future versions will
connect to a Geth JSON-RPC node.
"""

from __future__ import annotations

from ...primitives import canonical_hash_bytes
from ..model import VM_TAG_EVM
from ..types import StateQuery, StateResult, TxResult


class EVMExecutor:
    """EVM executor — account-based VM (tag 0x01)."""

    vm_tag = VM_TAG_EVM
    vm_name = "evm"
    family = "account"

    def __init__(self) -> None:
        self._state_root = canonical_hash_bytes(b"evm-genesis-state")
        self._tx_count = 0

    def execute(self, tx_bytes: bytes) -> TxResult:
        """Execute an EVM transaction. Updates internal state root."""
        self._tx_count += 1
        self._state_root = canonical_hash_bytes(
            self._state_root + tx_bytes + self._tx_count.to_bytes(8, "big")
        )
        return TxResult.accepted(gas_used=21000)

    def state_root(self) -> bytes:
        """Return current 32-byte EVM state root."""
        return self._state_root

    def validate_tx(self, tx_bytes: bytes) -> bool:
        return len(tx_bytes) > 0

    def query_state(self, query: StateQuery) -> StateResult:
        """Stub: no queryable state in this implementation."""
        return StateResult.not_found()
