"""Tests for MoveExecutor — gRPC client to Mysticeti sidecar."""

import pytest
from src.ltp.execution.types import TxResult, StateQuery, StateResult


class FakeMoveBackend:
    """Simulates the Mysticeti sidecar's gRPC responses."""
    def __init__(self):
        self._state = {}
        self._state_root = b"\x00" * 32
        self._tx_count = 0

    def execute_transaction(self, tx_bytes: bytes) -> tuple[bool, bytes]:
        """Returns (success, new_state_root)."""
        from src.ltp.primitives import canonical_hash_bytes
        self._tx_count += 1
        self._state_root = canonical_hash_bytes(
            self._state_root + tx_bytes + self._tx_count.to_bytes(8, "big")
        )
        return True, self._state_root

    def query_state(self, key: bytes) -> bytes | None:
        return self._state.get(key)

    def get_state_root(self) -> bytes:
        return self._state_root


class TestMoveExecutor:
    def test_satisfies_execution_model(self):
        from src.ltp.execution.executors.move import MoveExecutor
        from src.ltp.execution.model import ExecutionModel, VM_TAG_MOVE

        backend = FakeMoveBackend()
        executor = MoveExecutor(backend=backend)
        assert isinstance(executor, ExecutionModel)
        assert executor.vm_tag == VM_TAG_MOVE
        assert executor.vm_name == "move"
        assert executor.family == "object"

    def test_execute_updates_state_root(self):
        from src.ltp.execution.executors.move import MoveExecutor
        backend = FakeMoveBackend()
        executor = MoveExecutor(backend=backend)

        root_before = executor.state_root()
        result = executor.execute(b"move_transaction")
        root_after = executor.state_root()

        assert result.success is True
        assert root_before != root_after

    def test_state_root_32_bytes(self):
        from src.ltp.execution.executors.move import MoveExecutor
        backend = FakeMoveBackend()
        executor = MoveExecutor(backend=backend)
        assert len(executor.state_root()) == 32

    def test_query_state_found(self):
        from src.ltp.execution.executors.move import MoveExecutor
        backend = FakeMoveBackend()
        backend._state[b"\x01" * 32] = b"object_data"
        executor = MoveExecutor(backend=backend)

        result = executor.query_state(StateQuery(target_vm=0x10, query_type="object", key=b"\x01" * 32))
        assert result.found is True
        assert result.data == b"object_data"

    def test_query_state_not_found(self):
        from src.ltp.execution.executors.move import MoveExecutor
        backend = FakeMoveBackend()
        executor = MoveExecutor(backend=backend)

        result = executor.query_state(StateQuery(target_vm=0x10, query_type="object", key=b"\x02" * 32))
        assert result.found is False

    def test_backend_failure_returns_failed_result(self):
        from src.ltp.execution.executors.move import MoveExecutor

        class FailingBackend:
            def execute_transaction(self, tx_bytes):
                raise ConnectionError("sidecar down")
            def query_state(self, key):
                return None
            def get_state_root(self):
                raise ConnectionError("sidecar down")

        executor = MoveExecutor(backend=FailingBackend())
        result = executor.execute(b"tx")
        assert result.success is False
        assert "sidecar" in result.error
