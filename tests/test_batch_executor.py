"""Tests for BatchExecutor — wraps TransactionRouter with catastrophic capture (Spec D1c §3)."""

import pytest

from src.ltp.execution.batch_executor import BatchExecutor
from src.ltp.execution.registry import VMRegistry
from src.ltp.execution.router import TransactionRouter
from src.ltp.execution.types import BatchResult, OrderedBatch, StateResult, TxResult


class FakeExecutor:
    def __init__(self, tag: int, name: str = "fake", family: str = "account"):
        self.vm_tag = tag
        self.vm_name = name
        self.family = family
        self._root = bytes([tag]) * 32
        self._should_raise = False

    def execute(self, tx_bytes: bytes) -> TxResult:
        if self._should_raise:
            raise RuntimeError("executor crashed")
        return TxResult.accepted(gas_used=100)

    def state_root(self) -> bytes:
        if self._should_raise:
            raise RuntimeError("executor crashed")
        return self._root

    def validate_tx(self, tx_bytes: bytes) -> bool:
        return True

    def query_state(self, query) -> StateResult:
        return StateResult.not_found()


def _make_batch(txs: list[bytes], round_num: int = 0, epoch: int = 1) -> OrderedBatch:
    return OrderedBatch(
        round=round_num,
        epoch=epoch,
        transactions=txs,
        leader_authority=0,
        timestamp_ms=round_num * 1000,
        consensus_type="dag",
    )


def _build_router(*executors) -> TransactionRouter:
    reg = VMRegistry()
    for ex in executors:
        reg.register(ex)
    return TransactionRouter(reg)


class TestBatchExecutorNormal:
    def test_delegates_to_router(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        executor = BatchExecutor(router)
        batch = _make_batch([b"\x01hello"])
        result = executor.execute(batch)
        assert isinstance(result, BatchResult)
        assert len(result.tx_results) == 1
        assert result.tx_results[0].success is True

    def test_returns_state_root(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        executor = BatchExecutor(router)
        batch = _make_batch([b"\x01hello"])
        result = executor.execute(batch)
        assert result.state_root is not None
        assert len(result.state_root.root) == 32

    def test_not_catastrophic_on_success(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        executor = BatchExecutor(router)
        batch = _make_batch([b"\x01hello"])
        executor.execute(batch)
        assert executor.last_was_catastrophic() is False
        assert executor.last_error() is None

    def test_multiple_sequential_batches(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        executor = BatchExecutor(router)
        for i in range(3):
            result = executor.execute(_make_batch([b"\x01tx"], round_num=i))
            assert result.tx_results[0].success is True
        assert executor.last_was_catastrophic() is False

    def test_empty_transaction_batch(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        executor = BatchExecutor(router)
        result = executor.execute(_make_batch([]))
        assert len(result.tx_results) == 0
        assert result.state_root is not None

    def test_individual_tx_failure_not_catastrophic(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        executor = BatchExecutor(router)
        batch = _make_batch([b"\xffbad"])
        result = executor.execute(batch)
        assert result.tx_results[0].success is False
        assert executor.last_was_catastrophic() is False

    def test_batch_result_has_correct_round(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        executor = BatchExecutor(router)
        result = executor.execute(_make_batch([b"\x01tx"], round_num=7))
        assert result.round == 7


class TestBatchExecutorCatastrophic:
    def test_exception_captured(self):
        evm = FakeExecutor(0x01)
        evm._should_raise = True
        router = _build_router(evm)
        executor = BatchExecutor(router)
        batch = _make_batch([b"\x01crash"])
        result = executor.execute(batch)
        assert executor.last_was_catastrophic() is True
        assert "executor crashed" in executor.last_error()

    def test_catastrophic_returns_empty_result(self):
        evm = FakeExecutor(0x01)
        evm._should_raise = True
        router = _build_router(evm)
        executor = BatchExecutor(router)
        batch = _make_batch([b"\x01crash"], round_num=3)
        result = executor.execute(batch)
        assert result.round == 3
        assert result.tx_results == []
        assert result.state_root is None

    def test_catastrophic_resets_on_success(self):
        evm = FakeExecutor(0x01)
        evm._should_raise = True
        router = _build_router(evm)
        executor = BatchExecutor(router)
        executor.execute(_make_batch([b"\x01crash"]))
        assert executor.last_was_catastrophic() is True
        evm._should_raise = False
        executor.execute(_make_batch([b"\x01ok"]))
        assert executor.last_was_catastrophic() is False
        assert executor.last_error() is None

    def test_state_root_exception_is_catastrophic(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        executor = BatchExecutor(router)
        original = evm.state_root

        def bad_root():
            raise RuntimeError("state root unavailable")

        evm.state_root = bad_root
        batch = _make_batch([b"\x01tx"])
        result = executor.execute(batch)
        assert executor.last_was_catastrophic() is True
        assert result.state_root is None

    def test_last_error_contains_exception_message(self):
        evm = FakeExecutor(0x01)
        evm._should_raise = True
        router = _build_router(evm)
        executor = BatchExecutor(router)
        executor.execute(_make_batch([b"\x01crash"]))
        assert executor.last_error() == "executor crashed"
