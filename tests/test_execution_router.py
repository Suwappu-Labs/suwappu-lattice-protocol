"""Tests for TransactionRouter — tag-based batch dispatch."""

import pytest

from src.ltp.execution.types import OrderedBatch, StateQuery, StateResult, TxResult


class FakeExecutor:
    def __init__(self, tag, name, family):
        self.vm_tag = tag
        self.vm_name = name
        self.family = family
        self.executed = []
        self._root = bytes([tag]) * 32

    def execute(self, tx_bytes: bytes) -> TxResult:
        self.executed.append(tx_bytes)
        return TxResult.accepted(gas_used=100)

    def state_root(self) -> bytes:
        return self._root

    def validate_tx(self, tx_bytes: bytes) -> bool:
        return True

    def query_state(self, query: StateQuery) -> StateResult:
        return StateResult.not_found()


def _make_batch(txs: list[bytes], round_num: int = 1) -> OrderedBatch:
    return OrderedBatch(
        round=round_num,
        epoch=0,
        transactions=txs,
        leader_authority=0,
        timestamp_ms=1000,
        consensus_type="dag",
    )


class TestTransactionRouter:
    def _build_router(self, *executors):
        from src.ltp.execution.registry import VMRegistry
        from src.ltp.execution.router import TransactionRouter

        reg = VMRegistry()
        for ex in executors:
            reg.register(ex)
        return TransactionRouter(reg)

    def test_single_evm_tx(self):
        evm = FakeExecutor(0x01, "evm", "account")
        router = self._build_router(evm)
        result = router.execute_batch(_make_batch([b"\x01hello"]))
        assert len(result.tx_results) == 1
        assert result.tx_results[0].success is True
        assert evm.executed == [b"hello"]

    def test_mixed_batch_dispatches_correctly(self):
        evm = FakeExecutor(0x01, "evm", "account")
        move = FakeExecutor(0x10, "move", "object")
        router = self._build_router(evm, move)
        result = router.execute_batch(
            _make_batch(
                [
                    b"\x01evm_tx",
                    b"\x10move_tx",
                    b"\x01evm_tx2",
                ]
            )
        )
        assert len(result.tx_results) == 3
        assert evm.executed == [b"evm_tx", b"evm_tx2"]
        assert move.executed == [b"move_tx"]

    def test_unknown_tag_rejected(self):
        evm = FakeExecutor(0x01, "evm", "account")
        router = self._build_router(evm)
        result = router.execute_batch(_make_batch([b"\x99bad"]))
        assert result.tx_results[0].success is False
        assert "unknown_vm_tag" in result.tx_results[0].error

    def test_empty_batch(self):
        evm = FakeExecutor(0x01, "evm", "account")
        router = self._build_router(evm)
        result = router.execute_batch(_make_batch([]))
        assert len(result.tx_results) == 0
        assert result.state_root is not None

    def test_execution_order_preserved(self):
        """Transactions execute in the exact order consensus delivered them."""
        order = []

        class OrderTracker:
            def __init__(self, tag, name, family):
                self.vm_tag = tag
                self.vm_name = name
                self.family = family

            def execute(self, tx_bytes):
                order.append((self.vm_tag, tx_bytes))
                return TxResult.accepted()

            def state_root(self):
                return b"\x00" * 32

            def validate_tx(self, tx_bytes):
                return True

            def query_state(self, query):
                return StateResult.not_found()

        evm = OrderTracker(0x01, "evm", "account")
        move = OrderTracker(0x10, "move", "object")
        router = self._build_router(evm, move)

        router.execute_batch(
            _make_batch(
                [
                    b"\x10first",
                    b"\x01second",
                    b"\x10third",
                ]
            )
        )
        assert order == [
            (0x10, b"first"),
            (0x01, b"second"),
            (0x10, b"third"),
        ]

    def test_state_root_computed(self):
        from src.ltp.execution.state_root import MultiVMStateRoot

        evm = FakeExecutor(0x01, "evm", "account")
        move = FakeExecutor(0x10, "move", "object")
        router = self._build_router(evm, move)
        result = router.execute_batch(_make_batch([b"\x01tx"], round_num=7))
        assert isinstance(result.state_root, MultiVMStateRoot)
        assert result.round == 7

    def test_executor_unavailable_raises(self):
        from src.ltp.execution.router import ExecutorUnavailable

        class DownExecutor:
            vm_tag = 0x01
            vm_name = "evm"
            family = "account"

            def execute(self, tx_bytes):
                return TxResult.accepted()

            def state_root(self):
                raise ConnectionError("node down")

            def validate_tx(self, tx_bytes):
                return True

            def query_state(self, query):
                return StateResult.not_found()

        router = self._build_router(DownExecutor())
        with pytest.raises(ExecutorUnavailable, match="evm"):
            router.execute_batch(_make_batch([b"\x01tx"]))

    def test_empty_tx_bytes_rejected(self):
        evm = FakeExecutor(0x01, "evm", "account")
        router = self._build_router(evm)
        result = router.execute_batch(_make_batch([b""]))
        assert result.tx_results[0].success is False
