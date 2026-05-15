"""Tests for NodeExecutor — execution pipeline orchestrator (Spec D1c §6)."""

import pytest

from src.ltp.execution.node_executor import NodeExecutor, RoundResult
from src.ltp.execution.execution_config import ExecutionConfig
from src.ltp.execution.execution_events import ExecutionEventType
from src.ltp.execution.consensus import FakeConsensusAdapter
from src.ltp.execution.types import OrderedBatch, TxResult, BatchResult, StateResult
from src.ltp.execution.registry import VMRegistry
from src.ltp.execution.router import TransactionRouter
from src.ltp.consensus.events import ConsensusEventType


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
        round=round_num, epoch=epoch, transactions=txs,
        leader_authority=0, timestamp_ms=round_num * 1000, consensus_type="dag",
    )


def _build_router(*executors) -> TransactionRouter:
    reg = VMRegistry()
    for ex in executors:
        reg.register(ex)
    return TransactionRouter(reg)


def _make_adapter(batches: list[OrderedBatch]) -> FakeConsensusAdapter:
    return FakeConsensusAdapter(batches=batches)


class TestNodeExecutorPipeline:

    def test_execute_round_returns_round_result(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        adapter = _make_adapter([])
        executor = NodeExecutor(consensus=adapter, router=router)
        batch = _make_batch([b"\x01hello"])
        result = executor.execute_round(batch)
        assert isinstance(result, RoundResult)
        assert result.batch_result is not None
        assert result.batch_result.tx_results[0].success is True
        assert result.round == 0
        assert result.epoch == 1

    def test_execute_round_produces_batch_executed_event(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        adapter = _make_adapter([])
        executor = NodeExecutor(consensus=adapter, router=router)
        result = executor.execute_round(_make_batch([b"\x01tx"]))
        batch_events = [
            e for e in result.consensus_events
            if e.event_type == ConsensusEventType.BATCH_EXECUTED
        ]
        assert len(batch_events) == 1
        assert batch_events[0].payload["tx_count"] == 1
        assert batch_events[0].payload["success_count"] == 1

    def test_attestation_when_engine_present(self):
        from src.ltp import KeyPair
        from src.ltp.execution.attestation import AttestationEngine
        kp = KeyPair.generate("test-ne")
        engine = AttestationEngine(operator_keypair=kp, chain_id=103115120)

        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        adapter = _make_adapter([])
        executor = NodeExecutor(
            consensus=adapter, router=router, attestation_engine=engine,
        )
        result = executor.execute_round(_make_batch([b"\x01tx"]))
        assert result.attestation is not None
        assert result.attestation.mode == "mldsa_only"

    def test_state_root_attested_event_emitted(self):
        from src.ltp import KeyPair
        from src.ltp.execution.attestation import AttestationEngine
        kp = KeyPair.generate("test-ne2")
        engine = AttestationEngine(operator_keypair=kp, chain_id=103115120)

        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        adapter = _make_adapter([])
        executor = NodeExecutor(
            consensus=adapter, router=router, attestation_engine=engine,
        )
        result = executor.execute_round(_make_batch([b"\x01tx"]))
        attested = [
            e for e in result.consensus_events
            if e.event_type == ConsensusEventType.STATE_ROOT_ATTESTED
        ]
        assert len(attested) == 1
        assert attested[0].payload["mode"] == "mldsa_only"

    def test_no_attestation_without_engine(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        adapter = _make_adapter([])
        executor = NodeExecutor(consensus=adapter, router=router)
        result = executor.execute_round(_make_batch([b"\x01tx"]))
        assert result.attestation is None or result.attestation.mode == "none"


class TestNodeExecutorRunRounds:

    def test_run_rounds_produces_results(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        batches = [_make_batch([b"\x01tx"], round_num=i) for i in range(3)]
        adapter = _make_adapter(batches)
        executor = NodeExecutor(consensus=adapter, router=router)
        results = executor.run_rounds(3)
        assert len(results) == 3
        for r in results:
            assert isinstance(r, RoundResult)
            assert r.batch_result.tx_results[0].success is True

    def test_transactions_appear_in_results(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        batches = [_make_batch([b"\x01aaa", b"\x01bbb"], round_num=0)]
        adapter = _make_adapter(batches)
        executor = NodeExecutor(consensus=adapter, router=router)
        results = executor.run_rounds(1)
        assert len(results[0].batch_result.tx_results) == 2

    def test_submit_transaction_returns_hash(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        adapter = _make_adapter([])
        executor = NodeExecutor(consensus=adapter, router=router)
        tx_hash = executor.submit_transaction(b"\x01hello")
        assert isinstance(tx_hash, bytes)


class TestNodeExecutorLifecycle:

    def test_is_running_lifecycle(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        adapter = _make_adapter([])
        executor = NodeExecutor(consensus=adapter, router=router)
        assert executor.is_running() is False
        executor.start()
        assert executor.is_running() is True
        executor.stop()
        assert executor.is_running() is False

    def test_current_round_delegates(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        adapter = _make_adapter([])
        executor = NodeExecutor(consensus=adapter, router=router)
        assert executor.current_round() == 0

    def test_event_history_collects_all(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        adapter = _make_adapter([])
        executor = NodeExecutor(consensus=adapter, router=router)
        executor.execute_round(_make_batch([b"\x01tx"]))
        history = executor.event_history()
        assert len(history) >= 1

    def test_results_tracks_all(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        adapter = _make_adapter([])
        executor = NodeExecutor(consensus=adapter, router=router)
        executor.execute_round(_make_batch([b"\x01tx"], round_num=0))
        executor.execute_round(_make_batch([b"\x01tx"], round_num=1))
        assert len(executor.results()) == 2

    def test_works_with_fake_consensus_adapter(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        batches = [_make_batch([b"\x01tx"], round_num=i) for i in range(5)]
        adapter = _make_adapter(batches)
        executor = NodeExecutor(consensus=adapter, router=router)
        results = executor.run_rounds(5)
        assert len(results) == 5

    def test_works_without_attestation_engine(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        adapter = _make_adapter([])
        executor = NodeExecutor(
            consensus=adapter, router=router,
            attestation_engine=None, committee_manager=None,
        )
        result = executor.execute_round(_make_batch([b"\x01tx"]))
        assert result.batch_result.tx_results[0].success is True
