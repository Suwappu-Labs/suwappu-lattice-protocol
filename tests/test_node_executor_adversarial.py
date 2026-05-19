"""Adversarial tests for NodeExecutor and ConsensusNode bridge (Spec D1c §6-7)."""

import pytest

from src.ltp.consensus.events import ConsensusEventType
from src.ltp.execution.consensus import FakeConsensusAdapter
from src.ltp.execution.consensus_node import ConsensusNode
from src.ltp.execution.execution_config import ExecutionConfig
from src.ltp.execution.execution_events import ExecutionEventType
from src.ltp.execution.node_executor import NodeExecutor, RoundResult
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


class FailingExecutor:
    """Executor that always fails transactions (but doesn't raise)."""

    def __init__(self, tag: int):
        self.vm_tag = tag
        self.vm_name = "failing"
        self.family = "account"
        self._root = bytes([tag]) * 32

    def execute(self, tx_bytes: bytes) -> TxResult:
        return TxResult.rejected("always fails")

    def state_root(self) -> bytes:
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


class TestCatastrophicHalt:
    def test_catastrophic_error_sets_halted(self):
        evm = FakeExecutor(0x01)
        evm._should_raise = True
        router = _build_router(evm)
        adapter = FakeConsensusAdapter(batches=[])
        executor = NodeExecutor(
            consensus=adapter,
            router=router,
            config=ExecutionConfig(halt_on_catastrophic=True),
        )
        result = executor.execute_round(_make_batch([b"\x01crash"]))
        assert result.halted is True
        assert executor.is_halted() is True

    def test_catastrophic_without_halt_continues(self):
        evm = FakeExecutor(0x01)
        evm._should_raise = True
        router = _build_router(evm)
        adapter = FakeConsensusAdapter(batches=[])
        executor = NodeExecutor(
            consensus=adapter,
            router=router,
            config=ExecutionConfig(halt_on_catastrophic=False),
        )
        result = executor.execute_round(_make_batch([b"\x01crash"]))
        assert result.halted is False
        assert executor.is_halted() is False

    def test_halt_stops_run_rounds(self):
        evm = FakeExecutor(0x01)
        evm._should_raise = True
        router = _build_router(evm)
        batches = [_make_batch([b"\x01crash"], round_num=i) for i in range(5)]
        adapter = FakeConsensusAdapter(batches=batches)
        executor = NodeExecutor(
            consensus=adapter,
            router=router,
            config=ExecutionConfig(halt_on_catastrophic=True),
        )
        results = executor.run_rounds(5)
        assert len(results) == 1
        assert results[0].halted is True


class TestHighFailureRate:
    def test_high_failure_rate_triggers_warning(self):
        failing = FailingExecutor(0x01)
        router = _build_router(failing)
        adapter = FakeConsensusAdapter(batches=[])
        executor = NodeExecutor(
            consensus=adapter,
            router=router,
            config=ExecutionConfig(failure_threshold_pct=10.0, failure_window=10),
        )
        result = executor.execute_round(_make_batch([b"\x01tx1", b"\x01tx2", b"\x01tx3"]))
        warnings = [
            e
            for e in result.execution_events
            if e.event_type == ExecutionEventType.FAILURE_THRESHOLD_WARNING
        ]
        assert len(warnings) >= 1

    def test_high_failure_does_not_halt(self):
        failing = FailingExecutor(0x01)
        router = _build_router(failing)
        adapter = FakeConsensusAdapter(batches=[])
        executor = NodeExecutor(
            consensus=adapter,
            router=router,
            config=ExecutionConfig(failure_threshold_pct=10.0),
        )
        result = executor.execute_round(_make_batch([b"\x01tx"]))
        assert result.halted is False

    def test_all_transactions_fail_recorded(self):
        failing = FailingExecutor(0x01)
        router = _build_router(failing)
        adapter = FakeConsensusAdapter(batches=[])
        executor = NodeExecutor(consensus=adapter, router=router)
        result = executor.execute_round(_make_batch([b"\x01a", b"\x01b", b"\x01c"]))
        assert result.batch_result.tx_results[0].success is False
        batch_evt = [
            e for e in result.consensus_events if e.event_type == ConsensusEventType.BATCH_EXECUTED
        ]
        assert batch_evt[0].payload["failure_count"] == 3


class TestEmptyAndEdgeCases:
    def test_empty_batch_through_pipeline(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        adapter = FakeConsensusAdapter(batches=[])
        executor = NodeExecutor(consensus=adapter, router=router)
        result = executor.execute_round(_make_batch([]))
        assert result.batch_result is not None
        assert len(result.batch_result.tx_results) == 0

    def test_no_attestation_engine_no_committee_works(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        adapter = FakeConsensusAdapter(batches=[])
        executor = NodeExecutor(
            consensus=adapter,
            router=router,
            attestation_engine=None,
            committee_manager=None,
        )
        result = executor.execute_round(_make_batch([b"\x01tx"]))
        assert result.batch_result.tx_results[0].success is True
        attested = [
            e
            for e in result.consensus_events
            if e.event_type == ConsensusEventType.STATE_ROOT_ATTESTED
        ]
        assert len(attested) == 0


class FakeETPNode:
    """Minimal ETPNode stub for ConsensusNode tests."""

    def __init__(self):
        self._running = False
        self._anchored = []

    def start(self):
        self._running = True

    def stop(self):
        self._running = False

    @property
    def is_running(self):
        return self._running

    def anchor_state_root(self, state_root: bytes, signature: bytes | None):
        self._anchored.append((state_root, signature))


class TestConsensusNode:
    def test_start_stop_lifecycle(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        adapter = FakeConsensusAdapter(batches=[])
        ne = NodeExecutor(consensus=adapter, router=router)
        etp = FakeETPNode()
        cn = ConsensusNode(node_executor=ne, etp_node=etp)
        cn.start()
        assert cn.is_running() is True
        cn.stop()
        assert cn.is_running() is False

    def test_on_round_complete_forwards_attestation(self):
        from src.ltp.execution.state_attestor import AttestationResult

        etp = FakeETPNode()
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        adapter = FakeConsensusAdapter(batches=[])
        ne = NodeExecutor(consensus=adapter, router=router)
        cn = ConsensusNode(node_executor=ne, etp_node=etp)

        att = AttestationResult(
            state_root=b"\xaa" * 32,
            round=0,
            epoch=1,
            mldsa_attestation=None,
            bls_signature=b"\xbb" * 96,
            mode="dual",
        )
        result = RoundResult(
            batch_result=BatchResult(round=0, tx_results=[], state_root=None),
            attestation=att,
            consensus_events=[],
            execution_events=[],
            round=0,
            epoch=1,
            halted=False,
        )
        cn.on_round_complete(result)
        assert len(etp._anchored) == 1
        assert etp._anchored[0][0] == b"\xaa" * 32

    def test_on_round_complete_skips_without_attestation(self):
        etp = FakeETPNode()
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        adapter = FakeConsensusAdapter(batches=[])
        ne = NodeExecutor(consensus=adapter, router=router)
        cn = ConsensusNode(node_executor=ne, etp_node=etp)

        result = RoundResult(
            batch_result=BatchResult(round=0, tx_results=[], state_root=None),
            attestation=None,
            consensus_events=[],
            execution_events=[],
            round=0,
            epoch=1,
            halted=False,
        )
        cn.on_round_complete(result)
        assert len(etp._anchored) == 0

    def test_submit_transaction_delegates(self):
        evm = FakeExecutor(0x01)
        router = _build_router(evm)
        adapter = FakeConsensusAdapter(batches=[])
        ne = NodeExecutor(consensus=adapter, router=router)
        etp = FakeETPNode()
        cn = ConsensusNode(node_executor=ne, etp_node=etp)
        result = cn.submit_transaction(b"\x01hello")
        assert isinstance(result, bytes)
