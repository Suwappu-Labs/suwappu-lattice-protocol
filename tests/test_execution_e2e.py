"""End-to-end test: consensus → router → attestation → verify."""

import pytest
from src.ltp.execution.types import OrderedBatch, TxResult, StateQuery, StateResult


@pytest.fixture(scope="module")
def operator_kp():
    from src.ltp import KeyPair
    return KeyPair.generate("e2e-operator")


class TestE2EExecutionPipeline:
    def test_single_batch_full_pipeline(self, operator_kp):
        from src.ltp.execution.consensus import FakeConsensusAdapter
        from src.ltp.execution.registry import VMRegistry
        from src.ltp.execution.router import TransactionRouter
        from src.ltp.execution.attestation import AttestationEngine, MultiVMAttestation
        from src.ltp.execution.executors.evm import EVMExecutor
        from src.ltp.execution.executors.bridge import BridgeModule
        from src.ltp.execution.state_root import MultiVMStateRoot

        # 1. Set up executors
        registry = VMRegistry()
        evm = EVMExecutor()
        bridge = BridgeModule()
        registry.register(evm)
        registry.register(bridge)

        # 2. Set up consensus
        batch = OrderedBatch(
            round=1, epoch=0,
            transactions=[b"\x01evm_tx_1", b"\xE0bridge_op", b"\x01evm_tx_2"],
            leader_authority=0, timestamp_ms=1000, consensus_type="dag",
        )
        consensus = FakeConsensusAdapter(batches=[batch])

        # 3. Set up router and attestation engine
        router = TransactionRouter(registry)
        engine = AttestationEngine(operator_keypair=operator_kp, chain_id=103115120)

        # 4. Execute
        consensus.start()
        for b in consensus.stream_batches():
            result = router.execute_batch(b)

            assert len(result.tx_results) == 3
            assert all(r.success for r in result.tx_results)
            assert isinstance(result.state_root, MultiVMStateRoot)

            # 5. Attest
            attestation = engine.sign(
                result.state_root,
                consensus_round=b.round,
                epoch=b.epoch,
                active_vm_tags=registry.active_tags(),
            )

            assert isinstance(attestation, MultiVMAttestation)
            assert attestation.mldsa_signature is not None
            assert attestation.verify(operator_kp.vk) is True
            assert attestation.active_vm_tags == [0x01, 0xE0]

    def test_mixed_evm_and_move_batch(self, operator_kp):
        from src.ltp.execution.registry import VMRegistry
        from src.ltp.execution.router import TransactionRouter
        from src.ltp.execution.executors.evm import EVMExecutor
        from src.ltp.execution.executors.move import MoveExecutor
        from src.ltp.execution.state_root import MultiVMStateRoot
        from src.ltp.primitives import canonical_hash_bytes

        class InMemoryMoveBackend:
            def __init__(self):
                self._root = canonical_hash_bytes(b"move-genesis")
                self._n = 0
            def execute_transaction(self, tx_bytes):
                self._n += 1
                self._root = canonical_hash_bytes(self._root + tx_bytes)
                return True, self._root
            def query_state(self, key):
                return None
            def get_state_root(self):
                return self._root

        registry = VMRegistry()
        registry.register(EVMExecutor())
        registry.register(MoveExecutor(backend=InMemoryMoveBackend()))
        router = TransactionRouter(registry)

        batch = OrderedBatch(
            round=42, epoch=1,
            transactions=[b"\x01evm_tx", b"\x10move_tx", b"\x01evm_tx2", b"\x10move_tx2"],
            leader_authority=0, timestamp_ms=5000, consensus_type="dag",
        )
        result = router.execute_batch(batch)

        assert len(result.tx_results) == 4
        assert all(r.success for r in result.tx_results)
        assert isinstance(result.state_root, MultiVMStateRoot)
        assert 0x00 in result.state_root.active_families()  # Account (EVM)
        assert 0x01 in result.state_root.active_families()  # Object (Move)

    def test_cross_vm_precompile_in_pipeline(self, operator_kp):
        from src.ltp.execution.registry import VMRegistry
        from src.ltp.execution.precompile import CrossVMPrecompile
        from src.ltp.execution.executors.evm import EVMExecutor

        class QueryableMoveExecutor:
            vm_tag = 0x10
            vm_name = "move"
            family = "object"
            def execute(self, tx_bytes):
                return TxResult.accepted()
            def state_root(self):
                return b"\xbb" * 32
            def validate_tx(self, tx_bytes):
                return True
            def query_state(self, query: StateQuery) -> StateResult:
                if query.key == b"\x01" * 32:
                    return StateResult(data=b"move_object_data", found=True)
                return StateResult.not_found()

        registry = VMRegistry()
        registry.register(EVMExecutor())
        registry.register(QueryableMoveExecutor())
        precompile = CrossVMPrecompile(registry)

        # EVM reads Move state
        result = precompile.call(
            input_data=bytes([0x10]) + b"\x01" * 32,
            caller_vm_tag=0x01,
        )
        assert result.success is True
        assert result.data == b"move_object_data"

    def test_health_check(self):
        from src.ltp.execution.registry import VMRegistry
        from src.ltp.execution.executors.evm import EVMExecutor
        from src.ltp.execution.executors.bridge import BridgeModule

        registry = VMRegistry()
        registry.register(EVMExecutor())
        registry.register(BridgeModule())

        health = registry.health_check()
        assert health[0x01] is True
        assert health[0xE0] is True
