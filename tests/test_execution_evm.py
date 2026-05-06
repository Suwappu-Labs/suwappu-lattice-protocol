"""Tests for EVMExecutor."""

import pytest
from src.ltp.execution.types import TxResult, StateQuery, StateResult


class TestEVMExecutor:
    def test_satisfies_execution_model(self):
        from src.ltp.execution.executors.evm import EVMExecutor
        from src.ltp.execution.model import ExecutionModel, VM_TAG_EVM

        executor = EVMExecutor()
        assert isinstance(executor, ExecutionModel)
        assert executor.vm_tag == VM_TAG_EVM
        assert executor.vm_name == "evm"
        assert executor.family == "account"

    def test_state_root_returns_32_bytes(self):
        from src.ltp.execution.executors.evm import EVMExecutor
        executor = EVMExecutor()
        root = executor.state_root()
        assert isinstance(root, bytes)
        assert len(root) == 32

    def test_execute_returns_tx_result(self):
        from src.ltp.execution.executors.evm import EVMExecutor
        executor = EVMExecutor()
        result = executor.execute(b"some_tx_data")
        assert isinstance(result, TxResult)
        assert result.success is True

    def test_query_state(self):
        from src.ltp.execution.executors.evm import EVMExecutor
        executor = EVMExecutor()
        result = executor.query_state(StateQuery(target_vm=0x01, query_type="storage", key=b"\x00" * 32))
        assert isinstance(result, StateResult)
