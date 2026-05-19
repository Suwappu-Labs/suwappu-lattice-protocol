"""Tests for BridgeModule."""

from unittest.mock import MagicMock

import pytest

from src.ltp.execution.types import StateQuery, StateResult


class TestBridgeModule:
    def test_satisfies_execution_model(self):
        from src.ltp.execution.executors.bridge import BridgeModule
        from src.ltp.execution.model import VM_TAG_BRIDGE, ExecutionModel

        module = BridgeModule()
        assert isinstance(module, ExecutionModel)
        assert module.vm_tag == VM_TAG_BRIDGE
        assert module.vm_name == "bridge"
        assert module.family == "system"

    def test_state_root_returns_32_bytes(self):
        from src.ltp.execution.executors.bridge import BridgeModule

        module = BridgeModule()
        assert len(module.state_root()) == 32

    def test_execute_returns_result(self):
        from src.ltp.execution.executors.bridge import BridgeModule
        from src.ltp.execution.types import TxResult

        module = BridgeModule()
        result = module.execute(b"bridge_op")
        assert isinstance(result, TxResult)

    def test_query_state(self):
        from src.ltp.execution.executors.bridge import BridgeModule

        module = BridgeModule()
        result = module.query_state(
            StateQuery(target_vm=0xE0, query_type="storage", key=b"\x00" * 32)
        )
        assert isinstance(result, StateResult)
