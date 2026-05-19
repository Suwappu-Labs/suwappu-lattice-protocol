"""Tests for CrossVMPrecompile — universal cross-VM state reads."""

import pytest

from src.ltp.execution.types import StateQuery, StateResult, TxResult


class StatefulExecutor:
    """Executor with queryable state for precompile testing."""

    def __init__(self, tag, name, family, state=None):
        self.vm_tag = tag
        self.vm_name = name
        self.family = family
        self._state = state or {}

    def execute(self, tx_bytes):
        return TxResult.accepted()

    def state_root(self):
        return b"\x00" * 32

    def validate_tx(self, tx_bytes):
        return True

    def query_state(self, query: StateQuery) -> StateResult:
        val = self._state.get(query.key)
        if val is not None:
            return StateResult(data=val, found=True)
        return StateResult.not_found()


class TestCrossVMPrecompile:
    def _build(self, *executors):
        from src.ltp.execution.precompile import CrossVMPrecompile
        from src.ltp.execution.registry import VMRegistry

        reg = VMRegistry()
        for ex in executors:
            reg.register(ex)
        return CrossVMPrecompile(reg)

    def test_read_move_state_from_evm(self):
        move = StatefulExecutor(
            0x10,
            "move",
            "object",
            {
                b"\x01" * 32: b"move_value",
            },
        )
        pc = self._build(move)
        result = pc.call(
            input_data=bytes([0x10]) + b"\x01" * 32,
            caller_vm_tag=0x01,
        )
        assert result.success is True
        assert result.data == b"move_value"

    def test_key_not_found_returns_empty(self):
        move = StatefulExecutor(0x10, "move", "object", {})
        pc = self._build(move)
        result = pc.call(
            input_data=bytes([0x10]) + b"\x02" * 32,
            caller_vm_tag=0x01,
        )
        assert result.success is True
        assert result.data == b""

    def test_target_vm_not_registered(self):
        pc = self._build()  # empty registry
        result = pc.call(
            input_data=bytes([0x10]) + b"\x01" * 32,
            caller_vm_tag=0x01,
        )
        assert result.success is False
        assert "not registered" in result.error

    def test_input_too_short(self):
        pc = self._build()
        result = pc.call(input_data=b"\x10" + b"\x00" * 10, caller_vm_tag=0x01)
        assert result.success is False

    def test_same_vm_rejected(self):
        evm = StatefulExecutor(0x01, "evm", "account")
        pc = self._build(evm)
        result = pc.call(
            input_data=bytes([0x01]) + b"\x01" * 32,
            caller_vm_tag=0x01,
        )
        assert result.success is False
        assert "native" in result.error

    def test_gas_calculation(self):
        move = StatefulExecutor(
            0x10,
            "move",
            "object",
            {
                b"\x01" * 32: b"x" * 100,
            },
        )
        pc = self._build(move)
        result = pc.call(
            input_data=bytes([0x10]) + b"\x01" * 32,
            caller_vm_tag=0x01,
        )
        assert result.gas_used == 700 + 3 * 100  # BASE + PER_BYTE * 100
