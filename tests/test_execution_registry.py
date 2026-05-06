"""Tests for VMRegistry."""

import pytest
from src.ltp.execution.types import TxResult, StateQuery, StateResult


class FakeExecutor:
    """Minimal ExecutionModel for testing."""
    def __init__(self, tag: int, name: str, family: str, healthy: bool = True):
        self.vm_tag = tag
        self.vm_name = name
        self.family = family
        self._healthy = healthy
        self._root = b"\xaa" * 32

    def execute(self, tx_bytes: bytes) -> TxResult:
        return TxResult.accepted()

    def state_root(self) -> bytes:
        if not self._healthy:
            raise ConnectionError("executor down")
        return self._root

    def validate_tx(self, tx_bytes: bytes) -> bool:
        return True

    def query_state(self, query: StateQuery) -> StateResult:
        return StateResult.not_found()


class TestVMRegistry:
    def test_register_and_lookup(self):
        from src.ltp.execution.registry import VMRegistry
        reg = VMRegistry()
        evm = FakeExecutor(0x01, "evm", "account")
        reg.register(evm)
        assert reg.get(0x01) is evm

    def test_lookup_missing_returns_none(self):
        from src.ltp.execution.registry import VMRegistry
        reg = VMRegistry()
        assert reg.get(0x99) is None

    def test_register_duplicate_tag_raises(self):
        from src.ltp.execution.registry import VMRegistry
        reg = VMRegistry()
        reg.register(FakeExecutor(0x01, "evm", "account"))
        with pytest.raises(ValueError, match="already registered"):
            reg.register(FakeExecutor(0x01, "evm2", "account"))

    def test_all_executors(self):
        from src.ltp.execution.registry import VMRegistry
        reg = VMRegistry()
        reg.register(FakeExecutor(0x01, "evm", "account"))
        reg.register(FakeExecutor(0x10, "move", "object"))
        assert len(reg.all_executors()) == 2

    def test_active_tags_sorted(self):
        from src.ltp.execution.registry import VMRegistry
        reg = VMRegistry()
        reg.register(FakeExecutor(0x10, "move", "object"))
        reg.register(FakeExecutor(0x01, "evm", "account"))
        assert reg.active_tags() == [0x01, 0x10]

    def test_health_check_all_healthy(self):
        from src.ltp.execution.registry import VMRegistry
        reg = VMRegistry()
        reg.register(FakeExecutor(0x01, "evm", "account", healthy=True))
        reg.register(FakeExecutor(0x10, "move", "object", healthy=True))
        health = reg.health_check()
        assert health == {0x01: True, 0x10: True}

    def test_health_check_one_down(self):
        from src.ltp.execution.registry import VMRegistry
        reg = VMRegistry()
        reg.register(FakeExecutor(0x01, "evm", "account", healthy=True))
        reg.register(FakeExecutor(0x10, "move", "object", healthy=False))
        health = reg.health_check()
        assert health[0x01] is True
        assert health[0x10] is False
