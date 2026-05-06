"""Tests for ExecutionModel protocol and VM tag constants."""

import pytest


class TestVMTagRanges:
    def test_account_family_range(self):
        from src.ltp.execution.model import VM_FAMILY_ACCOUNT
        assert VM_FAMILY_ACCOUNT == 0x00

    def test_object_family_range(self):
        from src.ltp.execution.model import VM_FAMILY_OBJECT
        assert VM_FAMILY_OBJECT == 0x01

    def test_register_family_range(self):
        from src.ltp.execution.model import VM_FAMILY_REGISTER
        assert VM_FAMILY_REGISTER == 0x02

    def test_utxo_family_range(self):
        from src.ltp.execution.model import VM_FAMILY_UTXO
        assert VM_FAMILY_UTXO == 0x03

    def test_ledger_native_family_range(self):
        from src.ltp.execution.model import VM_FAMILY_LEDGER_NATIVE
        assert VM_FAMILY_LEDGER_NATIVE == 0x04

    def test_system_family_range(self):
        from src.ltp.execution.model import VM_FAMILY_SYSTEM
        assert VM_FAMILY_SYSTEM == 0x0E

    def test_family_from_tag(self):
        from src.ltp.execution.model import family_from_tag
        assert family_from_tag(0x01) == 0x00  # EVM → Account
        assert family_from_tag(0x10) == 0x01  # MoveVM → Object
        assert family_from_tag(0x20) == 0x02  # SVM → Register
        assert family_from_tag(0x30) == 0x03  # Bitcoin → UTXO
        assert family_from_tag(0x40) == 0x04  # Canton → Ledger-native
        assert family_from_tag(0xE0) == 0x0E  # Bridge → System


class TestVMTags:
    def test_evm_tag(self):
        from src.ltp.execution.model import VM_TAG_EVM
        assert VM_TAG_EVM == 0x01

    def test_tvm_tag(self):
        from src.ltp.execution.model import VM_TAG_TVM
        assert VM_TAG_TVM == 0x02

    def test_move_tag(self):
        from src.ltp.execution.model import VM_TAG_MOVE
        assert VM_TAG_MOVE == 0x10

    def test_svm_tag(self):
        from src.ltp.execution.model import VM_TAG_SVM
        assert VM_TAG_SVM == 0x20

    def test_bitcoin_tag(self):
        from src.ltp.execution.model import VM_TAG_BITCOIN
        assert VM_TAG_BITCOIN == 0x30

    def test_plutus_tag(self):
        from src.ltp.execution.model import VM_TAG_PLUTUS
        assert VM_TAG_PLUTUS == 0x31

    def test_canton_tag(self):
        from src.ltp.execution.model import VM_TAG_CANTON
        assert VM_TAG_CANTON == 0x40

    def test_bridge_tag(self):
        from src.ltp.execution.model import VM_TAG_BRIDGE
        assert VM_TAG_BRIDGE == 0xE0

    def test_precompile_tag(self):
        from src.ltp.execution.model import VM_TAG_PRECOMPILE
        assert VM_TAG_PRECOMPILE == 0xF0


class TestExecutionModelProtocol:
    def test_stub_executor_satisfies_protocol(self):
        from src.ltp.execution.model import ExecutionModel
        from src.ltp.execution.types import TxResult, StateQuery, StateResult

        class StubExecutor:
            vm_tag = 0x01
            vm_name = "stub"
            family = "account"

            def execute(self, tx_bytes: bytes) -> TxResult:
                return TxResult.accepted()

            def state_root(self) -> bytes:
                return b"\x00" * 32

            def validate_tx(self, tx_bytes: bytes) -> bool:
                return True

            def query_state(self, query: StateQuery) -> StateResult:
                return StateResult.not_found()

        executor = StubExecutor()
        assert isinstance(executor, ExecutionModel)

    def test_family_names(self):
        from src.ltp.execution.model import FAMILY_NAMES
        assert FAMILY_NAMES[0x00] == "account"
        assert FAMILY_NAMES[0x01] == "object"
        assert FAMILY_NAMES[0x0E] == "system"
