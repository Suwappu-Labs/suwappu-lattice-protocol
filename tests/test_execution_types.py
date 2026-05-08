"""Tests for multi-VM execution layer core types."""

import pytest


class TestDomainTags:
    def test_multi_vm_state_root_tag_exists(self):
        from src.ltp.domain import DOMAIN_MULTI_VM_STATE_ROOT
        assert DOMAIN_MULTI_VM_STATE_ROOT == b"GSX-LTP:multi-vm-state-root:v1\x00"

    def test_multi_vm_attest_tag_exists(self):
        from src.ltp.domain import DOMAIN_MULTI_VM_ATTEST
        assert DOMAIN_MULTI_VM_ATTEST == b"GSX-LTP:multi-vm-attest:v1\x00"

    def test_tags_in_all_registry(self):
        from src.ltp import domain
        assert "DOMAIN_MULTI_VM_STATE_ROOT" in domain._ALL_TAGS
        assert "DOMAIN_MULTI_VM_ATTEST" in domain._ALL_TAGS


class TestOrderedBatch:
    def test_construction(self):
        from src.ltp.execution.types import OrderedBatch
        batch = OrderedBatch(
            round=1,
            epoch=0,
            transactions=[b"\x01hello", b"\x10world"],
            leader_authority=0,
            timestamp_ms=1000,
            consensus_type="dag",
        )
        assert batch.round == 1
        assert len(batch.transactions) == 2
        assert batch.consensus_type == "dag"

    def test_empty_batch(self):
        from src.ltp.execution.types import OrderedBatch
        batch = OrderedBatch(
            round=5, epoch=1, transactions=[],
            leader_authority=0, timestamp_ms=2000, consensus_type="bft",
        )
        assert len(batch.transactions) == 0


class TestTxResult:
    def test_accepted(self):
        from src.ltp.execution.types import TxResult
        r = TxResult.accepted(gas_used=21000)
        assert r.success is True
        assert r.gas_used == 21000
        assert r.error == ""

    def test_rejected(self):
        from src.ltp.execution.types import TxResult
        r = TxResult.rejected("unknown_vm_tag")
        assert r.success is False
        assert r.error == "unknown_vm_tag"

    def test_failed(self):
        from src.ltp.execution.types import TxResult
        r = TxResult.failed("out_of_gas")
        assert r.success is False
        assert r.error == "out_of_gas"


class TestStateQuery:
    def test_construction(self):
        from src.ltp.execution.types import StateQuery, StateResult
        q = StateQuery(target_vm=0x10, query_type="object", key=b"\x00" * 32)
        assert q.target_vm == 0x10
        assert q.query_type == "object"

    def test_state_result_found(self):
        from src.ltp.execution.types import StateResult
        r = StateResult(data=b"value", found=True)
        assert r.found is True
        assert r.data == b"value"

    def test_state_result_not_found(self):
        from src.ltp.execution.types import StateResult
        r = StateResult.not_found()
        assert r.found is False
        assert r.data == b""


class TestOperationType:
    def test_all_five_variants_exist(self):
        from src.ltp.execution.types import OperationType
        assert len(OperationType) == 5
        names = {m.name for m in OperationType}
        assert names == {"TRANSFER", "DEPLOY", "CALL", "STATE_MODIFY", "STATE_READ"}


class TestInferOperationType:
    """infer_operation_type maps the first payload byte to an OperationType."""

    def test_empty_payload_defaults_to_transfer(self):
        from src.ltp.execution.types import infer_operation_type, OperationType
        assert infer_operation_type(b"") is OperationType.TRANSFER

    def test_byte_0x00_is_transfer(self):
        from src.ltp.execution.types import infer_operation_type, OperationType
        assert infer_operation_type(b"\x00rest") is OperationType.TRANSFER

    def test_byte_0x01_is_deploy(self):
        from src.ltp.execution.types import infer_operation_type, OperationType
        assert infer_operation_type(b"\x01rest") is OperationType.DEPLOY

    def test_byte_0x02_is_call(self):
        from src.ltp.execution.types import infer_operation_type, OperationType
        assert infer_operation_type(b"\x02rest") is OperationType.CALL

    def test_byte_0x03_is_state_modify(self):
        from src.ltp.execution.types import infer_operation_type, OperationType
        assert infer_operation_type(b"\x03rest") is OperationType.STATE_MODIFY

    def test_byte_0x04_is_state_read(self):
        from src.ltp.execution.types import infer_operation_type, OperationType
        assert infer_operation_type(b"\x04rest") is OperationType.STATE_READ

    def test_unknown_byte_defaults_to_transfer(self):
        from src.ltp.execution.types import infer_operation_type, OperationType
        assert infer_operation_type(b"\xff") is OperationType.TRANSFER
        assert infer_operation_type(b"\x05") is OperationType.TRANSFER
        assert infer_operation_type(b"\x80") is OperationType.TRANSFER

    def test_single_byte_payload(self):
        from src.ltp.execution.types import infer_operation_type, OperationType
        assert infer_operation_type(b"\x02") is OperationType.CALL
