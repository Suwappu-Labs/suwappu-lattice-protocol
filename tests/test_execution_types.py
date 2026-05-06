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
