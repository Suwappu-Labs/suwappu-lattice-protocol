"""Tests for DKG key registry (Spec C3b §7)."""

from __future__ import annotations

import pytest

from src.ltp.execution.committee.dkg.registry import DKGKeyRegistry
from src.ltp.execution.committee.dkg.types import DKGPhase, DKGResult


def _make_result(vm_tag: int = 0x01, epoch: int = 1) -> DKGResult:
    return DKGResult(
        vm_tag=vm_tag,
        epoch=epoch,
        group_pk=bytes([epoch]) * 48,
        participant_vks={b"\x01" * 32: b"\xaa" * 48},
        threshold=2,
        qual_set=frozenset([b"\x01" * 32]),
        phase=DKGPhase.EAGER,
    )


class TestDKGKeyRegistryStore:
    def test_store_and_get(self):
        reg = DKGKeyRegistry(0x01)
        result = _make_result(epoch=1)
        reg.store(result)
        assert reg.get(1) is result

    def test_store_duplicate_epoch_raises(self):
        reg = DKGKeyRegistry(0x01)
        reg.store(_make_result(epoch=1))
        with pytest.raises(ValueError, match="already has a group key"):
            reg.store(_make_result(epoch=1))

    def test_store_wrong_vm_tag_raises(self):
        reg = DKGKeyRegistry(0x01)
        with pytest.raises(ValueError, match="vm_tag mismatch"):
            reg.store(_make_result(vm_tag=0x02, epoch=1))

    def test_get_missing_raises(self):
        reg = DKGKeyRegistry(0x01)
        with pytest.raises(KeyError):
            reg.get(999)


class TestDKGKeyRegistryCurrent:
    def test_current_empty(self):
        reg = DKGKeyRegistry(0x01)
        assert reg.current() is None

    def test_current_returns_highest_epoch(self):
        reg = DKGKeyRegistry(0x01)
        reg.store(_make_result(epoch=1))
        reg.store(_make_result(epoch=3))
        reg.store(_make_result(epoch=2))
        current = reg.current()
        assert current.epoch == 3


class TestDKGKeyRegistryConvenience:
    def test_group_pk(self):
        reg = DKGKeyRegistry(0x01)
        reg.store(_make_result(epoch=1))
        pk = reg.group_pk(1)
        assert len(pk) == 48
        assert pk == bytes([1]) * 48

    def test_has_epoch(self):
        reg = DKGKeyRegistry(0x01)
        assert reg.has_epoch(1) is False
        reg.store(_make_result(epoch=1))
        assert reg.has_epoch(1) is True

    def test_epoch_count(self):
        reg = DKGKeyRegistry(0x01)
        assert reg.epoch_count() == 0
        reg.store(_make_result(epoch=1))
        reg.store(_make_result(epoch=2))
        assert reg.epoch_count() == 2
