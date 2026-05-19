"""Tests for ReplayDB — SQLite-backed event deduplication."""

import os
import tempfile

import pytest


class TestReplayDB:
    def test_mark_and_check(self):
        from src.ltp.gateway_vm.replay import ReplayDB

        db = ReplayDB(":memory:")
        assert db.is_processed("event-1") is False
        db.mark_processed("event-1", tx_hash="0xabc", block_number=100)
        assert db.is_processed("event-1") is True

    def test_duplicate_mark_is_idempotent(self):
        from src.ltp.gateway_vm.replay import ReplayDB

        db = ReplayDB(":memory:")
        db.mark_processed("event-1", tx_hash="0xabc", block_number=100)
        # Second mark should not raise
        db.mark_processed("event-1", tx_hash="0xabc", block_number=100)
        assert db.is_processed("event-1") is True

    def test_different_events_independent(self):
        from src.ltp.gateway_vm.replay import ReplayDB

        db = ReplayDB(":memory:")
        db.mark_processed("event-1", tx_hash="0xabc", block_number=100)
        assert db.is_processed("event-2") is False

    def test_persists_to_disk(self):
        from src.ltp.gateway_vm.replay import ReplayDB

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            path = f.name
        try:
            db1 = ReplayDB(path)
            db1.mark_processed("event-1", tx_hash="0xabc", block_number=100)
            db1.close()

            db2 = ReplayDB(path)
            assert db2.is_processed("event-1") is True
            db2.close()
        finally:
            os.unlink(path)

    def test_count(self):
        from src.ltp.gateway_vm.replay import ReplayDB

        db = ReplayDB(":memory:")
        assert db.count() == 0
        db.mark_processed("event-1", tx_hash="0xabc", block_number=100)
        db.mark_processed("event-2", tx_hash="0xdef", block_number=101)
        assert db.count() == 2

    def test_get_record(self):
        from src.ltp.gateway_vm.replay import ReplayDB

        db = ReplayDB(":memory:")
        db.mark_processed("event-1", tx_hash="0xabc", block_number=100)
        record = db.get("event-1")
        assert record is not None
        assert record["tx_hash"] == "0xabc"
        assert record["block_number"] == 100

    def test_get_missing_returns_none(self):
        from src.ltp.gateway_vm.replay import ReplayDB

        db = ReplayDB(":memory:")
        assert db.get("nonexistent") is None
