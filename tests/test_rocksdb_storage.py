"""
Tests for RocksDB (LSM-tree) shard storage backend.

Requires: pip install lsm-db
"""

from __future__ import annotations

import os
import tempfile

import pytest

lsm = pytest.importorskip("lsm", reason="lsm-db not installed")

from src.ltp.storage.rocksdb import RocksDBShardStore


@pytest.fixture
def store():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "test.lsm")
        s = RocksDBShardStore(path)
        yield s
        s.close()


class TestCRUD:
    def test_set_and_get(self, store):
        store[("entity-1", 0)] = b"shard-data"
        assert store[("entity-1", 0)] == b"shard-data"

    def test_get_missing_raises(self, store):
        with pytest.raises(KeyError):
            store[("missing", 0)]

    def test_contains(self, store):
        store[("entity-1", 0)] = b"data"
        assert ("entity-1", 0) in store
        assert ("missing", 0) not in store

    def test_delete(self, store):
        store[("entity-1", 0)] = b"data"
        del store[("entity-1", 0)]
        assert ("entity-1", 0) not in store

    def test_delete_missing_raises(self, store):
        with pytest.raises(KeyError):
            del store[("missing", 0)]

    def test_len(self, store):
        assert len(store) == 0
        store[("a", 0)] = b"1"
        store[("a", 1)] = b"2"
        store[("b", 0)] = b"3"
        assert len(store) == 3

    def test_get_with_default(self, store):
        assert store.get(("missing", 0)) is None
        assert store.get(("missing", 0), b"default") == b"default"

    def test_keys(self, store):
        store[("x", 0)] = b"a"
        store[("x", 1)] = b"b"
        store[("y", 0)] = b"c"
        keys = set(store.keys())
        assert ("x", 0) in keys
        assert ("x", 1) in keys
        assert ("y", 0) in keys

    def test_items(self, store):
        store[("a", 0)] = b"data-a"
        store[("b", 1)] = b"data-b"
        items = dict(store.items())
        assert items[("a", 0)] == b"data-a"
        assert items[("b", 1)] == b"data-b"


class TestPersistence:
    def test_data_survives_close_reopen(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "persist.lsm")

            # Write
            s1 = RocksDBShardStore(path)
            s1[("persist", 0)] = b"permanent"
            s1.close()

            # Reopen
            s2 = RocksDBShardStore(path)
            assert s2[("persist", 0)] == b"permanent"
            s2.close()

    def test_large_shard(self, store):
        """Store a large shard (1MB) and retrieve it."""
        big = os.urandom(1_000_000)
        store[("big", 0)] = big
        assert store[("big", 0)] == big


class TestPop:
    def test_pop_existing(self, store):
        store[("a", 0)] = b"val"
        assert store.pop(("a", 0)) == b"val"
        assert ("a", 0) not in store

    def test_pop_missing_with_default(self, store):
        assert store.pop(("missing", 0), b"fallback") == b"fallback"

    def test_pop_missing_raises(self, store):
        with pytest.raises(KeyError):
            store.pop(("missing", 0))
