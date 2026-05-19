"""
Tests for persistent shard storage backends.

Verifies MemoryShardStore, SQLiteShardStore, and FileShardStore all
implement the ShardStore interface identically.
"""

import os
import tempfile

import pytest

from src.ltp.storage import FileShardStore, MemoryShardStore, SQLiteShardStore

# ---------------------------------------------------------------------------
# Fixtures: each backend gets the same test suite
# ---------------------------------------------------------------------------


@pytest.fixture
def memory_store():
    return MemoryShardStore()


@pytest.fixture
def sqlite_store():
    store = SQLiteShardStore(":memory:")
    yield store
    store.close()


@pytest.fixture
def sqlite_file_store(tmp_path):
    db_path = str(tmp_path / "shards.db")
    store = SQLiteShardStore(db_path)
    yield store
    store.close()


@pytest.fixture
def file_store(tmp_path):
    return FileShardStore(str(tmp_path / "shard_data"))


ALL_STORES = ["memory_store", "sqlite_store", "file_store"]


# ---------------------------------------------------------------------------
# Shared interface tests (run against every backend)
# ---------------------------------------------------------------------------


class TestShardStoreInterface:
    """Tests that run against all ShardStore implementations."""

    @pytest.fixture(params=ALL_STORES)
    def store(self, request):
        return request.getfixturevalue(request.param)

    def test_set_and_get(self, store):
        store[("entity-1", 0)] = b"shard-data-0"
        assert store[("entity-1", 0)] == b"shard-data-0"

    def test_get_missing_raises(self, store):
        with pytest.raises(KeyError):
            _ = store[("nonexistent", 0)]

    def test_contains(self, store):
        assert ("entity-1", 0) not in store
        store[("entity-1", 0)] = b"data"
        assert ("entity-1", 0) in store

    def test_len(self, store):
        assert len(store) == 0
        store[("e1", 0)] = b"a"
        store[("e1", 1)] = b"b"
        store[("e2", 0)] = b"c"
        assert len(store) == 3

    def test_delete(self, store):
        store[("e1", 0)] = b"data"
        del store[("e1", 0)]
        assert ("e1", 0) not in store
        assert len(store) == 0

    def test_delete_missing_raises(self, store):
        with pytest.raises(KeyError):
            del store[("nonexistent", 0)]

    def test_get_default(self, store):
        assert store.get(("missing", 0)) is None
        assert store.get(("missing", 0), b"fallback") == b"fallback"

    def test_get_existing(self, store):
        store[("e1", 0)] = b"data"
        assert store.get(("e1", 0)) == b"data"

    def test_pop(self, store):
        store[("e1", 0)] = b"data"
        val = store.pop(("e1", 0))
        assert val == b"data"
        assert ("e1", 0) not in store

    def test_pop_missing_with_default(self, store):
        assert store.pop(("missing", 0), None) is None

    def test_pop_missing_raises(self, store):
        with pytest.raises(KeyError):
            store.pop(("missing", 0))

    def test_keys(self, store):
        store[("e1", 0)] = b"a"
        store[("e1", 1)] = b"b"
        store[("e2", 0)] = b"c"
        keys = set(store.keys())
        assert keys == {("e1", 0), ("e1", 1), ("e2", 0)}

    def test_items(self, store):
        store[("e1", 0)] = b"alpha"
        store[("e2", 1)] = b"beta"
        items = dict(store.items())
        assert items == {("e1", 0): b"alpha", ("e2", 1): b"beta"}

    def test_overwrite(self, store):
        store[("e1", 0)] = b"old"
        store[("e1", 0)] = b"new"
        assert store[("e1", 0)] == b"new"
        assert len(store) == 1

    def test_large_shard(self, store):
        big_data = os.urandom(1_000_000)  # 1MB shard
        store[("big", 0)] = big_data
        assert store[("big", 0)] == big_data

    def test_many_shards(self, store):
        for i in range(100):
            store[("entity", i)] = f"shard-{i}".encode()
        assert len(store) == 100
        for i in range(100):
            assert store[("entity", i)] == f"shard-{i}".encode()

    def test_repr(self, store):
        r = repr(store)
        assert "count=" in r or "Store" in r


# ---------------------------------------------------------------------------
# Backend-specific tests
# ---------------------------------------------------------------------------


class TestSQLiteSpecific:
    def test_persistence_across_connections(self, tmp_path):
        db_path = str(tmp_path / "persist.db")

        store1 = SQLiteShardStore(db_path)
        store1[("e1", 0)] = b"persistent-data"
        store1.close()

        store2 = SQLiteShardStore(db_path)
        assert store2[("e1", 0)] == b"persistent-data"
        store2.close()

    def test_bulk_insert(self, sqlite_store):
        entries = [(("bulk-entity", i), f"bulk-{i}".encode()) for i in range(50)]
        count = sqlite_store.bulk_insert(entries)
        assert count == 50
        assert len(sqlite_store) == 50
        assert sqlite_store[("bulk-entity", 25)] == b"bulk-25"

    def test_entity_shards(self, sqlite_store):
        for i in range(5):
            sqlite_store[("eid", i)] = f"s{i}".encode()
        sqlite_store[("other", 0)] = b"x"

        result = sqlite_store.entity_shards("eid")
        assert len(result) == 5
        assert result[0] == (0, b"s0")
        assert result[4] == (4, b"s4")


class TestFileStoreSpecific:
    def test_persistence_across_instances(self, tmp_path):
        base = str(tmp_path / "shards")

        store1 = FileShardStore(base)
        store1[("e1", 0)] = b"file-data"

        store2 = FileShardStore(base)
        assert store2[("e1", 0)] == b"file-data"

    def test_entity_shards(self, file_store):
        for i in range(5):
            file_store[("eid", i)] = f"s{i}".encode()
        file_store[("other", 0)] = b"x"

        result = file_store.entity_shards("eid")
        assert len(result) == 5

    def test_atomic_write(self, file_store):
        """Verify no .tmp files remain after write."""
        file_store[("e1", 0)] = b"atomic"
        import glob

        tmp_files = glob.glob(str(file_store._base_dir / "**/*.tmp"), recursive=True)
        assert len(tmp_files) == 0


# ---------------------------------------------------------------------------
# CommitmentNode integration
# ---------------------------------------------------------------------------


class TestCommitmentNodeWithStore:
    def test_node_with_memory_store(self):
        from src.ltp.commitment import CommitmentNode

        node = CommitmentNode("n1", "US-East")
        assert isinstance(node.shards, MemoryShardStore)
        node.store_shard("eid", 0, b"data")
        assert node.fetch_shard("eid", 0) == b"data"

    def test_node_with_sqlite_store(self):
        from src.ltp.commitment import CommitmentNode

        store = SQLiteShardStore(":memory:")
        node = CommitmentNode("n1", "US-East", shard_store=store)
        node.store_shard("eid", 0, b"sqlite-data")
        assert node.fetch_shard("eid", 0) == b"sqlite-data"
        assert len(store) == 1
        store.close()

    def test_node_with_file_store(self, tmp_path):
        from src.ltp.commitment import CommitmentNode

        store = FileShardStore(str(tmp_path / "node_shards"))
        node = CommitmentNode("n1", "US-East", shard_store=store)
        node.store_shard("eid", 0, b"file-data")
        assert node.fetch_shard("eid", 0) == b"file-data"

    def test_full_protocol_with_sqlite(self):
        """Complete COMMIT → MATERIALIZE with SQLite shard storage."""
        from src.ltp.commitment import CommitmentNetwork, CommitmentNode
        from src.ltp.entity import Entity
        from src.ltp.keypair import KeyPair
        from src.ltp.protocol import LTPProtocol

        net = CommitmentNetwork()
        for i in range(6):
            store = SQLiteShardStore(":memory:")
            node = CommitmentNode(f"n-{i}", f"region-{i % 3}", shard_store=store)
            net.add_existing_node(node)

        alice = KeyPair.generate("alice")
        bob = KeyPair.generate("bob")
        protocol = LTPProtocol(net)

        content = b"SQLite storage end-to-end test"
        entity = Entity(content=content, shape="text/plain")

        entity_id, record, cek = protocol.commit(entity, alice, n=8, k=4)
        sealed = protocol.lattice(entity_id, record, cek, bob)
        result = protocol.materialize(sealed, bob)
        assert result == content
