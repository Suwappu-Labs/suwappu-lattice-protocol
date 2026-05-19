"""SQLite-backed persistent shard store."""

from __future__ import annotations

import sqlite3
import threading
from typing import Iterator, Optional

from .base import ShardKey, ShardStore

__all__ = ["SQLiteShardStore"]


class SQLiteShardStore(ShardStore):
    """Persistent shard storage using SQLite.

    Each shard is stored as a row: (entity_id TEXT, shard_index INTEGER, data BLOB).
    Thread-safe via a per-instance lock (SQLite doesn't support concurrent writes
    from the same connection well).

    Args:
        db_path: Path to SQLite database file. Use ":memory:" for in-memory.
        node_id: Optional node identifier for multi-node databases.
    """

    def __init__(self, db_path: str = ":memory:", node_id: str = "") -> None:
        self._db_path = db_path
        self._node_id = node_id
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS shards (
                entity_id   TEXT    NOT NULL,
                shard_index INTEGER NOT NULL,
                data        BLOB    NOT NULL,
                stored_at   REAL    DEFAULT (strftime('%s', 'now')),
                PRIMARY KEY (entity_id, shard_index)
            )
        """)
        self._conn.commit()

    def __getitem__(self, key: ShardKey) -> bytes:
        entity_id, shard_index = key
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM shards WHERE entity_id=? AND shard_index=?",
                (entity_id, shard_index),
            ).fetchone()
        if row is None:
            raise KeyError(key)
        return row[0]

    def __setitem__(self, key: ShardKey, value: bytes) -> None:
        entity_id, shard_index = key
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO shards (entity_id, shard_index, data) VALUES (?, ?, ?)",
                (entity_id, shard_index, value),
            )
            self._conn.commit()

    def __delitem__(self, key: ShardKey) -> None:
        entity_id, shard_index = key
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM shards WHERE entity_id=? AND shard_index=?",
                (entity_id, shard_index),
            )
            self._conn.commit()
        if cursor.rowcount == 0:
            raise KeyError(key)

    def __contains__(self, key: ShardKey) -> bool:
        entity_id, shard_index = key
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM shards WHERE entity_id=? AND shard_index=?",
                (entity_id, shard_index),
            ).fetchone()
        return row is not None

    def __len__(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM shards").fetchone()
        return row[0]

    def keys(self) -> Iterator[ShardKey]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT entity_id, shard_index FROM shards ORDER BY entity_id, shard_index"
            ).fetchall()
        return iter([(r[0], r[1]) for r in rows])

    def get(self, key: ShardKey, default: Optional[bytes] = None) -> Optional[bytes]:
        try:
            return self[key]
        except KeyError:
            return default

    def items(self) -> Iterator[tuple[ShardKey, bytes]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT entity_id, shard_index, data FROM shards ORDER BY entity_id, shard_index"
            ).fetchall()
        return iter([((r[0], r[1]), r[2]) for r in rows])

    def bulk_insert(self, entries: list[tuple[ShardKey, bytes]]) -> int:
        """Insert multiple shards in a single transaction. Returns count inserted."""
        with self._lock:
            self._conn.executemany(
                "INSERT OR REPLACE INTO shards (entity_id, shard_index, data) VALUES (?, ?, ?)",
                [(k[0], k[1], v) for k, v in entries],
            )
            self._conn.commit()
        return len(entries)

    def entity_shards(self, entity_id: str) -> list[tuple[int, bytes]]:
        """Get all shards for an entity, sorted by index."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT shard_index, data FROM shards WHERE entity_id=? ORDER BY shard_index",
                (entity_id,),
            ).fetchall()
        return [(r[0], r[1]) for r in rows]

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __repr__(self) -> str:
        return f"SQLiteShardStore(db={self._db_path!r}, count={len(self)})"
