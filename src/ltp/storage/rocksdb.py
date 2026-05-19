"""
RocksDB-compatible shard storage using LSM-tree.

Uses lsm-db (pure Python LSM-tree, API-compatible with RocksDB semantics)
for production-grade write-heavy workloads. Drop-in replacement for
MemoryShardStore / SQLiteShardStore.

Key encoding: f"{entity_id}:{shard_index}" → bytes
Value: raw shard bytes

Requires: pip install lsm-db
"""

from __future__ import annotations

import logging
from typing import Iterator, Optional

from .base import ShardKey, ShardStore

logger = logging.getLogger(__name__)

__all__ = ["RocksDBShardStore"]


def _encode_key(key: ShardKey) -> bytes:
    """Encode (entity_id, shard_index) to bytes key."""
    entity_id, shard_index = key
    return f"{entity_id}:{shard_index}".encode("utf-8")


def _decode_key(raw: bytes) -> ShardKey:
    """Decode bytes key to (entity_id, shard_index)."""
    s = raw.decode("utf-8")
    parts = s.rsplit(":", 1)
    return (parts[0], int(parts[1]))


class RocksDBShardStore(ShardStore):
    """LSM-tree backed shard storage (RocksDB-compatible).

    Uses lsm-db for write-optimized persistent storage with:
    - O(1) amortized writes via LSM-tree append
    - Efficient range scans via sorted key ordering
    - Background compaction for read optimization
    - Crash recovery via write-ahead log

    Args:
        path: Directory path for the database files.
    """

    def __init__(self, path: str) -> None:
        try:
            import lsm
        except ImportError:
            raise ImportError("lsm-db is required for RocksDB storage: pip install lsm-db")

        self._path = path
        self._db = lsm.LSM(path)
        logger.info("RocksDBShardStore opened at %s", path)

    def __getitem__(self, key: ShardKey) -> bytes:
        encoded = _encode_key(key)
        try:
            value = self._db[encoded]
        except KeyError:
            raise KeyError(key)
        return value

    def __setitem__(self, key: ShardKey, value: bytes) -> None:
        encoded = _encode_key(key)
        self._db[encoded] = value

    def __delitem__(self, key: ShardKey) -> None:
        encoded = _encode_key(key)
        # lsm-db doesn't raise on missing delete — check existence first
        try:
            _ = self._db[encoded]
        except KeyError:
            raise KeyError(key)
        del self._db[encoded]

    def __contains__(self, key: ShardKey) -> bool:
        encoded = _encode_key(key)
        try:
            _ = self._db[encoded]
            return True
        except KeyError:
            return False

    def __len__(self) -> int:
        count = 0
        for _ in self._db.keys():
            count += 1
        return count

    def keys(self) -> Iterator[ShardKey]:
        for raw_key in self._db.keys():
            try:
                yield _decode_key(raw_key)
            except (ValueError, IndexError):
                continue  # Skip malformed keys

    def get(self, key: ShardKey, default: Optional[bytes] = None) -> Optional[bytes]:
        try:
            return self[key]
        except KeyError:
            return default

    def close(self) -> None:
        """Close the database and flush pending writes."""
        if self._db is not None:
            self._db.close()
            self._db = None
            logger.info("RocksDBShardStore closed at %s", self._path)
