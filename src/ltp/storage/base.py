"""
Abstract shard storage interface.

ShardStore is dict-like: supports __getitem__, __setitem__, __delitem__,
__contains__, __len__, keys(), items(), get(), pop(). This allows it to be
a drop-in replacement for the plain dict used in CommitmentNode.shards.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator, Optional

# Shard key: (entity_id: str, shard_index: int)
ShardKey = tuple[str, int]

__all__ = ["ShardStore", "ShardKey"]


class ShardStore(ABC):
    """Abstract dict-like shard storage.

    Concrete implementations: MemoryShardStore, SQLiteShardStore, FileShardStore.
    All methods are synchronous. For async I/O, wrap in an executor.
    """

    @abstractmethod
    def __getitem__(self, key: ShardKey) -> bytes:
        """Retrieve shard data. Raises KeyError if not found."""

    @abstractmethod
    def __setitem__(self, key: ShardKey, value: bytes) -> None:
        """Store shard data."""

    @abstractmethod
    def __delitem__(self, key: ShardKey) -> None:
        """Delete shard data. Raises KeyError if not found."""

    @abstractmethod
    def __contains__(self, key: ShardKey) -> bool:
        """Check if a shard exists."""

    @abstractmethod
    def __len__(self) -> int:
        """Return the number of stored shards."""

    @abstractmethod
    def keys(self) -> Iterator[ShardKey]:
        """Iterate over all shard keys."""

    @abstractmethod
    def get(self, key: ShardKey, default: Optional[bytes] = None) -> Optional[bytes]:
        """Get shard data, returning default if not found."""

    def pop(self, key: ShardKey, *args) -> Optional[bytes]:
        """Remove and return shard data. Optional default if not found."""
        try:
            value = self[key]
            del self[key]
            return value
        except KeyError:
            if args:
                return args[0]
            raise

    def items(self) -> Iterator[tuple[ShardKey, bytes]]:
        """Iterate over (key, value) pairs."""
        for key in self.keys():
            yield key, self[key]

    def close(self) -> None:
        """Release resources (connections, file handles). Default is no-op."""

    def __repr__(self) -> str:
        return f"{type(self).__name__}(count={len(self)})"
