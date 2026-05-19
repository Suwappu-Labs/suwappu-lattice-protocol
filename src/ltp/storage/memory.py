"""In-memory shard store — drop-in replacement for the plain dict."""

from __future__ import annotations

from typing import Iterator, Optional

from .base import ShardKey, ShardStore

__all__ = ["MemoryShardStore"]


class MemoryShardStore(ShardStore):
    """In-memory shard storage backed by a Python dict.

    This is the default store, providing identical behavior to the original
    CommitmentNode.shards dict. Use for testing or when persistence is not needed.
    """

    def __init__(self) -> None:
        self._data: dict[ShardKey, bytes] = {}

    def __getitem__(self, key: ShardKey) -> bytes:
        return self._data[key]

    def __setitem__(self, key: ShardKey, value: bytes) -> None:
        self._data[key] = value

    def __delitem__(self, key: ShardKey) -> None:
        del self._data[key]

    def __contains__(self, key: ShardKey) -> bool:
        return key in self._data

    def __len__(self) -> int:
        return len(self._data)

    def keys(self) -> Iterator[ShardKey]:
        return iter(list(self._data.keys()))

    def get(self, key: ShardKey, default: Optional[bytes] = None) -> Optional[bytes]:
        return self._data.get(key, default)

    def items(self) -> Iterator[tuple[ShardKey, bytes]]:
        return iter(list(self._data.items()))
