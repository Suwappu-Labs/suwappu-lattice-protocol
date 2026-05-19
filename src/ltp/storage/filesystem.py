"""Filesystem-backed persistent shard store — one file per shard."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Iterator, Optional

from .base import ShardKey, ShardStore

__all__ = ["FileShardStore"]


class FileShardStore(ShardStore):
    """Persistent shard storage using the filesystem.

    Each shard is stored as a separate file under a directory tree:
        base_dir/<entity_id_prefix>/<entity_id>/<shard_index>.bin

    entity_id_prefix is the first 4 hex chars of SHA-256(entity_id) for
    directory fan-out (avoids millions of entries in a single directory).

    Args:
        base_dir: Root directory for shard storage.
    """

    def __init__(self, base_dir: str) -> None:
        self._base_dir = Path(base_dir)
        self._base_dir.mkdir(parents=True, exist_ok=True)

    def _shard_path(self, key: ShardKey) -> Path:
        entity_id, shard_index = key
        prefix = hashlib.sha256(entity_id.encode()).hexdigest()[:4]
        # Sanitize entity_id for filesystem (replace path separators)
        safe_eid = entity_id.replace("/", "_").replace("\\", "_")
        return self._base_dir / prefix / safe_eid / f"{shard_index}.bin"

    def __getitem__(self, key: ShardKey) -> bytes:
        path = self._shard_path(key)
        if not path.exists():
            raise KeyError(key)
        return path.read_bytes()

    def __setitem__(self, key: ShardKey, value: bytes) -> None:
        path = self._shard_path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Write atomically: write to temp then rename
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(value)
        tmp.rename(path)

    def __delitem__(self, key: ShardKey) -> None:
        path = self._shard_path(key)
        if not path.exists():
            raise KeyError(key)
        path.unlink()
        # Clean up empty parent directories
        try:
            path.parent.rmdir()
            path.parent.parent.rmdir()
        except OSError:
            pass  # Directory not empty, that's fine

    def __contains__(self, key: ShardKey) -> bool:
        return self._shard_path(key).exists()

    def __len__(self) -> int:
        count = 0
        for _ in self._base_dir.rglob("*.bin"):
            count += 1
        return count

    def keys(self) -> Iterator[ShardKey]:
        for bin_path in sorted(self._base_dir.rglob("*.bin")):
            shard_index = int(bin_path.stem)
            entity_id = bin_path.parent.name
            yield (entity_id, shard_index)

    def get(self, key: ShardKey, default: Optional[bytes] = None) -> Optional[bytes]:
        try:
            return self[key]
        except KeyError:
            return default

    def entity_shards(self, entity_id: str) -> list[tuple[int, bytes]]:
        """Get all shards for an entity, sorted by index."""
        result = []
        prefix = hashlib.sha256(entity_id.encode()).hexdigest()[:4]
        safe_eid = entity_id.replace("/", "_").replace("\\", "_")
        entity_dir = self._base_dir / prefix / safe_eid
        if entity_dir.exists():
            for bin_path in sorted(entity_dir.glob("*.bin")):
                shard_index = int(bin_path.stem)
                result.append((shard_index, bin_path.read_bytes()))
        return result

    def __repr__(self) -> str:
        return f"FileShardStore(dir={self._base_dir!r}, count={len(self)})"
