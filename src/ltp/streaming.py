"""
Streaming entity protocol for the Lattice Transfer Protocol.

Enables chunked commit and incremental materialization for large entities
and real-time streams. Addresses Open Questions 4 (bandwidth amortization)
and 5 (real-time streaming).

Whitepaper reference: Open Questions 4 & 5
Design decision: docs/design-decisions/STREAMING_PROTOCOL.md
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .primitives import canonical_hash

__all__ = [
    "StreamState",
    "StreamConfig",
    "StreamChunk",
    "StreamManifest",
    "EntityStream",
]


class StreamState(Enum):
    """Lifecycle state of an entity stream."""

    OPEN = "open"  # Accepting chunks
    CLOSED = "closed"  # No more chunks, awaiting finalization
    FINALIZED = "finalized"  # Stream complete, aggregate entity_id computed
    FAILED = "failed"  # Stream failed (timeout, corruption)


@dataclass
class StreamConfig:
    """Configuration for streaming entity transfers."""

    chunk_size_bytes: int = 65_536  # 64 KB per chunk
    max_concurrent_chunks: int = 4  # Pipeline depth
    pipeline_enabled: bool = True  # Enable pipelined distribution
    max_chunks_per_stream: int = 100_000  # Safety limit
    stream_timeout_epochs: int = 720  # 30 days timeout


@dataclass
class StreamChunk:
    """
    A single chunk in an entity stream.

    Each chunk is independently committed to the network and can be
    materialized before the full stream is finalized.
    """

    stream_id: str
    sequence: int  # 0-indexed position in stream
    data: bytes  # Chunk content
    chunk_entity_id: str  # H(stream_id || sequence || data)
    committed: bool = False
    committed_epoch: int = -1

    @property
    def size_bytes(self) -> int:
        return len(self.data)


@dataclass
class StreamManifest:
    """
    Metadata binding all chunks to a single logical entity.

    The manifest is created when the stream is finalized and serves as
    the aggregate record that ties all chunks together.
    """

    stream_id: str
    stream_entity_id: str  # Aggregate entity_id over all chunks
    total_chunks: int
    total_size: int
    shape: str
    chunk_entity_ids: list[str] = field(default_factory=list)
    created_at: float = 0.0
    finalized_at: float = 0.0

    @property
    def is_complete(self) -> bool:
        return len(self.chunk_entity_ids) == self.total_chunks


class EntityStream:
    """
    Manages chunked entity streaming for LTP.

    Lifecycle:
      1. open_stream()     → Create a new stream
      2. add_chunk()       → Add chunks (can be pipelined)
      3. close_stream()    → Signal no more chunks
      4. finalize_stream() → Compute aggregate entity_id

    Bandwidth Amortization (OQ 4):
      Pipelined distribution allows shard distribution for chunk N
      to overlap with erasure encoding of chunk N+1.

    Real-Time Streaming (OQ 5):
      Incremental materialization allows receivers to start consuming
      chunks before the sender finishes committing.
    """

    def __init__(self, config: StreamConfig | None = None) -> None:
        self.config = config or StreamConfig()
        # stream_id → stream metadata
        self._streams: dict[str, dict] = {}
        # stream_id → ordered list of chunks
        self._chunks: dict[str, list[StreamChunk]] = {}

    def open_stream(
        self,
        sender_id: str,
        shape: str,
        total_size_hint: int = 0,
    ) -> str:
        """
        Open a new entity stream.

        Returns a stream_id that must be used for all subsequent operations.
        """
        stream_id = canonical_hash(f"{sender_id}:{shape}:{time.time()}:{id(self)}".encode())

        self._streams[stream_id] = {
            "state": StreamState.OPEN,
            "sender_id": sender_id,
            "shape": shape,
            "total_size_hint": total_size_hint,
            "created_at": time.time(),
            "created_epoch": -1,
            "chunk_count": 0,
            "total_bytes": 0,
        }
        self._chunks[stream_id] = []

        return stream_id

    def add_chunk(
        self,
        stream_id: str,
        data: bytes,
        sequence: Optional[int] = None,
    ) -> StreamChunk:
        """
        Add a chunk to an open stream.

        If sequence is None, appends to the end.
        Chunks can be added out of order (for parallel upload).
        """
        stream = self._streams.get(stream_id)
        if stream is None:
            raise ValueError(f"Unknown stream: {stream_id}")
        if stream["state"] != StreamState.OPEN:
            raise ValueError(f"Stream {stream_id} is {stream['state'].value}, not open")

        if sequence is None:
            sequence = stream["chunk_count"]

        # Safety limit
        if sequence >= self.config.max_chunks_per_stream:
            raise ValueError(
                f"Chunk sequence {sequence} exceeds maximum {self.config.max_chunks_per_stream}"
            )

        # Compute chunk entity_id
        chunk_entity_id = canonical_hash(stream_id.encode() + sequence.to_bytes(4, "big") + data)

        chunk = StreamChunk(
            stream_id=stream_id,
            sequence=sequence,
            data=data,
            chunk_entity_id=chunk_entity_id,
        )

        # Insert in order
        chunks = self._chunks[stream_id]
        while len(chunks) <= sequence:
            chunks.append(None)  # type: ignore
        chunks[sequence] = chunk

        stream["chunk_count"] = max(stream["chunk_count"], sequence + 1)
        stream["total_bytes"] += len(data)

        return chunk

    def mark_chunk_committed(
        self,
        stream_id: str,
        sequence: int,
        epoch: int,
    ) -> bool:
        """Mark a chunk as committed to the network."""
        chunks = self._chunks.get(stream_id)
        if chunks is None or sequence >= len(chunks) or chunks[sequence] is None:
            return False
        chunks[sequence].committed = True
        chunks[sequence].committed_epoch = epoch
        return True

    def close_stream(self, stream_id: str) -> bool:
        """
        Signal that no more chunks will be added.

        The stream can still be finalized after closing.
        """
        stream = self._streams.get(stream_id)
        if stream is None:
            return False
        if stream["state"] != StreamState.OPEN:
            return False
        stream["state"] = StreamState.CLOSED
        return True

    def finalize_stream(self, stream_id: str) -> Optional[StreamManifest]:
        """
        Finalize a closed stream and compute the aggregate entity_id.

        The aggregate entity_id is:
          H(stream_id || chunk_0_id || chunk_1_id || ... || chunk_n_id)

        This binds all chunks to a single logical entity.
        Returns None if stream has gaps (missing chunks).
        """
        stream = self._streams.get(stream_id)
        if stream is None:
            return None
        if stream["state"] not in (StreamState.CLOSED, StreamState.OPEN):
            return None

        chunks = self._chunks.get(stream_id, [])
        if not chunks or any(c is None for c in chunks):
            return None

        # Compute aggregate entity_id
        chunk_ids = [c.chunk_entity_id for c in chunks]
        aggregate_input = stream_id.encode()
        for cid in chunk_ids:
            aggregate_input += cid.encode()
        stream_entity_id = canonical_hash(aggregate_input)

        manifest = StreamManifest(
            stream_id=stream_id,
            stream_entity_id=stream_entity_id,
            total_chunks=len(chunks),
            total_size=stream["total_bytes"],
            shape=stream["shape"],
            chunk_entity_ids=chunk_ids,
            created_at=stream["created_at"],
            finalized_at=time.time(),
        )

        stream["state"] = StreamState.FINALIZED
        return manifest

    def get_chunk(self, stream_id: str, sequence: int) -> Optional[StreamChunk]:
        """Get a specific chunk from a stream."""
        chunks = self._chunks.get(stream_id)
        if chunks is None or sequence >= len(chunks):
            return None
        return chunks[sequence]

    def get_stream_state(self, stream_id: str) -> Optional[StreamState]:
        """Get the current state of a stream."""
        stream = self._streams.get(stream_id)
        return stream["state"] if stream else None

    def get_committed_chunks(self, stream_id: str) -> list[StreamChunk]:
        """Get all committed chunks for a stream (for incremental materialization)."""
        chunks = self._chunks.get(stream_id, [])
        return [c for c in chunks if c is not None and c.committed]

    def reassemble_stream(self, stream_id: str) -> Optional[bytes]:
        """
        Reassemble all chunks into the original entity content.

        For materialization: fetch all chunks in order and concatenate.
        Returns None if any chunk is missing.
        """
        chunks = self._chunks.get(stream_id, [])
        if not chunks or any(c is None for c in chunks):
            return None

        return b"".join(c.data for c in chunks)

    def compute_pipeline_schedule(self, total_size: int) -> dict:
        """
        Compute the pipelining schedule for bandwidth amortization.

        Returns timing info showing how pipelining reduces end-to-end
        latency compared to monolithic commit.
        """
        cfg = self.config
        chunk_count = max(1, (total_size + cfg.chunk_size_bytes - 1) // cfg.chunk_size_bytes)
        pipeline_depth = min(cfg.max_concurrent_chunks, chunk_count)

        # Monolithic: all shards distributed at once
        monolithic_phases = 1

        # Pipelined: chunks overlap distribution with encoding
        # First chunk starts immediately; subsequent chunks overlap
        pipelined_phases = 1 + max(0, chunk_count - pipeline_depth)

        return {
            "total_size": total_size,
            "chunk_size": cfg.chunk_size_bytes,
            "chunk_count": chunk_count,
            "pipeline_depth": pipeline_depth,
            "monolithic_sequential_phases": monolithic_phases,
            "pipelined_sequential_phases": pipelined_phases,
            "speedup_factor": round(chunk_count / max(1, pipelined_phases), 2)
            if pipeline_depth > 1
            else 1.0,
        }

    @property
    def active_streams(self) -> list[str]:
        return [
            sid
            for sid, s in self._streams.items()
            if s["state"] in (StreamState.OPEN, StreamState.CLOSED)
        ]

    @property
    def finalized_streams(self) -> list[str]:
        return [sid for sid, s in self._streams.items() if s["state"] == StreamState.FINALIZED]
