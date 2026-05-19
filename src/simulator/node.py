"""
Simulation node — a capacity-bounded, failure-aware commitment node.

SimNode wraps the LTP CommitmentNode with simulation-specific concerns:
  - Storage capacity limits (bytes and shard count)
  - Uptime modelling (scheduled failures, MTBF/MTTR)
  - Processing delay simulation
  - Audit response with realistic timing
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

from src.ltp.primitives import internal_hash


@dataclass
class StorageCapacity:
    """Storage limits for a simulation node."""

    max_bytes: int = 10 * 1024 * 1024 * 1024  # 10 GB default
    max_shards: int = 100_000
    used_bytes: int = 0
    shard_count: int = 0

    @property
    def available_bytes(self) -> int:
        return max(0, self.max_bytes - self.used_bytes)

    @property
    def available_shards(self) -> int:
        return max(0, self.max_shards - self.shard_count)

    @property
    def utilization(self) -> float:
        """Storage utilization as a fraction [0, 1]."""
        if self.max_bytes == 0:
            return 1.0
        return self.used_bytes / self.max_bytes

    def can_store(self, data_bytes: int) -> bool:
        return self.used_bytes + data_bytes <= self.max_bytes and self.shard_count < self.max_shards

    def allocate(self, data_bytes: int) -> None:
        self.used_bytes += data_bytes
        self.shard_count += 1

    def release(self, data_bytes: int) -> None:
        self.used_bytes = max(0, self.used_bytes - data_bytes)
        self.shard_count = max(0, self.shard_count - 1)


class SimNode:
    """
    A simulation-native commitment node with capacity, uptime, and timing.

    This is a parallel implementation to CommitmentNode, designed to be
    the closest analogue to a real-world LTP node. It stores encrypted
    shards, responds to audits, and models storage limits and failures.
    """

    def __init__(
        self,
        node_id: str,
        region: str,
        capacity: StorageCapacity | None = None,
        processing_delay_ms: float = 0.5,
    ) -> None:
        self.node_id = node_id
        self.region = region
        self.capacity = capacity or StorageCapacity()
        self.processing_delay_ms = processing_delay_ms

        # Shard storage: (entity_id, shard_index) → encrypted bytes
        self._shards: dict[tuple[str, int], bytes] = {}

        # State
        self._online: bool = True
        self._evicted: bool = False

        # Statistics
        self.total_stores: int = 0
        self.total_fetches: int = 0
        self.total_audits: int = 0
        self.failed_stores: int = 0
        self.failed_fetches: int = 0
        self.strikes: int = 0
        self.audit_passes: int = 0

        # Uptime tracking
        self._failure_schedule: list[tuple[float, float]] = []  # (start_ms, end_ms)

    # --- Online/offline state ---

    @property
    def online(self) -> bool:
        return self._online and not self._evicted

    def set_online(self, online: bool) -> None:
        self._online = online

    def evict(self) -> None:
        """Permanently evict this node from the network."""
        self._evicted = True
        self._online = False

    @property
    def is_evicted(self) -> bool:
        return self._evicted

    def schedule_failure(self, start_ms: float, end_ms: float) -> None:
        """Schedule a failure window. Node goes offline at start, recovers at end."""
        self._failure_schedule.append((start_ms, end_ms))

    def is_online_at(self, time_ms: float) -> bool:
        """Check if node is online at a given simulation time."""
        if self._evicted:
            return False
        for start, end in self._failure_schedule:
            if start <= time_ms < end:
                return False
        return self._online

    # --- Shard operations ---

    def store_shard(self, entity_id: str, shard_index: int, encrypted_data: bytes) -> bool:
        """
        Store an encrypted shard.

        Returns False if: node offline, evicted, or capacity exceeded.
        """
        if not self.online:
            self.failed_stores += 1
            return False

        if not self.capacity.can_store(len(encrypted_data)):
            self.failed_stores += 1
            return False

        key = (entity_id, shard_index)
        if key in self._shards:
            # Overwrite — release old capacity
            old_size = len(self._shards[key])
            self.capacity.release(old_size)

        self._shards[key] = encrypted_data
        self.capacity.allocate(len(encrypted_data))
        self.total_stores += 1
        return True

    def fetch_shard(self, entity_id: str, shard_index: int) -> Optional[bytes]:
        """
        Fetch an encrypted shard. Returns None if missing or offline.
        """
        if not self.online:
            self.failed_fetches += 1
            return None

        self.total_fetches += 1
        return self._shards.get((entity_id, shard_index))

    def has_shard(self, entity_id: str, shard_index: int) -> bool:
        return (entity_id, shard_index) in self._shards

    def remove_shard(self, entity_id: str, shard_index: int) -> bool:
        key = (entity_id, shard_index)
        if key in self._shards:
            size = len(self._shards[key])
            del self._shards[key]
            self.capacity.release(size)
            return True
        return False

    # --- Audit ---

    def respond_to_audit(self, entity_id: str, shard_index: int, nonce: bytes) -> Optional[str]:
        """
        Respond to a storage proof challenge.

        Protocol: Challenge(entity_id, shard_index, nonce) → H(ciphertext || nonce)
        Returns None if shard missing or node offline.
        """
        self.total_audits += 1
        if not self.online:
            return None
        ct = self._shards.get((entity_id, shard_index))
        if ct is None:
            return None
        self.audit_passes += 1
        return internal_hash(ct + nonce)

    # --- Replication support ---

    def get_all_shard_keys(self) -> list[tuple[str, int]]:
        """List all (entity_id, shard_index) pairs stored on this node."""
        return list(self._shards.keys())

    def copy_shard_to(self, entity_id: str, shard_index: int, target: "SimNode") -> bool:
        """Copy a shard to another node (for repair)."""
        data = self._shards.get((entity_id, shard_index))
        if data is None:
            return False
        return target.store_shard(entity_id, shard_index, data)

    # --- Stats ---

    @property
    def shard_count(self) -> int:
        return len(self._shards)

    def stats(self) -> dict:
        return {
            "node_id": self.node_id,
            "region": self.region,
            "online": self.online,
            "evicted": self._evicted,
            "shard_count": self.shard_count,
            "capacity_utilization": f"{self.capacity.utilization:.1%}",
            "total_stores": self.total_stores,
            "total_fetches": self.total_fetches,
            "total_audits": self.total_audits,
            "failed_stores": self.failed_stores,
            "failed_fetches": self.failed_fetches,
            "strikes": self.strikes,
        }

    def __repr__(self) -> str:
        status = "ONLINE" if self.online else ("EVICTED" if self._evicted else "OFFLINE")
        return (
            f"SimNode({self.node_id!r}, region={self.region!r}, "
            f"status={status}, shards={self.shard_count})"
        )
