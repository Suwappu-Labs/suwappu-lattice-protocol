"""
Thread-safe wrapper around CommitmentNetwork.

Protects concurrent access from gRPC threads, audit thread,
and main thread with an RLock.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..commitment import CommitmentNetwork, CommitmentNode

__all__ = ["SafeCommitmentNetwork"]


class SafeCommitmentNetwork:
    """Thread-safe wrapper around CommitmentNetwork.

    Uses wrap-and-delegate pattern: explicit locking for mutating methods,
    snapshot properties for collections accessed by multiple threads.
    RLock allows nested calls (e.g., distribute calls _placement internally).

    IMPORTANT: `.nodes` returns a snapshot (list copy) under the lock to
    prevent RuntimeError during concurrent iteration + mutation.  Code that
    needs the live list should use explicit locked methods instead.
    """

    def __init__(self, inner: "CommitmentNetwork") -> None:
        self._inner = inner
        self._lock = threading.RLock()

    # --- Properties that return snapshots under the lock ---

    @property
    def nodes(self) -> list:
        """Return a snapshot of the node list (safe to iterate concurrently)."""
        with self._lock:
            return list(self._inner.nodes)

    @property
    def log(self):
        """Return the commitment log.

        The log itself is append-only and its internal dict operations are
        atomic under the GIL, but callers doing log.append() during
        concurrent distribute should go through the locked methods.
        """
        return self._inner.log

    @property
    def active_node_count(self) -> int:
        with self._lock:
            return self._inner.active_node_count

    # --- Mutating methods (always locked) ---

    def add_existing_node(self, node: "CommitmentNode") -> "CommitmentNode":
        with self._lock:
            return self._inner.add_existing_node(node)

    def add_node(self, node_id: str, region: str) -> "CommitmentNode":
        with self._lock:
            return self._inner.add_node(node_id, region)

    def distribute_encrypted_shards(
        self, entity_id: str, encrypted_shards: list[bytes], replicas: int = 2
    ) -> str:
        with self._lock:
            return self._inner.distribute_encrypted_shards(entity_id, encrypted_shards, replicas)

    def fetch_encrypted_shards(self, entity_id: str, n: int, max_shards: int) -> dict[int, bytes]:
        with self._lock:
            return self._inner.fetch_encrypted_shards(entity_id, n, max_shards)

    def audit_node(self, node, burst: int = 1):
        with self._lock:
            return self._inner.audit_node(node, burst=burst)

    def audit_node_pdp(self, node, epoch: int, sample_size: int = 4, vdf_verifier=None):
        with self._lock:
            return self._inner.audit_node_pdp(
                node, epoch, sample_size=sample_size, vdf_verifier=vdf_verifier
            )

    def audit_all_nodes(self, burst: int = 1):
        with self._lock:
            return self._inner.audit_all_nodes(burst=burst)

    def set_enforcement_pipeline(self, pipeline):
        with self._lock:
            self._inner.set_enforcement_pipeline(pipeline)

    def set_geo_fence_policy(self, policy):
        with self._lock:
            self._inner.set_geo_fence_policy(policy)

    def set_audit_logger(self, logger):
        with self._lock:
            self._inner.set_audit_logger(logger)

    def records_since(self, index: int):
        """Delegate to CommitmentLog.records_since under the lock."""
        with self._lock:
            return self._inner.log.records_since(index)

    def auto_evict_if_needed(self, node, strike_threshold: int = 3):
        with self._lock:
            return self._inner.auto_evict_if_needed(node, strike_threshold)

    def evict_node(self, node, now=None):
        with self._lock:
            return self._inner.evict_node(node, now=now)

    # --- Fallthrough for read-only / config attributes ---

    # Whitelist of attributes safe to access without locking
    _SAFE_ATTRS = frozenset(
        {
            "endowment",
            "_eviction_registry",
            "_audit_epoch",
            "_audit_seed",
            "_enforcement_pipeline",
            "_geo_fence_policy",
            "_audit_logger",
        }
    )

    def __getattr__(self, name: str):
        # Block access to mutable collections that require locking
        if name in ("_node_shard_index", "_placement_cache", "nodes"):
            raise AttributeError(
                f"Direct access to {name!r} is not thread-safe; use a locked method instead"
            )
        if name in self._SAFE_ATTRS:
            return getattr(self._inner, name)
        # For any other attribute, acquire the lock
        with self._lock:
            return getattr(self._inner, name)
