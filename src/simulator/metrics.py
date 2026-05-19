"""
Metrics collector for the LTP network simulation.

Collects fine-grained timing and throughput metrics for every transfer,
broken down by phase (commit, lattice, materialize) and sub-operations
(shard encryption, network delivery, erasure decode). Provides aggregated
statistics and per-transfer analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ShardMetrics:
    """Metrics for a single shard operation."""

    shard_index: int
    target_node: str
    target_region: str
    latency_ms: float
    payload_bytes: int
    success: bool
    attempt: int = 1


@dataclass
class TransferMetrics:
    """
    Complete metrics for a single LTP transfer (all three phases).

    Captures timing, bandwidth, shard distribution, and locality data
    for analysis and benchmarking.
    """

    entity_id: str = ""
    entity_size_bytes: int = 0
    sender: str = ""
    receiver: str = ""
    sender_region: str = ""
    receiver_region: str = ""

    # Phase 1: COMMIT
    commit_start_ms: float = 0.0
    commit_end_ms: float = 0.0
    erasure_encode_ms: float = 0.0
    shard_encrypt_ms: float = 0.0
    shard_distribution_ms: float = 0.0
    commit_record_sign_ms: float = 0.0
    shard_store_metrics: list[ShardMetrics] = field(default_factory=list)
    n_shards: int = 0
    k_shards: int = 0
    replicas_per_shard: int = 0

    # Phase 2: LATTICE
    lattice_start_ms: float = 0.0
    lattice_end_ms: float = 0.0
    lattice_seal_ms: float = 0.0
    lattice_transfer_ms: float = 0.0
    lattice_key_bytes: int = 0

    # Phase 3: MATERIALIZE
    materialize_start_ms: float = 0.0
    materialize_end_ms: float = 0.0
    unseal_ms: float = 0.0
    record_fetch_ms: float = 0.0
    record_verify_ms: float = 0.0
    shard_fetch_ms: float = 0.0
    shard_decrypt_ms: float = 0.0
    erasure_decode_ms: float = 0.0
    entity_verify_ms: float = 0.0
    shard_fetch_metrics: list[ShardMetrics] = field(default_factory=list)
    shards_fetched: int = 0
    shards_from_local_region: int = 0

    # Outcome
    success: bool = False
    failure_reason: str = ""

    @property
    def commit_latency_ms(self) -> float:
        return self.commit_end_ms - self.commit_start_ms

    @property
    def lattice_latency_ms(self) -> float:
        return self.lattice_end_ms - self.lattice_start_ms

    @property
    def materialize_latency_ms(self) -> float:
        return self.materialize_end_ms - self.materialize_start_ms

    @property
    def total_latency_ms(self) -> float:
        return self.materialize_end_ms - self.commit_start_ms

    @property
    def sender_bandwidth_bytes(self) -> int:
        """Total bytes the sender transmits (lattice key only in LTP)."""
        return self.lattice_key_bytes

    @property
    def network_bandwidth_bytes(self) -> int:
        """Total bytes moved across the network (shard distribution + fetches)."""
        store_bytes = sum(s.payload_bytes for s in self.shard_store_metrics)
        fetch_bytes = sum(s.payload_bytes for s in self.shard_fetch_metrics)
        return store_bytes + fetch_bytes

    @property
    def locality_ratio(self) -> float:
        """Fraction of shards fetched from the receiver's local region."""
        if self.shards_fetched == 0:
            return 0.0
        return self.shards_from_local_region / self.shards_fetched

    def summary(self) -> dict:
        return {
            "entity_id": self.entity_id[:24] + "..." if self.entity_id else "",
            "entity_size": self.entity_size_bytes,
            "success": self.success,
            "commit_ms": round(self.commit_latency_ms, 2),
            "lattice_ms": round(self.lattice_latency_ms, 2),
            "materialize_ms": round(self.materialize_latency_ms, 2),
            "total_ms": round(self.total_latency_ms, 2),
            "sender_bandwidth": self.sender_bandwidth_bytes,
            "network_bandwidth": self.network_bandwidth_bytes,
            "locality_ratio": round(self.locality_ratio, 2),
            "shards_fetched": self.shards_fetched,
            "shards_local": self.shards_from_local_region,
        }


class MetricsCollector:
    """
    Aggregates metrics across all transfers in a simulation.

    Provides per-transfer lookup, aggregate statistics, and comparative
    analysis (e.g., varying entity sizes, comparing regions).
    """

    def __init__(self) -> None:
        self._transfers: dict[str, TransferMetrics] = {}
        self._transfer_order: list[str] = []

    def new_transfer(self, entity_id: str) -> TransferMetrics:
        """Create a new TransferMetrics for a transfer."""
        metrics = TransferMetrics(entity_id=entity_id)
        self._transfers[entity_id] = metrics
        self._transfer_order.append(entity_id)
        return metrics

    def get_transfer(self, entity_id: str) -> Optional[TransferMetrics]:
        return self._transfers.get(entity_id)

    @property
    def all_transfers(self) -> list[TransferMetrics]:
        return [self._transfers[eid] for eid in self._transfer_order]

    @property
    def successful_transfers(self) -> list[TransferMetrics]:
        return [t for t in self.all_transfers if t.success]

    @property
    def failed_transfers(self) -> list[TransferMetrics]:
        return [t for t in self.all_transfers if not t.success]

    # --- Aggregate statistics ---

    def avg_commit_latency_ms(self) -> float:
        transfers = self.successful_transfers
        if not transfers:
            return 0.0
        return sum(t.commit_latency_ms for t in transfers) / len(transfers)

    def avg_lattice_latency_ms(self) -> float:
        transfers = self.successful_transfers
        if not transfers:
            return 0.0
        return sum(t.lattice_latency_ms for t in transfers) / len(transfers)

    def avg_materialize_latency_ms(self) -> float:
        transfers = self.successful_transfers
        if not transfers:
            return 0.0
        return sum(t.materialize_latency_ms for t in transfers) / len(transfers)

    def avg_total_latency_ms(self) -> float:
        transfers = self.successful_transfers
        if not transfers:
            return 0.0
        return sum(t.total_latency_ms for t in transfers) / len(transfers)

    def avg_locality_ratio(self) -> float:
        transfers = self.successful_transfers
        if not transfers:
            return 0.0
        return sum(t.locality_ratio for t in transfers) / len(transfers)

    def total_network_bytes(self) -> int:
        return sum(t.network_bandwidth_bytes for t in self.all_transfers)

    def total_sender_bytes(self) -> int:
        return sum(t.sender_bandwidth_bytes for t in self.all_transfers)

    def percentile_latency(self, phase: str, p: float) -> float:
        """Compute p-th percentile latency for a phase (commit/lattice/materialize/total)."""
        transfers = self.successful_transfers
        if not transfers:
            return 0.0
        attr = f"{phase}_latency_ms"
        values = sorted(getattr(t, attr) for t in transfers)
        idx = int(len(values) * p / 100)
        idx = min(idx, len(values) - 1)
        return values[idx]

    def summary(self) -> dict:
        return {
            "total_transfers": len(self._transfers),
            "successful": len(self.successful_transfers),
            "failed": len(self.failed_transfers),
            "avg_commit_ms": round(self.avg_commit_latency_ms(), 2),
            "avg_lattice_ms": round(self.avg_lattice_latency_ms(), 2),
            "avg_materialize_ms": round(self.avg_materialize_latency_ms(), 2),
            "avg_total_ms": round(self.avg_total_latency_ms(), 2),
            "p50_total_ms": round(self.percentile_latency("total", 50), 2),
            "p95_total_ms": round(self.percentile_latency("total", 95), 2),
            "p99_total_ms": round(self.percentile_latency("total", 99), 2),
            "avg_locality_ratio": round(self.avg_locality_ratio(), 2),
            "total_network_bytes": self.total_network_bytes(),
            "total_sender_bytes": self.total_sender_bytes(),
        }

    def clear(self) -> None:
        self._transfers.clear()
        self._transfer_order.clear()
