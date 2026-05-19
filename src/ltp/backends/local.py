"""
Local in-memory commitment backend.

This is the default backend used by the PoC and tests.  It wraps the existing
CommitmentLog with the CommitmentBackend interface, providing instant finality
and no economic layer.  Useful for development, testing, and single-operator
private deployments.
"""

from __future__ import annotations

from typing import Optional

from ..primitives import canonical_hash
from .base import (
    BackendCapabilities,
    BackendConfig,
    CommitmentBackend,
    FinalityModel,
)


class LocalBackend(CommitmentBackend):
    """In-memory commitment backend with instant finality and no economics."""

    def __init__(self, config: BackendConfig) -> None:
        super().__init__(config)
        self._records: dict[str, dict] = {}
        self._chain: list[str] = []
        self._chain_hashes: list[str] = []
        self._nodes: dict[str, dict] = {}

    def capabilities(self) -> BackendCapabilities:
        return BackendCapabilities(
            finality=FinalityModel.INSTANT,
            max_tps=100_000,
            has_native_storage_proofs=False,
            has_slashing=False,
            has_node_registry=True,
            supports_zk_verification=False,
            estimated_finality_seconds=0.0,
            gas_cost_per_commit=None,
        )

    # --- Log operations ---

    def append_commitment(
        self,
        entity_id: str,
        record_bytes: bytes,
        signature: bytes,
        sender_vk: bytes,
    ) -> str:
        if entity_id in self._records:
            raise ValueError(f"Entity {entity_id} already committed")

        prev_hash = self._chain_hashes[-1] if self._chain_hashes else ("0" * 64)
        chain_hash = canonical_hash(record_bytes + prev_hash.encode())

        self._records[entity_id] = {
            "entity_id": entity_id,
            "record_bytes": record_bytes,
            "signature": signature.hex(),
            "sender_vk": sender_vk.hex(),
            "predecessor": prev_hash,
            "chain_hash": chain_hash,
        }
        self._chain.append(entity_id)
        self._chain_hashes.append(chain_hash)

        return canonical_hash(record_bytes)

    def fetch_commitment(self, entity_id: str) -> Optional[dict]:
        return self._records.get(entity_id)

    def verify_inclusion(self, entity_id: str, proof: dict) -> bool:
        record = self._records.get(entity_id)
        if record is None:
            return False
        return record["chain_hash"] == proof.get("chain_hash")

    def is_finalized(self, entity_id: str) -> bool:
        return entity_id in self._records

    # --- Node registry ---

    def register_node(self, node_id: str, region: str, stake_wei: int = 0) -> bool:
        self._nodes[node_id] = {
            "node_id": node_id,
            "region": region,
            "stake_wei": stake_wei,
            "active": True,
        }
        return True

    def evict_node(self, node_id: str, reason: str, evidence: bytes = b"") -> bool:
        if node_id in self._nodes:
            self._nodes[node_id]["active"] = False
            return True
        return False

    def get_active_nodes(self) -> list[dict]:
        return [n for n in self._nodes.values() if n["active"]]

    # --- Economic hooks (no-ops for local) ---

    def compensate_node(self, node_id: str, amount_wei: int, reason: str) -> bool:
        return True

    def slash_node(self, node_id: str, evidence: bytes) -> int:
        return 0

    def get_pricing(self) -> dict:
        return {
            "cost_per_shard_per_epoch": 0,
            "epoch_seconds": 0,
            "currency": "none",
        }
