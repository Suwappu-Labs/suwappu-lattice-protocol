"""
gRPC client for connecting to a remote commitment node.
"""

from __future__ import annotations

import logging
from typing import Optional

import grpc

from . import shard_service_pb2 as pb2
from . import shard_service_pb2_grpc as pb2_grpc

logger = logging.getLogger(__name__)

__all__ = ["NodeClient"]


class NodeClient:
    """gRPC client for a remote ShardService node.

    Usage:
        client = NodeClient("localhost:50051")
        client.store_shard("entity-1", 0, encrypted_data)
        data = client.fetch_shard("entity-1", 0)
        client.close()
    """

    def __init__(
        self,
        address: str,
        timeout: float = 10.0,
        tls_config: object | None = None,
    ) -> None:
        self._address = address
        self._timeout = timeout

        if tls_config is not None and getattr(tls_config, "enabled", False):
            from .credentials import load_channel_credentials

            credentials = load_channel_credentials(tls_config)
            if credentials is not None:
                self._channel = grpc.secure_channel(address, credentials)
            else:
                raise RuntimeError(
                    f"TLS enabled but credentials failed to load for {address}. "
                    "Fix TLS config or disable TLS — insecure fallback is not allowed."
                )
        else:
            self._channel = grpc.insecure_channel(address)

        self._stub = pb2_grpc.ShardServiceStub(self._channel)

    @property
    def address(self) -> str:
        return self._address

    def store_shard(self, entity_id: str, shard_index: int, encrypted_data: bytes) -> bool:
        """Store a shard on the remote node. Returns True on success."""
        resp = self._stub.StoreShard(
            pb2.StoreShardRequest(
                entity_id=entity_id,
                shard_index=shard_index,
                encrypted_data=encrypted_data,
            ),
            timeout=self._timeout,
        )
        return resp.success

    def fetch_shard(self, entity_id: str, shard_index: int) -> Optional[bytes]:
        """Fetch a shard from the remote node. Returns None if not found."""
        resp = self._stub.FetchShard(
            pb2.FetchShardRequest(entity_id=entity_id, shard_index=shard_index),
            timeout=self._timeout,
        )
        if not resp.found:
            return None
        return resp.encrypted_data

    def audit_challenge(self, entity_id: str, shard_index: int, nonce: bytes) -> Optional[str]:
        """Send an audit challenge. Returns proof hash or None if shard missing."""
        resp = self._stub.AuditChallenge(
            pb2.AuditChallengeRequest(
                entity_id=entity_id,
                shard_index=shard_index,
                nonce=nonce,
            ),
            timeout=self._timeout,
        )
        if not resp.found:
            return None
        return resp.proof_hash

    def remove_shard(self, entity_id: str, shard_index: int) -> bool:
        """Remove a shard from the remote node."""
        resp = self._stub.RemoveShard(
            pb2.RemoveShardRequest(entity_id=entity_id, shard_index=shard_index),
            timeout=self._timeout,
        )
        return resp.removed

    def get_node_info(self) -> dict:
        """Get status info from the remote node."""
        resp = self._stub.GetNodeInfo(pb2.NodeInfoRequest(), timeout=self._timeout)
        return {
            "node_id": resp.node_id,
            "region": resp.region,
            "shard_count": resp.shard_count,
            "evicted": resp.evicted,
            "reputation_score": resp.reputation_score,
        }

    def fetch_shards_batch(self, requests: list[tuple[str, int]]) -> list[Optional[bytes]]:
        """Fetch multiple shards in one RPC call."""
        batch_req = pb2.FetchShardsBatchRequest(
            requests=[
                pb2.FetchShardRequest(entity_id=eid, shard_index=idx) for eid, idx in requests
            ]
        )
        resp = self._stub.FetchShardsBatch(batch_req, timeout=self._timeout)
        return [r.encrypted_data if r.found else None for r in resp.responses]

    def close(self) -> None:
        """Close the gRPC channel."""
        self._channel.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
