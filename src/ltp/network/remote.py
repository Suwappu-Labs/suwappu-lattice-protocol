"""
RemoteNode: CommitmentNode-compatible proxy that routes through gRPC.

Allows CommitmentNetwork to treat remote nodes identically to local nodes.
The shard operations (store, fetch, audit, remove) go over the network.
"""

from __future__ import annotations

import logging
from typing import Optional

from .client import NodeClient

logger = logging.getLogger(__name__)

__all__ = ["RemoteNode"]


class RemoteNode:
    """A commitment node proxy that delegates shard operations to a remote gRPC server.

    Quacks like CommitmentNode — has the same shard methods and properties —
    so CommitmentNetwork can use it transparently.

    Usage:
        node = RemoteNode("n1", "US-East", "10.0.1.5:50051")
        network.add_existing_node(node)  # network treats it like any node
    """

    def __init__(
        self,
        node_id: str,
        region: str,
        address: str,
        timeout: float = 10.0,
    ) -> None:
        self.node_id = node_id
        self.region = region
        self.strikes: int = 0
        self.audit_passes: int = 0
        self.evicted: bool = False
        self.stake: float = 0.0
        self.stake_locked_until: float = 0.0
        self.pending_slashes: list = []
        self.offense_history: list = []
        self.reputation_score: float = 1.0
        self.registered_at: float = 0.0
        self.evicted_at: float = 0.0
        self.eviction_count: int = 0
        self.withheld_earnings: float = 0.0
        self.total_earnings: float = 0.0

        self._address = address
        self._client = NodeClient(address, timeout=timeout)
        self._shard_proxy = _RemoteShardProxy(self._client)

    @property
    def shards(self) -> "_RemoteShardProxy":
        """Dict-like proxy — allows `node.shards[key]` to go over gRPC."""
        return self._shard_proxy

    @property
    def shard_count(self) -> int:
        info = self._client.get_node_info()
        return info["shard_count"]

    def store_shard(self, entity_id: str, shard_index: int, encrypted_data: bytes) -> bool:
        if self.evicted:
            return False
        try:
            return self._client.store_shard(entity_id, shard_index, encrypted_data)
        except Exception as e:
            logger.warning("RemoteNode %s: store_shard failed: %s", self.node_id, e)
            return False

    def fetch_shard(self, entity_id: str, shard_index: int) -> Optional[bytes]:
        if self.evicted:
            return None
        try:
            return self._client.fetch_shard(entity_id, shard_index)
        except Exception as e:
            logger.warning("RemoteNode %s: fetch_shard failed: %s", self.node_id, e)
            return None

    def respond_to_audit(self, entity_id: str, shard_index: int, nonce: bytes) -> Optional[str]:
        if self.evicted:
            return None
        try:
            return self._client.audit_challenge(entity_id, shard_index, nonce)
        except Exception as e:
            logger.warning("RemoteNode %s: audit_challenge failed: %s", self.node_id, e)
            return None

    def remove_shard(self, entity_id: str, shard_index: int) -> bool:
        try:
            return self._client.remove_shard(entity_id, shard_index)
        except Exception as e:
            logger.warning("RemoteNode %s: remove_shard failed: %s", self.node_id, e)
            return False

    def create_pending_slash(self, amount: float, reason: str, now=None):
        """Stub — slash tracking is managed by the local network coordinator."""
        pass

    def record_offense(self, offense_type: str, weight: float = 1.0, now=None):
        """Record offense locally (remote node doesn't need to know)."""
        import time as _time

        now = now or _time.time()
        self.offense_history.append(
            {
                "type": offense_type,
                "weight": weight,
                "timestamp": now,
            }
        )

    def deposit_stake(self, amount: float, now=None) -> bool:
        """Stub — staking is local."""
        return True

    def finalize_pending_slashes(self) -> float:
        """Stub — slash tracking is managed by the local network coordinator."""
        return 0.0

    def _update_reputation(self, *args, **kwargs):
        """Stub — reputation is tracked locally."""
        pass

    def withholding_rate(self, *args, **kwargs) -> float:
        """Stub — withholding is local."""
        return 0.0

    def accrue_earnings(self, *args, **kwargs):
        """Stub — earnings are local."""
        pass

    def release_withheld(self, *args, **kwargs) -> float:
        """Stub — withholding is local."""
        return 0.0

    def close(self) -> None:
        self._client.close()


class _RemoteShardProxy:
    """Minimal dict-like proxy for remote shard access.

    Supports: __getitem__, __setitem__, __delitem__, __contains__,
    get(), keys() (limited — uses node info for count).
    """

    def __init__(self, client: NodeClient) -> None:
        self._client = client

    def __getitem__(self, key: tuple[str, int]) -> bytes:
        data = self._client.fetch_shard(key[0], key[1])
        if data is None:
            raise KeyError(key)
        return data

    def __setitem__(self, key: tuple[str, int], value: bytes) -> None:
        self._client.store_shard(key[0], key[1], value)

    def __delitem__(self, key: tuple[str, int]) -> None:
        if not self._client.remove_shard(key[0], key[1]):
            raise KeyError(key)

    def __contains__(self, key: tuple[str, int]) -> bool:
        return self._client.fetch_shard(key[0], key[1]) is not None

    def get(self, key: tuple[str, int], default=None):
        data = self._client.fetch_shard(key[0], key[1])
        return data if data is not None else default

    def items(self):
        """Return empty list — remote shard enumeration is not supported.

        evict_node() calls node.shards.items() to find orphaned shards.
        For remote nodes, orphaned shards are identified via the network's
        _node_shard_index instead. This returns an empty list so the
        eviction path runs without crashing.
        """
        return []

    def __len__(self) -> int:
        """Return 0 — use node.shard_count for the real count."""
        return 0
