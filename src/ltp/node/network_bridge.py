"""
NetworkBridge — bridges PeerManager <-> CommitmentNetwork.

Creates RemoteNode proxies for connected peers and registers them
with the commitment network, allowing distributed shard operations.

Thread-safe: all access to _remote_nodes is protected by a Lock
since add_peer can be called from gRPC callback threads.
"""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..commitment import CommitmentNetwork
    from ..network.remote import RemoteNode
    from .peer_manager import PeerManager

logger = logging.getLogger(__name__)

__all__ = ["NetworkBridge"]


class NetworkBridge:
    """Bridges PeerManager <-> CommitmentNetwork.

    Creates RemoteNode proxies for connected peers and registers
    them with the commitment network.
    """

    def __init__(
        self,
        network: "CommitmentNetwork",
        peer_manager: "PeerManager",
    ) -> None:
        self._network = network
        self._peer_manager = peer_manager
        self._lock = threading.Lock()
        self._remote_nodes: dict[str, "RemoteNode"] = {}

    def sync_peers(self) -> int:
        """Create RemoteNodes for all connected peers not yet wired.

        Returns count of newly added nodes.
        """
        added = 0
        for peer in self._peer_manager.get_connected_peers():
            if peer.node_id and peer.node_id not in self._remote_nodes:
                self.add_peer(peer.node_id, peer.region, peer.address)
                added += 1
        return added

    def add_peer(self, node_id: str, region: str, address: str) -> None:
        """Wire a single new peer (called from handshake callback)."""
        with self._lock:
            if node_id in self._remote_nodes:
                return

            from ..network.remote import RemoteNode

            remote = RemoteNode(node_id, region, address)
            self._network.add_existing_node(remote)
            self._remote_nodes[node_id] = remote
        logger.info("NetworkBridge: wired peer %s (%s) at %s", node_id, region, address)

    def remove_peer(self, node_id: str) -> bool:
        """Remove a disconnected peer's RemoteNode and close its gRPC channel.

        Also marks the RemoteNode as evicted so the commitment network
        skips it for future placement and fetches.

        Returns True if the peer was found and removed.
        """
        with self._lock:
            remote = self._remote_nodes.pop(node_id, None)
        if remote is None:
            return False
        remote.evicted = True
        try:
            remote.close()
        except Exception as e:
            logger.warning("NetworkBridge: error closing %s: %s", node_id, e)
        logger.info("NetworkBridge: removed peer %s", node_id)
        return True

    def close_all(self) -> None:
        """Close all RemoteNode gRPC channels."""
        with self._lock:
            nodes_snapshot = list(self._remote_nodes.items())
            self._remote_nodes.clear()
        for node_id, remote in nodes_snapshot:
            try:
                remote.close()
            except Exception as e:
                logger.warning("NetworkBridge: error closing %s: %s", node_id, e)

    @property
    def remote_nodes(self) -> dict[str, "RemoteNode"]:
        with self._lock:
            return dict(self._remote_nodes)
