"""
Peer tracking and state management for ETP nodes.

Maintains an in-memory registry of discovered and connected peers.
Sufficient for static seed-peer discovery. Can be upgraded
to persistent storage.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum

__all__ = ["PeerState", "PeerInfo", "PeerManager"]


class PeerState(Enum):
    """Lifecycle states for a peer connection."""

    DISCOVERED = "discovered"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    REJECTED = "rejected"


@dataclass
class PeerInfo:
    """Tracked information about a peer node."""

    node_id: str
    address: str  # "host:port"
    region: str = ""
    public_key: bytes = b""  # ML-DSA-65 vk (1952B)
    state: PeerState = PeerState.DISCOVERED
    last_seen: float = 0.0
    handshake_failures: int = 0


class PeerManager:
    """Thread-safe in-memory peer registry.

    Usage:
        pm = PeerManager()
        pm.add_seed_peer("10.0.1.10:50051")
        pm.mark_connected("node-2", vk_bytes, "10.0.1.10:50051", "US-East")
        assert pm.connected_count == 1
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._peers_by_id: dict[str, PeerInfo] = {}
        self._peers_by_addr: dict[str, PeerInfo] = {}

    def add_seed_peer(self, address: str) -> PeerInfo:
        """Register a seed peer address for discovery."""
        with self._lock:
            if address in self._peers_by_addr:
                return self._peers_by_addr[address]
            peer = PeerInfo(node_id="", address=address)
            self._peers_by_addr[address] = peer
            return peer

    def mark_connected(
        self,
        node_id: str,
        public_key: bytes,
        address: str,
        region: str = "",
    ) -> None:
        """Mark a peer as connected after successful handshake."""
        with self._lock:
            peer = self._peers_by_addr.get(address)
            if peer is None:
                peer = PeerInfo(node_id=node_id, address=address)
                self._peers_by_addr[address] = peer
            peer.node_id = node_id
            peer.public_key = public_key
            peer.region = region
            peer.state = PeerState.CONNECTED
            peer.last_seen = time.time()
            self._peers_by_id[node_id] = peer

    def mark_disconnected(self, node_id: str) -> None:
        """Mark a peer as disconnected."""
        with self._lock:
            peer = self._peers_by_id.get(node_id)
            if peer is not None:
                peer.state = PeerState.DISCONNECTED

    def mark_rejected(self, address: str) -> None:
        """Mark a peer as rejected after handshake failure."""
        with self._lock:
            peer = self._peers_by_addr.get(address)
            if peer is not None:
                peer.state = PeerState.REJECTED
                peer.handshake_failures += 1

    def get_connected_peers(self) -> list[PeerInfo]:
        """Return all peers in CONNECTED state."""
        with self._lock:
            return [p for p in self._peers_by_id.values() if p.state == PeerState.CONNECTED]

    def get_peer_by_address(self, address: str) -> PeerInfo | None:
        """Look up a peer by its network address."""
        with self._lock:
            return self._peers_by_addr.get(address)

    def get_peer_by_id(self, node_id: str) -> PeerInfo | None:
        """Look up a peer by its node ID."""
        with self._lock:
            return self._peers_by_id.get(node_id)

    def update_last_seen(self, node_id: str) -> None:
        """Update last_seen timestamp for a peer (called on successful ping)."""
        with self._lock:
            peer = self._peers_by_id.get(node_id)
            if peer is not None:
                peer.last_seen = time.time()

    def get_stale_peers(self, timeout_seconds: float) -> list[PeerInfo]:
        """Return connected peers whose last_seen exceeds timeout."""
        threshold = time.time() - timeout_seconds
        with self._lock:
            return [
                p
                for p in self._peers_by_id.values()
                if p.state == PeerState.CONNECTED and p.last_seen > 0 and p.last_seen < threshold
            ]

    @property
    def connected_count(self) -> int:
        """Number of currently connected peers."""
        with self._lock:
            return sum(1 for p in self._peers_by_id.values() if p.state == PeerState.CONNECTED)
