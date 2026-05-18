"""
Gossip-based peer discovery protocol for ETP nodes.

Periodic peer exchange: each node announces its known peers to connected
peers, signed with ML-DSA-65 and domain-separated (DOMAIN_PEER_GOSSIP).

Anti-amplification: max peers per exchange, per-peer rate limiting.
Liveness: periodic ping tracking, disconnect after timeout.
Bootstrap: seed peers remain initial contact points; gossip discovers the rest.

Deterministic tick() for testing without threads (matches AuditScheduler pattern).
"""

from __future__ import annotations

import logging
import struct
import threading
import time as _time
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..domain import DOMAIN_PEER_GOSSIP, domain_sign, domain_verify, signer_fingerprint
from ..encoding import CanonicalEncoder

__all__ = [
    "GossipConfig",
    "GossipTickResult",
    "PeerAnnouncement",
    "PeerExchangeMessage",
    "GossipProtocol",
]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class GossipConfig:
    """Gossip protocol configuration."""
    enabled: bool = True
    interval_seconds: float = 30.0
    max_peers: int = 20
    liveness_timeout_seconds: float = 90.0
    rate_limit_per_peer_per_minute: int = 10


@dataclass
class GossipTickResult:
    """Result of a single gossip round."""
    peers_announced: int = 0
    peers_discovered: int = 0
    peers_timed_out: int = 0
    errors: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------

@dataclass
class PeerAnnouncement:
    """Single peer entry in a gossip exchange message."""
    node_id: str
    address: str
    region: str
    vk_hash: str  # hex(SHA3-256(vk)) — 64 chars

    def to_bytes(self) -> bytes:
        """Canonical encoding for wire format."""
        return (
            CanonicalEncoder(DOMAIN_PEER_GOSSIP)
            .string(self.node_id)
            .string(self.address)
            .string(self.region)
            .string(self.vk_hash)
            .finalize()
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "PeerAnnouncement":
        """Decode from canonical wire format."""
        # Skip domain tag prefix
        offset = len(DOMAIN_PEER_GOSSIP)

        def _read_lp_string(off: int) -> tuple[str, int]:
            length = struct.unpack_from(">I", data, off)[0]
            off += 4
            value = data[off:off + length].decode("utf-8")
            return value, off + length

        node_id, offset = _read_lp_string(offset)
        address, offset = _read_lp_string(offset)
        region, offset = _read_lp_string(offset)
        vk_hash, offset = _read_lp_string(offset)

        return cls(node_id=node_id, address=address, region=region, vk_hash=vk_hash)


@dataclass
class PeerExchangeMessage:
    """Gossip message containing a list of known peers.

    Signed by the sender to prevent spoofed peer injection.
    """
    sender_id: str
    timestamp: float
    peers: list[PeerAnnouncement] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        """Canonical encoding of the full exchange message."""
        enc = (
            CanonicalEncoder(DOMAIN_PEER_GOSSIP)
            .string(self.sender_id)
            .float64(self.timestamp)
            .uint32(len(self.peers))
        )
        for peer in self.peers:
            enc.string(peer.node_id)
            enc.string(peer.address)
            enc.string(peer.region)
            enc.string(peer.vk_hash)
        return enc.finalize()

    @classmethod
    def from_bytes(cls, data: bytes) -> "PeerExchangeMessage":
        """Decode from canonical wire format."""
        offset = len(DOMAIN_PEER_GOSSIP)

        def _read_lp_string(off: int) -> tuple[str, int]:
            length = struct.unpack_from(">I", data, off)[0]
            off += 4
            value = data[off:off + length].decode("utf-8")
            return value, off + length

        sender_id, offset = _read_lp_string(offset)
        timestamp = struct.unpack_from(">d", data, offset)[0]
        offset += 8
        peer_count = struct.unpack_from(">I", data, offset)[0]
        offset += 4

        peers = []
        for _ in range(peer_count):
            node_id, offset = _read_lp_string(offset)
            address, offset = _read_lp_string(offset)
            region, offset = _read_lp_string(offset)
            vk_hash, offset = _read_lp_string(offset)
            peers.append(PeerAnnouncement(
                node_id=node_id, address=address, region=region, vk_hash=vk_hash,
            ))

        return cls(sender_id=sender_id, timestamp=timestamp, peers=peers)

    def sign(self, signer) -> bytes:
        """Sign the message with ML-DSA-65 and return signature.

        `signer` may be raw `sk` bytes (legacy) or a `KeyPair`
        (LTP-A-032 Phase 4d). `domain_sign` already accepts both.
        """
        return domain_sign(DOMAIN_PEER_GOSSIP, signer, self.to_bytes())

    def verify(self, vk: bytes, signature: bytes) -> bool:
        """Verify the ML-DSA-65 signature on this message."""
        return domain_verify(DOMAIN_PEER_GOSSIP, vk, self.to_bytes(), signature)


# ---------------------------------------------------------------------------
# Gossip Protocol
# ---------------------------------------------------------------------------

class GossipProtocol:
    """Periodic peer exchange protocol.

    Runs a daemon thread that:
    1. Every gossip_interval_seconds, announces known peers to connected peers
    2. Processes incoming peer exchange messages
    3. Tracks liveness via last_seen timestamps
    4. Marks stale peers as disconnected

    Deterministic tick() for testing without threads.
    """

    def __init__(
        self,
        peer_manager,
        keypair,
        node_id: str,
        region: str,
        config: Optional[GossipConfig] = None,
        on_new_peer_discovered: Optional[Callable[[str, str], None]] = None,
        clock: Optional[Callable[[], float]] = None,
        send_fn: Optional[Callable[[str, bytes, bytes, bytes], None]] = None,
    ) -> None:
        self._peer_manager = peer_manager
        self._keypair = keypair
        self._node_id = node_id
        self._region = region
        self._config = config or GossipConfig()
        self._on_new_peer_discovered = on_new_peer_discovered
        self._clock = clock or _time.time
        self._send_fn = send_fn  # Callable(address, msg_bytes, signature, sender_vk)

        self._epoch = 0
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Per-peer rate limiting: {node_id: [timestamps]}
        self._rate_tracker: dict[str, list[float]] = {}
        self._rate_lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self._running

    @property
    def epoch(self) -> int:
        return self._epoch

    def start(self) -> None:
        """Start the gossip daemon thread."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            daemon=True,
            name=f"gossip-{self._node_id}",
        )
        self._thread.start()
        logger.info("Gossip started (interval=%.1fs, max_peers=%d)",
                     self._config.interval_seconds, self._config.max_peers)

    def stop(self) -> None:
        """Stop the gossip daemon thread."""
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5.0)
            self._thread = None
        logger.info("Gossip stopped (epoch=%d)", self._epoch)

    def _run_loop(self) -> None:
        """Background loop: tick at configured interval."""
        while self._running:
            self._stop_event.wait(timeout=self._config.interval_seconds)
            if not self._running:
                break
            try:
                self.tick()
            except Exception:
                logger.exception("Gossip tick failed")

    def tick(self) -> GossipTickResult:
        """Execute one gossip round. Deterministic — safe for testing.

        1. Build exchange message from connected peers
        2. Send to connected peers via gRPC (if send callback configured)
        3. Check liveness — mark stale peers as disconnected
        4. Increment epoch

        Returns: GossipTickResult with round statistics.
        """
        self._epoch += 1
        result = GossipTickResult()

        # Build exchange message
        msg = self.build_exchange_message()
        result.peers_announced = len(msg.peers)

        # Send to connected peers via gRPC
        peers_sent_to = 0
        if self._send_fn is not None and msg.peers:
            sig = msg.sign(self._keypair)
            msg_bytes = msg.to_bytes()
            connected = self._peer_manager.get_connected_peers()
            for peer in connected:
                if peer.node_id == self._node_id:
                    continue
                try:
                    self._send_fn(peer.address, msg_bytes, sig, self._keypair.vk)
                    peers_sent_to += 1
                except Exception as e:
                    logger.warning("Gossip: send to %s failed: %s", peer.node_id, e)

        # Check liveness
        timed_out = self._check_liveness()
        result.peers_timed_out = len(timed_out)

        return result

    def build_exchange_message(self, exclude_node_id: str = "") -> PeerExchangeMessage:
        """Build a PeerExchangeMessage from current connected peers.

        Caps at gossip_max_peers entries. Excludes the target peer.
        """
        connected = self._peer_manager.get_connected_peers()
        announcements = []
        for peer in connected:
            if peer.node_id == exclude_node_id:
                continue
            if peer.node_id == self._node_id:
                continue
            vk_hash = signer_fingerprint(peer.public_key).hex() if peer.public_key else ""
            announcements.append(PeerAnnouncement(
                node_id=peer.node_id,
                address=peer.address,
                region=peer.region,
                vk_hash=vk_hash,
            ))
            if len(announcements) >= self._config.max_peers:
                break

        return PeerExchangeMessage(
            sender_id=self._node_id,
            timestamp=self._clock(),
            peers=announcements,
        )

    def handle_peer_exchange(
        self,
        message: PeerExchangeMessage,
        sender_vk: bytes,
        signature: bytes,
    ) -> int:
        """Process an incoming PeerExchangeMessage.

        Returns count of newly discovered peers.

        Validations:
        - Signature must be valid
        - Max peers per message enforced
        - Per-sender rate limiting
        """
        # Validate signature
        if not message.verify(sender_vk, signature):
            logger.warning("Gossip: invalid signature from %s", message.sender_id)
            return 0

        # Rate limiting
        if not self._check_rate(message.sender_id):
            logger.warning("Gossip: rate limited sender %s", message.sender_id)
            return 0

        # Enforce max peers
        peers = message.peers[:self._config.max_peers]

        discovered = 0
        for ann in peers:
            # Skip self
            if ann.node_id == self._node_id:
                continue
            # Skip already known peers
            existing = self._peer_manager.get_peer_by_id(ann.node_id)
            if existing is not None:
                continue
            existing_addr = self._peer_manager.get_peer_by_address(ann.address)
            if existing_addr is not None:
                continue

            # Register as discovered
            self._peer_manager.add_seed_peer(ann.address)
            discovered += 1
            logger.info("Gossip: discovered peer %s at %s (via %s)",
                        ann.node_id, ann.address, message.sender_id)

            # Notify callback for handshake attempt
            if self._on_new_peer_discovered:
                try:
                    self._on_new_peer_discovered(ann.node_id, ann.address)
                except Exception:
                    logger.exception("Gossip: on_new_peer_discovered callback failed")

        return discovered

    def _check_liveness(self) -> list[str]:
        """Check liveness of connected peers. Mark stale ones disconnected.

        Returns list of node_ids that timed out.
        """
        now = self._clock()
        threshold = now - self._config.liveness_timeout_seconds
        timed_out = []

        connected = self._peer_manager.get_connected_peers()
        for peer in connected:
            if peer.last_seen > 0 and peer.last_seen < threshold:
                self._peer_manager.mark_disconnected(peer.node_id)
                timed_out.append(peer.node_id)
                logger.info("Gossip: peer %s timed out (last_seen=%.0fs ago)",
                            peer.node_id, now - peer.last_seen)

        return timed_out

    def _check_rate(self, sender_id: str) -> bool:
        """Per-sender rate limiting. Returns True if allowed."""
        now = self._clock()
        window = 60.0  # 1 minute sliding window

        with self._rate_lock:
            timestamps = self._rate_tracker.get(sender_id, [])
            # Prune old entries
            timestamps = [t for t in timestamps if t > now - window]
            if len(timestamps) >= self._config.rate_limit_per_peer_per_minute:
                self._rate_tracker[sender_id] = timestamps
                return False
            timestamps.append(now)
            self._rate_tracker[sender_id] = timestamps
            return True

    def update_last_seen(self, node_id: str) -> None:
        """Update last_seen for a peer (called on successful interaction)."""
        with self._peer_manager._lock:
            peer = self._peer_manager._peers_by_id.get(node_id)
            if peer is not None:
                peer.last_seen = self._clock()
