"""
gRPC servicer for the NodeService control-plane.

Implements Handshake, Ping, and HealthCheck RPCs.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from . import node_service_pb2 as ns_pb2
from . import node_service_pb2_grpc as ns_pb2_grpc

if TYPE_CHECKING:
    from ..keypair import KeyPair
    from ..node.handshake import HandshakePayload
    from ..node.peer_manager import PeerManager

logger = logging.getLogger(__name__)

__all__ = ["NodeServicer"]


class NodeServicer(ns_pb2_grpc.NodeServiceServicer):
    """Control-plane gRPC servicer for ETP node discovery and health.

    Args:
        node_id: This node's unique identifier.
        region: This node's region label.
        keypair: ML-DSA-65 keypair for signing handshake responses.
        peer_manager: Peer registry for tracking connected peers.
        shard_count_fn: Callable returning current shard count.
        start_time: Node start timestamp (for uptime calculation).
    """

    def __init__(
        self,
        node_id: str,
        region: str,
        keypair: "KeyPair",
        peer_manager: "PeerManager",
        shard_count_fn=None,
        start_time: float | None = None,
        on_peer_connected=None,
        gossip_protocol=None,
    ) -> None:
        self._node_id = node_id
        self._region = region
        self._keypair = keypair
        self._peer_manager = peer_manager
        self._shard_count_fn = shard_count_fn or (lambda: 0)
        self._start_time = start_time or time.time()
        self._on_peer_connected = on_peer_connected
        self._gossip = gossip_protocol

    def Handshake(self, request, context):
        """Handle incoming handshake: verify, register peer, respond."""
        from ..node.handshake import (
            PROTOCOL_VERSION,
            HandshakePayload,
            create_handshake_envelope,
            deserialize_envelope,
            serialize_envelope,
            verify_handshake_envelope,
        )

        # Validate protocol version before doing any crypto work
        if request.protocol_version != PROTOCOL_VERSION:
            logger.warning(
                "Handshake rejected: protocol version %d (expected %d)",
                request.protocol_version,
                PROTOCOL_VERSION,
            )
            return ns_pb2.HandshakeResponse(
                accepted=False,
                reject_reason=(
                    f"unsupported protocol version {request.protocol_version} "
                    f"(expected {PROTOCOL_VERSION})"
                ),
            )

        # Deserialize and verify the incoming envelope
        try:
            incoming_env = deserialize_envelope(request.signed_envelope)
        except Exception as e:
            logger.warning("Handshake deserialization failed: %s", e)
            return ns_pb2.HandshakeResponse(
                accepted=False,
                reject_reason=f"deserialization error: {e}",
            )

        ok, payload = verify_handshake_envelope(incoming_env)
        if not ok or payload is None:
            logger.warning("Handshake verification failed from %s", incoming_env.signer_id)
            return ns_pb2.HandshakeResponse(
                accepted=False,
                reject_reason="signature verification failed",
            )

        # Register the peer
        self._peer_manager.mark_connected(
            node_id=payload.node_id,
            public_key=incoming_env.signer_vk,
            address=payload.listen_address,
            region=payload.region,
        )
        logger.info(
            "Handshake accepted: %s (%s) at %s",
            payload.node_id,
            payload.region,
            payload.listen_address,
        )

        # Notify bridge of new peer
        if self._on_peer_connected:
            try:
                self._on_peer_connected(
                    payload.node_id,
                    payload.region,
                    payload.listen_address,
                )
            except Exception as e:
                logger.warning("on_peer_connected callback failed: %s", e)

        # Build response envelope
        response_payload = HandshakePayload(
            node_id=self._node_id,
            listen_address="",  # responder doesn't need to advertise
            region=self._region,
            protocol_version=PROTOCOL_VERSION,
            timestamp=time.time(),
        )
        response_env = create_handshake_envelope(self._keypair, response_payload)

        return ns_pb2.HandshakeResponse(
            accepted=True,
            signed_envelope=serialize_envelope(response_env),
        )

    def Ping(self, request, context):
        """Lightweight liveness probe."""
        return ns_pb2.PingResponse(
            node_id=self._node_id,
            timestamp=time.time(),
        )

    def HealthCheck(self, request, context):
        """Full health status."""
        from ..node.handshake import PROTOCOL_VERSION

        uptime = time.time() - self._start_time
        return ns_pb2.HealthCheckResponse(
            status="ok",
            node_id=self._node_id,
            region=self._region,
            uptime_seconds=uptime,
            peer_count=self._peer_manager.connected_count,
            shard_count=self._shard_count_fn(),
            protocol_version=PROTOCOL_VERSION,
        )

    def ExchangePeers(self, request, context):
        """Handle incoming gossip peer exchange."""
        if self._gossip is None:
            return ns_pb2.PeerExchangeResponse(
                accepted=False,
                reject_reason="gossip not enabled on this node",
            )

        from ..node.gossip import PeerExchangeMessage

        # Deserialize and verify
        try:
            msg = PeerExchangeMessage.from_bytes(request.signed_message)
        except Exception as e:
            logger.warning("ExchangePeers: deserialization failed: %s", e)
            return ns_pb2.PeerExchangeResponse(
                accepted=False,
                reject_reason=f"deserialization error: {e}",
            )

        discovered = self._gossip.handle_peer_exchange(
            msg,
            request.sender_vk,
            request.signature,
        )

        # Build reciprocal response
        response_msg = self._gossip.build_exchange_message(
            exclude_node_id=msg.sender_id,
        )
        response_bytes = response_msg.to_bytes()
        response_sig = response_msg.sign(self._keypair)

        return ns_pb2.PeerExchangeResponse(
            accepted=True,
            signed_message=response_bytes,
            signature=response_sig,
            sender_vk=self._keypair.vk,
            peers_discovered=discovered,
        )
