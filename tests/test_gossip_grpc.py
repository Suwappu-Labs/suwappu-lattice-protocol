"""
Tests for gossip peer exchange over gRPC: ExchangePeers RPC,
bidirectional exchange, signature verification, send callback.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, call

import pytest

from src.ltp.domain import signer_fingerprint
from src.ltp.keypair import KeyPair
from src.ltp.network import node_service_pb2 as ns_pb2
from src.ltp.network.node_servicer import NodeServicer
from src.ltp.node.gossip import (
    GossipConfig,
    GossipProtocol,
    PeerAnnouncement,
    PeerExchangeMessage,
)
from src.ltp.node.peer_manager import PeerManager, PeerState

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def alice():
    return KeyPair.generate("alice")


@pytest.fixture
def bob():
    return KeyPair.generate("bob")


@pytest.fixture
def alice_pm():
    return PeerManager()


@pytest.fixture
def bob_pm():
    return PeerManager()


@pytest.fixture
def alice_gossip(alice_pm, alice):
    return GossipProtocol(
        peer_manager=alice_pm,
        keypair=alice,
        node_id="alice-node",
        region="US",
        config=GossipConfig(enabled=True, max_peers=10),
    )


@pytest.fixture
def bob_gossip(bob_pm, bob):
    return GossipProtocol(
        peer_manager=bob_pm,
        keypair=bob,
        node_id="bob-node",
        region="EU",
        config=GossipConfig(enabled=True, max_peers=10),
    )


# ---------------------------------------------------------------------------
# ExchangePeers RPC — ServiceR
# ---------------------------------------------------------------------------


class TestExchangePeersServicer:
    def test_gossip_disabled_rejects(self, alice):
        """Servicer without gossip rejects ExchangePeers."""
        pm = PeerManager()
        servicer = NodeServicer(
            node_id="alice",
            region="US",
            keypair=alice,
            peer_manager=pm,
            gossip_protocol=None,
        )
        request = ns_pb2.PeerExchangeRequest(
            signed_message=b"",
            signature=b"",
            sender_vk=b"",
        )
        response = servicer.ExchangePeers(request, None)
        assert response.accepted is False
        assert "not enabled" in response.reject_reason

    def test_valid_exchange_accepted(self, alice, bob, bob_gossip):
        """Servicer with gossip accepts valid exchange."""
        alice_pm = PeerManager()
        servicer = NodeServicer(
            node_id="alice",
            region="US",
            keypair=alice,
            peer_manager=alice_pm,
            gossip_protocol=bob_gossip,
        )
        # Build a valid message from bob
        msg = PeerExchangeMessage(
            sender_id="bob-node",
            timestamp=time.time(),
            peers=[PeerAnnouncement("charlie", "10.0.1.3:50051", "AP", "dd" * 32)],
        )
        msg_bytes = msg.to_bytes()
        sig = msg.sign(bob.sk)

        request = ns_pb2.PeerExchangeRequest(
            signed_message=msg_bytes,
            signature=sig,
            sender_vk=bob.vk,
            protocol_version=1,
        )
        response = servicer.ExchangePeers(request, None)
        assert response.accepted is True
        assert response.peers_discovered >= 0
        assert len(response.signed_message) > 0
        assert len(response.signature) > 0

    def test_invalid_message_rejected(self, alice, alice_gossip):
        """Servicer rejects malformed message."""
        pm = PeerManager()
        servicer = NodeServicer(
            node_id="alice",
            region="US",
            keypair=alice,
            peer_manager=pm,
            gossip_protocol=alice_gossip,
        )
        request = ns_pb2.PeerExchangeRequest(
            signed_message=b"garbage",
            signature=b"",
            sender_vk=b"",
        )
        response = servicer.ExchangePeers(request, None)
        assert response.accepted is False
        assert (
            "deserialization" in response.reject_reason.lower()
            or "error" in response.reject_reason.lower()
        )

    def test_reciprocal_response_contains_peers(self, alice, bob, alice_gossip, alice_pm):
        """Servicer's response includes its own known peers."""
        # Alice knows charlie
        charlie_kp = KeyPair.generate("charlie")
        alice_pm.mark_connected("charlie-node", charlie_kp.vk, "10.0.1.3:50051", "AP")

        servicer = NodeServicer(
            node_id="alice",
            region="US",
            keypair=alice,
            peer_manager=alice_pm,
            gossip_protocol=alice_gossip,
        )

        msg = PeerExchangeMessage(sender_id="bob-node", timestamp=time.time(), peers=[])
        request = ns_pb2.PeerExchangeRequest(
            signed_message=msg.to_bytes(),
            signature=msg.sign(bob.sk),
            sender_vk=bob.vk,
        )
        response = servicer.ExchangePeers(request, None)
        assert response.accepted is True

        # Verify response contains alice's peers
        resp_msg = PeerExchangeMessage.from_bytes(response.signed_message)
        peer_ids = [p.node_id for p in resp_msg.peers]
        assert "charlie-node" in peer_ids


# ---------------------------------------------------------------------------
# Send callback integration
# ---------------------------------------------------------------------------


class TestGossipSendCallback:
    def test_tick_calls_send_fn(self, alice, alice_pm):
        """tick() invokes send_fn for each connected peer."""
        bob_kp = KeyPair.generate("bob")
        alice_pm.mark_connected("bob-node", bob_kp.vk, "10.0.1.2:50051", "EU")

        send_calls = []

        def mock_send(address, msg_bytes, sig, sender_vk):
            send_calls.append(address)

        gossip = GossipProtocol(
            peer_manager=alice_pm,
            keypair=alice,
            node_id="alice-node",
            region="US",
            send_fn=mock_send,
        )
        gossip.tick()
        assert "10.0.1.2:50051" in send_calls

    def test_tick_skips_self(self, alice, alice_pm):
        """tick() does not send to self."""
        alice_pm.mark_connected("alice-node", alice.vk, "10.0.1.1:50051", "US")

        send_calls = []

        def mock_send(address, msg_bytes, sig, sender_vk):
            send_calls.append(address)

        gossip = GossipProtocol(
            peer_manager=alice_pm,
            keypair=alice,
            node_id="alice-node",
            region="US",
            send_fn=mock_send,
        )
        gossip.tick()
        assert "10.0.1.1:50051" not in send_calls

    def test_tick_without_send_fn_works(self, alice, alice_pm):
        """tick() works fine when no send_fn is configured."""
        bob_kp = KeyPair.generate("bob")
        alice_pm.mark_connected("bob-node", bob_kp.vk, "10.0.1.2:50051", "EU")

        gossip = GossipProtocol(
            peer_manager=alice_pm,
            keypair=alice,
            node_id="alice-node",
            region="US",
            send_fn=None,
        )
        result = gossip.tick()
        assert result.peers_announced >= 0  # No crash

    def test_send_failure_non_fatal(self, alice, alice_pm):
        """Failed send to a peer doesn't crash the tick."""
        bob_kp = KeyPair.generate("bob")
        alice_pm.mark_connected("bob-node", bob_kp.vk, "10.0.1.2:50051", "EU")

        def failing_send(address, msg_bytes, sig, sender_vk):
            raise ConnectionError("peer unreachable")

        gossip = GossipProtocol(
            peer_manager=alice_pm,
            keypair=alice,
            node_id="alice-node",
            region="US",
            send_fn=failing_send,
        )
        result = gossip.tick()  # Should not raise
        assert gossip.epoch == 1


# ---------------------------------------------------------------------------
# Bidirectional exchange simulation
# ---------------------------------------------------------------------------


class TestBidirectionalExchange:
    def test_two_nodes_exchange_peers(self, alice, bob):
        """Simulate bidirectional gossip: Alice and Bob exchange peer lists."""
        alice_pm = PeerManager()
        bob_pm = PeerManager()

        charlie_kp = KeyPair.generate("charlie")
        dave_kp = KeyPair.generate("dave")

        # Alice knows Charlie
        alice_pm.mark_connected("charlie", charlie_kp.vk, "10.0.1.3:50051", "AP")
        alice_pm.mark_connected("bob", bob.vk, "10.0.1.2:50051", "EU")

        # Bob knows Dave
        bob_pm.mark_connected("dave", dave_kp.vk, "10.0.1.4:50051", "SA")
        bob_pm.mark_connected("alice", alice.vk, "10.0.1.1:50051", "US")

        alice_gossip = GossipProtocol(
            peer_manager=alice_pm,
            keypair=alice,
            node_id="alice",
            region="US",
        )
        bob_gossip = GossipProtocol(
            peer_manager=bob_pm,
            keypair=bob,
            node_id="bob",
            region="EU",
        )

        # Alice → Bob
        alice_msg = alice_gossip.build_exchange_message(exclude_node_id="bob")
        alice_sig = alice_msg.sign(alice.sk)
        bob_discovered = bob_gossip.handle_peer_exchange(alice_msg, alice.vk, alice_sig)
        assert bob_discovered >= 1  # Bob discovers Charlie

        # Bob → Alice
        bob_msg = bob_gossip.build_exchange_message(exclude_node_id="alice")
        bob_sig = bob_msg.sign(bob.sk)
        alice_discovered = alice_gossip.handle_peer_exchange(bob_msg, bob.vk, bob_sig)
        assert alice_discovered >= 1  # Alice discovers Dave
