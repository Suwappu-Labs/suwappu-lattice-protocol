"""
Tests for gossip peer discovery: wire format, message handling, rate limiting,
liveness, and protocol lifecycle.
"""

from __future__ import annotations

import time

import pytest

from src.ltp.domain import _ALL_TAGS, DOMAIN_PEER_GOSSIP, signer_fingerprint
from src.ltp.keypair import KeyPair
from src.ltp.node.gossip import (
    GossipConfig,
    GossipProtocol,
    GossipTickResult,
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
def charlie():
    return KeyPair.generate("charlie")


@pytest.fixture
def peer_manager():
    return PeerManager()


@pytest.fixture
def gossip(peer_manager, alice):
    return GossipProtocol(
        peer_manager=peer_manager,
        keypair=alice,
        node_id="alice-node",
        region="US-East",
        config=GossipConfig(enabled=True, interval_seconds=1.0, max_peers=5),
    )


# ---------------------------------------------------------------------------
# Domain Tag
# ---------------------------------------------------------------------------


class TestDomainTag:
    def test_peer_gossip_tag_registered(self):
        assert "DOMAIN_PEER_GOSSIP" in _ALL_TAGS
        assert _ALL_TAGS["DOMAIN_PEER_GOSSIP"] == b"GSX-LTP:peer-gossip:v1\x00"


# ---------------------------------------------------------------------------
# Wire Format: PeerAnnouncement
# ---------------------------------------------------------------------------


class TestPeerAnnouncement:
    def test_roundtrip(self):
        ann = PeerAnnouncement(
            node_id="node-1",
            address="10.0.1.10:50051",
            region="US-East",
            vk_hash="a1b2c3" * 10,
        )
        data = ann.to_bytes()
        recovered = PeerAnnouncement.from_bytes(data)
        assert recovered.node_id == "node-1"
        assert recovered.address == "10.0.1.10:50051"
        assert recovered.region == "US-East"
        assert recovered.vk_hash == "a1b2c3" * 10

    def test_empty_fields(self):
        ann = PeerAnnouncement(node_id="", address="", region="", vk_hash="")
        data = ann.to_bytes()
        recovered = PeerAnnouncement.from_bytes(data)
        assert recovered.node_id == ""


# ---------------------------------------------------------------------------
# Wire Format: PeerExchangeMessage
# ---------------------------------------------------------------------------


class TestPeerExchangeMessage:
    def test_roundtrip_empty(self):
        msg = PeerExchangeMessage(sender_id="sender-1", timestamp=1234567890.5, peers=[])
        data = msg.to_bytes()
        recovered = PeerExchangeMessage.from_bytes(data)
        assert recovered.sender_id == "sender-1"
        assert recovered.timestamp == pytest.approx(1234567890.5)
        assert len(recovered.peers) == 0

    def test_roundtrip_with_peers(self):
        peers = [
            PeerAnnouncement("node-1", "10.0.1.1:50051", "US-East", "aa" * 32),
            PeerAnnouncement("node-2", "10.0.1.2:50051", "EU-West", "bb" * 32),
        ]
        msg = PeerExchangeMessage(sender_id="sender-1", timestamp=99.0, peers=peers)
        data = msg.to_bytes()
        recovered = PeerExchangeMessage.from_bytes(data)
        assert len(recovered.peers) == 2
        assert recovered.peers[0].node_id == "node-1"
        assert recovered.peers[1].address == "10.0.1.2:50051"

    def test_sign_and_verify(self, alice):
        msg = PeerExchangeMessage(
            sender_id="alice-node",
            timestamp=time.time(),
            peers=[PeerAnnouncement("bob", "1.2.3.4:5", "X", "cc" * 32)],
        )
        sig = msg.sign(alice.sk)
        assert len(sig) > 0
        assert msg.verify(alice.vk, sig) is True

    def test_verify_wrong_key_fails(self, alice, bob):
        msg = PeerExchangeMessage(sender_id="alice", timestamp=1.0, peers=[])
        sig = msg.sign(alice.sk)
        assert msg.verify(bob.vk, sig) is False

    def test_verify_tampered_message_fails(self, alice):
        msg = PeerExchangeMessage(sender_id="alice", timestamp=1.0, peers=[])
        sig = msg.sign(alice.sk)
        msg.sender_id = "tampered"
        assert msg.verify(alice.vk, sig) is False


# ---------------------------------------------------------------------------
# GossipProtocol: build_exchange_message
# ---------------------------------------------------------------------------


class TestBuildExchangeMessage:
    def test_builds_from_connected_peers(self, gossip, peer_manager, bob):
        peer_manager.mark_connected("bob-node", bob.vk, "10.0.1.2:50051", "EU")
        msg = gossip.build_exchange_message()
        assert msg.sender_id == "alice-node"
        assert len(msg.peers) == 1
        assert msg.peers[0].node_id == "bob-node"

    def test_excludes_self(self, gossip, peer_manager, alice):
        peer_manager.mark_connected("alice-node", alice.vk, "10.0.1.1:50051", "US")
        msg = gossip.build_exchange_message()
        assert all(p.node_id != "alice-node" for p in msg.peers)

    def test_excludes_target(self, gossip, peer_manager, bob, charlie):
        peer_manager.mark_connected("bob-node", bob.vk, "10.0.1.2:50051", "EU")
        peer_manager.mark_connected("charlie-node", charlie.vk, "10.0.1.3:50051", "AP")
        msg = gossip.build_exchange_message(exclude_node_id="bob-node")
        assert all(p.node_id != "bob-node" for p in msg.peers)
        assert any(p.node_id == "charlie-node" for p in msg.peers)

    def test_caps_at_max_peers(self, gossip, peer_manager):
        for i in range(10):
            kp = KeyPair.generate(f"node-{i}")
            peer_manager.mark_connected(f"node-{i}", kp.vk, f"10.0.1.{i}:50051", "X")
        msg = gossip.build_exchange_message()
        assert len(msg.peers) <= 5  # max_peers=5 in fixture

    def test_vk_hash_populated(self, gossip, peer_manager, bob):
        peer_manager.mark_connected("bob-node", bob.vk, "10.0.1.2:50051", "EU")
        msg = gossip.build_exchange_message()
        expected_hash = signer_fingerprint(bob.vk).hex()
        assert msg.peers[0].vk_hash == expected_hash


# ---------------------------------------------------------------------------
# GossipProtocol: handle_peer_exchange
# ---------------------------------------------------------------------------


class TestHandlePeerExchange:
    def test_discovers_new_peers(self, gossip, peer_manager, bob):
        msg = PeerExchangeMessage(
            sender_id="bob-node",
            timestamp=time.time(),
            peers=[
                PeerAnnouncement("charlie-node", "10.0.1.3:50051", "AP", "dd" * 32),
            ],
        )
        sig = msg.sign(bob.sk)
        discovered = gossip.handle_peer_exchange(msg, bob.vk, sig)
        assert discovered == 1
        assert peer_manager.get_peer_by_address("10.0.1.3:50051") is not None

    def test_ignores_known_peers(self, gossip, peer_manager, bob, charlie):
        # Charlie already known
        peer_manager.mark_connected("charlie-node", charlie.vk, "10.0.1.3:50051", "AP")

        msg = PeerExchangeMessage(
            sender_id="bob-node",
            timestamp=time.time(),
            peers=[
                PeerAnnouncement("charlie-node", "10.0.1.3:50051", "AP", "dd" * 32),
            ],
        )
        sig = msg.sign(bob.sk)
        discovered = gossip.handle_peer_exchange(msg, bob.vk, sig)
        assert discovered == 0

    def test_ignores_self(self, gossip, peer_manager, bob):
        msg = PeerExchangeMessage(
            sender_id="bob-node",
            timestamp=time.time(),
            peers=[
                PeerAnnouncement("alice-node", "10.0.1.1:50051", "US", "ee" * 32),
            ],
        )
        sig = msg.sign(bob.sk)
        discovered = gossip.handle_peer_exchange(msg, bob.vk, sig)
        assert discovered == 0

    def test_rejects_invalid_signature(self, gossip, bob, charlie):
        msg = PeerExchangeMessage(
            sender_id="bob-node",
            timestamp=time.time(),
            peers=[PeerAnnouncement("new", "1.2.3.4:5", "X", "ff" * 32)],
        )
        sig = msg.sign(bob.sk)
        # Verify with wrong key
        discovered = gossip.handle_peer_exchange(msg, charlie.vk, sig)
        assert discovered == 0

    def test_rate_limited(self, gossip, bob):
        config = GossipConfig(rate_limit_per_peer_per_minute=2)
        gossip._config = config

        for i in range(5):
            msg = PeerExchangeMessage(
                sender_id="bob-node",
                timestamp=time.time(),
                peers=[PeerAnnouncement(f"new-{i}", f"10.0.{i}.1:5", "X", "aa" * 32)],
            )
            sig = msg.sign(bob.sk)
            gossip.handle_peer_exchange(msg, bob.vk, sig)

        # After rate limit, new exchanges should be rejected
        msg = PeerExchangeMessage(
            sender_id="bob-node",
            timestamp=time.time(),
            peers=[PeerAnnouncement("final", "10.9.9.9:5", "X", "bb" * 32)],
        )
        sig = msg.sign(bob.sk)
        discovered = gossip.handle_peer_exchange(msg, bob.vk, sig)
        assert discovered == 0

    def test_enforces_max_peers(self, gossip, bob):
        """Even if message has 50 peers, only max_peers are processed."""
        peers = [
            PeerAnnouncement(f"node-{i}", f"10.0.{i}.1:50051", "X", "aa" * 32) for i in range(50)
        ]
        msg = PeerExchangeMessage(sender_id="bob-node", timestamp=time.time(), peers=peers)
        sig = msg.sign(bob.sk)
        discovered = gossip.handle_peer_exchange(msg, bob.vk, sig)
        assert discovered <= 5  # max_peers=5

    def test_callback_invoked_on_discovery(self, peer_manager, alice, bob):
        discovered_peers = []

        def on_discover(node_id, address):
            discovered_peers.append((node_id, address))

        gossip = GossipProtocol(
            peer_manager=peer_manager,
            keypair=alice,
            node_id="alice-node",
            region="US",
            on_new_peer_discovered=on_discover,
        )

        msg = PeerExchangeMessage(
            sender_id="bob-node",
            timestamp=time.time(),
            peers=[PeerAnnouncement("charlie", "10.0.1.3:50051", "AP", "dd" * 32)],
        )
        sig = msg.sign(bob.sk)
        gossip.handle_peer_exchange(msg, bob.vk, sig)
        assert len(discovered_peers) == 1
        assert discovered_peers[0] == ("charlie", "10.0.1.3:50051")


# ---------------------------------------------------------------------------
# GossipProtocol: liveness
# ---------------------------------------------------------------------------


class TestLiveness:
    def test_stale_peer_marked_disconnected(self, peer_manager, alice, bob):
        peer_manager.mark_connected("bob-node", bob.vk, "10.0.1.2:50051", "EU")
        # Set last_seen to 200 seconds ago
        with peer_manager._lock:
            peer_manager._peers_by_id["bob-node"].last_seen = time.time() - 200

        gossip = GossipProtocol(
            peer_manager=peer_manager,
            keypair=alice,
            node_id="alice-node",
            region="US",
            config=GossipConfig(liveness_timeout_seconds=90.0),
        )
        result = gossip.tick()
        assert result.peers_timed_out == 1

        peer = peer_manager.get_peer_by_id("bob-node")
        assert peer.state == PeerState.DISCONNECTED

    def test_fresh_peer_not_timed_out(self, peer_manager, alice, bob):
        peer_manager.mark_connected("bob-node", bob.vk, "10.0.1.2:50051", "EU")
        # last_seen is fresh (set by mark_connected)

        gossip = GossipProtocol(
            peer_manager=peer_manager,
            keypair=alice,
            node_id="alice-node",
            region="US",
            config=GossipConfig(liveness_timeout_seconds=90.0),
        )
        result = gossip.tick()
        assert result.peers_timed_out == 0

    def test_injectable_clock(self, peer_manager, alice, bob):
        """Clock injection allows deterministic liveness testing."""
        fake_time = [1000.0]
        peer_manager.mark_connected("bob-node", bob.vk, "10.0.1.2:50051", "EU")
        with peer_manager._lock:
            peer_manager._peers_by_id["bob-node"].last_seen = 900.0  # 100s ago at fake_time

        gossip = GossipProtocol(
            peer_manager=peer_manager,
            keypair=alice,
            node_id="alice-node",
            region="US",
            config=GossipConfig(liveness_timeout_seconds=90.0),
            clock=lambda: fake_time[0],
        )
        result = gossip.tick()
        assert result.peers_timed_out == 1


# ---------------------------------------------------------------------------
# GossipProtocol: lifecycle
# ---------------------------------------------------------------------------


class TestGossipLifecycle:
    def test_tick_increments_epoch(self, gossip):
        assert gossip.epoch == 0
        gossip.tick()
        assert gossip.epoch == 1
        gossip.tick()
        assert gossip.epoch == 2

    def test_start_stop(self, gossip):
        gossip.start()
        assert gossip.running is True
        gossip.stop()
        assert gossip.running is False

    def test_double_start_safe(self, gossip):
        gossip.start()
        gossip.start()  # Should not crash
        assert gossip.running is True
        gossip.stop()

    def test_stop_without_start_safe(self, gossip):
        gossip.stop()  # Should not crash

    def test_config_defaults(self):
        config = GossipConfig()
        assert config.enabled is True
        assert config.interval_seconds == 30.0
        assert config.max_peers == 20
        assert config.liveness_timeout_seconds == 90.0
        assert config.rate_limit_per_peer_per_minute == 10


# ---------------------------------------------------------------------------
# PeerManager: new methods
# ---------------------------------------------------------------------------


class TestPeerManagerExtensions:
    def test_update_last_seen(self):
        pm = PeerManager()
        kp = KeyPair.generate("test")
        pm.mark_connected("node-1", kp.vk, "10.0.1.1:50051", "US")
        old_ts = pm.get_peer_by_id("node-1").last_seen

        import time as t

        t.sleep(0.01)
        pm.update_last_seen("node-1")
        new_ts = pm.get_peer_by_id("node-1").last_seen
        assert new_ts > old_ts

    def test_update_last_seen_unknown_peer(self):
        pm = PeerManager()
        pm.update_last_seen("nonexistent")  # Should not crash

    def test_get_stale_peers(self):
        pm = PeerManager()
        kp1 = KeyPair.generate("stale")
        kp2 = KeyPair.generate("fresh")
        pm.mark_connected("stale-node", kp1.vk, "10.0.1.1:50051", "US")
        pm.mark_connected("fresh-node", kp2.vk, "10.0.1.2:50051", "EU")

        # Make stale-node old
        with pm._lock:
            pm._peers_by_id["stale-node"].last_seen = time.time() - 200

        stale = pm.get_stale_peers(timeout_seconds=90.0)
        assert len(stale) == 1
        assert stale[0].node_id == "stale-node"

    def test_get_stale_peers_none_stale(self):
        pm = PeerManager()
        kp = KeyPair.generate("fresh")
        pm.mark_connected("fresh-node", kp.vk, "10.0.1.1:50051", "US")
        stale = pm.get_stale_peers(timeout_seconds=90.0)
        assert len(stale) == 0
