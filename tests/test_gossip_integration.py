"""
Gossip integration tests: multi-node discovery, seed peer compatibility,
config loading, and ETPNode integration points.
"""

from __future__ import annotations

import os
import time

import pytest

from src.ltp.keypair import KeyPair
from src.ltp.node.config import NodeConfig
from src.ltp.node.gossip import (
    GossipConfig,
    GossipProtocol,
    PeerAnnouncement,
    PeerExchangeMessage,
)
from src.ltp.node.peer_manager import PeerManager, PeerState

# ---------------------------------------------------------------------------
# Multi-node discovery
# ---------------------------------------------------------------------------


class TestMultiNodeDiscovery:
    def test_two_nodes_discover_each_other(self):
        """Alice and Bob each know one peer; gossip exchange reveals the other."""
        alice_kp = KeyPair.generate("alice")
        bob_kp = KeyPair.generate("bob")
        charlie_kp = KeyPair.generate("charlie")

        # Alice's view: connected to Bob
        alice_pm = PeerManager()
        alice_pm.mark_connected("bob", bob_kp.vk, "10.0.1.2:50051", "EU")

        # Bob's view: connected to Alice and Charlie
        bob_pm = PeerManager()
        bob_pm.mark_connected("alice", alice_kp.vk, "10.0.1.1:50051", "US")
        bob_pm.mark_connected("charlie", charlie_kp.vk, "10.0.1.3:50051", "AP")

        # Bob builds exchange message
        bob_gossip = GossipProtocol(
            peer_manager=bob_pm,
            keypair=bob_kp,
            node_id="bob",
            region="EU",
        )
        msg = bob_gossip.build_exchange_message(exclude_node_id="alice")
        sig = msg.sign(bob_kp.sk)

        # Alice receives it
        alice_gossip = GossipProtocol(
            peer_manager=alice_pm,
            keypair=alice_kp,
            node_id="alice",
            region="US",
        )
        discovered = alice_gossip.handle_peer_exchange(msg, bob_kp.vk, sig)
        assert discovered == 1
        assert alice_pm.get_peer_by_address("10.0.1.3:50051") is not None

    def test_three_node_ring_converges(self):
        """Three nodes in a ring: A↔B, B↔C. After exchange, A discovers C."""
        kps = {name: KeyPair.generate(name) for name in ("A", "B", "C")}
        pms = {name: PeerManager() for name in ("A", "B", "C")}

        # A knows B
        pms["A"].mark_connected("B", kps["B"].vk, "10.0.0.2:5", "X")
        # B knows A and C
        pms["B"].mark_connected("A", kps["A"].vk, "10.0.0.1:5", "X")
        pms["B"].mark_connected("C", kps["C"].vk, "10.0.0.3:5", "X")
        # C knows B
        pms["C"].mark_connected("B", kps["B"].vk, "10.0.0.2:5", "X")

        # B sends to A (excluding A from the peer list)
        b_gossip = GossipProtocol(pms["B"], kps["B"], "B", "X")
        msg = b_gossip.build_exchange_message(exclude_node_id="A")
        sig = msg.sign(kps["B"].sk)

        a_gossip = GossipProtocol(pms["A"], kps["A"], "A", "X")
        discovered = a_gossip.handle_peer_exchange(msg, kps["B"].vk, sig)
        assert discovered == 1  # A discovers C

        # B sends to C (excluding C)
        msg2 = b_gossip.build_exchange_message(exclude_node_id="C")
        sig2 = msg2.sign(kps["B"].sk)

        c_gossip = GossipProtocol(pms["C"], kps["C"], "C", "X")
        discovered2 = c_gossip.handle_peer_exchange(msg2, kps["B"].vk, sig2)
        assert discovered2 == 1  # C discovers A


# ---------------------------------------------------------------------------
# Seed peer compatibility
# ---------------------------------------------------------------------------


class TestSeedPeerCompatibility:
    def test_seed_peers_still_work(self):
        """Static seed peers function alongside gossip."""
        pm = PeerManager()
        seed = pm.add_seed_peer("10.0.1.10:50051")
        assert seed.state == PeerState.DISCOVERED

        # Gossip can run on a PeerManager with seed peers
        kp = KeyPair.generate("node")
        gossip = GossipProtocol(pm, kp, "node-1", "US")
        result = gossip.tick()
        assert result.peers_timed_out == 0  # Seed peers have last_seen=0, skipped

    def test_gossip_disabled_by_default(self):
        """gossip_enabled defaults to False in NodeConfig."""
        config = NodeConfig()
        assert config.gossip_enabled is False

    def test_gossip_does_not_break_existing_peers(self):
        """Gossip exchange doesn't modify existing connected peers."""
        alice_kp = KeyPair.generate("alice")
        bob_kp = KeyPair.generate("bob")

        pm = PeerManager()
        pm.mark_connected("bob", bob_kp.vk, "10.0.1.2:50051", "EU")
        original_state = pm.get_peer_by_id("bob").state

        gossip = GossipProtocol(pm, alice_kp, "alice", "US")
        gossip.tick()

        assert pm.get_peer_by_id("bob").state == original_state


# ---------------------------------------------------------------------------
# Liveness timeout integration
# ---------------------------------------------------------------------------


class TestLivenessIntegration:
    def test_liveness_marks_stale_peer_disconnected(self):
        kp_a = KeyPair.generate("a")
        kp_b = KeyPair.generate("b")
        pm = PeerManager()
        pm.mark_connected("b", kp_b.vk, "10.0.1.2:50051", "EU")

        # Set last_seen to 200s ago
        with pm._lock:
            pm._peers_by_id["b"].last_seen = time.time() - 200

        gossip = GossipProtocol(
            pm, kp_a, "a", "US", config=GossipConfig(liveness_timeout_seconds=90.0)
        )
        result = gossip.tick()
        assert result.peers_timed_out == 1
        assert pm.get_peer_by_id("b").state == PeerState.DISCONNECTED

    def test_update_last_seen_prevents_timeout(self):
        kp_a = KeyPair.generate("a")
        kp_b = KeyPair.generate("b")
        pm = PeerManager()
        pm.mark_connected("b", kp_b.vk, "10.0.1.2:50051", "EU")

        # Update last_seen recently
        pm.update_last_seen("b")

        gossip = GossipProtocol(
            pm, kp_a, "a", "US", config=GossipConfig(liveness_timeout_seconds=90.0)
        )
        result = gossip.tick()
        assert result.peers_timed_out == 0


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------


class TestGossipConfig:
    def test_config_from_env(self):
        env = {
            "ETP_GOSSIP_ENABLED": "true",
            "ETP_GOSSIP_INTERVAL": "15.0",
            "ETP_GOSSIP_MAX_PEERS": "30",
            "ETP_GOSSIP_LIVENESS_TIMEOUT": "120.0",
        }
        for k, v in env.items():
            os.environ[k] = v
        try:
            config = NodeConfig.from_env()
            assert config.gossip_enabled is True
            assert config.gossip_interval_seconds == 15.0
            assert config.gossip_max_peers == 30
            assert config.gossip_liveness_timeout_seconds == 120.0
        finally:
            for k in env:
                os.environ.pop(k, None)

    def test_gossip_config_defaults(self):
        config = NodeConfig()
        assert config.gossip_enabled is False
        assert config.gossip_interval_seconds == 30.0
        assert config.gossip_max_peers == 20
        assert config.gossip_liveness_timeout_seconds == 90.0

    def test_gateway_config_from_env(self):
        env = {
            "ETP_GATEWAY_ENABLED": "true",
            "ETP_GATEWAY_PORT": "9090",
            "ETP_GATEWAY_JWT_ENABLED": "true",
            "ETP_GATEWAY_JWT_TTL": "7200",
            "ETP_GATEWAY_RATE_LIMIT": "120",
        }
        for k, v in env.items():
            os.environ[k] = v
        try:
            config = NodeConfig.from_env()
            assert config.gateway_enabled is True
            assert config.gateway_port == 9090
            assert config.gateway_jwt_enabled is True
            assert config.gateway_jwt_ttl_seconds == 7200
            assert config.gateway_rate_limit_per_minute == 120
        finally:
            for k in env:
                os.environ.pop(k, None)
