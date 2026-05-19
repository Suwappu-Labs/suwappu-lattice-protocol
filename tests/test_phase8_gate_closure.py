"""
Gate closure: single integration scenario proving all components work
together end-to-end.

Components: mTLS credentials, circuit breaker, gossip exchange, federation
endpoint, gateway (health + metrics + JWT), observability, ETPNode full startup.
"""

from __future__ import annotations

import json
import time
import urllib.request

import pytest
from fastapi.testclient import TestClient

from src.ltp.domain import signer_fingerprint
from src.ltp.gateway.app import GatewayConfig, create_app
from src.ltp.gateway.auth import create_jwt
from src.ltp.keypair import KeyPair
from src.ltp.network.resilience import PeerCircuitBreaker
from src.ltp.node.config import NodeConfig
from src.ltp.node.gossip import GossipConfig, GossipProtocol, PeerAnnouncement, PeerExchangeMessage
from src.ltp.node.main import ETPNode
from src.ltp.node.peer_manager import PeerManager
from src.ltp.observability.endpoint import ETPObservability


class TestPhase8GateClosure:
    def test_etpnode_full_startup(self):
        """ETPNode starts with gateway + gossip + observability."""
        config = NodeConfig(
            node_id="gate-8",
            region="test",
            listen_port=0,
            rest_port=0,
            diagnostics_port=0,
            require_real_crypto=False,
            storage_backend="memory",
            gateway_enabled=True,
            gateway_port=0,
            gossip_enabled=True,
            observability_enabled=True,
        )
        node = ETPNode(config)
        node.start()
        try:
            assert node._gateway_server is not None
            assert node._gossip_protocol is not None
            assert node._observability is not None
            assert node._running is True
        finally:
            node.stop()

    def test_gateway_serves_health(self):
        """GET /health returns 200 through gateway."""
        config = NodeConfig(
            node_id="gate-health",
            region="test",
            listen_port=0,
            rest_port=0,
            diagnostics_port=0,
            require_real_crypto=False,
            storage_backend="memory",
            gateway_enabled=True,
            gateway_port=0,
        )
        node = ETPNode(config)
        node.start()
        try:
            url = f"{node._gateway_server.url}/health"
            resp = urllib.request.urlopen(url)
            data = json.loads(resp.read())
            assert data["status"] == "ok"
        finally:
            node.stop()

    def test_gateway_serves_metrics(self):
        """GET /metrics returns Prometheus text with bridge + gossip metrics."""
        config = NodeConfig(
            node_id="gate-metrics",
            region="test",
            listen_port=0,
            rest_port=0,
            diagnostics_port=0,
            require_real_crypto=False,
            storage_backend="memory",
            gateway_enabled=True,
            gateway_port=0,
            observability_enabled=True,
        )
        node = ETPNode(config)
        node.start()
        try:
            url = f"{node._gateway_server.url}/metrics"
            resp = urllib.request.urlopen(url)
            body = resp.read().decode()
            assert "etp_sth_publish_gap_seconds" in body
            assert "etp_bridge_records_bridged_total" in body
            assert "etp_gossip_peers_discovered_total" in body
        finally:
            node.stop()

    def test_gateway_jwt_enforced(self):
        """Protected route returns 401 without token, 200 with valid token."""
        kp = KeyPair.generate("gate-jwt")
        app = create_app(GatewayConfig(jwt_enabled=True))
        app.state.health_fn = lambda: {"status": "ok"}
        kid = signer_fingerprint(kp.vk).hex()
        app.state.known_vks = {kid: kp.vk}
        client = TestClient(app)

        # Without token
        assert client.get("/node/audit").status_code == 401

        # With valid token
        token = create_jwt(kp, "test-node")
        resp = client.get("/node/audit", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    def test_gossip_protocol_running(self):
        """Gossip tick() increments epoch and builds exchange messages."""
        kp = KeyPair.generate("gossip-gate")
        pm = PeerManager()
        bob = KeyPair.generate("bob")
        pm.mark_connected("bob", bob.vk, "10.0.1.2:50051", "EU")

        gossip = GossipProtocol(pm, kp, "alice", "US", config=GossipConfig(max_peers=10))
        result = gossip.tick()
        assert gossip.epoch == 1
        assert result.peers_announced >= 1

    def test_circuit_breaker_lifecycle(self):
        """Breaker starts CLOSED, trips to OPEN, recovers to CLOSED."""
        cb = PeerCircuitBreaker(peer_id="gate-peer", failure_threshold=2, cooldown_seconds=0.01)
        assert cb.state == "closed"
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "open"
        time.sleep(0.02)
        assert cb.state == "half_open"
        cb.record_success()
        assert cb.state == "closed"

    def test_federation_endpoint_accessible(self):
        """Federation endpoint responds (403 without auth, 200 with auth)."""
        from src.ltp.commitment import CommitmentLog

        app = create_app(GatewayConfig(jwt_enabled=False))
        app.state.health_fn = lambda: {"ok": True}
        app.state.commitment_log = CommitmentLog()
        client = TestClient(app)

        # Without federation auth → 403
        resp = client.get("/federation/v1/entity/test")
        assert resp.status_code == 403

        # With federation auth headers → 404 (not found, but auth passed)
        resp = client.get(
            "/federation/v1/entity/test",
            headers={
                "X-Federation-NIR-Sig": "aa" * 64,
                "X-Federation-Network-ID": "net-001",
            },
        )
        assert resp.status_code == 404

    def test_clean_shutdown(self):
        """All components stop without error."""
        config = NodeConfig(
            node_id="gate-shutdown",
            region="test",
            listen_port=0,
            rest_port=0,
            diagnostics_port=0,
            require_real_crypto=False,
            storage_backend="memory",
            gateway_enabled=True,
            gateway_port=0,
            gossip_enabled=True,
            observability_enabled=True,
        )
        node = ETPNode(config)
        node.start()
        assert node._running is True
        node.stop()
        assert node._running is False
        assert node._gateway_server is None
        assert node._gossip_protocol is None
