"""
Security audit: adversarial tests for all security-relevant components.
"""

from __future__ import annotations

import json
import os
import tempfile
import time

import pytest
from fastapi.testclient import TestClient

from src.ltp.domain import signer_fingerprint
from src.ltp.gateway.app import GatewayConfig, create_app
from src.ltp.gateway.auth import _b64url_decode, _b64url_encode, create_jwt, verify_jwt
from src.ltp.keypair import KeyPair
from src.ltp.network.credentials import load_channel_credentials, load_server_credentials
from src.ltp.network.interceptors import NetworkPolicyInterceptor
from src.ltp.network.resilience import ExponentialBackoff, PeerCircuitBreaker
from src.ltp.node.config import NodeConfig
from src.ltp.node.gossip import GossipConfig, GossipProtocol, PeerAnnouncement, PeerExchangeMessage
from src.ltp.node.peer_manager import PeerManager
from src.ltp.observability.tls import NetworkPolicy, NetworkPolicyRegistry, TLSConfig

# ---------------------------------------------------------------------------
# JWT Security
# ---------------------------------------------------------------------------


class TestJWTSecurity:
    def test_expired_token_rejected_strict(self):
        kp = KeyPair.generate("jwt-test")
        token = create_jwt(kp, "node-1", ttl_seconds=-10)
        vks = {signer_fingerprint(kp.vk).hex(): kp.vk}
        assert verify_jwt(token, known_vks=vks, max_clock_skew=0.0) is None

    def test_tampered_payload_rejected(self):
        kp = KeyPair.generate("jwt-test")
        token = create_jwt(kp, "node-1")
        parts = token.split(".")
        claims = json.loads(_b64url_decode(parts[1]))
        claims["sub"] = "attacker"
        parts[1] = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
        tampered = ".".join(parts)
        vks = {signer_fingerprint(kp.vk).hex(): kp.vk}
        assert verify_jwt(tampered, known_vks=vks) is None

    def test_wrong_algorithm_rejected(self):
        header = {"alg": "RS256", "typ": "JWT"}
        claims = {"sub": "x", "iss": "y", "exp": time.time() + 3600, "iat": time.time()}
        h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        c = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
        s = _b64url_encode(b"\x00" * 64)
        assert verify_jwt(f"{h}.{c}.{s}", known_vks={}) is None


# ---------------------------------------------------------------------------
# Gateway Security
# ---------------------------------------------------------------------------


class TestGatewaySecurity:
    def test_500_never_leaks_exceptions(self):
        app = create_app(GatewayConfig(jwt_enabled=False))
        app.state.health_fn = lambda: {"status": "ok"}
        app.state.protocol = None  # Force 503 on transfer endpoints
        client = TestClient(app)
        resp = client.get("/node/transfers")
        assert resp.status_code == 503
        body = resp.json()
        assert "traceback" not in json.dumps(body).lower()
        assert "exception" not in json.dumps(body).lower()

    def test_rate_limit_returns_429(self):
        app = create_app(
            GatewayConfig(jwt_enabled=False, rate_limit_enabled=True, rate_limit_per_minute=2)
        )
        app.state.health_fn = lambda: {"status": "ok"}
        client = TestClient(app)
        statuses = [client.get("/health").status_code for _ in range(5)]
        assert 429 in statuses


# ---------------------------------------------------------------------------
# Gossip Security
# ---------------------------------------------------------------------------


class TestGossipSecurity:
    def test_oversized_message_capped(self):
        kp_a = KeyPair.generate("a")
        kp_b = KeyPair.generate("b")
        pm = PeerManager()
        gossip = GossipProtocol(pm, kp_a, "a", "US", config=GossipConfig(max_peers=5))
        peers = [PeerAnnouncement(f"n-{i}", f"10.0.{i}.1:5", "X", "aa" * 32) for i in range(50)]
        msg = PeerExchangeMessage("b", time.time(), peers)
        sig = msg.sign(kp_b.sk)
        discovered = gossip.handle_peer_exchange(msg, kp_b.vk, sig)
        assert discovered <= 5

    def test_invalid_signature_returns_zero(self):
        kp_a = KeyPair.generate("a")
        kp_b = KeyPair.generate("b")
        kp_c = KeyPair.generate("c")
        pm = PeerManager()
        gossip = GossipProtocol(pm, kp_a, "a", "US")
        msg = PeerExchangeMessage(
            "b", time.time(), [PeerAnnouncement("new", "1.2.3.4:5", "X", "dd" * 32)]
        )
        sig = msg.sign(kp_b.sk)
        assert gossip.handle_peer_exchange(msg, kp_c.vk, sig) == 0  # Wrong VK

    def test_rate_limited_sender_blocked(self):
        kp_a = KeyPair.generate("a")
        kp_b = KeyPair.generate("b")
        pm = PeerManager()
        gossip = GossipProtocol(
            pm, kp_a, "a", "US", config=GossipConfig(rate_limit_per_peer_per_minute=2)
        )
        for i in range(5):
            msg = PeerExchangeMessage(
                "b", time.time(), [PeerAnnouncement(f"n-{i}", f"10.{i}.1.1:5", "X", "aa" * 32)]
            )
            sig = msg.sign(kp_b.sk)
            gossip.handle_peer_exchange(msg, kp_b.vk, sig)
        # Final one should be rate limited
        msg = PeerExchangeMessage(
            "b", time.time(), [PeerAnnouncement("final", "10.9.9.9:5", "X", "bb" * 32)]
        )
        sig = msg.sign(kp_b.sk)
        assert gossip.handle_peer_exchange(msg, kp_b.vk, sig) == 0


# ---------------------------------------------------------------------------
# Federation Security
# ---------------------------------------------------------------------------


class TestFederationSecurity:
    def test_missing_auth_returns_403(self):
        app = create_app(GatewayConfig(jwt_enabled=False))
        app.state.health_fn = lambda: {"ok": True}
        from src.ltp.commitment import CommitmentLog, CommitmentNetwork

        app.state.commitment_network = CommitmentNetwork()
        app.state.commitment_log = CommitmentLog()
        client = TestClient(app)
        resp = client.get("/federation/v1/entity/test")
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Circuit Breaker Security
# ---------------------------------------------------------------------------


class TestCircuitBreakerSecurity:
    def test_tripped_breaker_blocks_requests(self):
        cb = PeerCircuitBreaker(peer_id="peer-1", failure_threshold=3, cooldown_seconds=60)
        for _ in range(3):
            cb.record_failure()
        assert cb.allow_request() is False
        assert cb.state == "open"

    def test_half_open_recovery(self):
        cb = PeerCircuitBreaker(peer_id="peer-1", failure_threshold=2, cooldown_seconds=0.01)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "open"
        time.sleep(0.02)
        assert cb.state == "half_open"
        assert cb.allow_request() is True
        cb.record_success()
        assert cb.state == "closed"


# ---------------------------------------------------------------------------
# Network Policy Security
# ---------------------------------------------------------------------------


class TestNetworkPolicySecurity:
    def test_unauthorized_caller_blocked(self):
        registry = NetworkPolicyRegistry()
        registry.register_policy(NetworkPolicy("svc", allowed_callers=["trusted"]))
        interceptor = NetworkPolicyInterceptor(registry, "svc")

        class MockDetails:
            invocation_metadata = [("x-caller-id", "attacker")]

        called = [False]

        def cont(d):
            called[0] = True
            return "ok"

        interceptor.intercept_service(cont, MockDetails())
        assert called[0] is False


# ---------------------------------------------------------------------------
# Bridge Operator Security
# ---------------------------------------------------------------------------


class TestBridgeOperatorSecurity:
    def test_idempotency(self):
        from unittest.mock import MagicMock

        from src.ltp.bridge.live import LiveBridgeResult
        from src.ltp.bridge.message import BridgeMessage
        from src.ltp.bridge.operator import BridgeOperatorService
        from src.ltp.commitment import CommitmentNetwork
        from src.ltp.entity import Entity
        from src.ltp.keypair import KeyRegistry
        from src.ltp.protocol import LTPProtocol

        kp = KeyPair.generate("op")
        kr = KeyRegistry()
        kr.register(kp)
        cn = CommitmentNetwork()
        for i in range(8):
            cn.register_node(f"n-{i}", "x", stake=1000.0)
        protocol = LTPProtocol(cn, key_registry=kr)

        mock_bridge = MagicMock()
        mock_bridge.transfer.return_value = LiveBridgeResult(
            message=BridgeMessage("x", "a", "b", "s", "r", {}, 1),
            entity_id="e",
            l1_anchor_tx_hash="0x1",
            is_anchored_on_l1=True,
            l1_entity_state=2,
            source_chain="a",
            dest_chain="b",
            l1_block_height=1,
            l1_chain_id=1,
            sequence=1,
        )

        op = BridgeOperatorService(network=cn, live_bridge=mock_bridge, operator_keypair=kp)
        entity = Entity(content=b"test", shape="application/octet-stream")
        protocol.commit(entity, kp)

        r1 = op.tick()
        assert r1.records_bridged == 1
        r2 = op.tick()
        assert r2.records_bridged == 0  # Idempotent


# ---------------------------------------------------------------------------
# Config Security
# ---------------------------------------------------------------------------


class TestConfigSecurity:
    def test_operator_key_redacted(self):
        config = NodeConfig(anchor_operator_key="0xSECRET_KEY_12345")
        r = repr(config)
        assert "0xSECRET_KEY_12345" not in r
        assert "REDACTED" in r


# ---------------------------------------------------------------------------
# mTLS Credential Security
# ---------------------------------------------------------------------------


class TestmTLSSecurity:
    def test_valid_pem_loads(self):
        from tests.test_grpc_tls import _generate_self_signed_cert

        with tempfile.TemporaryDirectory() as d:
            cert, key = _generate_self_signed_cert(d, "test")
            config = TLSConfig(enabled=True, cert_path=cert, key_path=key)
            creds = load_server_credentials(config)
            assert creds is not None

    def test_missing_cert_raises(self):
        config = TLSConfig(enabled=True, cert_path="/nonexistent", key_path="/nonexistent")
        with pytest.raises(FileNotFoundError):
            load_server_credentials(config)


# ---------------------------------------------------------------------------
# Backoff Security (predictability)
# ---------------------------------------------------------------------------


class TestBackoffSecurity:
    def test_exponential_growth(self):
        eb = ExponentialBackoff(base_delay=1.0, max_delay=60.0, jitter=0.0)
        assert eb.delay_for(0) == 1.0
        assert eb.delay_for(1) == 2.0
        assert eb.delay_for(2) == 4.0

    def test_capped_at_max(self):
        eb = ExponentialBackoff(base_delay=1.0, max_delay=10.0, jitter=0.0)
        assert eb.delay_for(20) == 10.0
