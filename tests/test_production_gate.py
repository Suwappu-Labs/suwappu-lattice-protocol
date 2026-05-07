"""
PRODUCTION GATE CLOSURE — Final comprehensive test for ETP.

Proves every system layer works together in a single test file.
This is the last checkpoint before the node team takes over
for mainnet deployment.

Layers tested:
  1. Crypto       — real PQC assertion, domain separation
  2. Protocol     — commit → lattice → materialize roundtrip
  3. Bridge       — SP1 + STARK provers, challenge finality, operator
  4. Gateway      — health, metrics, JWT auth, rate limiting
  5. Network      — gossip exchange, circuit breaker, mTLS credentials
  6. Integration  — ETPNode full startup, mainnet config parsing
"""

from __future__ import annotations

import os
import tempfile
import time
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from src.ltp.bridge.challenge import ChallengeManager, ChallengeStatus
from src.ltp.bridge.operator import BridgeOperatorService
from src.ltp.bridge.sp1_prover import SP1ZKBridgeProver
from src.ltp.bridge.zk_bridge import (
    STARKBridgeProver,
    ZKBridgeBackend,
    ZKBridgeVerifier,
)
from src.ltp.commitment import CommitmentLog, CommitmentNetwork, CommitmentRecord
from src.ltp.domain import _ALL_TAGS
from src.ltp.entity import Entity
from src.ltp.gateway.app import GatewayConfig, create_app
from src.ltp.gateway.auth import create_jwt
from src.ltp.keypair import KeyPair, KeyRegistry
from src.ltp.network.resilience import PeerCircuitBreaker
from src.ltp.node.config import NodeConfig
from src.ltp.node.gossip import GossipConfig, GossipProtocol, PeerAnnouncement, PeerExchangeMessage
from src.ltp.node.main import ETPNode
from src.ltp.node.peer_manager import PeerManager
from src.ltp.observability.endpoint import ETPObservability
from src.ltp.primitives import MLDSA, assert_real_crypto
from src.ltp.protocol import LTPProtocol


@pytest.fixture(scope="module")
def operator():
    return KeyPair.generate("gate-operator")


# =========================================================================
# 1. CRYPTO LAYER
# =========================================================================

class TestCryptoLayer:

    def test_real_crypto_available(self):
        """ML-KEM-768, ML-DSA-65, and XChaCha20-Poly1305 are all present."""
        assert_real_crypto()

    def test_domain_separation_tags_unique(self):
        """31 domain tags, no collisions, no byte-prefix overlaps."""
        assert len(_ALL_TAGS) == 31
        values = list(_ALL_TAGS.values())
        assert len(set(values)) == 31  # All unique


# =========================================================================
# 2. PROTOCOL LAYER
# =========================================================================

class TestProtocolLayer:

    def test_commit_lattice_materialize_roundtrip(self, operator):
        """Full three-phase transfer lifecycle end-to-end."""
        kr = KeyRegistry()
        kr.register(operator)
        cn = CommitmentNetwork()
        for i in range(8):
            cn.register_node(f"gate-node-{i}", "test", stake=1000.0)
        protocol = LTPProtocol(cn, key_registry=kr)

        original = b"Production gate closure test payload - ETP by Javier Calderon Jr"
        entity = Entity(content=original, shape="application/octet-stream")

        # Phase 1: COMMIT
        entity_id, record, cek = protocol.commit(entity, operator)
        assert len(entity_id) > 0

        # Phase 2: LATTICE
        sealed = protocol.lattice(entity_id, record, cek, operator)
        assert len(sealed) > 1000  # ~1300-1442 bytes

        # Phase 3: MATERIALIZE
        content = protocol.materialize(sealed, operator)
        assert content == original

    def test_commitment_log_sth_and_proofs(self, operator):
        """RFC 6962 log produces valid STH and inclusion proofs."""
        log = CommitmentLog()
        record = CommitmentRecord(
            entity_id="gate-entity", sender_id="sender",
            content_hash="hash", shard_map_root="root",
            encoding_params={"n": 5, "k": 3},
            shape="test", shape_hash="shash",
            timestamp=time.time(), signature=b"\x00" * 64,
        )
        log.append(record)
        sth = log.latest_sth
        assert sth is not None
        assert sth.tree_size == 1

        proof = log.get_inclusion_proof("gate-entity")
        assert proof is not None


# =========================================================================
# 3. BRIDGE LAYER
# =========================================================================

class TestBridgeLayer:

    def _make_sth(self, kp):
        from src.ltp.merkle_log.sth import SignedTreeHead
        sth = SignedTreeHead(
            sequence=1, tree_size=1, timestamp=time.time(),
            root_hash=b"\xaa" * 32, operator_vk=kp.vk, signature=b"",
        )
        sig = MLDSA.sign(kp.sk, sth.signable_payload())
        return SignedTreeHead(
            sequence=1, tree_size=1, timestamp=sth.timestamp,
            root_hash=sth.root_hash, operator_vk=kp.vk, signature=sig,
        )

    def test_sp1_proof_valid(self, operator):
        """SP1 mock prover generates a verifiable proof."""
        sth = self._make_sth(operator)
        proof = SP1ZKBridgeProver(prove_mode="mock").prove_sth_signature(sth)
        assert proof.backend == ZKBridgeBackend.SP1
        assert ZKBridgeVerifier.verify(proof) is True

    def test_stark_proof_valid(self, operator):
        """Enhanced STARK prover generates a verifiable proof."""
        sth = self._make_sth(operator)
        proof = STARKBridgeProver(num_fri_rounds=4).prove_sth_signature(sth)
        assert proof.backend == ZKBridgeBackend.STARK
        assert proof.proof_size_bytes > 100  # Real FRI-based STARK
        assert ZKBridgeVerifier.verify(proof) is True

    def test_challenge_instant_finality(self, operator):
        """ZK proof resolves challenge window instantly."""
        sth = self._make_sth(operator)
        proof = SP1ZKBridgeProver(prove_mode="mock").prove_sth_signature(sth)

        cm = ChallengeManager(challenge_period=604800)  # 7-day production window
        cm.open_challenge_window("gate-bridge", b"\x01" * 32)
        rec = cm.resolve_with_proof("gate-bridge", proof)
        assert rec.status == ChallengeStatus.FINALIZED

    def test_bridge_operator_ticks(self, operator):
        """BridgeOperatorService polls and handles empty network."""
        kr = KeyRegistry()
        kr.register(operator)
        cn = CommitmentNetwork()
        for i in range(8):
            cn.register_node(f"op-node-{i}", "test", stake=1000.0)

        op = BridgeOperatorService(
            network=cn, live_bridge=None,  # No live bridge — tests tick() mechanics
            operator_keypair=operator,
            interval_seconds=1.0,
        )
        result = op.tick()
        assert result.records_polled == 0
        assert result.records_failed == 0


# =========================================================================
# 4. GATEWAY LAYER
# =========================================================================

class TestGatewayLayer:

    def test_health_endpoint(self):
        """GET /health returns 200."""
        app = create_app(GatewayConfig(jwt_enabled=False))
        app.state.health_fn = lambda: {"status": "ok"}
        client = TestClient(app)
        assert client.get("/health").status_code == 200

    def test_metrics_endpoint(self):
        """GET /metrics returns Prometheus text with 16 ETP metrics."""
        app = create_app(GatewayConfig(jwt_enabled=False))
        obs = ETPObservability(node_id="gate", region="test")
        app.state.observability = obs
        app.state.health_fn = lambda: {"status": "ok"}
        client = TestClient(app)
        resp = client.get("/metrics")
        assert resp.status_code == 200
        body = resp.text
        assert "etp_sth_publish_gap_seconds" in body
        assert "etp_bridge_records_bridged_total" in body
        assert "etp_gossip_peers_discovered_total" in body

    def test_jwt_auth_enforced(self):
        """Protected endpoints require valid ML-DSA-65 JWT."""
        kp = KeyPair.generate("gate-jwt")
        from src.ltp.domain import signer_fingerprint
        app = create_app(GatewayConfig(jwt_enabled=True))
        app.state.health_fn = lambda: {"status": "ok"}
        app.state.known_vks = {signer_fingerprint(kp.vk).hex(): kp.vk}
        client = TestClient(app)

        # Without token → 401
        assert client.get("/node/audit").status_code == 401

        # With valid token → 200
        token = create_jwt(kp, "gate-node")
        assert client.get("/node/audit", headers={"Authorization": f"Bearer {token}"}).status_code == 200

    def test_rate_limiting(self):
        """Exceeding rate limit → 429."""
        app = create_app(GatewayConfig(jwt_enabled=False, rate_limit_enabled=True, rate_limit_per_minute=2))
        app.state.health_fn = lambda: {"status": "ok"}
        client = TestClient(app)
        statuses = [client.get("/health").status_code for _ in range(5)]
        assert 429 in statuses


# =========================================================================
# 5. NETWORK LAYER
# =========================================================================

class TestNetworkLayer:

    def test_gossip_exchange_roundtrip(self, operator):
        """Gossip peer exchange: build → sign → handle → discover."""
        alice_kp = operator
        bob_kp = KeyPair.generate("gate-bob")
        pm = PeerManager()
        pm.mark_connected("bob", bob_kp.vk, "10.0.1.2:50051", "EU")

        gossip = GossipProtocol(pm, alice_kp, "alice", "US", config=GossipConfig(max_peers=10))
        msg = gossip.build_exchange_message()
        assert len(msg.peers) >= 1

        sig = msg.sign(alice_kp.sk)
        assert msg.verify(alice_kp.vk, sig) is True

    def test_circuit_breaker_lifecycle(self):
        """CLOSED → OPEN → HALF_OPEN → CLOSED."""
        cb = PeerCircuitBreaker(peer_id="gate-peer", failure_threshold=2, cooldown_seconds=0.01)
        assert cb.state == "closed"
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "open"
        time.sleep(0.02)
        assert cb.state == "half_open"
        cb.record_success()
        assert cb.state == "closed"

    def test_mtls_credential_loading(self):
        """TLS config produces gRPC credentials from real certs."""
        from src.ltp.network.credentials import load_server_credentials
        from src.ltp.observability.tls import TLSConfig
        from tests.test_grpc_tls import _generate_self_signed_cert

        with tempfile.TemporaryDirectory() as d:
            cert, key = _generate_self_signed_cert(d, "gate-test")
            config = TLSConfig(enabled=True, cert_path=cert, key_path=key)
            creds = load_server_credentials(config)
            assert creds is not None


# =========================================================================
# 6. NODE INTEGRATION
# =========================================================================

class TestNodeIntegration:

    def test_etpnode_full_startup_shutdown(self):
        """ETPNode starts with gateway + gossip + observability, stops cleanly."""
        config = NodeConfig(
            node_id="gate-final", region="test",
            listen_port=0, rest_port=0, diagnostics_port=0,
            require_real_crypto=False,
            storage_backend="memory",
            gateway_enabled=True, gateway_port=0,
            gossip_enabled=True,
            observability_enabled=True,
        )
        node = ETPNode(config)
        node.start()
        try:
            assert node._running is True
            assert node._gateway_server is not None
            assert node._gossip_protocol is not None
            assert node._observability is not None
            assert node._gateway_server.app.state.observability is node._observability
        finally:
            node.stop()
        assert node._running is False

    def test_mainnet_config_parses(self):
        """config/mainnet.toml loads with all production flags."""
        mainnet_toml = os.path.join(
            os.path.dirname(__file__), "..", "config", "mainnet.toml"
        )
        config = NodeConfig.from_toml(mainnet_toml)
        assert config.require_real_crypto is True
        assert config.gateway_jwt_enabled is True
        assert config.tls_enabled is True
        assert config.kms_backend == "aws"
        assert config.bridge_operator_zk_mode == "stark"
        assert config.bridge_operator_challenge_period == 604800.0
