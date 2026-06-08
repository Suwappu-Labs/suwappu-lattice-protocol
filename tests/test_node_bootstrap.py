"""
Node Bootstrap & Discovery tests.

Tests NodeConfig, PeerManager, handshake protocol, gRPC integration,
and the exit criterion — two nodes discover each other via seed peers
and complete ML-DSA-65 authenticated handshakes over gRPC.
"""

import time

import pytest

from src.ltp import DOMAIN_NODE_HANDSHAKE, CommitmentNode, KeyPair
from src.ltp.node.config import NodeConfig
from src.ltp.node.handshake import (
    PROTOCOL_VERSION,
    HandshakePayload,
    create_handshake_envelope,
    deserialize_envelope,
    serialize_envelope,
    verify_handshake_envelope,
)
from src.ltp.node.peer_manager import PeerInfo, PeerManager, PeerState

# ===================================================================
# TestNodeConfig
# ===================================================================


class TestNodeConfig:
    """Test TOML/env configuration loading."""

    def test_defaults(self):
        """Default config values are sane."""
        config = NodeConfig()
        assert config.node_id == "etp-node-1"
        assert config.region == "default"
        assert config.listen_port == 50051
        assert config.rest_port == 8080
        assert config.seed_peers == []
        assert config.storage_backend == "memory"
        assert config.max_workers == 10
        assert config.require_real_crypto is True
        assert config.log_level == "INFO"

    def test_from_toml(self, tmp_path):
        """Parse TOML file and verify all fields."""
        toml_content = """
[node]
node_id = "test-node-1"
region = "EU-West"

[network]
listen_host = "127.0.0.1"
listen_port = 50100
rest_port = 9090
seed_peers = ["10.0.1.10:50051", "10.0.1.11:50051"]

[crypto]
keypair_path = "/tmp/keys"
require_real_crypto = false

[storage]
backend = "sqlite"
path = "/tmp/db"

[server]
max_workers = 4
log_level = "DEBUG"
"""
        toml_file = tmp_path / "test.toml"
        toml_file.write_text(toml_content)

        config = NodeConfig.from_toml(str(toml_file))
        assert config.node_id == "test-node-1"
        assert config.region == "EU-West"
        assert config.listen_host == "127.0.0.1"
        assert config.listen_port == 50100
        assert config.rest_port == 9090
        assert config.seed_peers == ["10.0.1.10:50051", "10.0.1.11:50051"]
        assert config.keypair_path == "/tmp/keys"
        assert config.require_real_crypto is False
        assert config.storage_backend == "sqlite"
        assert config.storage_path == "/tmp/db"
        assert config.max_workers == 4
        assert config.log_level == "DEBUG"

    def test_from_env(self, monkeypatch):
        """Environment variables populate config."""
        monkeypatch.setenv("ETP_NODE_ID", "env-node-1")
        monkeypatch.setenv("ETP_REGION", "AP-East")
        monkeypatch.setenv("ETP_LISTEN_PORT", "50200")
        monkeypatch.setenv("ETP_SEED_PEERS", "host1:50051,host2:50051")
        monkeypatch.setenv("ETP_REQUIRE_REAL_CRYPTO", "false")
        monkeypatch.setenv("ETP_LOG_LEVEL", "WARNING")

        config = NodeConfig.from_env()
        assert config.node_id == "env-node-1"
        assert config.region == "AP-East"
        assert config.listen_port == 50200
        assert config.seed_peers == ["host1:50051", "host2:50051"]
        assert config.require_real_crypto is False
        assert config.log_level == "WARNING"

    def test_repr_redacts_operator_key(self):
        """__repr__ never exposes anchor_operator_key value."""
        config = NodeConfig(anchor_operator_key="0xDEADBEEF_PRIVATE_KEY")
        r = repr(config)
        assert "0xDEADBEEF_PRIVATE_KEY" not in r
        assert "REDACTED" in r

    def test_repr_shows_empty_key_as_empty(self):
        """When operator key is empty, repr shows it normally."""
        config = NodeConfig(anchor_operator_key="")
        r = repr(config)
        assert "anchor_operator_key=''" in r

    def test_env_overlay(self, tmp_path, monkeypatch):
        """Env vars override TOML values."""
        toml_content = """
[node]
node_id = "toml-node"
region = "US-East"

[network]
listen_port = 50051
"""
        toml_file = tmp_path / "overlay.toml"
        toml_file.write_text(toml_content)

        monkeypatch.setenv("ETP_NODE_ID", "env-override")
        monkeypatch.setenv("ETP_LISTEN_PORT", "60000")

        config = NodeConfig.from_toml_with_env_overlay(str(toml_file))
        assert config.node_id == "env-override"
        assert config.region == "US-East"  # not overridden
        assert config.listen_port == 60000


# ===================================================================
# TestHandshake
# ===================================================================


class TestHandshake:
    """Test handshake payload and envelope creation/verification."""

    def test_payload_round_trip(self):
        """to_bytes/from_bytes preserves all fields."""
        payload = HandshakePayload(
            node_id="test-node",
            listen_address="10.0.1.5:50051",
            region="US-East",
            protocol_version=PROTOCOL_VERSION,
            timestamp=1700000000.0,
        )
        raw = payload.to_bytes()
        restored = HandshakePayload.from_bytes(raw)

        assert restored.node_id == payload.node_id
        assert restored.listen_address == payload.listen_address
        assert restored.region == payload.region
        assert restored.protocol_version == payload.protocol_version
        assert restored.timestamp == payload.timestamp

    def test_create_and_verify_envelope(self, alice):
        """Round-trip: create envelope, serialize, deserialize, verify."""
        payload = HandshakePayload(
            node_id="alice-node",
            listen_address="127.0.0.1:50051",
            region="US-East",
            protocol_version=PROTOCOL_VERSION,
            timestamp=time.time(),
        )
        env = create_handshake_envelope(alice, payload)
        assert env.domain == DOMAIN_NODE_HANDSHAKE
        assert env.payload_type == "node-handshake"

        # Verify
        ok, parsed = verify_handshake_envelope(env, max_drift=60.0)
        assert ok is True
        assert parsed is not None
        assert parsed.node_id == "alice-node"

    def test_serialization_round_trip(self, alice):
        """serialize/deserialize preserves envelope."""
        payload = HandshakePayload(
            node_id="ser-test",
            listen_address="10.0.0.1:50051",
            region="EU-West",
            protocol_version=PROTOCOL_VERSION,
            timestamp=time.time(),
        )
        env = create_handshake_envelope(alice, payload)

        wire = serialize_envelope(env)
        restored = deserialize_envelope(wire)

        assert restored.version == env.version
        assert restored.domain == env.domain
        assert restored.signer_vk == env.signer_vk
        assert restored.signer_id == env.signer_id
        assert restored.signer_kid == env.signer_kid
        assert restored.timestamp == env.timestamp
        assert restored.payload_type == env.payload_type
        assert restored.payload_hash == env.payload_hash
        assert restored.payload == env.payload
        assert restored.signature == env.signature

        # Deserialized envelope should still verify
        ok, _ = verify_handshake_envelope(restored, max_drift=60.0)
        assert ok is True

    def test_expired_envelope(self, alice):
        """Envelope with old timestamp is rejected by max_drift."""
        from src.ltp.envelope import SignedEnvelope

        payload = HandshakePayload(
            node_id="old-node",
            listen_address="10.0.0.1:50051",
            region="US-East",
            protocol_version=PROTOCOL_VERSION,
            timestamp=time.time() - 120,  # 2 minutes ago
        )
        env = SignedEnvelope.create_at(
            domain=DOMAIN_NODE_HANDSHAKE,
            signer_vk=alice.vk,
            signer_sk=alice.sk,
            signer_id=alice.label,
            payload_type="node-handshake",
            payload=payload.to_bytes(),
            timestamp=time.time() - 120,
        )

        ok, parsed = verify_handshake_envelope(env, max_drift=30.0)
        assert ok is False
        assert parsed is None

    def test_wrong_key_fails(self, alice, eve):
        """Envelope signed by alice cannot be verified with eve's vk."""
        payload = HandshakePayload(
            node_id="alice-node",
            listen_address="10.0.0.1:50051",
            region="US-East",
            protocol_version=PROTOCOL_VERSION,
            timestamp=time.time(),
        )
        env = create_handshake_envelope(alice, payload)

        # Tamper: replace signer_vk with eve's vk
        tampered = serialize_envelope(env)
        tampered_env = deserialize_envelope(tampered)
        tampered_env.signer_vk = eve.vk

        ok, _ = verify_handshake_envelope(tampered_env, max_drift=60.0)
        assert ok is False


# ===================================================================
# TestPeerManager
# ===================================================================


class TestPeerManager:
    """Test peer tracking and state management."""

    def test_add_seed_peer(self):
        pm = PeerManager()
        peer = pm.add_seed_peer("10.0.1.10:50051")
        assert peer.address == "10.0.1.10:50051"
        assert peer.state == PeerState.DISCOVERED
        assert peer.node_id == ""

    def test_add_seed_peer_idempotent(self):
        pm = PeerManager()
        p1 = pm.add_seed_peer("10.0.1.10:50051")
        p2 = pm.add_seed_peer("10.0.1.10:50051")
        assert p1 is p2

    def test_mark_connected(self):
        pm = PeerManager()
        pm.add_seed_peer("10.0.1.10:50051")
        pm.mark_connected("node-2", b"\x01" * 1952, "10.0.1.10:50051", "US-East")

        peer = pm.get_peer_by_address("10.0.1.10:50051")
        assert peer is not None
        assert peer.node_id == "node-2"
        assert peer.state == PeerState.CONNECTED
        assert peer.region == "US-East"
        assert len(peer.public_key) == 1952

    def test_mark_disconnected(self):
        pm = PeerManager()
        pm.mark_connected("node-2", b"\x01" * 32, "10.0.1.10:50051", "US-East")
        assert pm.connected_count == 1

        pm.mark_disconnected("node-2")
        peer = pm.get_peer_by_id("node-2")
        assert peer.state == PeerState.DISCONNECTED
        assert pm.connected_count == 0

    def test_connected_count(self):
        pm = PeerManager()
        assert pm.connected_count == 0

        pm.mark_connected("node-1", b"\x01", "addr1", "R1")
        pm.mark_connected("node-2", b"\x02", "addr2", "R2")
        assert pm.connected_count == 2

        pm.mark_disconnected("node-1")
        assert pm.connected_count == 1

    def test_get_connected_peers(self):
        pm = PeerManager()
        pm.mark_connected("n1", b"\x01", "a1", "R1")
        pm.mark_connected("n2", b"\x02", "a2", "R2")
        pm.mark_disconnected("n1")

        connected = pm.get_connected_peers()
        assert len(connected) == 1
        assert connected[0].node_id == "n2"

    def test_get_peer_by_address(self):
        pm = PeerManager()
        pm.add_seed_peer("10.0.1.10:50051")
        assert pm.get_peer_by_address("10.0.1.10:50051") is not None
        assert pm.get_peer_by_address("10.0.1.99:50051") is None

    def test_mark_rejected(self):
        pm = PeerManager()
        pm.add_seed_peer("10.0.1.10:50051")
        pm.mark_rejected("10.0.1.10:50051")

        peer = pm.get_peer_by_address("10.0.1.10:50051")
        assert peer.state == PeerState.REJECTED
        assert peer.handshake_failures == 1


# ===================================================================
# TestNodeHandshakeIntegration (EXIT CRITERION)
# ===================================================================


class TestNodeHandshakeIntegration:
    """Integration tests for two-node handshake over gRPC."""

    def test_two_node_handshake(self, alice, bob):
        """EXIT CRITERION: Two nodes start, discover each other, and complete
        ML-DSA-65 authenticated handshakes over gRPC."""
        import grpc

        from src.ltp.network import node_service_pb2 as ns_pb2
        from src.ltp.network import node_service_pb2_grpc as ns_pb2_grpc
        from src.ltp.network.node_servicer import NodeServicer
        from src.ltp.network.server import NodeServer

        # Create two commitment nodes
        node_a = CommitmentNode("node-a", "US-East")
        node_b = CommitmentNode("node-b", "EU-West")

        # Create peer managers
        pm_a = PeerManager()
        pm_b = PeerManager()

        # Create NodeServicers
        servicer_a = NodeServicer(
            node_id="node-a",
            region="US-East",
            keypair=alice,
            peer_manager=pm_a,
            shard_count_fn=lambda: node_a.shard_count,
        )
        servicer_b = NodeServicer(
            node_id="node-b",
            region="EU-West",
            keypair=bob,
            peer_manager=pm_b,
            shard_count_fn=lambda: node_b.shard_count,
        )

        # Start two gRPC servers on dynamic ports
        server_a = NodeServer(node_a, port=0, host="127.0.0.1", node_servicer=servicer_a)
        server_b = NodeServer(node_b, port=0, host="127.0.0.1", node_servicer=servicer_b)

        server_a.start()
        server_b.start()

        try:
            addr_a = f"127.0.0.1:{server_a.port}"
            addr_b = f"127.0.0.1:{server_b.port}"

            # Node A handshakes with Node B
            payload_a = HandshakePayload(
                node_id="node-a",
                listen_address=addr_a,
                region="US-East",
                protocol_version=PROTOCOL_VERSION,
                timestamp=time.time(),
            )
            env_a = create_handshake_envelope(alice, payload_a)

            channel_b = grpc.insecure_channel(addr_b)
            stub_b = ns_pb2_grpc.NodeServiceStub(channel_b)
            resp = stub_b.Handshake(
                ns_pb2.HandshakeRequest(
                    signed_envelope=serialize_envelope(env_a),
                    protocol_version=PROTOCOL_VERSION,
                ),
                timeout=10.0,
            )
            channel_b.close()

            assert resp.accepted is True
            assert resp.reject_reason == ""

            # Verify Node B's response envelope
            resp_env = deserialize_envelope(resp.signed_envelope)
            ok, resp_payload = verify_handshake_envelope(resp_env, max_drift=60.0)
            assert ok is True
            assert resp_payload.node_id == "node-b"
            assert resp_payload.region == "EU-West"

            # Node A registers Node B
            pm_a.mark_connected(
                node_id=resp_payload.node_id,
                public_key=resp_env.signer_vk,
                address=addr_b,
                region=resp_payload.region,
            )

            # Verify both peer managers show CONNECTED state
            assert pm_a.connected_count == 1
            assert pm_b.connected_count == 1

            peer_b_in_a = pm_a.get_peer_by_id("node-b")
            assert peer_b_in_a is not None
            assert peer_b_in_a.state == PeerState.CONNECTED

            peer_a_in_b = pm_b.get_peer_by_id("node-a")
            assert peer_a_in_b is not None
            assert peer_a_in_b.state == PeerState.CONNECTED

        finally:
            server_a.stop()
            server_b.stop()


# ===================================================================
# TestHealthCheck
# ===================================================================


class TestHealthCheck:
    """Test gRPC health and ping RPCs."""

    def test_ping(self, alice):
        """Ping RPC returns node_id and timestamp."""
        import grpc

        from src.ltp.network import node_service_pb2 as ns_pb2
        from src.ltp.network import node_service_pb2_grpc as ns_pb2_grpc
        from src.ltp.network.node_servicer import NodeServicer
        from src.ltp.network.server import NodeServer

        node = CommitmentNode("ping-node", "US-East")
        pm = PeerManager()
        servicer = NodeServicer(
            node_id="ping-node",
            region="US-East",
            keypair=alice,
            peer_manager=pm,
        )
        server = NodeServer(node, port=0, host="127.0.0.1", node_servicer=servicer)
        server.start()

        try:
            channel = grpc.insecure_channel(f"127.0.0.1:{server.port}")
            stub = ns_pb2_grpc.NodeServiceStub(channel)
            resp = stub.Ping(ns_pb2.PingRequest(sender_node_id="test"), timeout=5.0)
            channel.close()

            assert resp.node_id == "ping-node"
            assert resp.timestamp > 0
        finally:
            server.stop()

    def test_grpc_health(self, alice):
        """HealthCheck RPC returns correct data."""
        import grpc

        from src.ltp.network import node_service_pb2 as ns_pb2
        from src.ltp.network import node_service_pb2_grpc as ns_pb2_grpc
        from src.ltp.network.node_servicer import NodeServicer
        from src.ltp.network.server import NodeServer

        node = CommitmentNode("health-node", "EU-West")
        pm = PeerManager()
        servicer = NodeServicer(
            node_id="health-node",
            region="EU-West",
            keypair=alice,
            peer_manager=pm,
        )
        server = NodeServer(node, port=0, host="127.0.0.1", node_servicer=servicer)
        server.start()

        try:
            channel = grpc.insecure_channel(f"127.0.0.1:{server.port}")
            stub = ns_pb2_grpc.NodeServiceStub(channel)
            resp = stub.HealthCheck(ns_pb2.HealthCheckRequest(), timeout=5.0)
            channel.close()

            assert resp.status == "ok"
            assert resp.node_id == "health-node"
            assert resp.region == "EU-West"
            assert resp.uptime_seconds >= 0
            assert resp.protocol_version == PROTOCOL_VERSION
        finally:
            server.stop()

    def test_rest_health(self):
        """REST /health endpoint returns JSON."""
        import json
        import urllib.request

        from src.ltp.node.health import HealthServer

        def health_fn():
            return {"status": "ok", "node_id": "rest-test", "peer_count": 0}

        # HealthServer now captures actual bound port on start()
        server = HealthServer(health_fn, host="127.0.0.1", port=0)
        server.start()

        try:
            url = f"http://127.0.0.1:{server.port}/health"
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read())
            assert data["status"] == "ok"
            assert data["node_id"] == "rest-test"
        finally:
            server.stop()


# ===================================================================
# TestDeserializationSafety
# ===================================================================


class TestDeserializationSafety:
    """Verify bounds checking rejects truncated/malformed wire data."""

    def test_empty_data_raises(self):
        """Empty bytes must raise ValueError, not silently parse."""
        with pytest.raises(ValueError, match="empty"):
            deserialize_envelope(b"")

    def test_truncated_envelope_raises(self, alice):
        """Truncated wire data must raise ValueError."""
        payload = HandshakePayload(
            node_id="trunc-test",
            listen_address="10.0.0.1:50051",
            region="US-East",
            protocol_version=PROTOCOL_VERSION,
            timestamp=time.time(),
        )
        env = create_handshake_envelope(alice, payload)
        wire = serialize_envelope(env)

        # Chop off last 100 bytes (inside signature)
        with pytest.raises(ValueError, match="truncated"):
            deserialize_envelope(wire[:-100])

    def test_truncated_at_header_raises(self, alice):
        """Data truncated in the header region must raise."""
        payload = HandshakePayload(
            node_id="hdr-trunc",
            listen_address="10.0.0.1:50051",
            region="US-East",
            protocol_version=PROTOCOL_VERSION,
            timestamp=time.time(),
        )
        env = create_handshake_envelope(alice, payload)
        wire = serialize_envelope(env)

        # Only version byte + partial domain length
        with pytest.raises(ValueError, match="truncated"):
            deserialize_envelope(wire[:3])

    def test_payload_from_bytes_truncated(self):
        """HandshakePayload.from_bytes on truncated data must raise."""
        payload = HandshakePayload(
            node_id="x",
            listen_address="y",
            region="z",
            protocol_version=1,
            timestamp=1.0,
        )
        raw = payload.to_bytes()
        with pytest.raises(ValueError, match="truncated"):
            HandshakePayload.from_bytes(raw[:10])


# ===================================================================
# TestProtocolVersionValidation
# ===================================================================


class TestProtocolVersionValidation:
    """Verify protocol version mismatch is rejected at the gRPC layer."""

    def test_wrong_protocol_version_rejected(self, alice, bob):
        """Handshake with wrong protocol_version is rejected."""
        import grpc

        from src.ltp.network import node_service_pb2 as ns_pb2
        from src.ltp.network import node_service_pb2_grpc as ns_pb2_grpc
        from src.ltp.network.node_servicer import NodeServicer
        from src.ltp.network.server import NodeServer

        node = CommitmentNode("ver-node", "US-East")
        pm = PeerManager()
        servicer = NodeServicer(
            node_id="ver-node",
            region="US-East",
            keypair=bob,
            peer_manager=pm,
        )
        server = NodeServer(node, port=0, host="127.0.0.1", node_servicer=servicer)
        server.start()

        try:
            # Build valid envelope but send wrong protocol_version
            payload = HandshakePayload(
                node_id="alice-node",
                listen_address="127.0.0.1:50000",
                region="EU-West",
                protocol_version=PROTOCOL_VERSION,
                timestamp=time.time(),
            )
            env = create_handshake_envelope(alice, payload)

            channel = grpc.insecure_channel(f"127.0.0.1:{server.port}")
            stub = ns_pb2_grpc.NodeServiceStub(channel)
            resp = stub.Handshake(
                ns_pb2.HandshakeRequest(
                    signed_envelope=serialize_envelope(env),
                    protocol_version=999,  # wrong version
                ),
                timeout=5.0,
            )
            channel.close()

            assert resp.accepted is False
            assert "unsupported protocol version" in resp.reject_reason
            assert pm.connected_count == 0  # peer NOT registered
        finally:
            server.stop()

    def test_malformed_envelope_rejected(self, bob):
        """Garbage bytes in signed_envelope are rejected gracefully."""
        import grpc

        from src.ltp.network import node_service_pb2 as ns_pb2
        from src.ltp.network import node_service_pb2_grpc as ns_pb2_grpc
        from src.ltp.network.node_servicer import NodeServicer
        from src.ltp.network.server import NodeServer

        node = CommitmentNode("mal-node", "US-East")
        pm = PeerManager()
        servicer = NodeServicer(
            node_id="mal-node",
            region="US-East",
            keypair=bob,
            peer_manager=pm,
        )
        server = NodeServer(node, port=0, host="127.0.0.1", node_servicer=servicer)
        server.start()

        try:
            channel = grpc.insecure_channel(f"127.0.0.1:{server.port}")
            stub = ns_pb2_grpc.NodeServiceStub(channel)
            resp = stub.Handshake(
                ns_pb2.HandshakeRequest(
                    signed_envelope=b"\x00\x01\x02",  # garbage
                    protocol_version=PROTOCOL_VERSION,
                ),
                timeout=5.0,
            )
            channel.close()

            assert resp.accepted is False
            assert "deserialization error" in resp.reject_reason
        finally:
            server.stop()


# ===================================================================
# TestConfigErrors
# ===================================================================


class TestConfigErrors:
    """Test configuration error handling."""

    def test_toml_file_not_found(self):
        """Missing TOML file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            NodeConfig.from_toml("/nonexistent/path/node.toml")

    def test_toml_invalid_syntax(self, tmp_path):
        """Invalid TOML syntax raises appropriate error."""
        bad_toml = tmp_path / "bad.toml"
        bad_toml.write_text("this is not [valid toml = ")
        with pytest.raises(Exception):  # tomllib.TOMLDecodeError
            NodeConfig.from_toml(str(bad_toml))


# ===================================================================
# TestHealthAndCTSharedPort (Gap 7)
# ===================================================================


class TestHealthAndCTSharedPort:
    """Verify HealthServer + CT log share a single port without conflict."""

    def test_health_and_ct_share_port_no_conflict(self):
        """HealthServer with commitment_log serves both /health and /ct/v1/* on one port."""
        import json
        import urllib.error
        import urllib.request

        from src.ltp.commitment import CommitmentNetwork
        from src.ltp.node.health import HealthServer

        network = CommitmentNetwork()
        log = network.log

        def health_fn():
            return {"status": "ok", "node_id": "shared-port-test"}

        server = HealthServer(health_fn, host="127.0.0.1", port=0, commitment_log=log)
        server.start()

        try:
            base = f"http://127.0.0.1:{server.port}"

            # /health works
            with urllib.request.urlopen(f"{base}/health", timeout=5) as resp:
                data = json.loads(resp.read())
            assert data["status"] == "ok"
            assert data["node_id"] == "shared-port-test"

            # /ct/v1/get-sth works (CT log route)
            with urllib.request.urlopen(f"{base}/ct/v1/get-sth", timeout=5) as resp:
                sth = json.loads(resp.read())
            assert "tree_size" in sth
            assert sth["tree_size"] == 0  # empty log

            # Unknown route returns 404
            try:
                urllib.request.urlopen(f"{base}/bogus", timeout=5)
                assert False, "Expected 404"
            except urllib.error.HTTPError as exc:
                assert exc.code == 404
        finally:
            server.stop()

    def test_health_without_commitment_log_no_ct_routes(self):
        """HealthServer without commitment_log does NOT serve /ct/v1/*."""
        import json
        import urllib.error
        import urllib.request

        from src.ltp.node.health import HealthServer

        def health_fn():
            return {"status": "ok"}

        server = HealthServer(health_fn, host="127.0.0.1", port=0)
        server.start()

        try:
            base = f"http://127.0.0.1:{server.port}"

            # /health works
            with urllib.request.urlopen(f"{base}/health", timeout=5) as resp:
                data = json.loads(resp.read())
            assert data["status"] == "ok"

            # /ct/v1/get-sth returns 404 (no CT handler)
            try:
                urllib.request.urlopen(f"{base}/ct/v1/get-sth", timeout=5)
                assert False, "Expected 404"
            except urllib.error.HTTPError as exc:
                assert exc.code == 404
        finally:
            server.stop()


# ===================================================================
# TestMultiChainConfig
# ===================================================================


class TestMultiChainConfig:
    """Test multi-chain anchor configuration via [[anchor.chains]]."""

    _CHAIN_SUWAPPU = {
        "chain_id": 103115120,
        "label": "suwappu_testnet",
        "rpc_url": "https://rpc.testnet.suwappu.network",
        "registry_address": "0x" + "aB" * 20,
        "operator_key": "0xsuwappukey",
        "confirmation_depth": 3,
        "finality_depth": 1,
    }

    _CHAIN_BASE = {
        "chain_id": 84532,
        "label": "base_sepolia",
        "rpc_url": "https://sepolia.base.org",
        "registry_address": "0x" + "cD" * 20,
        "operator_key": "0xbasekey",
        "confirmation_depth": 6,
        "finality_depth": 2,
    }

    def test_anchor_chains_from_toml(self, tmp_path):
        """Parse [[anchor.chains]] sections from TOML."""
        toml_content = (
            """
[node]
node_id = "multi-chain-node"

[anchor]
enabled = true

[[anchor.chains]]
chain_id = 103115120
label = "suwappu_testnet"
rpc_url = "https://rpc.testnet.suwappu.network"
registry_address = "0x"""
            + "aB" * 20
            + """"
operator_key = "0xsuwappukey"
confirmation_depth = 3
finality_depth = 1

[[anchor.chains]]
chain_id = 84532
label = "base_sepolia"
rpc_url = "https://sepolia.base.org"
registry_address = "0x"""
            + "cD" * 20
            + """"
operator_key = "0xbasekey"
confirmation_depth = 6
finality_depth = 2
"""
        )
        toml_file = tmp_path / "multi.toml"
        toml_file.write_text(toml_content)

        config = NodeConfig.from_toml(str(toml_file))
        assert len(config.anchor_chains) == 2
        assert config.anchor_chains[0]["chain_id"] == 103115120
        assert config.anchor_chains[1]["chain_id"] == 84532

    def test_get_chain_configs_from_flat_fields(self):
        """Backward compat: flat fields produce single ChainConfig."""
        config = NodeConfig(
            anchor_rpc_url="https://rpc.testnet.suwappu.network",
            anchor_registry_address="0x" + "aB" * 20,
            anchor_operator_key="0xkey",
            anchor_chain_id=103115120,
        )
        chains = config.get_chain_configs()
        assert len(chains) == 1
        assert chains[0].chain_id == 103115120
        assert chains[0].rpc_url == "https://rpc.testnet.suwappu.network"

    def test_get_chain_configs_from_chains_list(self):
        """Multi-chain: anchor_chains list produces multiple ChainConfigs."""
        config = NodeConfig(
            anchor_chains=[self._CHAIN_SUWAPPU, self._CHAIN_BASE],
        )
        chains = config.get_chain_configs()
        assert len(chains) == 2
        assert chains[0].chain_id == 103115120
        assert chains[1].chain_id == 84532
        assert chains[1].confirmation_depth == 6

    def test_anchor_chains_override_flat_fields(self):
        """When anchor_chains is populated, flat fields are ignored."""
        config = NodeConfig(
            anchor_rpc_url="https://should.be.ignored",
            anchor_registry_address="0x" + "FF" * 20,
            anchor_operator_key="0xignored",
            anchor_chain_id=999,
            anchor_chains=[self._CHAIN_SUWAPPU],
        )
        chains = config.get_chain_configs()
        assert len(chains) == 1
        assert chains[0].chain_id == 103115120  # from chains list, not flat

    def test_get_chain_configs_empty_when_no_rpc_url(self):
        """Empty rpc_url and no chains → empty list."""
        config = NodeConfig(anchor_rpc_url="")
        assert config.get_chain_configs() == []

    def test_per_chain_depth_overrides_flat_config(self):
        """Per-chain confirmation_depth wins over flat config."""
        config = NodeConfig(
            anchor_confirmation_depth=3,  # flat
            anchor_chains=[
                {
                    **self._CHAIN_BASE,
                    "confirmation_depth": 12,  # per-chain override
                }
            ],
        )
        chains = config.get_chain_configs()
        assert chains[0].confirmation_depth == 12  # per-chain wins

    def test_anchor_chains_json_malformed(self, monkeypatch):
        """Invalid JSON in ETP_ANCHOR_CHAINS_JSON → clear error."""
        monkeypatch.setenv("ETP_ANCHOR_CHAINS_JSON", "{not valid json")
        with pytest.raises(ValueError, match="not valid JSON"):
            NodeConfig.from_env()

    def test_anchor_chains_json_not_a_list(self, monkeypatch):
        """JSON dict (not array) in ETP_ANCHOR_CHAINS_JSON → clear error."""
        monkeypatch.setenv("ETP_ANCHOR_CHAINS_JSON", '{"chain_id": 1}')
        with pytest.raises(ValueError, match="must be a JSON array"):
            NodeConfig.from_env()

    def test_anchor_chains_json_not_a_list_overlay(self, tmp_path, monkeypatch):
        """JSON dict in overlay path also rejected."""
        toml_file = tmp_path / "base.toml"
        toml_file.write_text('[node]\nnode_id = "test"\n')
        monkeypatch.setenv("ETP_ANCHOR_CHAINS_JSON", '"just a string"')
        with pytest.raises(ValueError, match="must be a JSON array"):
            NodeConfig.from_toml_with_env_overlay(str(toml_file))
