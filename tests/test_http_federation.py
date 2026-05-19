"""
Tests for HTTP federation transport: client-side HTTPFederationTransport
and server-side federation endpoints.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from src.ltp.commitment import CommitmentLog, CommitmentNetwork, CommitmentRecord
from src.ltp.federation import FederationAuth
from src.ltp.federation_http import HTTPFederationTransport
from src.ltp.gateway.app import GatewayConfig, create_app
from src.ltp.keypair import KeyPair

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def keypair():
    return KeyPair.generate("fed-test")


@pytest.fixture
def commitment_log():
    return CommitmentLog()


@pytest.fixture
def app(commitment_log, keypair):
    config = GatewayConfig(jwt_enabled=False)
    application = create_app(config)
    application.state.commitment_log = commitment_log
    application.state.health_fn = lambda: {"status": "ok"}

    # Create a minimal commitment network
    cn = CommitmentNetwork()
    for i in range(3):
        cn.register_node(f"node-{i}", f"region-{i}", stake=1000.0)
    application.state.commitment_network = cn
    return application


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def fed_headers():
    """Minimal federation auth headers."""
    return {
        "X-Federation-NIR-Sig": "aa" * 64,
        "X-Federation-Agreement-Sig": f"{'bb' * 64}|{'cc' * 64}",
        "X-Federation-Network-ID": "net-test-001",
    }


# ---------------------------------------------------------------------------
# Server-side: Federation endpoints
# ---------------------------------------------------------------------------


class TestFederationEndpoints:
    def test_query_entity_not_found(self, client, fed_headers):
        resp = client.get("/federation/v1/entity/nonexistent", headers=fed_headers)
        assert resp.status_code == 404

    def test_query_entity_found(self, client, commitment_log, keypair, fed_headers):
        record = CommitmentRecord(
            entity_id="fed-entity-001",
            sender_id="sender",
            content_hash="hash",
            shard_map_root="root",
            encoding_params={"n": 5, "k": 3},
            shape="application/octet-stream",
            shape_hash="shape-hash",
            timestamp=time.time(),
            signature=b"\x00" * 64,
        )
        commitment_log.append(record)

        resp = client.get("/federation/v1/entity/fed-entity-001", headers=fed_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["found"] is True
        assert data["entity_id"] == "fed-entity-001"

    def test_query_entity_missing_auth(self, client):
        resp = client.get("/federation/v1/entity/test")
        assert resp.status_code == 403

    def test_fetch_shards_missing_entity_id(self, client, fed_headers):
        resp = client.post(
            "/federation/v1/fetch-shards",
            json={"shard_indices": [0, 1]},
            headers=fed_headers,
        )
        assert resp.status_code == 400

    def test_fetch_shards_empty_network(self, client, fed_headers):
        resp = client.post(
            "/federation/v1/fetch-shards",
            json={"entity_id": "test", "shard_indices": [0]},
            headers=fed_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0

    def test_fetch_shards_missing_auth(self, client):
        resp = client.post(
            "/federation/v1/fetch-shards",
            json={"entity_id": "test", "shard_indices": [0]},
        )
        assert resp.status_code == 403

    def test_federation_endpoints_bypass_jwt(self):
        """Federation endpoints should NOT require JWT (use own auth)."""
        config = GatewayConfig(jwt_enabled=True)
        application = create_app(config)
        application.state.commitment_log = CommitmentLog()
        application.state.commitment_network = CommitmentNetwork()
        test_client = TestClient(application)

        # Should get 403 (missing fed auth), not 401 (missing JWT)
        resp = test_client.get("/federation/v1/entity/test")
        assert resp.status_code == 403  # Federation auth, not JWT


# ---------------------------------------------------------------------------
# Client-side: HTTPFederationTransport
# ---------------------------------------------------------------------------


class TestHTTPFederationTransport:
    def test_constructor_defaults(self):
        transport = HTTPFederationTransport()
        assert transport._timeout == 30.0
        assert transport._max_retries == 2

    def test_constructor_custom(self):
        transport = HTTPFederationTransport(
            timeout_seconds=10.0,
            max_retries=5,
            backoff_base=0.5,
            backoff_max=5.0,
        )
        assert transport._timeout == 10.0
        assert transport._max_retries == 5

    def test_auth_headers_built(self):
        transport = HTTPFederationTransport()

        # Build a mock FederationAuth
        auth = MagicMock(spec=FederationAuth)
        auth.verify.return_value = True
        auth.requester_nir = MagicMock()
        auth.requester_nir.signature = b"\xaa" * 32
        auth.requester_nir.network_id = "net-001"
        auth.agreement = MagicMock()
        auth.agreement.initiator_signature = b"\xbb" * 32
        auth.agreement.responder_signature = b"\xcc" * 32

        headers = transport._auth_headers(auth)
        assert "X-Federation-NIR-Sig" in headers
        assert "X-Federation-Network-ID" in headers
        assert headers["X-Federation-Network-ID"] == "net-001"
        assert "X-Federation-Agreement-Sig" in headers
        assert "|" in headers["X-Federation-Agreement-Sig"]

    def test_fetch_shards_auth_failure_returns_empty(self):
        transport = HTTPFederationTransport()
        auth = MagicMock(spec=FederationAuth)
        auth.verify.return_value = False

        result = transport.fetch_shards("http://example.com", "eid", [0], auth)
        assert result == {}

    def test_query_entity_auth_failure_returns_none(self):
        transport = HTTPFederationTransport()
        auth = MagicMock(spec=FederationAuth)
        auth.verify.return_value = False

        result = transport.query_entity("http://example.com", "eid", auth)
        assert result is None

    def test_close_safe(self):
        transport = HTTPFederationTransport()
        transport.close()  # No client initialized, should not crash
        transport.close()  # Double close safe
