"""
Tests for the FastAPI gateway: app factory, server lifecycle, CT log routes,
health endpoint, and route migration.
"""

from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

from src.ltp.commitment import CommitmentLog, CommitmentRecord
from src.ltp.domain import signer_fingerprint
from src.ltp.gateway.app import GatewayConfig, GatewayServer, create_app
from src.ltp.gateway.auth import create_jwt
from src.ltp.keypair import KeyPair

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def keypair():
    return KeyPair.generate("gateway-test")


@pytest.fixture
def commitment_log():
    log = CommitmentLog()
    return log


@pytest.fixture
def app(commitment_log, keypair):
    config = GatewayConfig(jwt_enabled=False)
    application = create_app(config)
    application.state.commitment_log = commitment_log
    application.state.health_fn = lambda: {"status": "ok", "uptime": 42}
    application.state.keypair = keypair
    kid = signer_fingerprint(keypair.vk).hex()
    application.state.known_vks = {kid: keypair.vk}
    return application


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def auth_app(commitment_log, keypair):
    config = GatewayConfig(jwt_enabled=True)
    application = create_app(config)
    application.state.commitment_log = commitment_log
    application.state.health_fn = lambda: {"status": "ok"}
    application.state.keypair = keypair
    kid = signer_fingerprint(keypair.vk).hex()
    application.state.known_vks = {kid: keypair.vk}
    return application


@pytest.fixture
def auth_client(auth_app):
    return TestClient(auth_app)


@pytest.fixture
def auth_headers(keypair):
    token = create_jwt(keypair, "test-node")
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["uptime"] == 42

    def test_health_unauthenticated_even_with_jwt(self, auth_client):
        """Health endpoint should NOT require auth."""
        resp = auth_client.get("/health")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# CT Log Endpoints
# ---------------------------------------------------------------------------


class TestCTLogEndpoints:
    def test_get_sth_empty_log(self, client):
        resp = client.get("/ct/v1/get-sth")
        assert resp.status_code == 200
        data = resp.json()
        assert data["tree_size"] == 0

    def test_get_sth_after_commit(self, client, commitment_log):
        """After appending, STH should reflect tree_size=1."""
        record = CommitmentRecord(
            entity_id="test-entity-001",
            sender_id="sender",
            content_hash="hash",
            shard_map_root="root",
            encoding_params={"n": 5, "k": 3, "algorithm": "reed-solomon"},
            shape="application/octet-stream",
            shape_hash="shape-hash",
            timestamp=time.time(),
            signature=b"\x00" * 64,
        )
        commitment_log.append(record)
        resp = client.get("/ct/v1/get-sth")
        assert resp.status_code == 200
        data = resp.json()
        assert data["tree_size"] == 1

    def test_get_entries_empty(self, client):
        resp = client.get("/ct/v1/get-entries?start=0&end=0")
        assert resp.status_code == 200
        data = resp.json()
        assert data["entries"] == []

    def test_get_entries_invalid_range(self, client):
        resp = client.get("/ct/v1/get-entries?start=-1&end=0")
        assert resp.status_code == 400

    def test_get_proof_missing_entity_id(self, client):
        resp = client.get("/ct/v1/get-proof-by-hash")
        assert resp.status_code == 400

    def test_get_proof_not_found(self, client):
        resp = client.get("/ct/v1/get-proof-by-hash?entity_id=nonexistent")
        assert resp.status_code == 404

    def test_get_consistency_invalid_range(self, client):
        resp = client.get("/ct/v1/get-sth-consistency?first=0&second=1")
        assert resp.status_code == 400

    def test_get_entry_and_proof_missing(self, client):
        resp = client.get("/ct/v1/get-entry-and-proof?entity_id=missing")
        assert resp.status_code == 404

    def test_get_entry_and_proof_no_entity_id(self, client):
        resp = client.get("/ct/v1/get-entry-and-proof")
        assert resp.status_code == 400

    def test_add_entry_empty_body(self, client):
        resp = client.post("/ct/v1/add-entry")
        assert resp.status_code == 400

    def test_add_entry_stub_response(self, client):
        resp = client.post("/ct/v1/add-entry", json={"entity_id": "test"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "received"

    def test_ct_routes_unauthenticated_with_jwt_enabled(self, auth_client):
        """CT log routes should NOT require JWT even when jwt_enabled=True."""
        resp = auth_client.get("/ct/v1/get-sth")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Unknown Routes
# ---------------------------------------------------------------------------


class TestCatchAll:
    def test_unknown_route_returns_404(self, client):
        resp = client.get("/nonexistent")
        assert resp.status_code == 404
        data = resp.json()
        assert "error" in data

    def test_unknown_ct_route_returns_404(self, client):
        resp = client.get("/ct/v1/unknown-endpoint")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# JWT Auth Enforcement
# ---------------------------------------------------------------------------


class TestJWTEnforcement:
    def test_anchor_routes_require_auth(self, auth_client):
        resp = auth_client.get("/anchor/stats")
        assert resp.status_code == 401

    def test_diagnostics_routes_require_auth(self, auth_client):
        resp = auth_client.get("/node/peers")
        assert resp.status_code == 401

    def test_anchor_routes_with_valid_jwt(self, auth_client, auth_headers):
        resp = auth_client.get("/anchor/health", headers=auth_headers)
        assert resp.status_code == 200

    def test_diagnostics_with_valid_jwt(self, auth_client, auth_headers):
        resp = auth_client.get("/node/audit", headers=auth_headers)
        assert resp.status_code == 200

    def test_invalid_bearer_rejected(self, auth_client):
        resp = auth_client.get("/anchor/health", headers={"Authorization": "Bearer invalid"})
        assert resp.status_code == 401

    def test_missing_bearer_prefix_rejected(self, auth_client):
        resp = auth_client.get("/anchor/health", headers={"Authorization": "Token abc"})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------------


class TestRateLimiting:
    def test_rate_limiter_allows_under_limit(self):
        config = GatewayConfig(rate_limit_enabled=True, rate_limit_per_minute=10, jwt_enabled=False)
        application = create_app(config)
        application.state.health_fn = lambda: {"status": "ok"}
        client = TestClient(application)

        for _ in range(10):
            resp = client.get("/health")
            assert resp.status_code == 200

    def test_rate_limiter_rejects_over_limit(self):
        config = GatewayConfig(rate_limit_enabled=True, rate_limit_per_minute=2, jwt_enabled=False)
        application = create_app(config)
        application.state.health_fn = lambda: {"status": "ok"}
        application.state.commitment_log = None
        client = TestClient(application)

        # Exhaust the bucket (initial burst = max_per_minute = 2)
        statuses = []
        for _ in range(5):
            resp = client.get("/health")
            statuses.append(resp.status_code)

        assert 429 in statuses


# ---------------------------------------------------------------------------
# GatewayServer Lifecycle
# ---------------------------------------------------------------------------


class TestGatewayServer:
    def test_server_starts_and_stops(self, keypair, commitment_log):
        server = GatewayServer(
            config=GatewayConfig(port=0),
            health_fn=lambda: {"status": "ok"},
            commitment_log=commitment_log,
            keypair=keypair,
        )
        server.start()
        try:
            assert server.port > 0
            assert server.url.startswith("http://")

            import urllib.request

            resp = urllib.request.urlopen(f"{server.url}/health")
            data = json.loads(resp.read())
            assert data["status"] == "ok"
        finally:
            server.stop()

    def test_server_ephemeral_port(self, keypair):
        server = GatewayServer(
            config=GatewayConfig(port=0),
            health_fn=lambda: {"ok": True},
            keypair=keypair,
        )
        server.start()
        try:
            assert server.port != 0
            assert server.port > 1024
        finally:
            server.stop()
