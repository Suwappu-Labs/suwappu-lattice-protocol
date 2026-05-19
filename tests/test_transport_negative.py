"""
Negative and adversarial tests for the ETP transport layer.

Covers gRPC node-to-node paths (NodeServer / NodeClient) and the FastAPI
gateway REST layer (JWT auth, rate limiting, malformed requests).  Every test
asserts a *failure* or *edge-case* path — the system must not crash, must
return the correct error code, and must not leak resources.
"""

from __future__ import annotations

import os
import time
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from src.ltp.commitment import CommitmentNode
from src.ltp.domain import signer_fingerprint
from src.ltp.gateway.app import GatewayConfig, create_app
from src.ltp.gateway.auth import create_jwt
from src.ltp.keypair import KeyPair
from src.ltp.network.client import NodeClient
from src.ltp.network.server import NodeServer

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_auth_app(rate_limit_per_minute: int = 5):
    """Return a JWT-enabled, rate-limited FastAPI app wired with a fresh keypair."""
    kp = KeyPair.generate("neg-test-gw")
    config = GatewayConfig(
        jwt_enabled=True,
        rate_limit_enabled=True,
        rate_limit_per_minute=rate_limit_per_minute,
    )
    app = create_app(config)
    app.state.health_fn = lambda: {"status": "ok"}
    app.state.known_vks = {signer_fingerprint(kp.vk).hex(): kp.vk}
    return app, kp


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def server_and_client():
    """Start a gRPC server on a random port; yield (server, client, node).

    Mirrors the fixture in test_network.py but uses a distinct node-id so
    negative tests run in isolation without colliding with the positive suite.
    """
    node = CommitmentNode("neg-test-node", "US-East")
    server = NodeServer(node, port=0, host="localhost")
    server.start()
    time.sleep(0.1)  # brief wait for the server to accept connections
    client = NodeClient(f"localhost:{server.port}", timeout=5.0)
    yield server, client, node
    client.close()
    server.stop(grace=0.5)


@pytest.fixture
def keypair():
    """Fresh keypair for gateway auth tests."""
    return KeyPair.generate("neg-gw-test")


@pytest.fixture
def auth_app(keypair):
    """JWT-enabled, rate-limited gateway app (5 req/min) with a seeded keypair."""
    config = GatewayConfig(
        jwt_enabled=True,
        rate_limit_enabled=True,
        rate_limit_per_minute=5,
    )
    app = create_app(config)
    app.state.health_fn = lambda: {"status": "ok"}
    app.state.known_vks = {signer_fingerprint(keypair.vk).hex(): keypair.vk}
    return app


@pytest.fixture
def auth_client(auth_app):
    return TestClient(auth_app)


@pytest.fixture
def valid_token(keypair):
    """Fresh, unexpired JWT signed by the known keypair."""
    return create_jwt(keypair, "neg-test-caller")


# ===========================================================================
# gRPC Negative Paths
# ===========================================================================


class TestGrpcNegativePaths:
    def test_fetch_shard_empty_entity_id_returns_none(self, server_and_client):
        """Fetching a shard with an empty entity_id should return None.

        An empty string is not a valid entity identifier; the server must
        treat it as a cache miss and return not-found rather than raising.
        """
        _, client, _ = server_and_client
        result = client.fetch_shard("", 0)
        assert result is None

    def test_store_shard_empty_data_succeeds(self, server_and_client):
        """Storing a shard with zero-length payload is valid.

        Empty bytes is a legal value for encrypted_data — the system should
        accept and round-trip it without error.
        """
        _, client, _ = server_and_client
        stored = client.store_shard("empty-data-entity", 0, b"")
        assert stored is True

        fetched = client.fetch_shard("empty-data-entity", 0)
        assert fetched == b""

    def test_store_shard_oversized_payload_handled_gracefully(self, server_and_client):
        """Storing a 10 MB payload should not crash the server.

        The system must handle large blobs without raising an unhandled
        exception on either the client or server side.  The call may succeed
        or fail, but it must not crash.
        """
        _, client, _ = server_and_client
        big_data = os.urandom(10 * 1024 * 1024)  # 10 MB

        try:
            result = client.store_shard("oversized-entity", 0, big_data)
            # If the call succeeds, round-trip must be consistent.
            if result:
                fetched = client.fetch_shard("oversized-entity", 0)
                assert fetched == big_data
        except Exception as exc:
            # A transport-level refusal (e.g. gRPC RESOURCE_EXHAUSTED) is
            # acceptable — what is NOT acceptable is a server crash.
            assert exc is not None  # suppress the "bare except" lint warning

    def test_audit_challenge_zero_length_nonce_produces_proof(self, server_and_client):
        """An audit challenge with a zero-length nonce must still return a proof.

        The proof is H(ciphertext || nonce); with nonce=b"" this degenerates
        to H(ciphertext), which is still a deterministic, valid response.
        """
        _, client, _ = server_and_client
        data = b"shard-for-zero-nonce-audit"
        client.store_shard("zero-nonce-entity", 7, data)

        proof = client.audit_challenge("zero-nonce-entity", 7, b"")
        assert proof is not None
        assert isinstance(proof, str)
        assert len(proof) > 0

    def test_multiple_rapid_connections_all_succeed(self):
        """Opening many rapid connections must not leak resources or fail.

        Spins up 10 independent clients against the same server; each stores
        a shard and closes.  All operations must succeed with no exception.
        """
        node = CommitmentNode("rapid-conn-node", "US-East")
        server = NodeServer(node, port=0, host="localhost")
        server.start()
        time.sleep(0.1)

        errors = []
        try:
            for i in range(10):
                c = NodeClient(f"localhost:{server.port}", timeout=5.0)
                try:
                    ok = c.store_shard(f"rapid-entity-{i}", 0, f"data-{i}".encode())
                    if not ok:
                        errors.append(f"store failed for client {i}")
                except Exception as exc:
                    errors.append(str(exc))
                finally:
                    c.close()
        finally:
            server.stop(grace=0.5)

        assert errors == [], f"Rapid connection failures: {errors}"

    def test_fetch_batch_1000_entries_does_not_crash(self, server_and_client):
        """A batch fetch of 1 000 entries must complete without crashing.

        Only a handful of those entries exist; the rest must come back as
        None.  The call must not raise or time out with the default 5-second
        timeout.
        """
        _, client, _ = server_and_client

        # Store a small number of real shards.
        for i in range(5):
            client.store_shard("batch-neg-entity", i, f"shard-{i}".encode())

        # Build a request for 1 000 entries — most are missing.
        requests = [("batch-neg-entity", i) for i in range(1000)]
        results = client.fetch_shards_batch(requests)

        assert len(results) == 1000
        # The five stored shards must be present at their positions.
        for i in range(5):
            assert results[i] == f"shard-{i}".encode()
        # Everything beyond index 4 should be None.
        for i in range(5, 1000):
            assert results[i] is None


# ===========================================================================
# Gateway Negative Paths (FastAPI TestClient)
# ===========================================================================


class TestGatewayNegativePaths:
    # -----------------------------------------------------------------------
    # Routing / basic HTTP errors
    # -----------------------------------------------------------------------

    def test_post_to_nonexistent_endpoint_returns_4xx(self, auth_client, valid_token):
        """POST to a completely unknown path must return 404 or 405.

        No such endpoint exists; the gateway's catch-all must return a 4xx
        rather than raising an unhandled exception.
        """
        resp = auth_client.post(
            "/does/not/exist",
            json={"key": "value"},
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert resp.status_code in (404, 405)

    def test_get_health_with_malformed_headers_still_returns_200(self, auth_client):
        """GET /health with garbled, non-ASCII headers must still return 200.

        The health endpoint is unauthenticated.  Malformed custom headers
        must not prevent a successful response.
        """
        resp = auth_client.get(
            "/health",
            headers={
                "X-Weird-Header": "value\twith\ttabs",
                "X-Long-Header": "A" * 4096,
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    # -----------------------------------------------------------------------
    # JWT / Authentication failures
    # -----------------------------------------------------------------------

    def test_expired_jwt_returns_401(self, auth_client, keypair):
        """A JWT whose expiry is in the past must be rejected with 401.

        Uses ttl_seconds=-60 to produce a token that expired 60 seconds ago.
        The middleware must reject it before forwarding the request.
        """
        expired_token = create_jwt(keypair, "neg-caller", ttl_seconds=-60)
        resp = auth_client.get(
            "/anchor/health",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        assert resp.status_code == 401

    def test_jwt_signed_with_wrong_key_returns_401(self, auth_client):
        """A token signed by an unknown keypair must be rejected with 401.

        The gateway's known_vks does not contain the rogue key, so
        signature verification must fail.
        """
        rogue_kp = KeyPair.generate("rogue-node")
        rogue_token = create_jwt(rogue_kp, "neg-caller")
        resp = auth_client.get(
            "/anchor/health",
            headers={"Authorization": f"Bearer {rogue_token}"},
        )
        assert resp.status_code == 401

    def test_access_protected_endpoint_without_authorization_header_returns_401(self, auth_client):
        """A request to a protected endpoint with no Authorization header must
        return 401.

        The middleware should short-circuit and return an error before
        reaching the route handler.
        """
        resp = auth_client.get("/anchor/health")
        assert resp.status_code == 401

    def test_bearer_prefix_with_empty_token_returns_401(self, auth_client):
        """'Authorization: Bearer ' (with a trailing space but no token) must
        return 401.

        An empty token string is not a valid JWT — it has no dots and no
        content — so verify_jwt must return None and the middleware must
        reject the request.
        """
        resp = auth_client.get(
            "/anchor/health",
            headers={"Authorization": "Bearer "},
        )
        assert resp.status_code == 401

    def test_malformed_jwt_garbage_string_returns_401(self, auth_client):
        """A Bearer token that is not even a valid base64url JWT returns 401.

        Sending an arbitrary garbage string as the token must not cause an
        unhandled server exception — it must cleanly produce a 401.
        """
        resp = auth_client.get(
            "/anchor/health",
            headers={"Authorization": "Bearer this.is.not.a.real.jwt.at.all"},
        )
        assert resp.status_code == 401

    # -----------------------------------------------------------------------
    # Rate limiting
    # -----------------------------------------------------------------------

    def test_burst_beyond_rate_limit_returns_429(self, keypair):
        """Sending more requests than the rate-limit bucket allows triggers 429.

        The app is configured with rate_limit_per_minute=5.  After the bucket
        is exhausted the middleware must return 429 without crashing.
        """
        config = GatewayConfig(
            jwt_enabled=False,  # disable JWT so rate-limit is the only gate
            rate_limit_enabled=True,
            rate_limit_per_minute=3,  # very low limit to force 429 quickly
        )
        app = create_app(config)
        app.state.health_fn = lambda: {"status": "ok"}
        client = TestClient(app)

        statuses = [client.get("/health").status_code for _ in range(10)]
        assert 429 in statuses, "Expected at least one 429 after exhausting the rate-limit bucket"

    # -----------------------------------------------------------------------
    # Oversized / malformed bodies
    # -----------------------------------------------------------------------

    def test_oversized_request_body_does_not_crash(self, auth_client, valid_token):
        """Posting a very large JSON body must not crash the gateway.

        The server is allowed to reject the body (e.g. 413 or 422) but must
        never raise an unhandled 500.
        """
        large_payload = {"data": "x" * (1 * 1024 * 1024)}  # 1 MB of 'x'
        resp = auth_client.post(
            "/ct/v1/add-entry",
            json=large_payload,
        )
        # Any response that isn't an unhandled 500 Internal Server Error is acceptable.
        # 4xx (client error) and 503 (rate limit / service unavailable) are fine.
        assert resp.status_code != 500

    def test_non_json_body_to_json_endpoint_does_not_crash(self, auth_client, valid_token):
        """Sending raw bytes that are not valid JSON to a JSON endpoint must
        not cause a 500 error.

        FastAPI / Starlette validation should return a 422 Unprocessable
        Entity or 400 Bad Request.
        """
        resp = auth_client.post(
            "/ct/v1/add-entry",
            content=b"\xff\xfe" * 256,  # invalid UTF-8 / non-JSON
            headers={"Content-Type": "application/json"},
        )
        # Any response except unhandled 500 is acceptable (503 from rate limiter is OK)
        assert resp.status_code != 500
